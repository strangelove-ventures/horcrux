package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/cosigner"

	"github.com/strangelove-ventures/horcrux/pkg/config"
	"github.com/strangelove-ventures/horcrux/pkg/connector"
	"github.com/strangelove-ventures/horcrux/pkg/metrics"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/cometbft/cometbft/libs/log"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ connector.IPrivValidator = &ThresholdValidator{}

// TODO: Must be a better way to do this?
type nodecacheconfigs struct {
	defaultGetNoncesInterval time.Duration
	defaultGetNoncesTimeout  time.Duration
	defaultNonceExpiration   time.Duration
}

func nodecacheconfig() nodecacheconfigs {
	return nodecacheconfigs{
		defaultGetNoncesInterval: config.DefaultGetNoncesInterval,
		defaultGetNoncesTimeout:  config.DefaultGetNoncesTimeout,
		defaultNonceExpiration:   config.DefaultNonceExpiration,
	}
}

// ThresholdValidator is the server that responds to sign requests from the "sentry"
type ThresholdValidator struct {
	config *config.RuntimeConfig

	threshold int

	grpcTimeout time.Duration

	chainState sync.Map // map[string]SignState, chainState["chainid"] -> types.SignState

	// our own cosigner
	MyCosigner *cosigner.LocalCosigner // TODO Should be an interface as well.

	// peer cosigners
	peerCosigners ICosigners // "i.e clients to call"

	leader ILeader

	logger log.Logger

	pendingDiskWG sync.WaitGroup

	maxWaitForSameBlockAttempts int

	cosignerHealth *CosignerHealth

	// FIX: This f-up a lot. Now its like 3-4 places that
	// spaggettio leaders, cosigners etc etc
	nonceCache *CosignerNonceCache
}

type StillWaitingForBlockError struct {
	msg string
}

func (e *StillWaitingForBlockError) Error() string { return e.msg }

func newStillWaitingForBlockError(chainID string, hrs types.HRS) *StillWaitingForBlockError {
	return &StillWaitingForBlockError{
		msg: fmt.Sprintf("[%s] Still waiting for block %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

type SameBlockError struct {
	msg string
}

func (e *SameBlockError) Error() string { return e.msg }

func newSameBlockError(chainID string, hrs types.HRS) *SameBlockError {
	return &SameBlockError{
		msg: fmt.Sprintf("[%s] Same block: %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

type ChainSignState struct {
	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState      *types.SignState
	lastSignStateMutex *sync.Mutex

	// stores the last sign state that we've started progress on
	lastSignStateInitiated      *types.SignState
	lastSignStateInitiatedMutex *sync.Mutex
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

func (pv *ThresholdValidator) newBeyondBlockError(chainID string, hrs types.HRS) *BeyondBlockError {
	css := pv.mustLoadChainState(chainID)

	lss := css.lastSignStateInitiated
	return &BeyondBlockError{
		msg: fmt.Sprintf("[%s] Progress already started on block %d.%d.%d, skipping %d.%d.%d",
			chainID,
			lss.Height, lss.Round, lss.Step,
			hrs.Height, hrs.Round, hrs.Step,
		),
	}
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(
	logger log.Logger,
	config *config.RuntimeConfig,
	threshold int,
	grpcTimeout time.Duration,
	maxWaitForSameBlockAttempts int,
	myCosigner *cosigner.LocalCosigner,
	peerCosigners []ICosigner,
	leader ILeader,
) *ThresholdValidator {
	allCosigners := make([]ICosigner, len(peerCosigners)+1)
	allCosigners[0] = myCosigner
	copy(allCosigners[1:], peerCosigners)

	for _, cosigner := range peerCosigners {
		logger.Debug("Peer cosigner", "id", cosigner.GetIndex())
	}

	nodecacheconfig := nodecacheconfig()
	nc := NewCosignerNonceCache(
		logger,
		allCosigners,
		leader,
		nodecacheconfig.defaultGetNoncesInterval,
		nodecacheconfig.defaultGetNoncesTimeout,
		nodecacheconfig.defaultNonceExpiration,
		uint8(threshold),
		nil,
	)
	return &ThresholdValidator{
		logger:                      logger,
		config:                      config,
		threshold:                   threshold,
		grpcTimeout:                 grpcTimeout,
		maxWaitForSameBlockAttempts: maxWaitForSameBlockAttempts,
		MyCosigner:                  myCosigner,
		peerCosigners:               peerCosigners,
		leader:                      leader,
		cosignerHealth:              NewCosignerHealth(logger, peerCosigners, leader),
		nonceCache:                  nc,
	}
}

// Start starts the ThresholdValidator.
func (pv *ThresholdValidator) Start(ctx context.Context) error {
	pv.logger.Info("Starting ThresholdValidator services")

	go pv.cosignerHealth.Start(ctx)

	go pv.nonceCache.Start(ctx)

	go pv.MyCosigner.StartNoncePruner(ctx)

	return nil
}

// SaveLastSignedState updates the high watermark height/round/step (HRS) for a completed
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedState(chainID string, signState types.SignStateConsensus) error {
	css := pv.mustLoadChainState(chainID)

	css.lastSignStateMutex.Lock()
	defer css.lastSignStateMutex.Unlock()
	return css.lastSignState.Save(signState, &pv.pendingDiskWG)
}

func (pv *ThresholdValidator) mustLoadChainState(chainID string) ChainSignState {
	cs, ok := pv.chainState.Load(chainID) //
	if !ok {
		panic(fmt.Errorf("failed to load chain state for %s", chainID))
	}

	css, ok := cs.(ChainSignState)
	if !ok {
		panic(fmt.Errorf("expected: type (ChainSignState), actual type is: (%T)", cs))
	}

	return css
}

// SaveLastSignedStateInitiated updates the high watermark height/round/step (HRS) for an initiated
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedStateInitiated(
	chainID string, block *types.Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	height, round, step := block.Height, block.Round, block.Step

	err := css.lastSignStateInitiated.Save(types.NewSignStateConsensus(height, round, step), &pv.pendingDiskWG)
	if err == nil {
		// good to sign
		return nil, time.Time{}, nil
	}

	// There was an error saving the last sign state, so check if there is an existing signature for this block.
	existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)

	var sameHRSError *types.SameHRSError
	if !errors.As(err, &sameHRSError) {
		if sameBlockErr == nil {
			return existingSignature, block.Timestamp, nil
		}
		return nil, existingTimestamp, pv.newBeyondBlockError(chainID, block.GetHRS())
	}

	if sameBlockErr == nil {
		if existingSignature != nil {
			// signature already exists for this block. return it.
			return existingSignature, existingTimestamp, nil
		}
		// good to sign again
		return nil, time.Time{}, nil
	}

	var stillWaitingForBlockError *StillWaitingForBlockError
	if !errors.As(sameBlockErr, &stillWaitingForBlockError) {
		// we have an error other than still waiting for block. return error.
		return nil, existingTimestamp, fmt.Errorf(
			"same block error, but we are not still waiting for signature: %w",
			sameBlockErr,
		)
	}

	// the cluster is already in progress signing this block
	// wait for cluster to finish before proceeding

	// intended usage of cond lock prior to cond.Wait().
	// cond.Wait() will unlock cond.L while it blocks waiting, then re-lock when unblocking from
	// the cond.Broadcast().
	css.lastSignState.CondLock()
	defer css.lastSignState.CondUnlock()
	for i := 0; i < pv.maxWaitForSameBlockAttempts; i++ {
		// block until sign state is saved. It will notify and unblock when block is next signed.
		css.lastSignState.CondWaitWithTimeout(pv.grpcTimeout)

		// check if HRS exists in cache now
		ssc, ok := css.lastSignState.GetCache(block.GetHRS())
		if !ok {
			pv.logger.Debug(
				"Block does not yet exist in cache while waiting for signature",
				"height", height,
				"round", round,
				"step", step,
			)
			continue
		}

		existingSignature, existingTimestamp, sameBlockErr = pv.compareBlockSignatureAgainstSSC(chainID, block, &ssc)
		if sameBlockErr == nil {
			return existingSignature, existingTimestamp, nil
		}
		if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
			return nil, existingTimestamp, fmt.Errorf(
				"same block error in loop, but we are not still waiting for signature: %w",
				sameBlockErr,
			)
		}

		latest := css.lastSignState

		pv.logger.Debug(
			"Waiting for block to be signed",
			"height", height,
			"round", round,
			"step", step,
			"latest_height", latest.Height,
			"latest_round", latest.Round,
			"latest_step", latest.Step,
		)
	}

	return nil, existingTimestamp, fmt.Errorf(
		"exceeded max attempts waiting for block to be signed. height: %d, round: %d, step: %d",
		height, round, step,
	)
}

// notifyBlockSignError will alert any waiting goroutines that an error
// has occurred during signing and a retry can be attempted.
func (pv *ThresholdValidator) notifyBlockSignError(chainID string, hrs types.HRS, signBytes []byte) {
	css := pv.mustLoadChainState(chainID)

	css.lastSignState.Lock() // Call alias lock function.
	css.lastSignState.SetCache(hrs, types.SignStateConsensus{
		Height: hrs.Height,
		Round:  hrs.Round,
		Step:   hrs.Step,
		// empty signature to indicate error
		SignBytes: signBytes,
	})

	css.lastSignState.Unlock()
	css.lastSignState.CondBroadcast()
}

// Stop safely shuts down the ThresholdValidator.
func (pv *ThresholdValidator) Stop() {
	pv.waitForSignStatesToFlushToDisk()
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (pv *ThresholdValidator) waitForSignStatesToFlushToDisk() {
	pv.pendingDiskWG.Wait()

	pv.MyCosigner.WaitForSignStatesToFlushToDisk()
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey(_ context.Context, chainID string) ([]byte, error) {
	pubKey, err := pv.MyCosigner.GetPubKey(chainID)
	if err != nil {
		return nil, err
	}
	return pubKey.Bytes(), nil
}

func (pv *ThresholdValidator) LoadSignStateIfNecessary(chainID string) error {
	if _, ok := pv.chainState.Load(chainID); ok {
		return nil
	}

	signState, err := types.LoadOrCreateSignState(pv.config.PrivValStateFile(chainID))
	if err != nil {
		return err
	}

	lastSignStateInitiated := signState.FreshCache()
	lastSignStateInitiated.FilePath = os.DevNull

	pv.chainState.Store(chainID, ChainSignState{
		lastSignState:          signState,
		lastSignStateInitiated: lastSignStateInitiated,

		lastSignStateMutex:          &sync.Mutex{},
		lastSignStateInitiatedMutex: &sync.Mutex{},
	})

	return pv.MyCosigner.LoadSignStateIfNecessary(chainID)
}

// getExistingBlockSignature returns the existing block signature and no error if the signature is valid for the block.
// It returns nil signature and nil error if there is no signature and it's okay to sign (fresh or again).
// It returns an error if we have already signed a greater block, or if we are still waiting for in in-progress sign.
func (pv *ThresholdValidator) getExistingBlockSignature(chainID string, block *types.Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	latestBlock, existingSignature := css.lastSignState.GetFromCache(block.GetHRS())
	if existingSignature != nil {
		// signature exists in cache, so compare against that
		return pv.compareBlockSignatureAgainstSSC(chainID, block, existingSignature)
	}

	// signature does not exist in cache, so compare against latest signed block.
	return nil, block.Timestamp, compareBlockSignatureAgainstHRS(pv, chainID, block, latestBlock)
}

// compareBlockSignatureAgainstSSC compares a block's HRS against a cached signature.
//
// If the existing signature is for a greater HRS than the block, we are already beyond
// the requested HRS, so we can error and move on.
//
// If the existing signature is for a lesser HRS than the block, then we can return
// a stillWaitingForBlock error to continue waiting for the HRS to be signed.
//
// If the HRS of the existing signature and the block are the same, we return the existing signature
// if the block sign request is for a proposal or if the bytes to sign are identical.
func (pv *ThresholdValidator) compareBlockSignatureAgainstSSC(
	chainID string,
	block *types.Block,
	existingSignature *types.SignStateConsensus,
) ([]byte, time.Time, error) {
	stamp, signBytes := block.Timestamp, block.SignBytes

	if err := compareBlockSignatureAgainstHRS(pv, chainID, block, existingSignature.HRSKey()); err != nil {
		if _, ok := err.(*metrics.SameBlockError); !ok {
			return nil, stamp, err
		}
	}

	// If a proposal has already been signed for this HRS, or the sign payload is identical, return the existing signature.
	if block.Step == types.StepPropose || bytes.Equal(signBytes, existingSignature.SignBytes) {
		return existingSignature.Signature, block.Timestamp, nil
	}

	// If there is a difference in the existing signature payload other than timestamp, return that error.
	if err := existingSignature.OnlyDifferByTimestamp(signBytes); err != nil {
		return nil, stamp, err
	}

	// only differ by timestamp, okay to sign again
	return nil, stamp, nil
}

// compareBlockSignatureAgainstHRS returns a BeyondBlockError if the hrs is greater than the
// block. It returns a StillWaitingForBlockError if the hrs is less than the block. If returns nil if the hrs is
// equal to the block.
func compareBlockSignatureAgainstHRS(
	pv *ThresholdValidator,
	chainID string,
	block *types.Block,
	hrs types.HRS,
) error {
	blockHRS := block.GetHRS()

	if hrs.GreaterThan(blockHRS) {
		return pv.newBeyondBlockError(chainID, blockHRS)
	}

	if hrs == blockHRS {
		return newSameBlockError(chainID, blockHRS)
	}

	return newStillWaitingForBlockError(chainID, blockHRS)
}

func (pv *ThresholdValidator) getNoncesFallback(
	ctx context.Context,
) (*cosigner.CosignerUUIDNonces, []ICosigner, error) {
	nonces := make(map[ICosigner]cosigner.CosignerNonces)

	metrics.DrainedNonceCache.Inc()
	metrics.TotalDrainedNonceCache.Inc()

	var wg sync.WaitGroup
	wg.Add(pv.threshold)

	var mu sync.Mutex

	u := uuid.New()

	allCosigners := make([]ICosigner, len(pv.peerCosigners)+1)
	allCosigners[0] = pv.MyCosigner
	copy(allCosigners[1:], pv.peerCosigners)

	for _, c := range allCosigners {
		go pv.waitForPeerNonces(ctx, u, c, &wg, nonces, &mu)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&wg, pv.grpcTimeout) {
		return nil, nil, errors.New("timed out waiting for ephemeral shares")
	}

	var thresholdNonces cosigner.CosignerNonces
	thresholdCosigners := make([]ICosigner, len(nonces))
	i := 0
	for c, n := range nonces {
		thresholdCosigners[i] = c
		i++

		thresholdNonces = append(thresholdNonces, n...)
	}

	return &cosigner.CosignerUUIDNonces{
		UUID:   u,
		Nonces: thresholdNonces,
	}, thresholdCosigners, nil
}

func waitUntilCompleteOrTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func (pv *ThresholdValidator) waitForPeerNonces(
	ctx context.Context,
	u uuid.UUID,
	peer ICosigner,
	wg *sync.WaitGroup,
	nonces map[ICosigner]cosigner.CosignerNonces,
	mu sync.Locker,
) {
	peerStartTime := time.Now()
	peerNonces, err := peer.GetNonces(ctx, []uuid.UUID{u})
	if err != nil {
		metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Inc()
		metrics.TotalMissedNonces.WithLabelValues(peer.GetAddress()).Inc()

		pv.logger.Error("Error getting nonces", "cosigner", peer.GetIndex(), "err", err)
		return
	}

	metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Set(0)
	metrics.TimedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	// Check so that wg.Done is not called more than (threshold - 1) times which causes hardlock
	mu.Lock()
	if len(nonces) < pv.threshold {
		nonces[peer] = peerNonces[0].Nonces
		defer wg.Done()
	}
	mu.Unlock()
}

func (pv *ThresholdValidator) proxyIfNecessary(
	ctx context.Context,
	chainID string,
	block types.Block,
) (bool, []byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

	if pv.leader.IsLeader() {
		return false, nil, time.Time{}, nil
	}

	leader := pv.leader.GetLeader()

	// TODO is there a better way than to poll during leader election?
	for i := 0; i < 500 && leader == -1; i++ {
		time.Sleep(10 * time.Millisecond)
		leader = pv.leader.GetLeader()
	}

	if leader == -1 {
		metrics.TotalRaftLeaderElectionTimeout.Inc()
		return true, nil, stamp, fmt.Errorf("timed out waiting for raft leader")
	}

	if leader == pv.MyCosigner.GetIndex() {
		return false, nil, time.Time{}, nil
	}

	pv.logger.Debug("I am not the leader. Proxying request to the leader",
		"chain_id", chainID,
		"height", height,
		"round", round,
		"step", step,
	)
	metrics.TotalNotRaftLeader.Inc()

	cosignerLeader := pv.peerCosigners.GetByIndex(leader)
	if cosignerLeader == nil {
		return true, nil, stamp, fmt.Errorf("failed to find cosigner with id %d", leader)
	}

	signRes, err := cosignerLeader.(*cosigner.RemoteCosigner).Sign(ctx, cosigner.CosignerSignBlockRequest{
		ChainID: chainID,
		Block:   &block,
	})
	if err != nil {
		if _, ok := err.(*cometrpcjsontypes.RPCError); ok {
			rpcErrUnwrapped := err.(*cometrpcjsontypes.RPCError).Data
			// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
			if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
				return true, nil, stamp, &metrics.BeyondBlockError{Msg: rpcErrUnwrapped}
			}
		}
		return true, nil, stamp, err
	}
	return true, signRes.Signature, stamp, nil
}

func (pv *ThresholdValidator) Sign(ctx context.Context, chainID string, block types.Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes

	log := pv.logger.With(
		"chain_id", chainID,
		"height", height,
		"round", round,
		"type", types.SignType(step),
	)

	if err := pv.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, stamp, err
	}

	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	isProxied, proxySig, proxyStamp, err := pv.proxyIfNecessary(ctx, chainID, block)
	if isProxied {
		return proxySig, proxyStamp, err
	}

	metrics.TotalRaftLeader.Inc()

	log.Debug("I am the leader. Managing the sign process for this block")

	timeStartSignBlock := time.Now()

	hrst := block.ToHRST()
	/*
		types.HRST{
			Height:    height,
			Round:     round,
			Step:      step,
			Timestamp: stamp.UnixNano(),
		}
	*/

	// Keep track of the last block that we began the signing process for. Only allow one attempt per block
	existingSignature, existingTimestamp, err := pv.SaveLastSignedStateInitiated(chainID, &block)
	if err != nil {
		return nil, stamp, fmt.Errorf("error saving last sign state initiated: %w", err)
	}
	if existingSignature != nil {
		log.Debug("Returning existing signature", "signature", fmt.Sprintf("%x", existingSignature))
		return existingSignature, existingTimestamp, nil
	}

	numPeers := len(pv.peerCosigners)
	total := uint8(numPeers + 1)

	peerStartTime := time.Now()

	cosignersOrderedByFastest := pv.cosignerHealth.GetFastest()
	cosignersForThisBlock := make([]ICosigner, pv.threshold)
	cosignersForThisBlock[0] = pv.MyCosigner
	copy(cosignersForThisBlock[1:], cosignersOrderedByFastest[:pv.threshold-1])

	nonces, err := pv.nonceCache.GetNonces(cosignersForThisBlock)

	var dontIterateFastestCosigners bool

	if err != nil {
		var fallbackErr error
		nonces, cosignersForThisBlock, fallbackErr = pv.getNoncesFallback(ctx)
		if fallbackErr != nil {
			pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
			return nil, stamp, fmt.Errorf("failed to get nonces: %w", errors.Join(err, fallbackErr))
		}
		dontIterateFastestCosigners = true
	} else {
		metrics.DrainedNonceCache.Set(0)
	}

	nextFastestCosignerIndex := pv.threshold - 1
	var nextFastestCosignerIndexMu sync.Mutex
	getNextFastestCosigner := func() ICosigner {
		nextFastestCosignerIndexMu.Lock()
		defer nextFastestCosignerIndexMu.Unlock()
		if nextFastestCosignerIndex >= len(cosignersOrderedByFastest) {
			return nil
		}
		cosigner := cosignersOrderedByFastest[nextFastestCosignerIndex]
		nextFastestCosignerIndex++
		return cosigner
	}

	metrics.TimedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())

	for _, peer := range pv.peerCosigners {
		metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Set(0)
		metrics.TimedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	}

	cosignersForThisBlockInt := make([]int, len(cosignersForThisBlock))

	for i, cosigner := range cosignersForThisBlock {
		cosignersForThisBlockInt[i] = cosigner.GetIndex()
	}

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	var eg errgroup.Group
	for _, remote_cosigner := range cosignersForThisBlock {
		remote_cosigner := remote_cosigner
		eg.Go(func() error {
			for remote_cosigner != nil {
				signCtx, cancel := context.WithTimeout(ctx, pv.grpcTimeout)
				defer cancel()

				peerStartTime := time.Now()

				// set peerNonces and sign in single rpc call.
				sigRes, err := remote_cosigner.SetNoncesAndSign(signCtx, cosigner.CosignerSetNoncesAndSignRequest{
					ChainID:   chainID,
					Nonces:    nonces.For(remote_cosigner.GetIndex()),
					HRST:      hrst,
					SignBytes: signBytes,
				})
				if err != nil {
					log.Error(
						"Cosigner failed to set nonces and sign",
						"cosigner", remote_cosigner.GetIndex(),
						"err", err.Error(),
					)

					if strings.Contains(err.Error(), cosigner.ErrUnexpectedState) {
						pv.nonceCache.ClearNonces(remote_cosigner)
					}

					if remote_cosigner.GetIndex() == pv.MyCosigner.GetIndex() {
						return err
					}

					if c := status.Code(err); c == codes.DeadlineExceeded || c == codes.NotFound || c == codes.Unavailable {
						pv.cosignerHealth.MarkUnhealthy(remote_cosigner)
						pv.nonceCache.ClearNonces(remote_cosigner)
					}

					if dontIterateFastestCosigners {
						remote_cosigner = nil
						continue
					}

					// this will only work if the next cosigner has the nonces we've already decided to use for this block
					// otherwise the sign attempt will fail
					remote_cosigner = getNextFastestCosigner()
					continue
				}

				if remote_cosigner != pv.MyCosigner {
					metrics.TimedCosignerSignLag.WithLabelValues(remote_cosigner.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
				}
				shareSignatures[remote_cosigner.GetIndex()-1] = sigRes.Signature

				return nil
			}
			return fmt.Errorf("no cosigners available to sign")
		})
	}

	if err := eg.Wait(); err != nil {
		pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
		return nil, stamp, fmt.Errorf("error from cosigner(s): %s", err)
	}

	metrics.TimedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())

	// collect all valid responses into array of partial signatures
	shareSigs := make([]types.PartialSignature, 0, pv.threshold)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}

		sig := make([]byte, len(shareSig))
		copy(sig, shareSig)

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, types.PartialSignature{
			Index:     idx + 1,
			Signature: sig,
		})
	}

	if len(shareSigs) < pv.threshold {
		metrics.TotalInsufficientCosigners.Inc()
		pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble into final signature
	signature, err := pv.MyCosigner.CombineSignatures(chainID, shareSigs)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
		return nil, stamp, fmt.Errorf("error combining signatures: %w", err)
	}

	// verify the combined signature before saving to watermark
	if !pv.MyCosigner.VerifySignature(chainID, signBytes, signature) {
		metrics.TotalInvalidSignature.Inc()

		pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
		return nil, stamp, errors.New("combined signature is not valid")
	}

	newLss := types.ChainSignStateConsensus{
		ChainID: chainID,
		SignStateConsensus: types.SignStateConsensus{
			Height:    height,
			Round:     round,
			Step:      step,
			Signature: signature,
			SignBytes: signBytes,
		},
	}

	css := pv.mustLoadChainState(chainID)

	// Err will be present if newLss is not above high watermark
	css.lastSignStateMutex.Lock()
	err = css.lastSignState.Save(newLss.SignStateConsensus, &pv.pendingDiskWG)
	css.lastSignStateMutex.Unlock()
	if err != nil {
		if _, isSameHRSError := err.(*types.SameHRSError); !isSameHRSError {

			pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
			return nil, stamp, fmt.Errorf("error saving last sign state: %w", err)
		}
	}

	// Emit last signed state to cluster
	err = pv.leader.ShareSigned(newLss)
	if err != nil {
		// this is not required for double sign protection, so we don't need to return an error here.
		// this is only an additional mechanism that will catch double signs earlier in the sign process.
		log.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock)
	timeSignBlockSec := timeSignBlock.Seconds()
	metrics.TimedSignBlockLag.Observe(timeSignBlockSec)

	log.Info(
		"Signed",
		"duration_ms", float64(timeSignBlock.Microseconds())/1000,
	)

	return signature, stamp, nil
}
