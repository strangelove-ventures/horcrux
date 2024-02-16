package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	"github.com/strangelove-ventures/horcrux/src/cosigner"

	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/metrics"

	"github.com/strangelove-ventures/horcrux/src/types"

	"github.com/cometbft/cometbft/libs/log"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

// ThresholdValidator is the server that responds to sign requests from the "sentry" client
// Implements the [connector.IPrivValidator] interface.
/*
TODO: Move some parts of this to the MPC
*/

type MPC struct {
	MyCosigner *cosigner.LocalCosigner // TODO Should be an interface as well.
	// peer cosigners
	peerCosigners ICosigners // "i.e clients to call"
	// our own cosigner

	cosignerHealth *CosignerHealth
	nonceCache     *CosignerNonceCache
}

func (mpc *MPC) Sign(
	ctx context.Context) {
}
func (mpc *MPC) GetClientIndex(index int) ICosigner {
	return mpc.peerCosigners[index]
}

// TODO: This is not called anywhere it seems!
type ThresholdClient struct {
	id      int
	address string

	Client proto.NodeServiceClient // GRPC Client

	nonceCache *CosignerNonceCache
}

func (tc *ThresholdClient) SignBlock(
	ctx context.Context,
	chainID string,
	block types.Block,
) ([]byte, time.Time, error) {
	res, err := tc.Client.SignBlock(ctx, &proto.SignBlockRequest{
		ChainID: chainID,
		Block:   block.ToProto(),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return res.GetSignature(), block.Timestamp, nil
}

type ThresholdClients []ThresholdClient

func (clients ThresholdClients) GetClientIndex(index int) (ThresholdClient, error) {
	if index > (len(clients) + 1) {
		return ThresholdClient{}, fmt.Errorf("index out of range")
	}
	return clients[index-1], nil
}

// ThresholdValidator is the conductor for the threshold signing process.
type ThresholdValidator struct {
	config *config.RuntimeConfig

	clients   ThresholdClients
	threshold int

	grpcTimeout time.Duration // TODO ask if this should move to icosigner?

	// chainSignState is the watermark for sent blocks we have started to process
	chainSignState sync.Map // - chainSignState["chainid"] -> types.chainSignState

	mpc *MPC

	leader ILeader // Basically our RAFT implementation

	logger log.Logger

	pendingDiskWG sync.WaitGroup

	maxWaitForSameBlockAttempts int
	// TODO: Should separate node and cosigner health
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
	lastInitiatedSignState      *types.SignState
	lastSignStateInitiatedMutex *sync.Mutex
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

func (pv *ThresholdValidator) newBeyondBlockError(chainID string, hrs types.HRS) *BeyondBlockError {
	css := pv.mustLoadChainState(chainID)

	lss := css.lastInitiatedSignState
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

	for _, peer := range peerCosigners {
		logger.Debug("Peer peer", "id", peer.GetIndex())
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
	fmt.Printf("peerCosigner: %v\nleader: %v\n", peerCosigners, leader)
	nch := NewCosignerHealth(logger, peerCosigners, leader)
	fmt.Printf("nch: %v\n", nch)
	return &ThresholdValidator{
		logger:                      logger,
		config:                      config,
		threshold:                   threshold,
		grpcTimeout:                 grpcTimeout,
		maxWaitForSameBlockAttempts: maxWaitForSameBlockAttempts,
		mpc:                         &MPC{MyCosigner: myCosigner, peerCosigners: peerCosigners, cosignerHealth: nch, nonceCache: nc},
		leader:                      leader,
	}
}

func (pv *ThresholdValidator) getLeaderClient(index int) (ThresholdClient, error) {
	client, err := pv.clients.GetClientIndex(index)
	if err != nil {
		return client, err
	}
	return client, nil
}

// Start starts the ThresholdValidator.
func (pv *ThresholdValidator) Start(ctx context.Context) error {
	pv.logger.Info("Starting ThresholdValidator services")

	// TODO: Should be moved to MPC
	go pv.mpc.cosignerHealth.Start(ctx)
	go pv.mpc.nonceCache.Start(ctx)
	go pv.mpc.MyCosigner.StartNoncePruner(ctx)

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
	cs, ok := pv.chainSignState.Load(chainID) //
	if !ok {
		panic(fmt.Errorf("failed to load chain state for %s", chainID))
	}

	css, ok := cs.(ChainSignState)
	if !ok {
		panic(fmt.Errorf("expected: type (ChainSignState), actual type is: (%T)", cs))
	}

	return css
}

// saveLastSignedStateInitiated updates the high watermark height/round/step (HRS) for an initiated
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) saveLastSignedStateInitiated(
	chainID string, block *types.Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	height, round, step := block.Height, block.Round, block.Step

	err := css.lastInitiatedSignState.Save(types.NewSignStateConsensus(height, round, step), &pv.pendingDiskWG)
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
		var stillWaitingForBlockError *StillWaitingForBlockError
		if !errors.As(sameBlockErr, &stillWaitingForBlockError) {
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

	pv.mpc.MyCosigner.WaitForSignStatesToFlushToDisk()
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey(_ context.Context, chainID string) ([]byte, error) {
	pubKey, err := pv.mpc.MyCosigner.GetPubKey(chainID)
	if err != nil {
		return nil, err
	}
	return pubKey.Bytes(), nil
}

func (pv *ThresholdValidator) LoadSignStateIfNecessary(chainID string) error {
	if _, ok := pv.chainSignState.Load(chainID); ok {
		return nil
	}

	signState, err := types.LoadOrCreateSignState(pv.config.PrivValStateFile(chainID))
	if err != nil {
		return err
	}

	lastInitiatedSignState := signState.FreshCache()
	lastInitiatedSignState.FilePath = os.DevNull

	pv.chainSignState.Store(chainID, ChainSignState{
		lastSignState:          signState,
		lastInitiatedSignState: lastInitiatedSignState,

		lastSignStateMutex:          &sync.Mutex{},
		lastSignStateInitiatedMutex: &sync.Mutex{},
	})

	return pv.mpc.MyCosigner.LoadSignStateIfNecessary(chainID)
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
		var sameBlockError *metrics.SameBlockError
		if !errors.As(err, &sameBlockError) {
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
	nonces := make(map[ICosigner]cosigner.Nonces)

	metrics.DrainedNonceCache.Inc()
	metrics.TotalDrainedNonceCache.Inc()

	var wg sync.WaitGroup
	wg.Add(pv.threshold)

	var mu sync.Mutex

	u := uuid.New()

	allCosigners := make([]ICosigner, len(pv.mpc.peerCosigners)+1)
	allCosigners[0] = pv.mpc.MyCosigner
	copy(allCosigners[1:], pv.mpc.peerCosigners)

	for _, c := range allCosigners {
		go pv.waitForPeerNonces(ctx, u, c, &wg, nonces, &mu)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&wg, pv.grpcTimeout) {
		return nil, nil, errors.New("timed out waiting for ephemeral shares")
	}

	var thresholdNonces cosigner.Nonces
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
	nonces map[ICosigner]cosigner.Nonces,
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

func (pv *ThresholdValidator) SignBlock(
	ctx context.Context,
	req *proto.SignBlockRequest,

) (*proto.SignBlockResponse, error) {
	res, _, err := pv.Sign(ctx, req.ChainID, types.BlockFromProto(req.Block))
	if err != nil {
		return nil, err
	}
	return &proto.SignBlockResponse{
		Signature: res,
	}, nil
}

func (pv *ThresholdValidator) proxyIfNecessary(
	ctx context.Context,
	chainID string,
	block types.Block,
) (bool, []byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

	// Don't proxy if we are the leader
	if pv.leader.IsLeader() {
		return false, nil, time.Time{}, nil
	}

	leader := pv.leader.GetLeader()

	// TODO is there a better way than to poll during leader election?
	// NOTE: This is really strange?
	for i := 0; i < 500 && leader == -1; i++ {
		time.Sleep(10 * time.Millisecond)
		leader = pv.leader.GetLeader()
	}

	if leader == -1 {
		metrics.TotalRaftLeaderElectionTimeout.Inc()
		return true, nil, stamp, fmt.Errorf("timed out waiting for raft leader")
	}

	// Don't proxy call if we are the leader
	if leader == pv.mpc.MyCosigner.GetIndex() {
		return false, nil, time.Time{}, nil
	}

	pv.logger.Debug("I am not the leader. Proxying request to the leader",
		"chain_id", chainID,
		"height", height,
		"round", round,
		"step", step,
	)
	metrics.TotalNotRaftLeader.Inc()

	// Get Node by leader index
	// TODO: Change so the this is the node.
	nodeLeader, err := pv.getLeaderClient(leader) // This is a nodeclient
	if err != nil {
		return true, nil, stamp, fmt.Errorf("failed to find cosigner (node) with id %d", leader)
	}

	// Here we actually sending the request to the node who is leader. Should be
	// ProxySign
	// nodeLeader.(*cosigner.CosignerClient)
	signRes, stamp, err := nodeLeader.SignBlock(ctx, chainID, block)

	if err != nil {
		var RPCError *cometrpcjsontypes.RPCError
		if errors.As(err, &RPCError) {
			var RPCError *cometrpcjsontypes.RPCError
			errors.As(err, &RPCError)
			rpcErrUnwrapped := RPCError.Data
			// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
			if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
				return true, nil, stamp, &metrics.BeyondBlockError{Msg: rpcErrUnwrapped}
			}
		}
		return true, nil, stamp, err
	}

	return true, signRes, stamp, nil

	// return false, nil, stamp, nil
}

// Sign returns the signature in byte for the given block and the time
// This function is called by the sentry and its responsible for in its turn calling the MPC
// to get a valid signature to return to the sentry.
// Sign implements the [connector.IPrivValidator] interface.
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
	// but they just need to proxy the request to the raft leader which handles the orchestration of signing
	isProxied, proxySig, proxyStamp, err := pv.proxyIfNecessary(ctx, chainID, block)
	if isProxied {
		// Returns the proxy signature if the request was proxied
		return proxySig, proxyStamp, err
	}

	// isSigned, Sig, Stamp, err := pv.Sign(ctx, chainID, block)

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
	existingSignature, existingTimestamp, err := pv.saveLastSignedStateInitiated(chainID, &block)
	if err != nil {
		return nil, stamp, fmt.Errorf("error saving last sign state initiated: %w", err)
	}
	if existingSignature != nil {
		log.Debug("Returning existing signature", "signature", fmt.Sprintf("%x", existingSignature))
		return existingSignature, existingTimestamp, nil
	}

	// More or less everything belov here shoud be moved to a "cosigners"
	// package. This is the actual MPC.
	// MPC.SignBlock() is the actual function that does the MPC.
	numPeers := len(pv.mpc.peerCosigners)
	total := uint8(numPeers + 1)

	peerStartTime := time.Now()

	fmt.Println("pv.cosignerHealth: ", pv.mpc.cosignerHealth)
	cosignersOrderedByFastest := pv.mpc.cosignerHealth.GetFastest()

	fmt.Println("cosignersOrderedByFastest", len(cosignersOrderedByFastest))
	cosignersForThisBlock := make([]ICosigner, pv.threshold)

	fmt.Println("cosignersForThisBlock", len(cosignersForThisBlock), pv.threshold)
	cosignersForThisBlock[0] = pv.mpc.MyCosigner
	copy(cosignersForThisBlock[1:], cosignersOrderedByFastest[:pv.threshold-1])

	nonces, err := pv.mpc.nonceCache.GetNonces(cosignersForThisBlock)

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

	for _, peer := range pv.mpc.peerCosigners {
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
	for _, remote_Cosigner := range cosignersForThisBlock {
		// NOTE: This is really odd isnt it?
		remoteCosigner := remote_Cosigner
		eg.Go(func() error {
			for remoteCosigner != nil {
				signCtx, cancel := context.WithTimeout(ctx, pv.grpcTimeout)
				defer cancel()

				peerStartTime := time.Now()

				// set peerNonces and sign in single rpc call.
				sigRes, err := remoteCosigner.SetNoncesAndSign(signCtx, cosigner.CosignerSetNoncesAndSignRequest{
					ChainID:   chainID,
					Nonces:    nonces.For(remoteCosigner.GetIndex()),
					HRST:      hrst,
					SignBytes: signBytes,
				})
				if err != nil {
					log.Error(
						"Cosigner failed to set nonces and sign",
						"cosigner", remoteCosigner.GetIndex(),
						"err", err.Error(),
					)

					if strings.Contains(err.Error(), cosigner.ErrUnexpectedState) {
						pv.mpc.nonceCache.ClearNonces(remoteCosigner)
					}

					if remoteCosigner.GetIndex() == pv.mpc.MyCosigner.GetIndex() {
						return err
					}

					if c := status.Code(err); c == codes.DeadlineExceeded || c == codes.NotFound || c == codes.Unavailable {
						pv.mpc.cosignerHealth.MarkUnhealthy(remoteCosigner)
						pv.mpc.nonceCache.ClearNonces(remoteCosigner)
					}

					if dontIterateFastestCosigners {
						remoteCosigner = nil
						continue
					}

					// this will only work if the next cosigner has the nonces we've already decided to use for this block
					// otherwise the sign attempt will fail
					remoteCosigner = getNextFastestCosigner()
					continue
				}

				if remoteCosigner != pv.mpc.MyCosigner {
					metrics.TimedCosignerSignLag.WithLabelValues(remoteCosigner.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
				}
				shareSignatures[remoteCosigner.GetIndex()-1] = sigRes.Signature

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
	signature, err := pv.mpc.MyCosigner.CombineSignatures(chainID, shareSigs)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.GetHRS(), signBytes)
		return nil, stamp, fmt.Errorf("error combining signatures: %w", err)
	}

	// verify the combined signature before saving to watermark
	if !pv.mpc.MyCosigner.VerifySignature(chainID, signBytes, signature) {
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
		var sameHRSError *types.SameHRSError
		if !errors.As(err, &sameHRSError) {

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
