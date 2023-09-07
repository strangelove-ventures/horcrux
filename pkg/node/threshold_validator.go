package node

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/strangelove-ventures/horcrux/pkg/metrics"
	"github.com/strangelove-ventures/horcrux/pkg/proto"
)

var _ IPrivValidator = &ThresholdValidator{}

type ValidatorSignBlockRequest struct {
	ChainID string
	Block   *Block
}

type ValidatorSignBlockResponse struct {
	Signature []byte
}
type ThresholdValidator struct {
	config *cosigner.RuntimeConfig

	threshold int

	grpcTimeout time.Duration

	chainState sync.Map

	// our own cosigner
	myCosigner *cosigner.LocalCosigner

	// peer cosigners
	peerCosigners []ICosigner

	leader ILeader

	logger log.Logger

	pendingDiskWG sync.WaitGroup

	maxWaitForSameBlockAttempts int
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

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(
	logger log.Logger,
	config *cosigner.RuntimeConfig,
	threshold int,
	grpcTimeout time.Duration,
	maxWaitForSameBlockAttempts int,
	myCosigner *cosigner.LocalCosigner,
	peerCosigners []ICosigner,
	leader ILeader,
) *ThresholdValidator {
	return &ThresholdValidator{
		logger:                      logger,
		config:                      config,
		threshold:                   threshold,
		grpcTimeout:                 grpcTimeout,
		maxWaitForSameBlockAttempts: maxWaitForSameBlockAttempts,
		myCosigner:                  myCosigner,
		peerCosigners:               peerCosigners,
		leader:                      leader,
	}
}

// SaveLastSignedState updates the high watermark height/round/step (HRS) for a completed(!)
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
	cs, ok := pv.chainState.Load(chainID)
	if !ok {
		panic(fmt.Errorf("failed to load chain state for %s", chainID))
	}

	css, ok := cs.(ChainSignState)
	if !ok {
		panic(fmt.Errorf("expected: (ChainSignState), actual: (%T)", cs))
	}

	return css
}

// SaveLastSignedStateInitiated updates the high watermark height/round/step (HRS) for an initiated
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedStateInitiated(chainID string, block *Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	height, round, step := block.Height, block.Round, block.Step

	err := css.lastSignStateInitiated.Save(types.NewSignStateConsensus(height, round, step), &pv.pendingDiskWG)
	if err == nil {
		// good to sign
		return nil, time.Time{}, nil
	}

	// There was an error saving the last sign state, so check if there is an existing signature for this block.
	existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)

	if _, ok := err.(*types.SameHRSError); !ok {
		if sameBlockErr == nil {
			return existingSignature, block.Timestamp, nil
		}
		return nil, existingTimestamp, pv.newBeyondBlockError(chainID, block.HRSKey())
	}

	if sameBlockErr == nil {
		if existingSignature != nil {
			// signature already exists for this block. return it.
			return existingSignature, existingTimestamp, nil
		}
		// good to sign again
		return nil, time.Time{}, nil
	}

	if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
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
	css.lastSignState.CondLlock()
	defer css.lastSignState.CondLunlock()
	for i := 0; i < pv.maxWaitForSameBlockAttempts; i++ {
		// block until sign state is saved. It will notify and unblock when block is next signed.
		css.lastSignState.WaitWithTimeout(pv.grpcTimeout)

		// check if HRS exists in cache now
		ssc, ok := css.lastSignState.GetCache(block.HRSKey())
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
func (pv *ThresholdValidator) notifyBlockSignError(chainID string, hrs types.HRSKey) {
	css := pv.mustLoadChainState(chainID)

	css.lastSignState.MuLock()
	css.lastSignState.SetCache(hrs,
		types.SignStateConsensus{
			Height: hrs.Height,
			Round:  hrs.Round,
			Step:   hrs.Step,
			// empty signature to indicate error
		})

	css.lastSignState.MuUnlock()
	css.lastSignState.CondBroadcast()
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (pv *ThresholdValidator) waitForSignStatesToFlushToDisk() {
	pv.pendingDiskWG.Wait()

	pv.myCosigner.WaitForSignStatesToFlushToDisk()
}

// Stop safely shuts down the ThresholdValidator.
// Stop implements IPrivValidator from threshold_remote_signer.go
func (pv *ThresholdValidator) Stop() {
	pv.waitForSignStatesToFlushToDisk()
}

// GetPubKey returns the public key of the validator.
// Implements IPrivValidator fromt threshold_remote_signer.go
func (pv *ThresholdValidator) GetPubKey(chainID string) (crypto.PubKey, error) {
	return pv.myCosigner.GetPubKey(chainID)
}

// SignVote signs a canonical representation of the vote, along with the
// chainID.
// SignVote implements IPrivValidator fromt threshold_remote_signer.go
func (pv *ThresholdValidator) SignVote(chainID string, vote *cometproto.Vote) error {
	block := &Block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      types.VoteToStep(vote),
		Timestamp: vote.Timestamp,
		SignBytes: comet.VoteSignBytes(chainID, vote),
	}

	sig, stamp, err := pv.SignBlock(chainID, block)

	vote.Signature = sig
	vote.Timestamp = stamp

	return err
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID.
// SignProposal implements IPrivValidator fromt threshold_remote_signer.go
func (pv *ThresholdValidator) SignProposal(chainID string, proposal *cometproto.Proposal) error {
	block := &Block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      types.ProposalToStep(proposal),
		Timestamp: proposal.Timestamp,
		SignBytes: comet.ProposalSignBytes(chainID, proposal),
	}

	sig, stamp, err := pv.SignBlock(chainID, block)

	proposal.Signature = sig
	proposal.Timestamp = stamp

	return err
}

type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

func (block Block) HRSKey() types.HRSKey {
	return types.HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) HRSTKey() types.HRSTKey {
	return types.HRSTKey{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) toProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

func (pv *ThresholdValidator) newBeyondBlockError(chainID string, hrs types.HRSKey) *BeyondBlockError {
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

type StillWaitingForBlockError struct {
	msg string
}

func (e *StillWaitingForBlockError) Error() string { return e.msg }

func newStillWaitingForBlockError(chainID string, hrs types.HRSKey) *StillWaitingForBlockError {
	return &StillWaitingForBlockError{
		msg: fmt.Sprintf("[%s] Still waiting for block %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

type SameBlockError struct {
	msg string
}

func (e *SameBlockError) Error() string { return e.msg }

func newSameBlockError(chainID string, hrs types.HRSKey) *SameBlockError {
	return &SameBlockError{
		msg: fmt.Sprintf("[%s] Same block: %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

func (pv *ThresholdValidator) waitForPeerNonces(
	chainID string,
	peer ICosigner,
	hrst types.HRSTKey,
	wg *sync.WaitGroup,
	nonces map[ICosigner][]cosigner.WrappedNonce,
	thresholdPeersMutex *sync.Mutex,
) {
	peerStartTime := time.Now()
	peerNonces, err := peer.GetNonces(chainID, hrst)
	if err != nil {
		// Significant missing shares may lead to signature failure
		metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Add(float64(1))
		metrics.TotalMissedNonces.WithLabelValues(peer.GetAddress()).Inc()
		pv.logger.Error("Error getting nonces", "cosigner", peer.GetID(), "err", err)
		return
	}
	// Significant missing shares may lead to signature failure
	metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Set(0)
	metrics.TimedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	// Check so that wg.Done is not called more than (threshold - 1) times which causes hardlock
	thresholdPeersMutex.Lock()
	if len(nonces) < pv.threshold-1 {
		nonces[peer] = peerNonces.Nonces
		defer wg.Done()
	}
	thresholdPeersMutex.Unlock()
}
func (pv *ThresholdValidator) waitForPeerSetNoncesAndSign(
	chainID string,
	peer ICosigner,
	hrst types.HRSTKey,
	noncesMap map[ICosigner][]cosigner.WrappedNonce,
	signBytes []byte,
	shareSignatures *[][]byte,
	shareSignaturesMutex *sync.Mutex,
	wg *sync.WaitGroup,
) {
	peerStartTime := time.Now()
	defer wg.Done()
	peerNonces := make([]cosigner.WrappedNonce, 0, pv.threshold-1)

	peerID := peer.GetID()

	for _, nonces := range noncesMap {
		for _, nonce := range nonces {
			// if share is intended for peer, check to make sure source peer is included in threshold
			if nonce.DestinationID != peerID {
				continue
			}
			for thresholdPeer := range noncesMap {
				if thresholdPeer.GetID() != nonce.SourceID {
					continue
				}
				// source peer is included in threshold signature, include in sharing
				peerNonces = append(peerNonces, nonce)
				break
			}
			break
		}
	}

	sigRes, err := peer.SetNoncesAndSign(cosigner.SetNoncesAndSignRequest{
		ChainID:   chainID,
		Nonces:    peerNonces,
		HRST:      hrst,
		SignBytes: signBytes,
	})

	if err != nil {
		pv.logger.Error(
			"Cosigner failed to set nonces and sign",
			"id", peerID,
			"err", err.Error(),
		)
		return
	}

	metrics.TimedCosignerSignLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	pv.logger.Debug(
		"Received signature part",
		"cosigner", peerID,
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	shareSignaturesMutex.Lock()
	defer shareSignaturesMutex.Unlock()

	peerIdx := peerID - 1
	(*shareSignatures)[peerIdx] = make([]byte, len(sigRes.Signature))
	copy((*shareSignatures)[peerIdx], sigRes.Signature)
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

	return pv.myCosigner.LoadSignStateIfNecessary(chainID)
}

// getExistingBlockSignature returns the existing block signature and no error if the signature is valid for the block.
// It returns nil signature and nil error if there is no signature and it's okay to sign (fresh or again).
// It returns an error if we have already signed a greater block, or if we are still waiting for in in-progress sign.
func (pv *ThresholdValidator) getExistingBlockSignature(chainID string, block *Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	latestBlock, existingSignature := css.lastSignState.GetFromCache(block.HRSKey())
	if existingSignature != nil {
		// signature exists in cache, so compare against that
		return pv.compareBlockSignatureAgainstSSC(chainID, block, existingSignature)
	}

	// signature does not exist in cache, so compare against latest signed block.
	return nil, block.Timestamp, pv.compareBlockSignatureAgainstHRS(chainID, block, latestBlock)
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
	block *Block,
	existingSignature *types.SignStateConsensus,
) ([]byte, time.Time, error) {
	stamp, signBytes := block.Timestamp, block.SignBytes

	if err := pv.compareBlockSignatureAgainstHRS(chainID, block, existingSignature.HRSKey()); err != nil {
		if _, ok := err.(*SameBlockError); !ok {
			return nil, stamp, err
		}
	}

	// If a proposal has already been signed for this HRS, or the sign payload is identical, return the existing signature.
	if block.Step == types.StepPropose() || bytes.Equal(signBytes, existingSignature.SignBytes) {
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
func (pv *ThresholdValidator) compareBlockSignatureAgainstHRS(
	chainID string,
	block *Block,
	hrs types.HRSKey,
) error {
	blockHRS := block.HRSKey()

	if hrs.GreaterThan(blockHRS) {
		return pv.newBeyondBlockError(chainID, blockHRS)
	}

	if hrs == blockHRS {
		return newSameBlockError(chainID, blockHRS)
	}

	return newStillWaitingForBlockError(chainID, blockHRS)
}

// SignBlock is the arranger of the whole signature/signing process.
func (pv *ThresholdValidator) SignBlock(chainID string, block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes

	if err := pv.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, stamp, err
	}

	timeStartSignBlock := time.Now()

	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	if !pv.leader.IsLeader() {
		pv.logger.Debug("I am not the raft leader. Proxying request to the leader",
			"chain_id", chainID,
			"height", height,
			"round", round,
			"step", step,
		)
		metrics.TotalNotRaftLeader.Inc()
		// Ask the (RAFT) leader to manage the signing of the block
		signRes, err := pv.leader.SignBlock(ValidatorSignBlockRequest{
			ChainID: chainID,
			Block:   block,
		})
		if err != nil {
			if _, ok := err.(*cometrpcjsontypes.RPCError); ok {
				rpcErrUnwrapped := err.(*cometrpcjsontypes.RPCError).Data
				// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
				if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
					return nil, stamp, &BeyondBlockError{msg: rpcErrUnwrapped}
				}
			}
			return nil, stamp, err
		}
		return signRes.Signature, stamp, nil
	}

	metrics.TotalRaftLeader.Inc()
	pv.logger.Debug(
		"I am the raft leader. Managing the sign process for this block",
		"chain_id", chainID,
		"height", height,
		"round", round,
		"step", step,
	)

	hrst := types.HRSTKey{
		Height:    height,
		Round:     round,
		Step:      step,
		Timestamp: stamp.UnixNano(),
	}

	// Keep track of the last block that we began the signing process for. Only allow one attempt per block
	existingSignature, existingTimestamp, err := pv.SaveLastSignedStateInitiated(chainID, block)
	if err != nil {
		return nil, stamp, err
	}
	if existingSignature != nil {
		pv.logger.Debug("Returning existing signature", "signature", fmt.Sprintf("%x", existingSignature))
		return existingSignature, existingTimestamp, nil
	}

	numPeers := len(pv.peerCosigners)
	total := uint8(numPeers + 1)
	getEphemeralWaitGroup := sync.WaitGroup{}

	// Only wait until we have enough threshold signatures
	getEphemeralWaitGroup.Add(pv.threshold - 1)
	// Used to track how close we are to threshold

	// Here the actual signing process starts from a cryptological perspective
	nonces := make(map[ICosigner][]cosigner.WrappedNonce)
	thresholdPeersMutex := sync.Mutex{}

	// From each cosigner peer we are requesting the nonce.
	// This is done asynchronously.
	// pv.waitForPeersNonces uses GRPC to get the nonce from the peer.
	for _, c := range pv.peerCosigners {
		go pv.waitForPeerNonces(chainID, c, hrst, &getEphemeralWaitGroup,
			nonces, &thresholdPeersMutex)
	}

	// Requesting a nonce from our own cosigner (a.k.a. the local cosigner)
	myNonces, err := pv.myCosigner.GetNonces(chainID, hrst)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		// Our ephemeral secret parts are required, cannot proceed
		return nil, stamp, err
	}

	// Wait for cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&getEphemeralWaitGroup, pv.grpcTimeout) {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for ephemeral shares")
	}

	thresholdPeersMutex.Lock()
	nonces[pv.myCosigner] = myNonces.Nonces
	thresholdPeersMutex.Unlock()

	metrics.TimedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug(
		"Have threshold peers",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	setEphemeralAndSignWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	setEphemeralAndSignWaitGroup.Add(pv.threshold)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	for cosigner := range nonces {
		// set peerNonces and sign in single rpc call.
		go pv.waitForPeerSetNoncesAndSign(chainID, cosigner, hrst, nonces,
			signBytes, &shareSignatures, &shareSignaturesMutex, &setEphemeralAndSignWaitGroup)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&setEphemeralAndSignWaitGroup, 4*time.Second) {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	metrics.TimedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug(
		"Done waiting for cosigners, assembling signatures",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	// collect all valid responses into array of partial signatures
	shareSigs := make([]cosigner.PartialSignature, 0, pv.threshold)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, cosigner.PartialSignature{
			ID:        idx + 1,
			Signature: shareSig,
		})
	}

	if len(shareSigs) < pv.threshold {
		metrics.TotalInsufficientCosigners.Inc()
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble the partial signatures into a valid signature
	signature, err := pv.myCosigner.CombineSignatures(chainID, shareSigs)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, err
	}

	pv.logger.Debug(
		"Assembled full signature",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	// verify the combined signature before saving to watermark
	if !pv.myCosigner.VerifySignature(chainID, signBytes, signature) {
		metrics.TotalInvalidSignature.Inc()
		pv.notifyBlockSignError(chainID, block.HRSKey())
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
			pv.notifyBlockSignError(chainID, block.HRSKey())
			return nil, stamp, err
		}
	}

	// Emit last signed state to cluster
	err = pv.leader.ShareSigned(newLss)
	if err != nil {
		pv.logger.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock).Seconds()
	metrics.TimedSignBlockLag.Observe(timeSignBlock)

	return signature, stamp, nil
}
