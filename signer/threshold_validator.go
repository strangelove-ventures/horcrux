package signer

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cometbft/cometbft/crypto"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/signer/proto"
)

var _ PrivValidator = &ThresholdValidator{}

type ThresholdValidator struct {
	config *RuntimeConfig

	threshold int

	grpcTimeout time.Duration

	chainState   map[string]ChainSignState
	chainStateMu sync.RWMutex

	// our own cosigner
	myCosigner *LocalCosigner

	// peer cosigners
	peerCosigners []Cosigner

	raftStore *RaftStore

	logger cometlog.Logger

	pendingDiskWG sync.WaitGroup
}

type ChainSignState struct {
	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState *SignState

	// stores the last sign state that we've started progress on
	lastSignStateInitiated *SignState
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(
	logger cometlog.Logger,
	config *RuntimeConfig,
	threshold int,
	grpcTimeout time.Duration,
	myCosigner *LocalCosigner,
	peerCosigners []Cosigner,
	raftStore *RaftStore,
) *ThresholdValidator {
	return &ThresholdValidator{
		logger:        logger,
		config:        config,
		threshold:     threshold,
		grpcTimeout:   grpcTimeout,
		myCosigner:    myCosigner,
		peerCosigners: peerCosigners,
		raftStore:     raftStore,
		chainState:    make(map[string]ChainSignState),
	}
}

// SaveLastSignedState updates the high watermark height/round/step (HRS) for a completed
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
	css := pv.mustLoadChainState(chainID)

	return css.lastSignState.Save(signState, &pv.pendingDiskWG)
}

func (pv *ThresholdValidator) mustLoadChainState(chainID string) ChainSignState {
	pv.chainStateMu.RLock()
	defer pv.chainStateMu.RUnlock()
	return pv.chainState[chainID]
}

// SaveLastSignedStateInitiated updates the high watermark height/round/step (HRS) for an initiated
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedStateInitiated(chainID string, block *Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	height, round, step := block.Height, block.Round, block.Step

	err := css.lastSignStateInitiated.Save(NewSignStateConsensus(height, round, step), &pv.pendingDiskWG)
	if err == nil {
		// good to sign
		return nil, time.Time{}, nil
	}

	existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)

	switch err.(type) {
	case *SameHRSError:
		// Wait for last sign state signature to be the same block

		if sameBlockErr == nil {
			if existingSignature != nil {
				return existingSignature, existingTimestamp, nil
			}
			// good to sign again
			return nil, time.Time{}, nil
		}

		if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
			return nil, existingTimestamp, sameBlockErr
		}

		// the cluster is already in progress signing this block
		// wait for cluster to finish before proceeding

		css.lastSignState.cond.L.Lock()
		defer css.lastSignState.cond.L.Unlock()
		for {
			css.lastSignState.cond.Wait()

			ssc, ok := css.lastSignState.cache[block.HRSKey()]
			if !ok {
				pv.logger.Debug(
					"Cond does not exist in cache",
					"height", height,
					"round", round,
					"step", step,
				)
				continue
			}

			existingSignature, existingTimestamp, sameBlockErr = pv.compareBlockSignature(
				chainID, block, block.HRSKey(), &ssc)
			if sameBlockErr == nil {
				return existingSignature, existingTimestamp, nil
			}
			if _, ok := sameBlockErr.(*StillWaitingForBlockError); !ok {
				return nil, existingTimestamp, sameBlockErr
			}

			pv.logger.Debug(
				"Stil waiting for block to be signed",
				"height", height,
				"round", round,
				"step", step,
			)
		}
	default:
		if sameBlockErr == nil {
			return existingSignature, block.Timestamp, nil
		}
		return nil, existingTimestamp, pv.newBeyondBlockError(chainID, block.HRSKey())
	}
}

// HandleError will alert any waiting goroutines that an error
// has occurred during signing and a retry can be attempted.
func (pv *ThresholdValidator) notifyBlockSignError(chainID string, hrs HRSKey) {
	css := pv.mustLoadChainState(chainID)

	css.lastSignState.cond.L.Lock()
	css.lastSignState.cache[hrs] = SignStateConsensus{
		Height: hrs.Height,
		Round:  hrs.Round,
		Step:   hrs.Step,
		// empty signature to indicate error
	}
	css.lastSignState.cond.L.Unlock()
	css.lastSignState.cond.Broadcast()
}

// Stop safely shuts down the ThresholdValidator.
func (pv *ThresholdValidator) Stop() {
	pv.waitForSignStatesToFlushToDisk()
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (pv *ThresholdValidator) waitForSignStatesToFlushToDisk() {
	pv.pendingDiskWG.Wait()

	pv.myCosigner.waitForSignStatesToFlushToDisk()
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey(chainID string) (crypto.PubKey, error) {
	return pv.myCosigner.GetPubKey(chainID)
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignVote(chainID string, vote *cometproto.Vote) error {
	block := &Block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      VoteToStep(vote),
		Timestamp: vote.Timestamp,
		SignBytes: comet.VoteSignBytes(chainID, vote),
	}

	sig, stamp, err := pv.SignBlock(chainID, block)

	vote.Signature = sig
	vote.Timestamp = stamp

	return err
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignProposal(chainID string, proposal *cometproto.Proposal) error {
	block := &Block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      ProposalToStep(proposal),
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

func (block Block) HRSKey() HRSKey {
	return HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) HRSTKey() HRSTKey {
	return HRSTKey{
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

func (pv *ThresholdValidator) newBeyondBlockError(chainID string, hrs HRSKey) *BeyondBlockError {
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

func newStillWaitingForBlockError(chainID string, hrs HRSKey) *StillWaitingForBlockError {
	return &StillWaitingForBlockError{
		msg: fmt.Sprintf("[%s] Still waiting for block %d.%d.%d",
			chainID, hrs.Height, hrs.Round, hrs.Step),
	}
}

func (pv *ThresholdValidator) waitForPeerEphemeralShares(
	chainID string,
	peer Cosigner,
	hrst HRSTKey,
	wg *sync.WaitGroup,
	encryptedEphemeralSharesThresholdMap map[Cosigner][]CosignerNonce,
	thresholdPeersMutex *sync.Mutex,
) {
	peerStartTime := time.Now()
	ephemeralSecretParts, err := peer.GetNonces(chainID, hrst)
	if err != nil {

		// Significant missing shares may lead to signature failure
		missedEphemeralShares.WithLabelValues(peer.GetAddress()).Add(float64(1))
		totalMissedEphemeralShares.WithLabelValues(peer.GetAddress()).Inc()
		pv.logger.Error("Error getting secret parts", "peer", peer.GetID(), "err", err)
		return
	}
	// Significant missing shares may lead to signature failure
	missedEphemeralShares.WithLabelValues(peer.GetAddress()).Set(0)
	timedCosignerEphemeralShareLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	// Check so that getEphemeralWaitGroup.Done is not called more than (threshold - 1) times which causes hardlock
	thresholdPeersMutex.Lock()
	if len(encryptedEphemeralSharesThresholdMap) < pv.threshold-1 {
		(encryptedEphemeralSharesThresholdMap)[peer] = ephemeralSecretParts.EncryptedSecrets
		defer wg.Done()
	}
	thresholdPeersMutex.Unlock()

	pv.logger.Debug(
		"Received nonces",
		"cosigner", peer.GetID(),
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)
}

func (pv *ThresholdValidator) waitForPeerSetEphemeralSharesAndSign(
	chainID string,
	peer Cosigner,
	hrst HRSTKey,
	encryptedEphemeralSharesThresholdMap map[Cosigner][]CosignerNonce,
	signBytes []byte,
	shareSignatures *[][]byte,
	shareSignaturesMutex *sync.Mutex,
	wg *sync.WaitGroup,
) {
	peerStartTime := time.Now()
	defer wg.Done()
	peerNonces := make([]CosignerNonce, 0, pv.threshold-1)

	peerID := peer.GetID()

	for _, encryptedSecrets := range encryptedEphemeralSharesThresholdMap {
		for _, ephemeralSecretPart := range encryptedSecrets {
			// if share is intended for peer, check to make sure source peer is included in threshold
			if ephemeralSecretPart.DestinationID == peerID {
				for thresholdPeer := range encryptedEphemeralSharesThresholdMap {
					if thresholdPeer.GetID() == ephemeralSecretPart.SourceID {
						// source peer is included in threshold signature, include in sharing
						peerNonces = append(peerNonces, ephemeralSecretPart)
						break
					}
				}
				break
			}
		}
	}

	sigRes, err := peer.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:          chainID,
		EncryptedSecrets: peerNonces,
		HRST:             hrst,
		SignBytes:        signBytes,
	})

	if err != nil {
		pv.logger.Error("Sign error", err.Error())
		return
	}

	timedCosignerSignLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
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

func (pv *ThresholdValidator) LoadSignStateIfNecessary(chainID string) (ChainSignState, error) {
	if css, ok := pv.chainState[chainID]; ok {
		return css, nil
	}

	signState, err := LoadOrCreateSignState(pv.config.PrivValStateFile(chainID))
	if err != nil {
		return ChainSignState{}, err
	}

	css := ChainSignState{
		lastSignState:          signState,
		lastSignStateInitiated: signState.FreshCache(),
	}

	pv.chainStateMu.Lock()
	pv.chainState[chainID] = css
	pv.chainStateMu.Unlock()

	return css, pv.myCosigner.LoadSignStateIfNecessary(chainID)
}

func (pv *ThresholdValidator) getExistingBlockSignature(chainID string, block *Block) ([]byte, time.Time, error) {
	css := pv.mustLoadChainState(chainID)

	latestBlock, existingSignature := css.lastSignState.GetFromCache(block.HRSKey())

	return pv.compareBlockSignature(chainID, block, latestBlock, existingSignature)
}

func (pv *ThresholdValidator) compareBlockSignature(
	chainID string,
	block *Block,
	latestBlock HRSKey,
	existingSignature *SignStateConsensus,
) ([]byte, time.Time, error) {
	stamp, signBytes := block.Timestamp, block.SignBytes

	blockHRS := block.HRSKey()

	if existingSignature != nil {
		existingHRS := existingSignature.HRSKey()

		if existingHRS.GreaterThan(blockHRS) {
			return nil, stamp, pv.newBeyondBlockError(chainID, blockHRS)
		}

		if existingHRS != blockHRS {
			return nil, stamp, newStillWaitingForBlockError(chainID, blockHRS)
		}

		// If a proposal has already been signed for this HRS, return that
		if block.Step == stepPropose || bytes.Equal(signBytes, existingSignature.SignBytes) {
			return existingSignature.Signature, block.Timestamp, nil
		}
		if err := existingSignature.OnlyDifferByTimestamp(signBytes); err != nil {
			return nil, stamp, err
		}

		// only differ by timestamp, okay to sign again
		return nil, stamp, nil
	}

	if latestBlock.GreaterThan(blockHRS) {
		return nil, stamp, pv.newBeyondBlockError(chainID, blockHRS)
	}

	return nil, stamp, newStillWaitingForBlockError(chainID, blockHRS)
}

func (pv *ThresholdValidator) SignBlock(chainID string, block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes

	css, err := pv.LoadSignStateIfNecessary(chainID)
	if err != nil {
		return nil, stamp, err
	}

	timeStartSignBlock := time.Now()

	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	if pv.raftStore.raft == nil {
		return nil, stamp, errors.New("raft not yet initialized")
	}
	if pv.raftStore.raft.State() != raft.Leader {
		pv.logger.Debug("I am not the raft leader. Proxying request to the leader",
			"chain_id", chainID,
			"height", height,
			"round", round,
			"step", step,
		)
		totalNotRaftLeader.Inc()
		signRes, err := pv.raftStore.LeaderSignBlock(CosignerSignBlockRequest{
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

	totalRaftLeader.Inc()
	pv.logger.Debug(
		"I am the raft leader. Managing the sign process for this block",
		"chain_id", chainID,
		"height", height,
		"round", round,
		"step", step,
	)

	hrst := HRSTKey{
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

	// Only wait until we have threshold sigs
	getEphemeralWaitGroup.Add(pv.threshold - 1)
	// Used to track how close we are to threshold

	ephSecrets := make(map[Cosigner][]CosignerNonce)
	thresholdPeersMutex := sync.Mutex{}

	for _, c := range pv.peerCosigners {
		go pv.waitForPeerEphemeralShares(chainID, c, hrst, &getEphemeralWaitGroup,
			ephSecrets, &thresholdPeersMutex)
	}

	myEphSecrets, err := pv.myCosigner.GetNonces(chainID, hrst)
	if err != nil {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		// Our ephemeral secret parts are required, cannot proceed
		return nil, stamp, err
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&getEphemeralWaitGroup, pv.grpcTimeout) {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for ephemeral shares")
	}

	thresholdPeersMutex.Lock()
	ephSecrets[pv.myCosigner] = myEphSecrets.EncryptedSecrets
	thresholdPeersMutex.Unlock()

	timedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug(
		"Have nonces from threshold number of cosigners",
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

	for cosigner := range ephSecrets {
		// set peerNonces and sign in single rpc call.
		go pv.waitForPeerSetEphemeralSharesAndSign(chainID, cosigner, hrst, ephSecrets,
			signBytes, &shareSignatures, &shareSignaturesMutex, &setEphemeralAndSignWaitGroup)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&setEphemeralAndSignWaitGroup, 4*time.Second) {
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	timedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())

	// collect all valid responses into array of ids and signatures for the threshold lib
	shareSigs := make([]PartialSignature, 0, pv.threshold)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, PartialSignature{
			ID:        idx + 1,
			Signature: shareSig,
		})
	}

	if len(shareSigs) < pv.threshold {
		totalInsufficientCosigners.Inc()
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble into final signature
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
		totalInvalidSignature.Inc()
		pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("combined signature is not valid")
	}

	newLss := ChainSignStateConsensus{
		ChainID: chainID,
		SignStateConsensus: SignStateConsensus{
			Height:    height,
			Round:     round,
			Step:      step,
			Signature: signature,
			SignBytes: signBytes,
		},
	}

	// Err will be present if newLss is not above high watermark
	if err = css.lastSignState.Save(newLss.SignStateConsensus, &pv.pendingDiskWG); err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			pv.notifyBlockSignError(chainID, block.HRSKey())
			return nil, stamp, err
		}
	}

	// Emit last signed state to cluster
	if err := pv.raftStore.Emit(raftEventLSS, newLss); err != nil {
		pv.logger.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock)
	timedSignBlockLag.Observe(timeSignBlock.Seconds())

	return signature, stamp, nil
}
