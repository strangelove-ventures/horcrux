package signer

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cometrpcjsontypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

var _ PrivValidator = &ThresholdValidator{}

type ThresholdValidator struct {
	config *RuntimeConfig

	threshold uint8

	grpcTimeout time.Duration

	chainState sync.Map

	// our own cosigner
	myCosigner Cosigner

	// peer cosigners
	peerCosigners []Cosigner

	raftStore *RaftStore

	logger log.Logger

	pendingDiskWG sync.WaitGroup
}

type ChainSignState struct {
	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState      *SignState
	lastSignStateMutex *sync.Mutex

	// stores the last sign state that we've started progress on
	lastSignStateInitiated      *SignState
	lastSignStateInitiatedMutex *sync.Mutex
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(
	logger log.Logger,
	config *RuntimeConfig,
	threshold uint8,
	grpcTimeout time.Duration,
	myCosigner Cosigner,
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
	}
}

// SaveLastSignedState updates the high watermark height/round/step (HRS) for a completed
// sign process if it is greater than the current high watermark. A mutex is used to avoid concurrent
// state updates. The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (pv *ThresholdValidator) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
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
func (pv *ThresholdValidator) SaveLastSignedStateInitiated(chainID string, signState SignStateConsensus) error {
	css := pv.mustLoadChainState(chainID)

	css.lastSignStateInitiatedMutex.Lock()
	defer css.lastSignStateInitiatedMutex.Unlock()
	return css.lastSignStateInitiated.Save(signState, &pv.pendingDiskWG)
}

// Stop safely shuts down the ThresholdValidator.
func (pv *ThresholdValidator) Stop() {
	pv.waitForSignStatesToFlushToDisk()
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (pv *ThresholdValidator) waitForSignStatesToFlushToDisk() {
	pv.pendingDiskWG.Wait()

	switch cosigner := pv.myCosigner.(type) {
	case *LocalCosigner:
		cosigner.waitForSignStatesToFlushToDisk()
	default:
	}
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
	encryptedEphemeralSharesThresholdMap map[Cosigner][]CosignerEphemeralSecretPart,
	thresholdPeersMutex *sync.Mutex,
) {
	peerStartTime := time.Now()
	ephemeralSecretParts, err := peer.GetEphemeralSecretParts(chainID, hrst)
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
	if len(encryptedEphemeralSharesThresholdMap) < int(pv.threshold)-1 {
		(encryptedEphemeralSharesThresholdMap)[peer] = ephemeralSecretParts.EncryptedSecrets
		defer wg.Done()
	}
	thresholdPeersMutex.Unlock()
}

func (pv *ThresholdValidator) waitForPeerSetEphemeralSharesAndSign(
	chainID string,
	ourID uint8,
	peer Cosigner,
	hrst HRSTKey,
	encryptedEphemeralSharesThresholdMap map[Cosigner][]CosignerEphemeralSecretPart,
	signBytes []byte,
	shareSignatures *[][]byte,
	shareSignaturesMutex *sync.Mutex,
	ephemeralPublic *[]byte,
	wg *sync.WaitGroup,
) {
	peerStartTime := time.Now()
	defer wg.Done()
	peerEphemeralSecretParts := make([]CosignerEphemeralSecretPart, 0, pv.threshold-1)

	for _, encryptedSecrets := range encryptedEphemeralSharesThresholdMap {
		for _, ephemeralSecretPart := range encryptedSecrets {
			// if share is intended for peer, check to make sure source peer is included in threshold
			if ephemeralSecretPart.DestinationID == peer.GetID() {
				for thresholdPeer := range encryptedEphemeralSharesThresholdMap {
					if thresholdPeer.GetID() == ephemeralSecretPart.SourceID {
						// source peer is included in threshold signature, include in sharing
						peerEphemeralSecretParts = append(peerEphemeralSecretParts, ephemeralSecretPart)
						break
					}
				}
				break
			}
		}
	}

	pv.logger.Debug(
		"Number of ephemeral parts for peer",
		"peer", peer.GetID(),
		"count", len(peerEphemeralSecretParts),
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	peerID := peer.GetID()
	sigRes, err := peer.SetEphemeralSecretPartsAndSign(CosignerSetEphemeralSecretPartsAndSignRequest{
		ChainID:          chainID,
		EncryptedSecrets: peerEphemeralSecretParts,
		HRST:             hrst,
		SignBytes:        signBytes,
	})

	if err != nil {
		pv.logger.Error("Sign error", err.Error())
		return
	}

	timedCosignerSignLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	pv.logger.Debug(
		"Received signature from peer",
		"peer", peerID,
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
	if peerID == ourID {
		*ephemeralPublic = sigRes.EphemeralPublic
	}
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

	signState, err := LoadOrCreateSignState(pv.config.PrivValStateFile(chainID))
	if err != nil {
		return err
	}

	pv.chainState.Store(chainID, ChainSignState{
		lastSignState:          signState,
		lastSignStateInitiated: signState.FreshCache(),

		lastSignStateMutex:          &sync.Mutex{},
		lastSignStateInitiatedMutex: &sync.Mutex{},
	})

	switch cosigner := pv.myCosigner.(type) {
	case *LocalCosigner:
		return cosigner.LoadSignStateIfNecessary(chainID)
	default:
		return fmt.Errorf("unknown cosigner type: %T", cosigner)
	}
}

func (pv *ThresholdValidator) getExistingBlockSignature(chainID string, block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes
	hrs := HRSKey{
		height,
		round,
		step,
	}

	css := pv.mustLoadChainState(chainID)

	latestBlock, existingSignature := css.lastSignState.GetFromCache(
		hrs,
		css.lastSignStateMutex,
	)
	if existingSignature != nil {
		// If a proposal has already been signed for this HRS, return that
		if block.Step == stepPropose || bytes.Equal(signBytes, existingSignature.SignBytes) {
			return existingSignature.Signature, block.Timestamp, nil
		}
		if err := existingSignature.OnlyDifferByTimestamp(signBytes); err != nil {
			return nil, stamp, err
		}

		// only differ by timestamp, okay to sign again
		return nil, stamp, nil
	} else if latestBlock.Height > height ||
		(latestBlock.Height == height && latestBlock.Round > round) ||
		(latestBlock.Height == height && latestBlock.Round == round && latestBlock.Step > step) {
		return nil, stamp, pv.newBeyondBlockError(chainID, hrs)
	}
	return nil, stamp, newStillWaitingForBlockError(chainID, hrs)
}

func (pv *ThresholdValidator) SignBlock(chainID string, block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes

	if err := pv.LoadSignStateIfNecessary(chainID); err != nil {
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
	if err := pv.SaveLastSignedStateInitiated(chainID, NewSignStateConsensus(height, round, step)); err != nil {
		switch err.(type) {
		case *SameHRSError:
			// Wait for last sign state signature to be the same block
			signAgain := false
			for i := 0; i < 100; i++ {
				existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)
				if sameBlockErr == nil {
					if existingSignature == nil {
						signAgain = true
						break
					}
					return existingSignature, existingTimestamp, nil
				}
				switch sameBlockErr.(type) {
				case *StillWaitingForBlockError:
					time.Sleep(10 * time.Millisecond)
					continue
				default:
					return nil, existingTimestamp, sameBlockErr
				}

			}
			if !signAgain {
				return nil, stamp, errors.New("timed out waiting for block signature from cluster")
			}
		default:
			existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(chainID, block)
			if sameBlockErr == nil {
				return existingSignature, stamp, nil
			}
			hrs := HRSKey{
				Height: height,
				Round:  round,
				Step:   step,
			}
			return nil, existingTimestamp, pv.newBeyondBlockError(chainID, hrs)
		}
	}

	numPeers := len(pv.peerCosigners)
	total := uint8(numPeers + 1)
	getEphemeralWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	getEphemeralWaitGroup.Add(int(pv.threshold) - 1)
	// Used to track how close we are to threshold

	ourID := pv.myCosigner.GetID()

	ephSecrets := make(map[Cosigner][]CosignerEphemeralSecretPart)
	thresholdPeersMutex := sync.Mutex{}

	for _, c := range pv.peerCosigners {
		go pv.waitForPeerEphemeralShares(chainID, c, hrst, &getEphemeralWaitGroup,
			ephSecrets, &thresholdPeersMutex)
	}

	myEphSecrets, err := pv.myCosigner.GetEphemeralSecretParts(chainID, hrst)
	if err != nil {
		// Our ephemeral secret parts are required, cannot proceed
		return nil, stamp, err
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&getEphemeralWaitGroup, pv.grpcTimeout) {
		return nil, stamp, errors.New("timed out waiting for ephemeral shares")
	}

	thresholdPeersMutex.Lock()
	ephSecrets[pv.myCosigner] = myEphSecrets.EncryptedSecrets
	thresholdPeersMutex.Unlock()

	timedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug(
		"Have threshold peers",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	setEphemeralAndSignWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	setEphemeralAndSignWaitGroup.Add(int(pv.threshold))

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	var ephemeralPublic []byte

	for cosigner := range ephSecrets {
		// set peerEphemeralSecretParts and sign in single rpc call.
		go pv.waitForPeerSetEphemeralSharesAndSign(chainID, ourID, cosigner, hrst, ephSecrets,
			signBytes, &shareSignatures, &shareSignaturesMutex, &ephemeralPublic, &setEphemeralAndSignWaitGroup)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&setEphemeralAndSignWaitGroup, 4*time.Second) {
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	timedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug(
		"Done waiting for cosigners, assembling signatures",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	// collect all valid responses into array of ids and signatures for the threshold lib
	sigIds := make([]int, 0)
	shareSigs := make([][]byte, 0)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}
		sigIds = append(sigIds, idx+1)

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, shareSig)
	}

	if len(sigIds) < int(pv.threshold) {
		totalInsufficientCosigners.Inc()
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble into final signature
	combinedSig := tsed25519.CombineShares(total, sigIds, shareSigs)

	signature := ephemeralPublic
	signature = append(signature, combinedSig...)

	// verify the combined signature before saving to watermark
	if !pv.myCosigner.VerifySignature(chainID, signBytes, signature) {
		totalInvalidSignature.Inc()
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

	css := pv.mustLoadChainState(chainID)

	// Err will be present if newLss is not above high watermark
	css.lastSignStateMutex.Lock()
	err = css.lastSignState.Save(newLss.SignStateConsensus, &pv.pendingDiskWG)
	css.lastSignStateMutex.Unlock()
	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			return nil, stamp, err
		}
	}

	// Emit last signed state to cluster
	err = pv.raftStore.Emit(raftEventLSS, newLss)
	if err != nil {
		pv.logger.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock).Seconds()
	timedSignBlockLag.Observe(timeSignBlock)

	return signature, stamp, nil
}
