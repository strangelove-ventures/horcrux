package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/log"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	rpcTypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

type ThresholdValidator struct {
	threshold int

	pubkey crypto.PubKey

	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState      SignState
	lastSignStateMutex sync.Mutex

	// stores the last sign state that we've started progress on
	lastSignStateInitiated      SignState
	lastSignStateInitiatedMutex sync.Mutex

	// our own cosigner
	cosigner Cosigner

	// peer cosigners
	peers []Cosigner

	raftStore *RaftStore

	logger log.Logger

	thresholdPossibilities [][]int
}

const (
	peerTimeout = 4 * time.Second
)

type ThresholdValidatorOpt struct {
	Pubkey    crypto.PubKey
	Threshold int
	SignState SignState
	Cosigner  Cosigner
	Peers     []Cosigner
	RaftStore *RaftStore
	Logger    log.Logger
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(opt *ThresholdValidatorOpt) *ThresholdValidator {
	validator := &ThresholdValidator{}
	validator.cosigner = opt.Cosigner
	validator.peers = opt.Peers
	validator.threshold = opt.Threshold
	validator.pubkey = opt.Pubkey
	validator.lastSignState = opt.SignState
	validator.lastSignStateMutex = sync.Mutex{}
	validator.lastSignStateInitiated = SignState{
		Height:   opt.SignState.Height,
		Round:    opt.SignState.Round,
		Step:     opt.SignState.Step,
		filePath: "none",
	}
	validator.lastSignStateInitiatedMutex = sync.Mutex{}
	validator.raftStore = opt.RaftStore
	validator.logger = opt.Logger
	validator.initializeThresholdPossibilities()
	return validator
}

func (pv *ThresholdValidator) GetErrorIfLessOrEqual(height int64, round int64, step int8) error {
	return pv.lastSignState.GetErrorIfLessOrEqual(height, round, step, &pv.lastSignStateMutex)
}

func (pv *ThresholdValidator) SaveLastSignedState(signState SignStateConsensus) error {
	return pv.lastSignState.Save(signState, &pv.lastSignStateMutex)
}

func (pv *ThresholdValidator) SaveLastSignedStateInitiated(signState SignStateConsensus) error {
	return pv.lastSignStateInitiated.Save(signState, &pv.lastSignStateInitiatedMutex)
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey() (crypto.PubKey, error) {
	return pv.pubkey, nil
}

// Create a list of the possible threshold possibilities that include this node.
// A threshold possibility is a list of peers that when they have mutually shared
// their ephemeral secret parts, the threshold signing process can proceed to sign.
// For example, if the LocalCosigner's peer ID is 3, and the threshold is 3, and
// there are 5 total signers, possible threshold possibilities are [1,2,3], [1,3,5],
// etc. This is used in the waitForEphemeralSharing iteration to make sure that mutual
// sharing has occurred between at least the threshold of signers
func (pv *ThresholdValidator) recursiveCreateThresholdPossibilities(
	thresholdPossibilities *[][]int, thresholdPossibility []int, peerID int) {
	for possiblePeer := peerID; possiblePeer < len(pv.peers)+2; possiblePeer++ {
		newThresholdPossibility := make([]int, len(thresholdPossibility))
		_ = copy(newThresholdPossibility, thresholdPossibility)
		newThresholdPossibility = append(newThresholdPossibility, possiblePeer)
		if len(newThresholdPossibility) == pv.threshold {
			for _, peerID := range newThresholdPossibility {
				if peerID == pv.cosigner.GetID() {
					// only include threshold possibilities that include the local cosigner
					(*thresholdPossibilities) = append((*thresholdPossibilities), newThresholdPossibility)
					break
				}
			}
		} else {
			pv.recursiveCreateThresholdPossibilities(thresholdPossibilities, newThresholdPossibility, possiblePeer+1)
		}
	}
}

func (pv *ThresholdValidator) initializeThresholdPossibilities() {
	thresholdFloat := float64(pv.threshold)
	numThresholdSharingPossibilities := int((0.5 * thresholdFloat * thresholdFloat) - (0.5 * thresholdFloat))
	pv.thresholdPossibilities = make([][]int, 0, numThresholdSharingPossibilities)

	emptyThresholdPossibility := make([]int, 0, pv.threshold)
	pv.recursiveCreateThresholdPossibilities(&pv.thresholdPossibilities, emptyThresholdPossibility, 1)
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignVote(chainID string, vote *tmProto.Vote) error {
	block := &block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      VoteToStep(vote),
		Timestamp: vote.Timestamp,
		SignBytes: tm.VoteSignBytes(chainID, vote),
	}
	sig, stamp, err := pv.SignBlock(chainID, block)

	vote.Signature = sig
	vote.Timestamp = stamp

	return err
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	block := &block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      ProposalToStep(proposal),
		Timestamp: proposal.Timestamp,
		SignBytes: tm.ProposalSignBytes(chainID, proposal),
	}
	sig, stamp, err := pv.SignBlock(chainID, block)

	proposal.Signature = sig
	proposal.Timestamp = stamp

	return err
}

type block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

// These are emitted by signers after the ephemeral secret part is saved
// during SetEphemeralSecretPart to send a receipt back to the raft leader,
// done with EmitEphemeralSecretPartReceipt
func getDoneSharingKey(hrs HRSKey, peerID, otherPeer int) string {
	return fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", hrs.Height, hrs.Round, hrs.Step, peerID, otherPeer)
}

// Get the peer IDs in order from least to greatest for comparison against
// the thresholdPossibilities
func getOrderedPair(num1, num2 int) (int, int) {
	if num1 < num2 {
		return num1, num2
	}
	return num2, num1
}

// Watches for receipts from the signers to indicate the ephemeral secret part sharing is complete
// Needs to ensure that sharing has occurred mutually between at least threshold peers. For example,
// if the threshold is 3, and there are 3 cosigners, then cosigner 1 will need to have saved 2 and 3's secret parts,
// 2 will need 1 and 3's, and 3 will need 1 and 2's, before the SignBlock method can proceed to get signatures.
func (pv *ThresholdValidator) waitForEphemeralSharing(hrs HRSKey, allSigners []int) ([]int, error) {
	peerWaitCtx, peerWaitCtxCancel := context.WithTimeout(context.Background(), peerTimeout)
	defer peerWaitCtxCancel()

	var foundThresholdPeers []int

	for peerWaitCtx.Err() == nil {
		time.Sleep(100 * time.Millisecond)

		// assemble map of peers to which peers they have saved ephemeral secret parts from
		doneSharingWith := make(map[int][]int)

		for _, peerID := range allSigners {
			for _, nestedPeerID := range allSigners {
				if peerID == nestedPeerID {
					continue
				}
				doneSharingKey := getDoneSharingKey(hrs, peerID, nestedPeerID)
				doneSharing, _ := pv.raftStore.Get(doneSharingKey)
				if doneSharing == "true" {
					doneSharingWith[peerID] = append(doneSharingWith[peerID], nestedPeerID)
				}
			}
		}

		// Assemble the pairs of peers where both peers have shared with each other
		mutualSharingPairs := make([][2]int, 0, 2*len(allSigners)-1)

		for peerID, doneSharingWithPeers := range doneSharingWith {
			for _, doneSharingWithPeerID := range doneSharingWithPeers {
				for _, otherPeersDoneSharingWithPeerID := range doneSharingWith[doneSharingWithPeerID] {
					if peerID == otherPeersDoneSharingWithPeerID {
						// there is mutual sharing between peerID and doneSharingWithPeerID
						found := false
						firstPeer, secondPeer := getOrderedPair(peerID, doneSharingWithPeerID)
						for _, mutualSharingPair := range mutualSharingPairs {
							if mutualSharingPair[0] == firstPeer && mutualSharingPair[1] == secondPeer {
								found = true
								break
							}
						}
						if !found {
							mutualSharingPairs = append(mutualSharingPairs, [2]int{firstPeer, secondPeer})
						}
						break
					}
				}
			}
		}

		// Iterate through the possible threshold peer scenarios and see if we have enough sharing
		foundThreshold := false
		for _, thresholdPossibility := range pv.thresholdPossibilities {
			thresholdPossibilityValid := true
			for i := 0; i < len(thresholdPossibility)-1; i++ {
				firstPeer := thresholdPossibility[i]
				secondPeer := thresholdPossibility[i+1]
				foundInMutualSharingPairs := false
				for _, mutualSharingPair := range mutualSharingPairs {
					firstMutualPeer := mutualSharingPair[0]
					secondMutualPeer := mutualSharingPair[1]
					if firstPeer == firstMutualPeer && secondPeer == secondMutualPeer {
						foundInMutualSharingPairs = true
						break
					}
				}
				if !foundInMutualSharingPairs {
					thresholdPossibilityValid = false
					break
				}
			}
			if thresholdPossibilityValid {
				foundThresholdPeers = thresholdPossibility
				foundThreshold = true
				break
			}
		}
		if foundThreshold {
			// We have threshold mutual sharing
			break
		}
	}

	if peerWaitCtx.Err() != nil {
		return nil, errors.New("ephemeral sharing timed out")
	}
	pv.logger.Debug(fmt.Sprintf("Ephemeral sharing done, threshold peers: +%v", foundThresholdPeers))

	return foundThresholdPeers, nil
}

func (pv *ThresholdValidator) peerSign(
	ourID int,
	peer Cosigner,
	hrs HRSKey,
	allSigners []int,
	signReq CosignerSignRequest,
	shareSignatures *[][]byte,
	ephemeralPublic *[]byte,
	wg *sync.WaitGroup,
	shareSignaturesMutex *sync.Mutex,
	thresholdProgressMutex *sync.Mutex,
	thresholdProgress *int,
) {
	peerID := peer.GetID()

	sigResp, err := peer.Sign(signReq)

	if err != nil {
		pv.logger.Error("Sign error", err.Error())
	}

	pv.logger.Debug(fmt.Sprintf("Received signature from %d", peerID))

	shareSignaturesMutex.Lock()
	defer shareSignaturesMutex.Unlock()

	peerIdx := peerID - 1
	(*shareSignatures)[peerIdx] = make([]byte, len(sigResp.Signature))
	copy((*shareSignatures)[peerIdx], sigResp.Signature)
	if peerID == ourID {
		*ephemeralPublic = sigResp.EphemeralPublic
	}

	// need this check so that wg.Done is not called more than (threshold - 1) times, which causes hardlock
	thresholdProgressMutex.Lock()
	defer thresholdProgressMutex.Unlock()
	*thresholdProgress -= 1
	if *thresholdProgress >= 0 {
		wg.Done()
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

func (pv *ThresholdValidator) SignBlock(chainID string, block *block) ([]byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	if pv.raftStore.raft.State() != raft.Leader {
		pv.logger.Debug("I am not the raft leader. Proxying request to the leader")
		signRes, err := pv.raftStore.LeaderSignBlock(CosignerSignBlockRequest{chainID, block})
		if err != nil {
			if _, ok := err.(*rpcTypes.RPCError); ok {
				rpcErrUnwrapped := err.(*rpcTypes.RPCError).Data
				// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
				if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
					return nil, stamp, &BeyondBlockError{msg: rpcErrUnwrapped}
				}
			}
			return nil, stamp, err
		}
		return signRes.Signature, stamp, nil
	}

	pv.logger.Debug("I am the raft leader. Managing the sign process for this block")

	// Keep track of the last block that we began the signing process for. Only allow one attempt per block
	err := pv.SaveLastSignedStateInitiated(SignStateConsensus{
		Height: height,
		Round:  round,
		Step:   step,
	})
	if err != nil {
		return nil, stamp, &BeyondBlockError{
			msg: fmt.Sprintf("Progress already started on block %d.%d.%d, skipping %d.%d.%d",
				pv.lastSignStateInitiated.Height, pv.lastSignStateInitiated.Round, pv.lastSignStateInitiated.Step,
				height, round, step),
		}
	}

	// the block sign state for caching full block signatures
	lss := pv.lastSignState

	// check watermark
	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return nil, stamp, err
	}

	signBytes := block.SignBytes

	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			return lss.Signature, block.Timestamp, nil
		} else if timestamp, ok := lss.OnlyDifferByTimestamp(signBytes); ok {
			return lss.Signature, timestamp, nil
		}

		return nil, stamp, errors.New("conflicting data")
	}

	signReq := CosignerSignRequest{
		SignBytes: signBytes,
	}

	numPeers := len(pv.peers)

	total := uint8(numPeers + 1)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	wg := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	wg.Add(pv.threshold)
	// Used to track how close we are to threshold
	thresholdProgress := pv.threshold
	thresholdProgressMutex := sync.Mutex{}

	ourID := pv.cosigner.GetID()

	// have our cosigner generate ephemeral info at the current height
	_, err = pv.cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
		ID:     ourID,
		Height: height,
		Round:  round,
		Step:   step,
	})
	if err != nil {
		return nil, stamp, err
	}

	hrs := HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}

	// Send requested HRS to cluster to initiate ephemeral secret sharing amongst cosigners
	err = pv.raftStore.Emit(raftEventHRS, hrs)

	if err != nil {
		return nil, stamp, err
	}

	allSigners := []int{ourID}
	allPeers := []Cosigner{pv.cosigner}
	for _, peer := range pv.peers {
		allSigners = append(allSigners, peer.GetID())
		allPeers = append(allPeers, peer)
	}

	thresholdPeerIDs, err := pv.waitForEphemeralSharing(hrs, allSigners)

	if err != nil {
		return nil, stamp, err
	}

	thresholdPeers := make([]Cosigner, 0, len(thresholdPeerIDs))
	for _, peerID := range thresholdPeerIDs {
		for _, peer := range allPeers {
			if peerID == peer.GetID() {
				thresholdPeers = append(thresholdPeers, peer)
			}
		}
	}

	var ephemeralPublic []byte

	for _, peer := range thresholdPeers {
		// Wait for the peers to sign the request
		go pv.peerSign(ourID, peer, hrs, allSigners,
			signReq, &shareSignatures, &ephemeralPublic, &wg,
			&shareSignaturesMutex, &thresholdProgressMutex, &thresholdProgress)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&wg, 4*time.Second) {
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	pv.logger.Debug("Done waiting for cosigners, assembling signatures")

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

	if len(sigIds) < pv.threshold {
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble into final signature
	combinedSig := tsed25519.CombineShares(total, sigIds, shareSigs)

	signature := ephemeralPublic
	signature = append(signature, combinedSig...)

	// verify the combined signature before saving to watermark
	if !pv.pubkey.VerifySignature(signBytes, signature) {
		return nil, stamp, errors.New("combined signature is not valid")
	}

	newLss := SignStateConsensus{
		Height:    height,
		Round:     round,
		Step:      step,
		Signature: signature,
		SignBytes: signBytes,
	}
	// Err will be present if newLss is not above high watermark
	err = pv.lastSignState.Save(newLss, &pv.lastSignStateMutex)
	if err != nil {
		return nil, stamp, err
	}

	// Emit last signed state to cluster
	err = pv.raftStore.Emit(raftEventLSS, newLss)
	if err != nil {
		pv.logger.Error("Error emitting LSS", err.Error())
	}

	return signature, stamp, nil
}
