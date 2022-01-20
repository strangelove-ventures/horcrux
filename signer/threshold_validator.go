package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/tendermint/tendermint/crypto"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

type ThresholdValidator struct {
	threshold int

	pubkey crypto.PubKey

	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState SignState

	// our own cosigner
	cosigner Cosigner

	// peer cosigners
	peers []Cosigner

	raftStore *RaftStore
}

type ThresholdValidatorOpt struct {
	Pubkey    crypto.PubKey
	Threshold int
	SignState SignState
	Cosigner  Cosigner
	Peers     []Cosigner
	RaftStore *RaftStore
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(opt *ThresholdValidatorOpt) *ThresholdValidator {
	validator := &ThresholdValidator{}
	validator.cosigner = opt.Cosigner
	validator.peers = opt.Peers
	validator.threshold = opt.Threshold
	validator.pubkey = opt.Pubkey
	validator.lastSignState = opt.SignState
	validator.raftStore = opt.RaftStore
	return validator
}

func (pv *ThresholdValidator) GetLastSigned() HRSKey {
	return HRSKey{
		Height: pv.lastSignState.Height,
		Round:  pv.lastSignState.Round,
		Step:   pv.lastSignState.Step,
	}
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey() (crypto.PubKey, error) {
	return pv.pubkey, nil
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

func (pv *ThresholdValidator) SignBlock(chainID string, block *block) ([]byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

	if pv.raftStore.raft.State() != raft.Leader {
		signRes, err := pv.raftStore.LeaderSignBlock(RPCRaftSignBlockRequest{chainID, block})
		if err != nil {
			return nil, stamp, err
		}
		return signRes.Signature, stamp, nil
	}

	// the block sign state for caching full block signatures
	lss := pv.lastSignState

	// check watermark
	sameHRS, err := lss.CheckHRS(height, int64(round), step)
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

	signReq, err := json.Marshal(&CosignerSignRequest{
		SignBytes: signBytes,
	})
	if err != nil {
		fmt.Printf("ERROR GetEphemeralSecretPart %v\n", err)
	}

	numPeers := len(pv.peers)

	total := uint8(numPeers + 1)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	wg := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	wg.Add(pv.threshold - 1)
	// Used to track how close we are to threshold
	thresholdProgress := pv.threshold - 1

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
	hrsJSON, err := json.Marshal(hrs)
	if err != nil {
		return nil, stamp, err
	}

	// Send requested HRS to cluster to initiate ephemeral secret sharing amongst cosigners
	err = pv.raftStore.Set("HRS", string(hrsJSON))

	if err != nil {
		return nil, stamp, err
	}

	// There are two layers of goroutines for each cosigner.
	// The outer routine for each cosigner to dispatch signing in parallel. This outer routine
	// block on the signing request completing.
	// The inner routine (formed within each request goroutine), dispatches the actual signing call.
	// This is to support a time out which can happen when using remote signers.
	for _, peer := range pv.peers {
		request := func(peer Cosigner) {
			peerId := peer.GetID()
			peerIdx := peerId - 1

			// cosigner.Sign makes a blocking RPC request (with no timeout)
			// to prevent it from hanging our process indefinitely, we use a timeout context
			// and another goroutine
			signCtx, signCtxCancel := context.WithTimeout(context.Background(), 4*time.Second)

			go func() {
				var doneSharingKeys []string
				getDoneSharingKey := func(otherPeer int) string {
					return fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", height, round, step, peerId, otherPeer)
				}
				doneSharingKeys = append(doneSharingKeys, getDoneSharingKey(ourID))
				for _, nestedPeer := range pv.peers {
					nestedPeerID := nestedPeer.GetID()
					if peerId == nestedPeerID {
						continue
					}
					doneSharingKeys = append(doneSharingKeys, getDoneSharingKey(nestedPeerID))
				}

				// Wait for (threshold - 1) cosigner ephemeral shares to be saved for this peer
				for signCtx.Err() == nil {
					time.Sleep(100 * time.Millisecond)

					doneSharingWithCount := 0

					for _, doneSharingKey := range doneSharingKeys {
						doneSharing, _ := pv.raftStore.Get(doneSharingKey)
						if doneSharing == "true" {
							doneSharingWithCount += 1
						}
					}
					if doneSharingWithCount >= pv.threshold-1 {
						// We have reached threshold ephemeral secret sharing for peer. Break out of poll
						break
					}
				}

				// Cleanup keys
				for _, doneSharingKey := range doneSharingKeys {
					err = pv.raftStore.Delete(doneSharingKey)
					if err != nil {
						fmt.Printf("Error deleting raft key: %v\n", err)
					}
				}

				// Request signature from this peer since it has enough shares
				err = pv.raftStore.Set(fmt.Sprintf("SignReq.%d", peerId), string(signReq))

				var sigResp = &CosignerSignResponse{}
				peerSignWatchKey := fmt.Sprintf("SignRes.%d.%d.%d.%d", height, round, step, peerId)
				// Wait for sign response from this peer (or timeout)
				for signCtx.Err() == nil {
					time.Sleep(100 * time.Millisecond)
					value, err := pv.raftStore.Get(peerSignWatchKey)
					if err != nil || len(value) == 0 {
						continue
					}
					err = json.Unmarshal([]byte(value), sigResp)
					if err != nil {
						fmt.Printf("Error during sign response unmarshal %v\n", err)
						continue
					}
					// Got signature from peer, break out of poll
					break
				}

				err = pv.raftStore.Delete(peerSignWatchKey)
				if err != nil {
					fmt.Printf("Error deleting raft key: %v\n", err)
				}

				// The signCtx is done if it times out or if the blockCtx done cancels it
				select {
				case <-signCtx.Done():
					return
				default:
				}

				defer signCtxCancel()

				shareSignaturesMutex.Lock()
				defer shareSignaturesMutex.Unlock()

				shareSignatures[peerIdx] = make([]byte, len(sigResp.Signature))
				copy(shareSignatures[peerIdx], sigResp.Signature)
			}()

			// the sign context finished or timed out
			select {
			case <-signCtx.Done():
			}

			// need this check so that wg.Done is not called more than (threshold - 1) times, which causes hardlock
			thresholdProgress -= 1
			if thresholdProgress >= 0 {
				wg.Done()
			}
		}

		go request(peer)
	}

	// Wait for (threshold - 1) cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	wg.Wait()

	shareSignaturesMutex.Lock()
	defer shareSignaturesMutex.Unlock()

	// sign with our share now
	signResp, err := pv.cosigner.Sign(CosignerSignRequest{
		SignBytes: signBytes,
	})
	if err != nil {
		return nil, stamp, err
	}

	ephemeralPublic := signResp.EphemeralPublic

	shareSignatures[ourID-1] = make([]byte, len(signResp.Signature))
	copy(shareSignatures[ourID-1], signResp.Signature)

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
		return nil, stamp, errors.New("Not enough co-signers")
	}

	// assemble into final signature
	combinedSig := tsed25519.CombineShares(total, sigIds, shareSigs)

	signature := append(ephemeralPublic, combinedSig...)

	// verify the combined signature before saving to watermark
	if !pv.pubkey.VerifySignature(signBytes, signature) {
		return nil, stamp, errors.New("Combined signature is not valid")
	}

	pv.lastSignState.Height = height
	pv.lastSignState.Round = round
	pv.lastSignState.Step = step
	pv.lastSignState.Signature = signature
	pv.lastSignState.SignBytes = signBytes
	pv.lastSignState.Save()

	return signature, stamp, nil
}
