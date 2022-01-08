package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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
}

type ThresholdValidatorOpt struct {
	Pubkey    crypto.PubKey
	Threshold int
	SignState SignState
	Cosigner  Cosigner
	Peers     []Cosigner
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(opt *ThresholdValidatorOpt) *ThresholdValidator {
	validator := &ThresholdValidator{}
	validator.cosigner = opt.Cosigner
	validator.peers = opt.Peers
	validator.threshold = opt.Threshold
	validator.pubkey = opt.Pubkey
	validator.lastSignState = opt.SignState
	return validator
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
	sig, stamp, err := pv.signBlock(chainID, block)

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
	sig, stamp, err := pv.signBlock(chainID, block)

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

func (pv *ThresholdValidator) signBlock(chainID string, block *block) ([]byte, time.Time, error) {
	height, round, step, stamp := block.Height, block.Round, block.Step, block.Timestamp

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

	numPeers := len(pv.peers)

	total := uint8(numPeers + 1)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	wg := sync.WaitGroup{}
	wg.Add(numPeers)

	ourID := pv.cosigner.GetID()

	// have our cosigner generate ephemeral info at the current height
	_, err = pv.cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
		ID:           ourID,
		Height:       height,
		Round:        round,
		Step:         step,
		FindOrCreate: true,
	})
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
				hasResp, err := pv.cosigner.HasEphemeralSecretPart(CosignerHasEphemeralSecretPartRequest{
					ID:     peerId,
					Height: height,
					Round:  round,
					Step:   step,
				})

				// did we timeout or finish elsewhere?
				select {
				case <-signCtx.Done():
					return
				default:
				}

				if err != nil {
					fmt.Printf("ERROR HasEphemeralSecretPart: %s\n", err)
					signCtxCancel()
					return
				}

				if !hasResp.Exists {
					// if we don't already have an ephemeral secret part for the HRS, we need to get one
					ephSecretResp, err := peer.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
						ID:           ourID,
						Height:       height,
						Round:        round,
						Step:         step,
						FindOrCreate: false,
					})

					if err != nil {
						fmt.Printf("ERROR GetEphemeralSecretPart %s\n", err)
					}

					// did we timeout or finish elsewhere?
					select {
					case <-signCtx.Done():
						return
					default:
					}

					if err != nil {
						signCtxCancel()
						return
					}

					// set the response for ourselves
					err = pv.cosigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
						SourceSig:                      ephSecretResp.SourceSig,
						SourceID:                       ephSecretResp.SourceID,
						SourceEphemeralSecretPublicKey: ephSecretResp.SourceEphemeralSecretPublicKey,
						EncryptedSharePart:             ephSecretResp.EncryptedSharePart,
						Height:                         height,
						Round:                          round,
						Step:                           step,
					})

					if err != nil {
						fmt.Printf("ERROR SetEphemeralSecretPart %s\n", err)
					}

					// did we timeout or finish elsewhere?
					select {
					case <-signCtx.Done():
						return
					default:
					}

					if err != nil {
						signCtxCancel()
						return
					}
				}

				// ask the cosigner to sign with their share
				sigResp, err := peer.Sign(CosignerSignRequest{
					SignBytes: signBytes,
				})

				if err != nil {
					fmt.Printf("ERROR Sign %s\n", err)
				}

				// did we timeout or finish elsewhere?
				select {
				case <-signCtx.Done():
					return
				default:
				}

				if err != nil {
					signCtxCancel()
					return
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

			wg.Done()
		}

		go request(peer)
	}

	// Wait for all cosigners to be complete
	// A Cosigner will either respond in time, or be canceled with timeout
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
