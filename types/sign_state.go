package types

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/v3/comet/libs/tempfile"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	"github.com/strangelove-ventures/horcrux/v3/signer/cond"
)

const (
	StepPropose   int8 = 1
	StepPrevote   int8 = 2
	StepPrecommit int8 = 3
	blocksToCache      = 3
)

func SignType(step int8) string {
	switch step {
	case StepPropose:
		return "proposal"
	case StepPrevote:
		return "prevote"
	case StepPrecommit:
		return "precommit"
	default:
		return "unknown"
	}
}

func VoteTypeToStep(voteType cometproto.SignedMsgType) int8 {
	switch voteType {
	case cometproto.PrevoteType:
		return StepPrevote
	case cometproto.PrecommitType:
		return StepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToBlock(vote *cometproto.Vote) Block {
	return Block{
		Height: vote.Height,
		Round:  int64(vote.Round),
		Step:   VoteTypeToStep(vote.Type),
		BlockID: &BlockID{
			Hash: vote.BlockID.Hash,
			PartSetHeader: PartSetHeader{
				Total: vote.BlockID.PartSetHeader.Total,
				Hash:  vote.BlockID.PartSetHeader.Hash,
			},
		},
		VoteExtension: vote.Extension,
		Timestamp:     vote.Timestamp,
	}
}

func ProposalToStep(_ *cometproto.Proposal) int8 {
	return StepPropose
}

func ProposalToBlock(proposal *cometproto.Proposal) Block {
	return Block{
		Height: proposal.Height,
		Round:  int64(proposal.Round),
		Step:   ProposalToStep(proposal),
		BlockID: &BlockID{
			Hash: proposal.BlockID.Hash,
			PartSetHeader: PartSetHeader{
				Total: proposal.BlockID.PartSetHeader.Total,
				Hash:  proposal.BlockID.PartSetHeader.Hash,
			},
		},
		POLRound:  int64(proposal.PolRound),
		Timestamp: proposal.Timestamp,
	}
}

func StepToType(step int8) cometproto.SignedMsgType {
	switch step {
	case StepPropose:
		return cometproto.ProposalType
	case StepPrevote:
		return cometproto.PrevoteType
	case StepPrecommit:
		return cometproto.PrecommitType
	default:
		panic("Unknown step")
	}
}

type SignStateLegacy struct {
	Height string `json:"height"`
	Round  string `json:"round"`
	Step   int8   `json:"step"`

	SignBytes string `json:"signbytes,omitempty"`

	Signature              string `json:"signature,omitempty"`
	VoteExtensionSignature string `json:"vote_ext_signature,omitempty"`
}

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height    int64    `json:"height"`
	Round     int64    `json:"round"`
	Step      int8     `json:"step"`
	BlockID   *BlockID `json:"block_id"`
	POLRound  int64    `json:"pol_round"`
	Timestamp int64    `json:"timestamp"`

	SignBytes []byte `json:"sign_bytes,omitempty"`

	Signature              []byte `json:"signature,omitempty"`
	VoteExtensionSignature []byte `json:"vote_ext_signature,omitempty"`

	filePath string

	// mu protects the cache and is used for signaling with cond.
	mu    sync.RWMutex
	cache map[HRSKey]SignStateConsensus
	cond  *cond.Cond
}

func (signState *SignState) Block() Block {
	return Block{
		Height:    signState.Height,
		Round:     signState.Round,
		Step:      signState.Step,
		BlockID:   signState.BlockID,
		POLRound:  signState.POLRound,
		Timestamp: time.Unix(0, signState.Timestamp),
	}
}

func (signState *SignState) CondLock() {
	signState.cond.L.Lock()
}

func (signState *SignState) CondUnlock() {
	signState.cond.L.Unlock()
}

func (signState *SignState) CondWaitWithTimeout(timeout time.Duration) {
	signState.cond.WaitWithTimeout(timeout)
}

func (signState *SignState) CondBroadcast() {
	signState.cond.Broadcast()
}

func (signState *SignState) Cached(hrs HRSKey) (SignStateConsensus, bool) {
	val, ok := signState.cache[hrs]
	return val, ok
}

func (signState *SignState) Cache(hrs HRSKey, ssc SignStateConsensus) {
	signState.cache[hrs] = ssc
}

func (signState *SignState) ClearFile() {
	signState.filePath = os.DevNull
}

func (signState *SignState) ExistingSignatureOrErrorIfRegression(block Block, signBytes []byte) ([]byte, error) {
	signState.mu.RLock()
	defer signState.mu.RUnlock()

	sameHRS, err := signState.CheckHRS(block.HRSTKey())
	if err != nil {
		return nil, err
	}

	if !sameHRS {
		// not a regression in height. okay to sign
		return nil, nil
	}

	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	if bytes.Equal(signBytes, signState.SignBytes) {
		return signState.Signature, nil
	} else if err := signState.Block().EqualForSigning(block); err != nil {
		return nil, err
	}

	// same HRS, and only differ by timestamp - ok to sign again
	return nil, nil
}

func (signState *SignState) HRSKey() HRSKey {
	signState.mu.RLock()
	defer signState.mu.RUnlock()
	return HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
}

func (signState *SignState) hrsKeyLocked() HRSKey {
	return HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
}

type SignStateConsensus struct {
	Height    int64
	Round     int64
	Step      int8
	BlockID   *BlockID
	POLRound  int64
	Timestamp int64

	SignBytes []byte

	Signature              []byte
	VoteExtensionSignature []byte
}

func (signState SignStateConsensus) Block() Block {
	return Block{
		Height:    signState.Height,
		Round:     signState.Round,
		Step:      signState.Step,
		BlockID:   signState.BlockID,
		POLRound:  signState.POLRound,
		Timestamp: time.Unix(0, signState.Timestamp),
	}
}

func (signState SignStateConsensus) HRSKey() HRSKey {
	return HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
}

type ChainSignStateConsensus struct {
	ChainID            string
	SignStateConsensus SignStateConsensus
}

func NewSignStateConsensus(height int64, round int64, step int8) SignStateConsensus {
	return SignStateConsensus{
		Height: height,
		Round:  round,
		Step:   step,
	}
}

// GetFromCache will return the latest signed block within the SignState
// and the relevant SignStateConsensus from the cache, if present.
func (signState *SignState) GetFromCache(hrs HRSKey) (HRSKey, *SignStateConsensus) {
	signState.mu.RLock()
	defer signState.mu.RUnlock()
	latestBlock := signState.hrsKeyLocked()
	if ssc, ok := signState.cache[hrs]; ok {
		return latestBlock, &ssc
	}
	return latestBlock, nil
}

// cacheAndMarshal will cache a SignStateConsensus for it's HRS and return the marshalled bytes.
func (signState *SignState) cacheAndMarshal(ssc SignStateConsensus) []byte {
	signState.mu.Lock()
	defer signState.mu.Unlock()

	signState.cache[ssc.HRSKey()] = ssc

	for hrs := range signState.cache {
		if hrs.Height < ssc.Height-blocksToCache {
			delete(signState.cache, hrs)
		}
	}

	signState.Height = ssc.Height
	signState.Round = ssc.Round
	signState.Step = ssc.Step
	signState.BlockID = ssc.BlockID
	signState.POLRound = ssc.POLRound
	signState.Timestamp = ssc.Timestamp

	signState.SignBytes = ssc.SignBytes

	signState.Signature = ssc.Signature
	signState.VoteExtensionSignature = ssc.VoteExtensionSignature

	jsonBytes, err := json.MarshalIndent(signState, "", "  ")
	if err != nil {
		panic(err)
	}

	return jsonBytes
}

// Save updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. If pendingDiskWG is provided, the write operation
// will be a separate goroutine (async). This allows pendingDiskWG to be used to .Wait()
// for all pending SignState disk writes.
func (signState *SignState) Save(
	ssc SignStateConsensus,
	pendingDiskWG *sync.WaitGroup,
) error {
	err := signState.GetErrorIfLessOrEqual(ssc.Height, ssc.Round, ssc.Step)
	if err != nil {
		return err
	}

	// HRS is greater than existing state, move forward with caching and saving.

	jsonBytes := signState.cacheAndMarshal(ssc)

	// Broadcast to waiting goroutines to notify them that an
	// existing signature for their HRS may now be available.
	signState.cond.Broadcast()

	if pendingDiskWG != nil {
		pendingDiskWG.Add(1)
		go func() {
			defer pendingDiskWG.Done()
			signState.save(jsonBytes)
		}()
	} else {
		signState.save(jsonBytes)
	}

	return nil
}

// Save persists the FilePvLastSignState to its filePath.
func (signState *SignState) save(jsonBytes []byte) {
	outFile := signState.filePath
	if outFile == os.DevNull {
		return
	}
	if outFile == "" {
		panic("cannot save SignState: filePath not set")
	}

	err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

type HeightRegressionError struct {
	regressed, last int64
}

func (e *HeightRegressionError) Error() string {
	return fmt.Sprintf(
		"height regression. Got %v, last height %v",
		e.regressed, e.last,
	)
}

func newHeightRegressionError(regressed, last int64) *HeightRegressionError {
	return &HeightRegressionError{
		regressed: regressed,
		last:      last,
	}
}

type RoundRegressionError struct {
	height          int64
	regressed, last int64
}

func (e *RoundRegressionError) Error() string {
	return fmt.Sprintf(
		"round regression at height %d. Got %d, last round %d",
		e.height, e.regressed, e.last,
	)
}

func newRoundRegressionError(height, regressed, last int64) *RoundRegressionError {
	return &RoundRegressionError{
		height:    height,
		regressed: regressed,
		last:      last,
	}
}

type StepRegressionError struct {
	height, round   int64
	regressed, last int8
}

func (e *StepRegressionError) Error() string {
	return fmt.Sprintf(
		"step regression at height %d, round %d. Got %d, last step %d",
		e.height, e.round, e.regressed, e.last,
	)
}

func newStepRegressionError(height, round int64, regressed, last int8) *StepRegressionError {
	return &StepRegressionError{
		height:    height,
		round:     round,
		regressed: regressed,
		last:      last,
	}
}

var ErrEmptySignBytes = errors.New("no SignBytes found")

// CheckHRS checks the given height, round, step (HRS) against that of the
// SignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// Returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (signState *SignState) CheckHRS(hrst HRSTKey) (bool, error) {
	if signState.Height > hrst.Height {
		return false, newHeightRegressionError(hrst.Height, signState.Height)
	}

	if signState.Height == hrst.Height {
		if signState.Round > hrst.Round {
			return false, newRoundRegressionError(hrst.Height, hrst.Round, signState.Round)
		}

		if signState.Round == hrst.Round {
			if signState.Step > hrst.Step {
				return false, newStepRegressionError(hrst.Height, hrst.Round, hrst.Step, signState.Step)
			} else if signState.Step == hrst.Step {
				if signState.SignBytes != nil {
					if signState.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, ErrEmptySignBytes
			}
		}
	}
	return false, nil
}

type SameHRSError struct {
	msg string
}

func (e *SameHRSError) Error() string { return e.msg }

func newSameHRSError(hrs HRSKey) *SameHRSError {
	return &SameHRSError{
		msg: fmt.Sprintf("HRS is the same as current: %d:%d:%d", hrs.Height, hrs.Round, hrs.Step),
	}
}

func (signState *SignState) GetErrorIfLessOrEqual(height int64, round int64, step int8) error {
	hrs := HRSKey{Height: height, Round: round, Step: step}
	signStateHRS := signState.HRSKey()
	if signStateHRS.GreaterThan(hrs) {
		return errors.New("regression not allowed")
	}

	if hrs == signStateHRS {
		// same HRS as current
		return newSameHRSError(HRSKey{Height: height, Round: round, Step: step})
	}
	// Step is greater, so all good
	return nil
}

// FreshCache returns a clone of a SignState with a new cache
// including the most recent sign state.
func (signState *SignState) FreshCache() *SignState {
	newSignState := &SignState{
		Height:                 signState.Height,
		Round:                  signState.Round,
		Step:                   signState.Step,
		BlockID:                signState.BlockID,
		POLRound:               signState.POLRound,
		Timestamp:              signState.Timestamp,
		Signature:              signState.Signature,
		SignBytes:              signState.SignBytes,
		VoteExtensionSignature: signState.VoteExtensionSignature,
		cache:                  make(map[HRSKey]SignStateConsensus),

		filePath: signState.filePath,
	}

	newSignState.cond = cond.New(&newSignState.mu)

	newSignState.cache[HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}] = SignStateConsensus{
		Height:                 signState.Height,
		Round:                  signState.Round,
		Step:                   signState.Step,
		BlockID:                signState.BlockID,
		POLRound:               signState.POLRound,
		Timestamp:              signState.Timestamp,
		SignBytes:              signState.SignBytes,
		Signature:              signState.Signature,
		VoteExtensionSignature: signState.VoteExtensionSignature,
	}

	return newSignState
}

// LoadSignState loads a sign state from disk.
func LoadSignState(filepath string) (*SignState, error) {
	stateJSONBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	state := new(SignState)

	legacyState := new(SignStateLegacy)

	if legacyErr := json.Unmarshal(stateJSONBytes, legacyState); legacyErr == nil {
		state.Height, err = strconv.ParseInt(legacyState.Height, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse height: %w", err)
		}

		state.Round, err = strconv.ParseInt(legacyState.Round, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse round: %w", err)
		}

		state.Step = legacyState.Step

		if legacyState.SignBytes != "" {
			// If the sign bytes are not valid hex, we don't need to throw an error.
			// It will just force that we do not ever sign again for this HRS.
			state.SignBytes, _ = hex.DecodeString(legacyState.SignBytes)
		}

		if legacyState.Signature != "" {
			// If the signature is not valid base64, we don't need to throw an error.
			// It will just force that we do not ever sign again for this HRS.
			state.Signature, _ = base64.StdEncoding.DecodeString(legacyState.Signature)
		}

		if legacyState.VoteExtensionSignature != "" {
			// If the signature is not valid base64, we don't need to throw an error.
			// It will just force that we do not ever sign again for this HRS.
			state.VoteExtensionSignature, _ = base64.StdEncoding.DecodeString(legacyState.VoteExtensionSignature)
		}
	} else {
		if err := json.Unmarshal(stateJSONBytes, state); err != nil {
			return nil, fmt.Errorf("failed to unmarshal sign state: %w", errors.Join(legacyErr, err))
		}
	}

	state.filePath = filepath

	return state.FreshCache(), nil
}

// LoadOrCreateSignState loads the sign state from filepath
// If the sign state could not be loaded, an empty sign state is initialized
// and saved to filepath.
func LoadOrCreateSignState(filepath string) (*SignState, error) {
	if _, err := os.Stat(filepath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("unexpected error checking file existence (%s): %w", filepath, err)
		}
		// the only scenario where we want to create a new sign state file is when the file does not exist.
		// Make an empty sign state and save it.
		state := &SignState{
			filePath: filepath,
			cache:    make(map[HRSKey]SignStateConsensus),
		}
		state.cond = cond.New(&state.mu)

		jsonBytes, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			panic(err)
		}

		state.save(jsonBytes)
		return state, nil
	}

	return LoadSignState(filepath)
}
