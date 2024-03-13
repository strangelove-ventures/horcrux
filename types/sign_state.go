package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cosmos/gogoproto/proto"
	cometjson "github.com/strangelove-ventures/horcrux/v3/comet/libs/json"
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
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
		Height:                 vote.Height,
		Round:                  int64(vote.Round),
		Step:                   VoteTypeToStep(vote.Type),
		BlockID: &BlockID{
			Hash: vote.BlockID.Hash,
			PartSetHeader: PartSetHeader{
				Total: vote.BlockID.PartSetHeader.Total,
				Hash:  vote.BlockID.PartSetHeader.Hash,
			},
		},
		VoteExtensionSignBytes: vote.Extension,
		Timestamp:              vote.Timestamp,
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

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height      int64  `json:"height"`
	Round       int64  `json:"round"`
	Step        int8   `json:"step"`
	NoncePublic []byte `json:"nonce_public"`
	Signature   []byte `json:"signature,omitempty"`
	SignBytes   []byte `json:"signbytes,omitempty"`
	VoteExtensionSignature []byte              `json:"vote_ext_signature,omitempty"`

	filePath string

	// mu protects the cache and is used for signaling with cond.
	mu    sync.RWMutex
	cache map[HRSKey]SignStateConsensus
	cond  *cond.Cond
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

func (signState *SignState) ExistingSignatureOrErrorIfRegression(hrst HRSTKey, signBytes []byte) ([]byte, error) {
	signState.mu.RLock()
	defer signState.mu.RUnlock()

	sameHRS, err := signState.CheckHRS(hrst)
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
	} else if err := signState.OnlyDifferByTimestamp(signBytes); err != nil {
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
	Signature []byte
	VoteExtensionSignature []byte
	SignBytes []byte
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

type ConflictingDataError struct {
	msg string
}

func (e *ConflictingDataError) Error() string { return e.msg }

func newConflictingDataError(existingSignBytes, newSignBytes []byte) *ConflictingDataError {
	return &ConflictingDataError{
		msg: fmt.Sprintf("conflicting data. existing: %s - new: %s",
			hex.EncodeToString(existingSignBytes), hex.EncodeToString(newSignBytes)),
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
	signState.Signature = ssc.Signature
	signState.SignBytes = ssc.SignBytes
	signState.VoteExtensionSignature = ssc.VoteExtensionSignature

	jsonBytes, err := cometjson.MarshalIndent(signState, "", "  ")
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
		NoncePublic:            signState.NoncePublic,
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
		Signature:              signState.Signature,
		SignBytes:              signState.SignBytes,
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

	err = cometjson.Unmarshal(stateJSONBytes, &state)
	if err != nil {
		return nil, err
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

		jsonBytes, err := cometjson.MarshalIndent(state, "", "  ")
		if err != nil {
			panic(err)
		}

		state.save(jsonBytes)
		return state, nil
	}

	return LoadSignState(filepath)
}

// OnlyDifferByTimestamp returns true if the sign bytes of the sign state
// are the same as the new sign bytes excluding the timestamp.
func (signState *SignState) OnlyDifferByTimestamp(signBytes []byte) error {
	return onlyDifferByTimestamp(signState.Step, signState.SignBytes, signBytes)
}

func (signState *SignStateConsensus) OnlyDifferByTimestamp(signBytes []byte) error {
	return onlyDifferByTimestamp(signState.Step, signState.SignBytes, signBytes)
}

func onlyDifferByTimestamp(step int8, signStateSignBytes, signBytes []byte) error {
	if step == StepPropose {
		return checkProposalOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	} else if step == StepPrevote || step == StepPrecommit {
		return checkVoteOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	}

	panic(fmt.Errorf("unexpected sign step: %d", step))
}

type UnmarshalError struct {
	name     string
	signType string
	err      error
}

func (e *UnmarshalError) Error() string {
	return fmt.Sprintf("%s cannot be unmarshalled into %s: %v", e.name, e.signType, e.err)
}

func newUnmarshalError(name, signType string, err error) *UnmarshalError {
	return &UnmarshalError{
		name:     name,
		signType: signType,
		err:      err,
	}
}

type AlreadySignedVoteError struct {
	nonFirst bool
}

func (e *AlreadySignedVoteError) Error() string {
	if e.nonFirst {
		return "already signed vote with non-nil BlockID. refusing to sign vote on nil BlockID"
	}
	return "already signed vote with nil BlockID. refusing to sign vote on non-nil BlockID"
}

func newAlreadySignedVoteError(nonFirst bool) *AlreadySignedVoteError {
	return &AlreadySignedVoteError{
		nonFirst: nonFirst,
	}
}

type DiffBlockIDsError struct {
	first  []byte
	second []byte
}

func (e *DiffBlockIDsError) Error() string {
	return fmt.Sprintf("differing block IDs - last Vote: %s, new Vote: %s", e.first, e.second)
}

func newDiffBlockIDsError(first, second []byte) *DiffBlockIDsError {
	return &DiffBlockIDsError{
		first:  first,
		second: second,
	}
}

func checkVoteOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastVote, newVote cometproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		return newUnmarshalError("lastSignBytes", "vote", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		return newUnmarshalError("newSignBytes", "vote", err)
	}

	// set the times to the same value and check equality
	newVote.Timestamp = lastVote.Timestamp

	if proto.Equal(&newVote, &lastVote) {
		return nil
	}

	lastVoteBlockID := lastVote.GetBlockID()
	newVoteBlockID := newVote.GetBlockID()
	if newVoteBlockID == nil && lastVoteBlockID != nil {
		return newAlreadySignedVoteError(true)
	}
	if newVoteBlockID != nil && lastVoteBlockID == nil {
		return newAlreadySignedVoteError(false)
	}
	if !bytes.Equal(lastVoteBlockID.GetHash(), newVoteBlockID.GetHash()) {
		return newDiffBlockIDsError(lastVoteBlockID.GetHash(), newVoteBlockID.GetHash())
	}
	return newConflictingDataError(lastSignBytes, newSignBytes)
}

func checkProposalOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastProposal, newProposal cometproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		return newUnmarshalError("lastSignBytes", "proposal", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		return newUnmarshalError("newSignBytes", "proposal", err)
	}

	// set the times to the same value and check equality
	newProposal.Timestamp = lastProposal.Timestamp

	isEqual := proto.Equal(&newProposal, &lastProposal)

	if !isEqual {
		return newConflictingDataError(lastSignBytes, newSignBytes)
	}

	return nil
}
