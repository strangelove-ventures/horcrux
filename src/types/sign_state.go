package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	cometbytes "github.com/cometbft/cometbft/libs/bytes"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/libs/tempfile"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/gogo/protobuf/proto"
	"github.com/strangelove-ventures/horcrux/src/cond"
)

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height      int64               `json:"height"`
	Round       int64               `json:"round"`
	Step        int8                `json:"step"`
	NoncePublic []byte              `json:"nonce_public"`
	Signature   []byte              `json:"signature,omitempty"`
	SignBytes   cometbytes.HexBytes `json:"signbytes,omitempty"`

	FilePath string

	// mu protects the cache and is used for signaling with Cond.
	mu    sync.RWMutex               // private to avoid marshall issues
	cache map[HRS]SignStateConsensus // private to avoid marshall issues
	cond  *cond.Cond                 // private to avoid marshall issues
}

// GetCache is a get wrapper for [SignState.cache]
func (signState *SignState) GetCache(hrs HRS) (SignStateConsensus, bool) {
	ssc, err := signState.cache[hrs]
	return ssc, err
}

func (signState *SignState) SetCache(hrs HRS, signStateConsensus SignStateConsensus) {
	signState.cache[hrs] = signStateConsensus
}

// CondWaitWithTimeout is the same as
// WaitWithTimeout is same as Wait() call, but will only wait up to a given timeout.
func (signState *SignState) CondWaitWithTimeout(t time.Duration) {
	signState.cond.WaitWithTimeout(t)
}

// CondUnlock unlocks the SignState's cond.L field.
func (signState *SignState) CondUnlock() {
	signState.cond.L.Unlock()
}

// CondBroadcast notifies all waiting goroutines that something has changed.
func (signState *SignState) CondBroadcast() {
	signState.cond.Broadcast()
}

// CondLock locks the SignState's cond.sync.locker
func (signState *SignState) CondLock() {
	signState.cond.L.Lock()
}

// Lock locks the SignState's mutex.
func (signState *SignState) Lock() {
	signState.mu.Lock()
}

// Unlock unlocks the SignState's mutex.
func (signState *SignState) Unlock() {
	signState.mu.Unlock()
}
func (signState *SignState) ExistingSignatureOrErrorIfRegression(hrst HRST, signBytes []byte) ([]byte, error) {
	return signState.existingSignatureOrErrorIfRegression(hrst, signBytes)
}
func (signState *SignState) existingSignatureOrErrorIfRegression(hrst HRST, signBytes []byte) ([]byte, error) {
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

func (signState *SignState) hrs() HRS {
	signState.mu.RLock()
	defer signState.mu.RUnlock()
	return HRS{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
}

func (signState *SignState) hrsKeyLocked() HRS {
	return HRS{
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
	SignBytes cometbytes.HexBytes
}

func (signState SignStateConsensus) HRSKey() HRS {
	return HRS{
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
func (signState *SignState) GetFromCache(hrs HRS) (HRS, *SignStateConsensus) {
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
		if hrs.Height < ssc.Height-blocksTocache {
			delete(signState.cache, hrs)
		}
	}

	signState.Height = ssc.Height
	signState.Round = ssc.Round
	signState.Step = ssc.Step
	signState.Signature = ssc.Signature
	signState.SignBytes = ssc.SignBytes

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
	outFile := signState.FilePath
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
func (signState *SignState) CheckHRS(hrst HRST) (bool, error) {
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

func newSameHRSError(hrs HRS) *SameHRSError {
	return &SameHRSError{
		msg: fmt.Sprintf("HRS is the same as current: %d:%d:%d", hrs.Height, hrs.Round, hrs.Step),
	}
}

func (signState *SignState) GetErrorIfLessOrEqual(height int64, round int64, step int8) error {
	hrs := HRS{Height: height, Round: round, Step: step}
	signStateHRS := signState.hrs()
	if signStateHRS.GreaterThan(hrs) {
		return errors.New("regression not allowed")
	}

	if hrs == signStateHRS {
		// same HRS as current
		return newSameHRSError(HRS{Height: height, Round: round, Step: step})
	}
	// Step is greater, so all good
	return nil
}

// Freshcache returns a clone of a SignState with a new cache
// including the most recent sign state.
func (signState *SignState) FreshCache() *SignState {
	newSignState := &SignState{
		Height:      signState.Height,
		Round:       signState.Round,
		Step:        signState.Step,
		NoncePublic: signState.NoncePublic,
		Signature:   signState.Signature,
		SignBytes:   signState.SignBytes,
		cache:       make(map[HRS]SignStateConsensus),

		FilePath: signState.FilePath,
	}

	newSignState.cond = cond.New(&newSignState.mu)

	newSignState.cache[HRS{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}] = SignStateConsensus{
		Height:    signState.Height,
		Round:     signState.Round,
		Step:      signState.Step,
		Signature: signState.Signature,
		SignBytes: signState.SignBytes,
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

	state.FilePath = filepath

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
			FilePath: filepath,
			cache:    make(map[HRS]SignStateConsensus),
		}
		state.cond = cond.New(&state.mu)

		jsonBytes, err := cometjson.MarshalIndent(state, "", "  ")
		if err != nil {
			err = fmt.Errorf("\n unexpected error reading file existence (%v): %v", state, err)
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
