package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	cometbytes "github.com/cometbft/cometbft/libs/bytes"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/libs/tempfile"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/gogo/protobuf/proto"
)

const (
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
	blocksToCache      = 3
)

func CanonicalVoteToStep(vote *cometproto.CanonicalVote) int8 {
	switch vote.Type {
	case cometproto.PrevoteType:
		return stepPrevote
	case cometproto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToStep(vote *cometproto.Vote) int8 {
	switch vote.Type {
	case cometproto.PrevoteType:
		return stepPrevote
	case cometproto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func ProposalToStep(_ *cometproto.Proposal) int8 {
	return stepPropose
}

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height          int64               `json:"height"`
	Round           int64               `json:"round"`
	Step            int8                `json:"step"`
	EphemeralPublic []byte              `json:"ephemeral_public"`
	Signature       []byte              `json:"signature,omitempty"`
	SignBytes       cometbytes.HexBytes `json:"signbytes,omitempty"`
	cache           map[HRSKey]SignStateConsensus

	filePath string
}

type SignStateConsensus struct {
	Height    int64
	Round     int64
	Step      int8
	Signature []byte
	SignBytes cometbytes.HexBytes
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

func (signState *SignState) GetFromCache(hrs HRSKey, lock *sync.Mutex) (HRSKey, *SignStateConsensus) {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	latestBlock := HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
	if ssc, ok := signState.cache[hrs]; ok {
		return latestBlock, &ssc
	}
	return latestBlock, nil
}

// Save updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. If pendingDiskWG is provided, the write operation
// will be a separate goroutine (async). This allows pendingDiskWG to be used to .Wait()
// for all pending SignState disk writes.
func (signState *SignState) Save(
	ssc SignStateConsensus,
	pendingDiskWG *sync.WaitGroup,
) error {
	err := signState.GetErrorIfLessOrEqual(ssc.Height, ssc.Round, ssc.Step, nil)
	if err != nil {
		return err
	}
	// HRS is greater than existing state, allow

	signState.cache[HRSKey{Height: ssc.Height, Round: ssc.Round, Step: ssc.Step}] = ssc
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
	if pendingDiskWG != nil {
		pendingDiskWG.Add(1)
		go func() {
			defer pendingDiskWG.Done()
			signState.save()
		}()
	} else {
		signState.save()
	}

	return nil
}

// Save persists the FilePvLastSignState to its filePath.
func (signState *SignState) save() {
	outFile := signState.filePath
	if outFile == "none" {
		return
	}
	if outFile == "" {
		panic("cannot save SignState: filePath not set")
	}
	jsonBytes, err := cometjson.MarshalIndent(signState, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// SignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// Returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (signState *SignState) CheckHRS(hrst HRSTKey) (bool, error) {
	if signState.Height > hrst.Height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", hrst.Height, signState.Height)
	}

	if signState.Height == hrst.Height {
		if signState.Round > hrst.Round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v",
				hrst.Height, hrst.Round, signState.Round)
		}

		if signState.Round == hrst.Round {
			if signState.Step > hrst.Step {
				return false, fmt.Errorf("step regression at height %v round %v. Got %v, last step %v",
					hrst.Height, hrst.Round, hrst.Step, signState.Step)
			} else if signState.Step == hrst.Step {
				if signState.SignBytes != nil {
					if signState.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, errors.New("no SignBytes found")
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

func (signState *SignState) GetErrorIfLessOrEqual(height int64, round int64, step int8, lock *sync.Mutex) error {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	if height < signState.Height {
		// lower height than current, don't allow state rollback
		return errors.New("height regression not allowed")
	}
	if height > signState.Height {
		return nil
	}
	// Height is equal

	if round < signState.Round {
		// lower round than current round for same block, don't allow state rollback
		return errors.New("round regression not allowed")
	}
	if round > signState.Round {
		return nil
	}
	// Height and Round are equal

	if step < signState.Step {
		// lower round than current round for same block, don't allow state rollback
		return errors.New("step regression not allowed")
	}
	if step == signState.Step {
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
		Height:          signState.Height,
		Round:           signState.Round,
		Step:            signState.Step,
		EphemeralPublic: signState.EphemeralPublic,
		Signature:       signState.Signature,
		SignBytes:       signState.SignBytes,
		cache:           make(map[HRSKey]SignStateConsensus),
		filePath:        signState.filePath,
	}

	newSignState.cache[HRSKey{
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
		state.save()
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
	if step == stepPropose {
		return checkProposalOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	} else if step == stepPrevote || step == stepPrecommit {
		return checkVoteOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	}

	return fmt.Errorf("unexpected sign step: %d", step)
}

func checkVoteOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastVote, newVote cometproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		return fmt.Errorf("lastSignBytes cannot be unmarshalled into vote: %v", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		return fmt.Errorf("signBytes cannot be unmarshalled into vote: %v", err)
	}

	// set the times to the same value and check equality
	newVote.Timestamp = lastVote.Timestamp

	isEqual := proto.Equal(&newVote, &lastVote)

	if !isEqual {
		lastVoteBlockID := lastVote.GetBlockID()
		newVoteBlockID := newVote.GetBlockID()
		if newVoteBlockID == nil && lastVoteBlockID != nil {
			return errors.New("already signed vote with non-nil BlockID. refusing to sign vote on nil BlockID")
		}
		if newVoteBlockID != nil && lastVoteBlockID == nil {
			return errors.New("already signed vote with nil BlockID. refusing to sign vote on non-nil BlockID")
		}
		if !bytes.Equal(lastVoteBlockID.GetHash(), newVoteBlockID.GetHash()) {
			return fmt.Errorf("differing block IDs - last Vote: %s, new Vote: %s",
				lastVoteBlockID.GetHash(), newVoteBlockID.GetHash())
		}
		return newConflictingDataError(lastSignBytes, newSignBytes)
	}

	return nil
}

func checkProposalOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastProposal, newProposal cometproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		return fmt.Errorf("lastSignBytes cannot be unmarshalled into proposal: %v", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		return fmt.Errorf("signBytes cannot be unmarshalled into proposal: %v", err)
	}

	// set the times to the same value and check equality
	newProposal.Timestamp = lastProposal.Timestamp

	isEqual := proto.Equal(&newProposal, &lastProposal)

	if !isEqual {
		return newConflictingDataError(lastSignBytes, newSignBytes)
	}

	return nil
}
