package signer

import (
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	tmBytes "github.com/tendermint/tendermint/libs/bytes"
	tmJson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/libs/protoio"
	"github.com/tendermint/tendermint/libs/tempfile"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

const (
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
	blocksToCache      = 3
)

func CanonicalVoteToStep(vote *tmProto.CanonicalVote) int8 {
	switch vote.Type {
	case tmProto.PrevoteType:
		return stepPrevote
	case tmProto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToStep(vote *tmProto.Vote) int8 {
	switch vote.Type {
	case tmProto.PrevoteType:
		return stepPrevote
	case tmProto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func ProposalToStep(_ *tmProto.Proposal) int8 {
	return stepPropose
}

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height          int64            `json:"height"`
	Round           int64            `json:"round"`
	Step            int8             `json:"step"`
	EphemeralPublic []byte           `json:"ephemeral_public"`
	Signature       []byte           `json:"signature,omitempty"`
	SignBytes       tmBytes.HexBytes `json:"signbytes,omitempty"`
	cache           map[HRSKey]SignStateConsensus

	filePath string
}

type SignStateConsensus struct {
	Height    int64
	Round     int64
	Step      int8
	Signature []byte
	SignBytes tmBytes.HexBytes
}

func NewSignStateConsensus(height int64, round int64, step int8) SignStateConsensus {
	return SignStateConsensus{
		Height: height,
		Round:  round,
		Step:   step,
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

func (signState *SignState) Save(ssc SignStateConsensus, lock *sync.Mutex) error {
	// One lock/unlock for less/equal check and mutation.
	// Setting nil for lock for getErrorIfLessOrEqual to avoid recursive lock
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}

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
	go func() {
		signState.save()
	}()

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
	jsonBytes, err := tmJson.MarshalIndent(signState, "", "  ")
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
func (signState *SignState) CheckHRS(hrs HRSKey) (bool, error) {
	if signState.Height > hrs.Height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", hrs.Height, signState.Height)
	}

	if signState.Height == hrs.Height {
		if signState.Round > hrs.Round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v",
				hrs.Height, hrs.Round, signState.Round)
		}

		if signState.Round == hrs.Round {
			if signState.Step > hrs.Step {
				return false, fmt.Errorf("step regression at height %v round %v. Got %v, last step %v",
					hrs.Height, hrs.Round, hrs.Step, signState.Step)
			} else if signState.Step == hrs.Step {
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

// LoadSignState loads a sign state from disk.
func LoadSignState(filepath string) (SignState, error) {
	state := SignState{}
	stateJSONBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return state, err
	}

	err = tmJson.Unmarshal(stateJSONBytes, &state)
	if err != nil {
		return state, err
	}
	state.cache = make(map[HRSKey]SignStateConsensus)
	state.cache[HRSKey{Height: state.Height, Round: state.Round, Step: state.Step}] = SignStateConsensus{
		Height:    state.Height,
		Round:     state.Round,
		Step:      state.Step,
		Signature: state.Signature,
		SignBytes: state.SignBytes,
	}
	state.filePath = filepath
	return state, nil
}

// LoadOrCreateSignState loads the sign state from filepath
// If the sign state could not be loaded, an empty sign state is initialized
// and saved to filepath.
func LoadOrCreateSignState(filepath string) (SignState, error) {
	existing, err := LoadSignState(filepath)
	if err == nil {
		return existing, nil
	}

	// There was an error loading the sign state
	// Make an empty sign state and save it
	state := SignState{}
	state.filePath = filepath
	state.cache = make(map[HRSKey]SignStateConsensus)
	state.save()
	return state, nil
}

// OnlyDifferByTimestamp returns true if the sign bytes of the sign state
// are the same as the new sign bytes excluding the timestamp.
func (signState *SignState) OnlyDifferByTimestamp(signBytes []byte) (time.Time, bool) {
	if signState.Step == stepPropose {
		return checkProposalOnlyDifferByTimestamp(signState.SignBytes, signBytes)
	} else if signState.Step == stepPrevote || signState.Step == stepPrecommit {
		return checkVoteOnlyDifferByTimestamp(signState.SignBytes, signBytes)
	}

	return time.Time{}, false
}

func (signState *SignStateConsensus) OnlyDifferByTimestamp(signBytes []byte) (time.Time, bool) {
	if signState.Step == stepPropose {
		return checkProposalOnlyDifferByTimestamp(signState.SignBytes, signBytes)
	} else if signState.Step == stepPrevote || signState.Step == stepPrecommit {
		return checkVoteOnlyDifferByTimestamp(signState.SignBytes, signBytes)
	}

	return time.Time{}, false
}

func checkVoteOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote tmProto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into vote: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into vote: %v", err))
	}

	lastTime := lastVote.Timestamp

	// set the times to the same value and check equality
	now := tmtime.Now()
	lastVote.Timestamp = now
	newVote.Timestamp = now

	return lastTime, proto.Equal(&newVote, &lastVote)
}

func checkProposalOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal tmProto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into proposal: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into proposal: %v", err))
	}

	lastTime := lastProposal.Timestamp
	// set the times to the same value and check equality
	now := tmtime.Now()
	lastProposal.Timestamp = now
	newProposal.Timestamp = now

	return lastTime, proto.Equal(&newProposal, &lastProposal)
}
