package signer

import (
	"errors"
	"fmt"
	"io/ioutil"
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
	stepNone      int8 = 0 // Used to distinguish the initial state
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
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

	filePath string
}

// Save persists the FilePvLastSignState to its filePath.
func (signState *SignState) Save() {
	outFile := signState.filePath
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
func (signState *SignState) CheckHRS(height int64, round int64, step int8) (bool, error) {
	if signState.Height > height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", height, signState.Height)
	}

	if signState.Height == height {
		if signState.Round > round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v", height, round, signState.Round)
		}

		if signState.Round == round {
			if signState.Step > step {
				return false, fmt.Errorf("step regression at height %v round %v. Got %v, last step %v", height, round, step, signState.Step)
			} else if signState.Step == step {
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
	state.Save()
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
