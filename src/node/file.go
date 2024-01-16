package node

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	htypes "github.com/strangelove-ventures/horcrux/src/types"

	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/libs/tempfile"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// -------------------------------------------------------------------------------

// FilePVKey stores the immutable part of PrivValidator.
type FilePVKey struct {
	Address types.Address  `json:"address"`
	PubKey  crypto.PubKey  `json:"pub_key"`
	PrivKey crypto.PrivKey `json:"priv_key"`

	filePath string
}

// Save persists the FilePVKey to its filePath.
func (pvKey FilePVKey) Save() {
	outFile := pvKey.filePath
	if outFile == "" {
		panic("cannot save PrivValidator key: filePath not set")
	}

	jsonBytes, err := cometjson.MarshalIndent(pvKey, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0600); err != nil {
		panic(err)
	}
}

// -------------------------------------------------------------------------------

// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height    int64  `json:"height"`
	Round     int32  `json:"round"`
	Step      int8   `json:"step"`
	Signature []byte `json:"signature,omitempty"`
	SignBytes []byte `json:"signbytes,omitempty"`

	filePath string
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// FilePVLastSignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// The returned boolean indicates whether the last Signature should be reused -
// it returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (lss *FilePVLastSignState) CheckHRS(height int64, round int32, step int8) (bool, error) {

	if lss.Height > height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", height, lss.Height)
	}

	if lss.Height == height {
		if lss.Round > round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v", height, round, lss.Round)
		}

		if lss.Round == round {
			if lss.Step > step {
				return false, fmt.Errorf(
					"step regression at height %v round %v. Got %v, last step %v",
					height,
					round,
					step,
					lss.Step,
				)
			} else if lss.Step == step {
				if lss.SignBytes != nil {
					if lss.Signature == nil {
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

// Save persists the FilePvLastSignState to its filePath.
func (lss *FilePVLastSignState) Save() {
	outFile := lss.filePath
	if outFile == "" {
		panic("cannot save FilePVLastSignState: filePath not set")
	}
	jsonBytes, err := cometjson.MarshalIndent(lss, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// -------------------------------------------------------------------------------

// FilePV implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.LastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type FilePV struct {
	Key           FilePVKey
	LastSignState FilePVLastSignState
}

// NewFilePV generates a new validator from the given key and paths.
func NewFilePV(privKey crypto.PrivKey, keyFilePath, stateFilePath string) *FilePV {
	return &FilePV{
		Key: FilePVKey{
			Address:  privKey.PubKey().Address(),
			PubKey:   privKey.PubKey(),
			PrivKey:  privKey,
			filePath: keyFilePath,
		},
		LastSignState: FilePVLastSignState{
			Step:     0,
			filePath: stateFilePath,
		},
	}
}

// GenFilePV generates a new validator with randomly generated private key
// and sets the filePaths, but does not call Save().
func GenFilePV(keyFilePath, stateFilePath string) *FilePV {
	return NewFilePV(ed25519.GenPrivKey(), keyFilePath, stateFilePath)
}

// If loadState is true, we load from the stateFilePath. Otherwise, we use an empty LastSignState.
func LoadPVFile(keyFilePath, stateFilePath string, loadState bool) (*FilePV, error) {
	keyJSONBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	pvKey := FilePVKey{}
	err = cometjson.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return nil, fmt.Errorf("error reading PrivValidator key from %s: %w", keyFilePath, err)
	}

	// overwrite pubkey and address for convenience
	pvKey.PubKey = pvKey.PrivKey.PubKey()
	pvKey.Address = pvKey.PubKey.Address()
	pvKey.filePath = keyFilePath

	pvState := FilePVLastSignState{}

	if loadState {
		stateJSONBytes, err := os.ReadFile(stateFilePath)
		if err != nil {
			return nil, err
		}
		err = cometjson.Unmarshal(stateJSONBytes, &pvState)
		if err != nil {
			return nil, fmt.Errorf("error reading PrivValidator state from %s: %w", stateFilePath, err)
		}
	}

	pvState.filePath = stateFilePath

	return &FilePV{
		Key:           pvKey,
		LastSignState: pvState,
	}, nil
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetAddress() types.Address {
	return pv.Key.Address
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetPubKey() (crypto.PubKey, error) {
	return pv.Key.PubKey, nil
}

func (pv *FilePV) Sign(block htypes.Block) ([]byte, time.Time, error) {
	height, round, step, signBytes := block.Height, int32(block.Round), block.Step, block.SignBytes

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return nil, block.Timestamp, err
	}

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		switch {
		case bytes.Equal(signBytes, lss.SignBytes):
			return lss.Signature, block.Timestamp, nil
		case block.Step == htypes.StepPropose:
			if timestamp, ok := checkProposalsOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
				return lss.Signature, timestamp, nil
			}
		case block.Step == htypes.StepPrevote || block.Step == htypes.StepPrecommit:
			if timestamp, ok := checkVotesOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
				return lss.Signature, timestamp, nil
			}
		}

		return nil, block.Timestamp, fmt.Errorf("conflicting data")
	}

	// It passed the checks. Sign the vote
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return nil, block.Timestamp, err
	}
	pv.saveSigned(height, round, step, signBytes, sig)

	return sig, block.Timestamp, nil
}

// Save persists the FilePV to disk.
func (pv *FilePV) Save() {
	pv.Key.Save()
	pv.LastSignState.Save()
}

// Reset resets all fields in the FilePV.
// NOTE: Unsafe!
func (pv *FilePV) Reset() {
	var sig []byte
	pv.LastSignState.Height = 0
	pv.LastSignState.Round = 0
	pv.LastSignState.Step = 0
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = nil
	pv.Save()
}

// String returns a string representation of the FilePV.
func (pv *FilePV) String() string {
	return fmt.Sprintf(
		"PrivValidator{%v LH:%v, LR:%v, LS:%v}",
		pv.GetAddress(),
		pv.LastSignState.Height,
		pv.LastSignState.Round,
		pv.LastSignState.Step,
	)
}

// Persist height/round/step and signature
func (pv *FilePV) saveSigned(height int64, round int32, step int8,
	signBytes []byte, sig []byte) {

	pv.LastSignState.Height = height
	pv.LastSignState.Round = round
	pv.LastSignState.Step = step
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = signBytes
	pv.LastSignState.Save()
}

// -----------------------------------------------------------------------------------------

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the votes is their timestamp.
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote cometproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into vote: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into vote: %v", err))
	}

	lastTime := lastVote.Timestamp
	// set the times to the same value and check equality
	now := time.Now()
	lastVote.Timestamp = now
	newVote.Timestamp = now

	return lastTime, proto.Equal(&newVote, &lastVote)
}

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the proposals is their timestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal cometproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into proposal: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into proposal: %v", err))
	}

	lastTime := lastProposal.Timestamp
	// set the times to the same value and check equality
	now := time.Now()
	lastProposal.Timestamp = now
	newProposal.Timestamp = now

	return lastTime, proto.Equal(&newProposal, &lastProposal)
}
