package privval

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	"github.com/strangelove-ventures/horcrux/v3/comet/crypto/bn254"
	"github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	cometjson "github.com/strangelove-ventures/horcrux/v3/comet/libs/json"
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/tempfile"
	comettypes "github.com/strangelove-ventures/horcrux/v3/comet/types"
	horcruxbn254 "github.com/strangelove-ventures/horcrux/v3/signer/bn254"
	horcruxed25519 "github.com/strangelove-ventures/horcrux/v3/signer/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

// FilePVKey stores the immutable part of PrivValidator.
type FilePVKey struct {
	Address comettypes.Address `json:"address"`
	PubKey  crypto.PubKey      `json:"pub_key"`
	PrivKey crypto.PrivKey     `json:"priv_key"`

	filePath string
}

func NewFilePVKey(privKey crypto.PrivKey, filePath string) FilePVKey {
	pubKey := privKey.PubKey()
	return FilePVKey{
		Address:  pubKey.Address(),
		PubKey:   pubKey,
		PrivKey:  privKey,
		filePath: filePath,
	}
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

//-------------------------------------------------------------------------------

// FilePV implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.LastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type FilePV struct {
	Key           FilePVKey
	LastSignState *types.SignState
}

// If loadState is true, we load from the stateFilePath. Otherwise, we use an empty LastSignState.
func LoadFilePV(keyFilePath, stateFilePath string) (*FilePV, error) {
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

	lss, err := types.LoadOrCreateSignState(stateFilePath)
	if err != nil {
		return nil, err
	}

	return &FilePV{
		Key:           pvKey,
		LastSignState: lss,
	}, nil
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetAddress() comettypes.Address {
	return pv.Key.Address
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetPubKey() (crypto.PubKey, error) {
	return pv.Key.PubKey, nil
}

func (pv *FilePV) Sign(chainID string, block types.Block) ([]byte, []byte, time.Time, error) {
	var signBytes, voteExtSignBytes []byte
	var err error
	switch pv.Key.PrivKey.(type) {
	case ed25519.PrivKey:
		signBytes, voteExtSignBytes, err = horcruxed25519.SignBytes(chainID, block)
		if err != nil {
			return nil, nil, block.Timestamp, err
		}
	case bn254.PrivKey:
		signBytes, voteExtSignBytes, err = horcruxbn254.SignBytes(chainID, block)
		if err != nil {
			return nil, nil, block.Timestamp, err
		}
	}

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(block.HRSTKey())
	if err != nil {
		return nil, nil, block.Timestamp, err
	}

	// Vote extensions are non-deterministic, so it is possible that an
	// application may have created a different extension. We therefore always
	// re-sign the vote extensions of precommits. For prevotes and nil
	// precommits, the extension signature will always be empty.
	// Even if the signed over data is empty, we still add the signature
	var extSig []byte
	if len(voteExtSignBytes) > 0 {
		extSig, err = pv.Key.PrivKey.Sign(voteExtSignBytes)
		if err != nil {
			return nil, nil, block.Timestamp, err
		}
	}

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			return lss.Signature, nil, block.Timestamp, nil
		} else if err := lss.Block().EqualForSigning(block); err != nil {
			return nil, nil, block.Timestamp, err
		}
	}

	// It passed the checks. Sign the vote
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return nil, nil, block.Timestamp, err
	}
	pv.saveSigned(block, signBytes, sig, extSig)

	return sig, extSig, block.Timestamp, nil
}

// Reset resets all fields in the FilePV.
// NOTE: Unsafe!
func (pv *FilePV) Reset() {
	pv.LastSignState.Save(types.NewSignStateConsensus(0, 0, 0), nil)
	pv.Key.Save()
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
func (pv *FilePV) saveSigned(block types.Block, signBytes, sig []byte, voteExtSig []byte) {
	ssc := block.SignStateConsensus(signBytes, sig, voteExtSig)
	pv.LastSignState.Save(ssc, nil)
}
