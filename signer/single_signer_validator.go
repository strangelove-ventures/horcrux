package signer

import (
	"fmt"
	"os"
	"sync"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmjson "github.com/tendermint/tendermint/libs/json"
	tmprivval "github.com/tendermint/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

var _ PrivValidator = &SingleSignerValidator{}

// SingleSignerValidator guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type SingleSignerValidator struct {
	config     *RuntimeConfig
	chainState sync.Map
	pubKey     tmcrypto.PubKey
}

type SingleSignerChainState struct {
	filePV  *tmprivval.FilePV
	pvMutex sync.Mutex
}

// NewSingleSignerValidator constructs a validator for single-sign mode (not recommended).
// NewThresholdValidator is recommended, but single-sign mode can be used for convenience.
func NewSingleSignerValidator(config *RuntimeConfig) (*SingleSignerValidator, error) {
	pv := &SingleSignerValidator{
		config: config,
	}

	if err := pv.loadPubKey(); err != nil {
		return nil, fmt.Errorf("failed to load priv validator key: %w", err)
	}

	return pv, nil
}

func (pv *SingleSignerValidator) loadPubKey() error {
	keyFile := pv.config.KeyFilePathSingleSigner()

	keyJSONBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	pvKey := tmprivval.FilePVKey{}
	err = tmjson.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return err
	}

	pv.pubKey = pvKey.PrivKey.PubKey()

	return nil
}

// GetPubKey implements types.PrivValidator
func (pv *SingleSignerValidator) GetPubKey() (tmcrypto.PubKey, error) {
	return pv.pubKey, nil
}

// SignVote implements types.PrivValidator
func (pv *SingleSignerValidator) SignVote(chainID string, vote *tmproto.Vote) error {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()
	return chainState.filePV.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator
func (pv *SingleSignerValidator) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()
	return chainState.filePV.SignProposal(chainID, proposal)
}

func (pv *SingleSignerValidator) loadChainStateIfNecessary(chainID string) (*SingleSignerChainState, error) {
	cachedChainState, ok := pv.chainState.Load(chainID)
	if ok {
		return cachedChainState.(*SingleSignerChainState), nil
	}

	keyFile := pv.config.KeyFilePathSingleSigner()
	stateFile := pv.config.PrivValStateFile(chainID)
	var filePV *tmprivval.FilePV
	if _, err := os.Stat(stateFile); err != nil {
		if !os.IsNotExist(err) {
			panic(fmt.Errorf("failed to load state file (%s) - %w", stateFile, err))
		}
		// The only scenario in which we want to initialize a new state file
		// is when the state file does not exist.
		filePV = tmprivval.LoadFilePVEmptyState(keyFile, stateFile)
	} else {
		filePV = tmprivval.LoadFilePV(keyFile, stateFile)
	}

	chainState := &SingleSignerChainState{
		filePV: filePV,
	}
	pv.chainState.Store(chainID, chainState)

	return chainState, nil
}

func (pv *SingleSignerValidator) Stop() {}
