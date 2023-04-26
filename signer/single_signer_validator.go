package signer

import (
	"fmt"
	"os"
	"sync"

	cbftcrypto "github.com/cometbft/cometbft/crypto"
	cbftjson "github.com/cometbft/cometbft/libs/json"
	cbftprivval "github.com/cometbft/cometbft/privval"
	cbftproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

var _ PrivValidator = &SingleSignerValidator{}

// SingleSignerValidator guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type SingleSignerValidator struct {
	config     *RuntimeConfig
	chainState sync.Map
	pubKey     cbftcrypto.PubKey
}

// SingleSignerChainState holds the priv validator and associated mutex for a single chain.
type SingleSignerChainState struct {
	filePV *cbftprivval.FilePV

	// The filePV does not have any locking internally for signing operations.
	// The high-watermark/last-signed-state within the FilePV prevents double sign
	// as long as operations are synchronous. This lock is used to ensure that.
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
	pvKey := cbftprivval.FilePVKey{}
	err = cbftjson.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return err
	}

	pv.pubKey = pvKey.PrivKey.PubKey()

	return nil
}

// GetPubKey implements types.PrivValidator
func (pv *SingleSignerValidator) GetPubKey() (cbftcrypto.PubKey, error) {
	return pv.pubKey, nil
}

// SignVote implements types.PrivValidator
func (pv *SingleSignerValidator) SignVote(chainID string, vote *cbftproto.Vote) error {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()
	return chainState.filePV.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator
func (pv *SingleSignerValidator) SignProposal(chainID string, proposal *cbftproto.Proposal) error {
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
	var filePV *cbftprivval.FilePV
	if _, err := os.Stat(stateFile); err != nil {
		if !os.IsNotExist(err) {
			panic(fmt.Errorf("failed to load state file (%s) - %w", stateFile, err))
		}
		// The only scenario in which we want to create a new state file
		// on disk is when the state file does not exist.
		filePV = cbftprivval.LoadFilePVEmptyState(keyFile, stateFile)
	} else {
		filePV = cbftprivval.LoadFilePV(keyFile, stateFile)
	}

	chainState := &SingleSignerChainState{
		filePV: filePV,
	}
	pv.chainState.Store(chainID, chainState)

	return chainState, nil
}

func (pv *SingleSignerValidator) Stop() {}
