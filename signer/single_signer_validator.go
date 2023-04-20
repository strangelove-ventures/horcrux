package signer

import (
	"fmt"
	"os"
	"sync"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/privval"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// SingleSignerValidator guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type SingleSignerValidator struct {
	config     *RuntimeConfig
	chainState map[string]*SingleSignerChainState
}

type SingleSignerChainState struct {
	filePV  *privval.FilePV
	pvMutex sync.Mutex
}

func NewSingleSignerValidator(config *RuntimeConfig) *SingleSignerValidator {
	return &SingleSignerValidator{
		config:     config,
		chainState: make(map[string]*SingleSignerChainState),
	}
}

// GetPubKey implements types.PrivValidator
func (pv *SingleSignerValidator) GetPubKey() (crypto.PubKey, error) {
	keyFile := pv.config.KeyFilePathSingleSigner()
	filePV := privval.LoadFilePVEmptyState(keyFile, "")
	return filePV.GetPubKey()
}

// SignVote implements types.PrivValidator
func (pv *SingleSignerValidator) SignVote(chainID string, vote *tmProto.Vote) error {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()
	return chainState.filePV.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator
func (pv *SingleSignerValidator) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()
	return chainState.filePV.SignProposal(chainID, proposal)
}

func (pv *SingleSignerValidator) loadChainStateIfNecessary(chainID string) (*SingleSignerChainState, error) {
	if chainState, ok := pv.chainState[chainID]; ok {
		return chainState, nil
	}

	keyFile := pv.config.KeyFilePathSingleSigner()
	stateFile := pv.config.PrivValStateFile(chainID)
	var filePV *privval.FilePV
	if _, err := os.Stat(stateFile); err != nil {
		if !os.IsNotExist(err) {
			panic(fmt.Errorf("failed to load state file (%s) - %w", stateFile, err))
		}
		// The only scenario in which we want to initialize a new state file
		// is when the state file does not exist.
		filePV = privval.LoadFilePVEmptyState(keyFile, stateFile)
	} else {
		filePV = privval.LoadFilePV(keyFile, stateFile)
	}

	chainState := &SingleSignerChainState{
		filePV: filePV,
	}
	pv.chainState[chainID] = chainState

	return chainState, nil
}
