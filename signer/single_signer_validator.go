package signer

import (
	"sync"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

var _ PrivValidator = &SingleSignerValidator{}

// SingleSignerValidator guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type SingleSignerValidator struct {
	PrivValidator tm.PrivValidator
	pvMutex       sync.Mutex
}

// GetPubKey implements types.PrivValidator
func (pv *SingleSignerValidator) GetPubKey() (tmcrypto.PubKey, error) {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.GetPubKey()
}

// SignVote implements types.PrivValidator
func (pv *SingleSignerValidator) SignVote(chainID string, vote *tmproto.Vote) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator
func (pv *SingleSignerValidator) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignProposal(chainID, proposal)
}

// SignProposal implements PrivValidator
func (pv *SingleSignerValidator) Stop() {}
