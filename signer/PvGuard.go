package signer

import (
	"sync"

	"github.com/tendermint/tendermint/crypto"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

var _ PrivValidator = &PvGuard{}

// PvGuard guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type PvGuard struct {
	PrivValidator tm.PrivValidator
	pvMutex       sync.Mutex
}

// GetPubKey implements PrivValidator
func (pv *PvGuard) GetPubKey() (crypto.PubKey, error) {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.GetPubKey()
}

// SignVote implements PrivValidator
func (pv *PvGuard) SignVote(chainID string, vote *tmProto.Vote) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignVote(chainID, vote)
}

// SignProposal implements PrivValidator
func (pv *PvGuard) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignProposal(chainID, proposal)
}

// SignProposal implements PrivValidator
func (pv *PvGuard) Stop() {}
