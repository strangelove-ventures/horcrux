package signer

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	// required to register bn254 types for signing
	cometcrypto "github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	"github.com/strangelove-ventures/horcrux/v3/comet/privval"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

var _ PrivValidator = &SingleSignerValidator{}

// SingleSignerValidator guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type SingleSignerValidator struct {
	config     *RuntimeConfig
	chainState sync.Map
}

// SingleSignerChainState holds the priv validator and associated mutex for a single chain.
type SingleSignerChainState struct {
	filePV *privval.FilePV

	// The filePV does not have any locking internally for signing operations.
	// The high-watermark/last-signed-state within the FilePV prevents double sign
	// as long as operations are synchronous. This lock is used to ensure that.
	pvMutex sync.Mutex
}

// NewSingleSignerValidator constructs a validator for single-sign mode (not recommended).
// NewThresholdValidator is recommended, but single-sign mode can be used for convenience.
func NewSingleSignerValidator(config *RuntimeConfig) *SingleSignerValidator {
	return &SingleSignerValidator{
		config: config,
	}
}

// GetPubKey implements types.PrivValidator
func (pv *SingleSignerValidator) GetPubKey(_ context.Context, chainID string) (cometcrypto.PubKey, error) {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return nil, err
	}
	pubKey, err := chainState.filePV.GetPubKey()
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// SignVote implements types.PrivValidator
func (pv *SingleSignerValidator) Sign(
	_ context.Context,
	chainID string,
	block types.Block,
) ([]byte, []byte, time.Time, error) {
	chainState, err := pv.loadChainStateIfNecessary(chainID)
	if err != nil {
		return nil, nil, block.Timestamp, err
	}
	chainState.pvMutex.Lock()
	defer chainState.pvMutex.Unlock()

	return chainState.filePV.Sign(chainID, block)
}

func (pv *SingleSignerValidator) loadChainStateIfNecessary(chainID string) (*SingleSignerChainState, error) {
	cachedChainState, ok := pv.chainState.Load(chainID)
	if ok {
		return cachedChainState.(*SingleSignerChainState), nil
	}

	keyFile := pv.config.KeyFilePathSingleSigner(chainID)
	if _, err := os.Stat(keyFile); err != nil {
		return nil, fmt.Errorf("failed to load key file (%s) - %w", keyFile, err)
	}

	stateFile := pv.config.PrivValStateFile(chainID)

	filePV, err := privval.LoadFilePV(keyFile, stateFile)
	if err != nil {
		return nil, err
	}

	chainState := &SingleSignerChainState{
		filePV: filePV,
	}
	pv.chainState.Store(chainID, chainState)

	return chainState, nil
}

func (pv *SingleSignerValidator) Stop() {}
