package signer

import (
	"path/filepath"
	"time"

	"os"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometjson "github.com/cometbft/cometbft/libs/json"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometprivval "github.com/cometbft/cometbft/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	pcosigner "github.com/strangelove-ventures/horcrux/pkg/signer/cosigner"
	"github.com/stretchr/testify/require"
)

const testChainID = "test"

func TestSingleSignerValidator(t *testing.T) {

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0700)
	require.NoError(t, err)

	runtimeConfig := &pcosigner.RuntimeConfig{
		HomeDir:  tmpDir,
		StateDir: filepath.Join(tmpDir, "state"),
	}

	privateKey := cometcryptoed25519.GenPrivKey()

	marshaled, err := cometjson.Marshal(cometprivval.FilePVKey{
		Address: privateKey.PubKey().Address(),
		PubKey:  privateKey.PubKey(),
		PrivKey: privateKey,
	})
	require.NoError(t, err)

	err = os.WriteFile(runtimeConfig.KeyFilePathSingleSigner(testChainID), marshaled, 0600)
	require.NoError(t, err)

	err = os.WriteFile(runtimeConfig.KeyFilePathSingleSigner("different"), marshaled, 0600)
	require.NoError(t, err)

	validator := NewSingleSignerValidator(runtimeConfig)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	signBytes := comet.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	// should be able to sign same proposal with only differing timestamp
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := cometrand.Bytes(tmhash.Size)
	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	// should not be able to sign same proposal at same height as highest signed with different BlockID
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height: 1,
		Round:  19,
		Type:   cometproto.ProposalType,
	}

	// should not be able to sign lower than highest signed
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain ID
	err = validator.SignProposal("different", &proposal)
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	validator = NewSingleSignerValidator(runtimeConfig)

	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height: 1,
		Round:  21,
		Type:   cometproto.ProposalType,
	}

	// signing higher block now should succeed
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)
}
