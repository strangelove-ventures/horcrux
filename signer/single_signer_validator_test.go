package signer

import (
	"path/filepath"
	"time"

	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmcryptoed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmjson "github.com/tendermint/tendermint/libs/json"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmprivval "github.com/tendermint/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

func TestSingleSignerValidator(t *testing.T) {

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0700)
	require.NoError(t, err)

	runtimeConfig := &RuntimeConfig{
		HomeDir:  tmpDir,
		StateDir: filepath.Join(tmpDir, "state"),
	}

	privateKey := tmcryptoed25519.GenPrivKey()

	marshaled, err := tmjson.Marshal(tmprivval.FilePVKey{
		Address: privateKey.PubKey().Address(),
		PubKey:  privateKey.PubKey(),
		PrivKey: privateKey,
	})
	require.NoError(t, err)

	err = os.WriteFile(runtimeConfig.KeyFilePathSingleSigner(), marshaled, 0600)
	require.NoError(t, err)

	validator, err := NewSingleSignerValidator(runtimeConfig)
	require.NoError(t, err)

	proposal := tmproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	proposal = tmproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      tmproto.ProposalType,
		Timestamp: time.Now(),
	}

	// should be able to sign same proposal with only differing timestamp
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := tmrand.Bytes(tmhash.Size)
	blockID := tmproto.BlockID{Hash: randHash,
		PartSetHeader: tmproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = tmproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    tmproto.ProposalType,
		BlockID: blockID,
	}

	// should not be able to sign same proposal at same height as highest signed with different BlockID
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = tmproto.Proposal{
		Height: 1,
		Round:  19,
		Type:   tmproto.ProposalType,
	}

	// should not be able to sign lower than highest signed
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain ID
	err = validator.SignProposal("different", &proposal)
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	validator, err = NewSingleSignerValidator(runtimeConfig)
	require.NoError(t, err)

	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = tmproto.Proposal{
		Height: 1,
		Round:  21,
		Type:   tmproto.ProposalType,
	}

	// signing higher block now should succeed
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)
}
