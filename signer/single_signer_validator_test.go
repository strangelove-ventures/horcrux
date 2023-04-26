package signer

import (
	"path/filepath"
	"time"

	"os"
	"testing"

	cbftcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cbftjson "github.com/cometbft/cometbft/libs/json"
	cbftrand "github.com/cometbft/cometbft/libs/rand"
	cbftprivval "github.com/cometbft/cometbft/privval"
	cbftproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cbft "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
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

	privateKey := cbftcryptoed25519.GenPrivKey()

	marshaled, err := cbftjson.Marshal(cbftprivval.FilePVKey{
		Address: privateKey.PubKey().Address(),
		PubKey:  privateKey.PubKey(),
		PrivKey: privateKey,
	})
	require.NoError(t, err)

	err = os.WriteFile(runtimeConfig.KeyFilePathSingleSigner(), marshaled, 0600)
	require.NoError(t, err)

	validator, err := NewSingleSignerValidator(runtimeConfig)
	require.NoError(t, err)

	proposal := cbftproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cbftproto.ProposalType,
	}

	signBytes := cbft.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	proposal = cbftproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cbftproto.ProposalType,
		Timestamp: time.Now(),
	}

	// should be able to sign same proposal with only differing timestamp
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := cbftrand.Bytes(tmhash.Size)
	blockID := cbftproto.BlockID{Hash: randHash,
		PartSetHeader: cbftproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cbftproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cbftproto.ProposalType,
		BlockID: blockID,
	}

	// should not be able to sign same proposal at same height as highest signed with different BlockID
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = cbftproto.Proposal{
		Height: 1,
		Round:  19,
		Type:   cbftproto.ProposalType,
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

	proposal = cbftproto.Proposal{
		Height: 1,
		Round:  21,
		Type:   cbftproto.ProposalType,
	}

	// signing higher block now should succeed
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)
}
