package node_test

import (
	"context"
	"path/filepath"
	"time"

	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/connector"
	"github.com/strangelove-ventures/horcrux/src/node"
	"github.com/strangelove-ventures/horcrux/src/types"

	"os"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometjson "github.com/cometbft/cometbft/libs/json"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometprivval "github.com/cometbft/cometbft/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

const (
	testChainID  = "chain-1"
	testChainID2 = "chain-2"
	BitSize      = 4096
)

var _ connector.IPrivValidator = &node.SingleSignerValidator{}

func TestSingleSignerValidator(t *testing.T) {
	// t.Skip("TODO: fix this test when run with 'make test'")

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0700)
	require.NoError(t, err)

	runtimeConfig := &config.RuntimeConfig{
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

	validator := node.NewSingleSignerValidator(runtimeConfig)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	block := types.ProposalToBlock(testChainID, &proposal)

	ctx := context.Background()

	signature, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(block.SignBytes, signature))

	proposal.Timestamp = time.Now()

	// should be able to sign same proposal with only differing timestamp
	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.NoError(t, err)

	// construct different block Index for proposal at same height as highest signed
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
	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	proposal.Round = 19

	// should not be able to sign lower than highest signed
	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain Index
	_, _, err = validator.Sign(ctx, "different", types.ProposalToBlock("different", &proposal))
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	validator = node.NewSingleSignerValidator(runtimeConfig)

	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	proposal.Round = 21

	// signing higher block now should succeed
	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.NoError(t, err)
}
