package signer

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"time"

	"os"
	"testing"

	cometcryptoed25519 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	cometjson "github.com/strangelove-ventures/horcrux/v3/comet/libs/json"
	cometprivval "github.com/strangelove-ventures/horcrux/v3/comet/privval"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	horcruxed25519 "github.com/strangelove-ventures/horcrux/v3/signer/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/types"
	"github.com/stretchr/testify/require"
)

func TestSingleSignerValidator(t *testing.T) {
	// t.Skip("TODO: fix this test when run with 'make test'")

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0700)
	require.NoError(t, err)

	runtimeConfig := &RuntimeConfig{
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

	block := types.ProposalToBlock(&proposal)

	ctx := context.Background()

	signature, _, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	signBytes, _, err := horcruxed25519.SignBytes(testChainID, block)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, signature))

	proposal.Timestamp = time.Now()

	// should be able to sign same proposal with only differing timestamp
	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := make([]byte, 32)
	_, err = rand.Read(randHash)
	require.NoError(t, err)

	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	// should not be able to sign same proposal at same height as highest signed with different BlockID
	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.Error(t, err, "double sign!")

	proposal.Round = 19

	// should not be able to sign lower than highest signed
	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain ID
	_, _, _, err = validator.Sign(ctx, "different", types.ProposalToBlock(&proposal))
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	validator = NewSingleSignerValidator(runtimeConfig)

	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.Error(t, err, "double sign!")

	proposal.Round = 21

	// signing higher block now should succeed
	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.NoError(t, err)

	precommit := cometproto.Vote{
		Height:    2,
		Round:     0,
		Type:      cometproto.PrecommitType,
		Timestamp: time.Now(),
		Extension: []byte("test"),
	}

	block = types.VoteToBlock(&precommit)
	sig, voteExtSig, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	signBytes, voteExtSignBytes, err := horcruxed25519.SignBytes(testChainID, block)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, sig), "signature verification failed")

	require.True(t, privateKey.PubKey().VerifySignature(voteExtSignBytes, voteExtSig),
		"vote extension signature verification failed")

}
