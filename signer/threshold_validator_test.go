package signer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"time"

	"os"
	"testing"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

func TestThresholdValidator2of2(t *testing.T) {
	testThresholdValidator(t, 2, 2)
}

func TestThresholdValidator3of3(t *testing.T) {
	testThresholdValidator(t, 3, 3)
}

func TestThresholdValidator2of3(t *testing.T) {
	testThresholdValidator(t, 2, 3)
}

func TestThresholdValidator3of5(t *testing.T) {
	testThresholdValidator(t, 3, 5)
}

func getMockRaftStore(cosigner Cosigner, tmpDir string) *RaftStore {
	return &RaftStore{
		NodeID:      "1",
		RaftDir:     tmpDir,
		RaftBind:    "127.0.0.1:0",
		RaftTimeout: 1 * time.Second,
		m:           make(map[string]string),
		logger:      nil,
		cosigner:    cosigner.(*LocalCosigner),
		Peers:       []Cosigner{},
	}
}

func loadKeyForLocalCosigner(
	cosigner *LocalCosigner,
	pubKey cometcrypto.PubKey,
	chainID string,
	secretShare []byte,
) error {
	key := CosignerKey{
		PubKey:   pubKey,
		ShareKey: secretShare,
		ID:       cosigner.GetID(),
	}

	keyBz, err := key.MarshalJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(cosigner.config.KeyFilePathCosigner(chainID), keyBz, 0600)
}

func testThresholdValidator(t *testing.T, threshold, total uint8) {
	rsaKeys := make([]*rsa.PrivateKey, total)
	peers := make([]CosignerPeer, total)
	cosigners := make([]*LocalCosigner, total)

	for i := uint8(0); i < total; i++ {
		rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		rsaKeys[i] = rsaKey

		peers[i] = CosignerPeer{
			ID:        int(i) + 1,
			PublicKey: rsaKey.PublicKey,
		}
	}

	privateKey := cometcryptoed25519.GenPrivKey()
	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	for i, peer := range peers {
		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner_%d", peer.ID))
		err := os.MkdirAll(cosignerDir, 0777)
		require.NoError(t, err)

		cosignerConfig := &RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
		}

		cosigner := NewLocalCosigner(
			cosignerConfig,
			CosignerKeyRSA{
				ID:     peer.ID,
				RSAKey: *rsaKeys[i],
			},
			peers, "", threshold,
		)
		require.NoError(t, err)

		cosigners[i] = cosigner

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID, secretShares[i])
		require.NoError(t, err)

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID2, secretShares[i])
		require.NoError(t, err)
	}

	thresholdPeers := make([]Cosigner, 0, threshold-1)

	for i, cosigner := range cosigners {
		require.Equal(t, i+1, cosigner.GetID())

		if i != 0 && len(thresholdPeers) != int(threshold)-1 {
			thresholdPeers = append(thresholdPeers, cosigner)
		}
	}

	raftStore := getMockRaftStore(cosigners[0], tmpDir)

	validator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigners[0].config,
		int(threshold),
		cosigners[0],
		thresholdPeers,
		raftStore,
	)
	defer validator.Stop()

	err := validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	signBytes := comet.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	firstSignature := proposal.Signature

	require.Len(t, firstSignature, 64)

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

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, proposal.Signature))

	proposal = cometproto.Proposal{
		Height: 1,
		Round:  19,
		Type:   cometproto.ProposalType,
	}

	// should not be able to sign lower than highest signed
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain ID
	err = validator.SignProposal(testChainID2, &proposal)
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigners[0].config,
		int(threshold),
		cosigners[0],
		thresholdPeers,
		raftStore,
	)
	defer newValidator.Stop()

	err = newValidator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height: 1,
		Round:  21,
		Type:   cometproto.ProposalType,
	}

	// signing higher block now should succeed
	err = newValidator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)
}
