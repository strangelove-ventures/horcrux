package signer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"time"

	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmcryptoed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

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

func TestThresholdValidator2of2(t *testing.T) {
	total := uint8(2)
	threshold := uint8(2)

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0777)
	require.NoError(t, err)

	runtimeConfig := &RuntimeConfig{
		HomeDir:  tmpDir,
		StateDir: filepath.Join(tmpDir, "state"),
	}

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	peers := []CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}}

	privateKey := tmcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	var cosigner1, cosigner2 Cosigner

	cosigner1 = NewLocalCosigner(
		runtimeConfig,
		key1, *rsaKey1,
		peers, "", total, threshold,
	)
	cosigner2 = NewLocalCosigner(
		runtimeConfig,
		key2, *rsaKey2,
		peers, "", total, threshold,
	)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)

	thresholdPeers := []Cosigner{cosigner2}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := tmproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))
}

func TestThresholdValidator3of3(t *testing.T) {
	total := uint8(3)
	threshold := uint8(3)

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0777)
	require.NoError(t, err)

	runtimeConfig := &RuntimeConfig{
		HomeDir:  tmpDir,
		StateDir: filepath.Join(tmpDir, "state"),
	}

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	peers := []CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}, {
		ID:        3,
		PublicKey: rsaKey3.PublicKey,
	}}

	privateKey := tmcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	var cosigner1, cosigner2, cosigner3 Cosigner

	cosigner1 = NewLocalCosigner(
		runtimeConfig,
		key1, *rsaKey1,
		peers, "", total, threshold,
	)
	cosigner2 = NewLocalCosigner(
		runtimeConfig,
		key2, *rsaKey2,
		peers, "", total, threshold,
	)
	cosigner3 = NewLocalCosigner(
		runtimeConfig,
		key3, *rsaKey3,
		peers, "", total, threshold,
	)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := []Cosigner{cosigner2, cosigner3}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := tmproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	if err != nil {
		t.Logf("%v", err)
	}
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))
}

func TestThresholdValidator2of3(t *testing.T) {
	total := uint8(3)
	threshold := uint8(2)

	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	err := os.MkdirAll(stateDir, 0777)
	require.NoError(t, err)

	runtimeConfig := &RuntimeConfig{
		HomeDir:  tmpDir,
		StateDir: filepath.Join(tmpDir, "state"),
	}

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	peers := []CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}, {
		ID:        3,
		PublicKey: rsaKey3.PublicKey,
	}}

	privateKey := tmcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	var cosigner1, cosigner2, cosigner3 Cosigner

	cosigner1 = NewLocalCosigner(
		runtimeConfig,
		key1, *rsaKey1,
		peers, "", total, threshold,
	)
	cosigner2 = NewLocalCosigner(
		runtimeConfig,
		key2, *rsaKey2,
		peers, "", total, threshold,
	)
	cosigner3 = NewLocalCosigner(
		runtimeConfig,
		key3, *rsaKey3,
		peers, "", total, threshold,
	)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := []Cosigner{cosigner2, cosigner3}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)

	err = validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := tmproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	firstSignature := proposal.Signature

	require.Len(t, firstSignature, 64)

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

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, proposal.Signature))

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
	validator = NewThresholdValidator(
		tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)

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
