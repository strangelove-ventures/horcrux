package signer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"time"

	"os"
	"testing"

	cbftcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cbftlog "github.com/cometbft/cometbft/libs/log"
	cbftrand "github.com/cometbft/cometbft/libs/rand"
	cbftproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cbft "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
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

	privateKey := cbftcryptoed25519.GenPrivKey()

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
		cbftlog.NewTMLogger(cbftlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)
	defer validator.Stop()

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := cbftproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   cbftproto.ProposalType,
	}

	signBytes := cbft.ProposalSignBytes(testChainID, &proposal)

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

	privateKey := cbftcryptoed25519.GenPrivKey()

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
		cbftlog.NewTMLogger(cbftlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)
	defer validator.Stop()

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := cbftproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   cbftproto.ProposalType,
	}

	signBytes := cbft.ProposalSignBytes(testChainID, &proposal)

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

	privateKey := cbftcryptoed25519.GenPrivKey()

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
		cbftlog.NewTMLogger(cbftlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)
	defer validator.Stop()

	err = validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	proposal := cbftproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cbftproto.ProposalType,
	}

	signBytes := cbft.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

	firstSignature := proposal.Signature

	require.Len(t, firstSignature, 64)

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

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, proposal.Signature))

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
	newValidator := NewThresholdValidator(
		cbftlog.NewTMLogger(cbftlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		runtimeConfig,
		privateKey.PubKey(),
		int(threshold),
		cosigner1,
		thresholdPeers,
		raftStore,
	)
	defer newValidator.Stop()

	err = newValidator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	proposal = cbftproto.Proposal{
		Height: 1,
		Round:  21,
		Type:   cbftproto.ProposalType,
	}

	// signing higher block now should succeed
	err = newValidator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)
}
