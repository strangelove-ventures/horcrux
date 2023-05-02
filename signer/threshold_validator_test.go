package signer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"time"

	"os"
	"testing"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
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

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	var cosigner1, cosigner2 Cosigner

	cosigner1Dir := filepath.Join(tmpDir, "cosigner1")
	err = os.MkdirAll(cosigner1Dir, 0777)
	require.NoError(t, err)

	cosigner1Config := &RuntimeConfig{
		HomeDir:  cosigner1Dir,
		StateDir: cosigner1Dir,
	}

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	cosigner1 = NewLocalCosigner(
		cosigner1Config,
		key1.ID, *rsaKey1,
		peers, "", total, threshold,
	)

	key1Bz, err := key1.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner1Config.KeyFilePathCosigner(testChainID), key1Bz, 0600)
	require.NoError(t, err)

	cosigner2Dir := filepath.Join(tmpDir, "cosigner2")
	err = os.MkdirAll(cosigner2Dir, 0777)
	require.NoError(t, err)

	cosigner2Config := &RuntimeConfig{
		HomeDir:  cosigner2Dir,
		StateDir: cosigner2Dir,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	cosigner2 = NewLocalCosigner(
		cosigner2Config,
		key2.ID, *rsaKey2,
		peers, "", total, threshold,
	)

	key2Bz, err := key2.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner2Config.KeyFilePathCosigner(testChainID), key2Bz, 0600)
	require.NoError(t, err)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)

	thresholdPeers := []Cosigner{cosigner2}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigner1Config,
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

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   cometproto.ProposalType,
	}

	signBytes := comet.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))
}

func TestThresholdValidator3of3(t *testing.T) {
	total := uint8(3)
	threshold := uint8(3)

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

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	var cosigner1, cosigner2, cosigner3 Cosigner

	cosigner1Dir := filepath.Join(tmpDir, "cosigner1")
	err = os.MkdirAll(cosigner1Dir, 0777)
	require.NoError(t, err)

	cosigner1Config := &RuntimeConfig{
		HomeDir:  cosigner1Dir,
		StateDir: cosigner1Dir,
	}

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	cosigner1 = NewLocalCosigner(
		cosigner1Config,
		key1.ID, *rsaKey1,
		peers, "", total, threshold,
	)

	key1Bz, err := key1.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner1Config.KeyFilePathCosigner(testChainID), key1Bz, 0600)
	require.NoError(t, err)

	cosigner2Dir := filepath.Join(tmpDir, "cosigner2")
	err = os.MkdirAll(cosigner2Dir, 0777)
	require.NoError(t, err)

	cosigner2Config := &RuntimeConfig{
		HomeDir:  cosigner2Dir,
		StateDir: cosigner2Dir,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	cosigner2 = NewLocalCosigner(
		cosigner2Config,
		key2.ID, *rsaKey2,
		peers, "", total, threshold,
	)

	key2Bz, err := key2.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner2Config.KeyFilePathCosigner(testChainID), key2Bz, 0600)
	require.NoError(t, err)

	cosigner3Dir := filepath.Join(tmpDir, "cosigner3")
	err = os.MkdirAll(cosigner3Dir, 0777)
	require.NoError(t, err)

	cosigner3Config := &RuntimeConfig{
		HomeDir:  cosigner3Dir,
		StateDir: cosigner3Dir,
	}

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	cosigner3 = NewLocalCosigner(
		cosigner3Config,
		key3.ID, *rsaKey3,
		peers, "", total, threshold,
	)

	key3Bz, err := key3.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner3Config.KeyFilePathCosigner(testChainID), key3Bz, 0600)
	require.NoError(t, err)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := []Cosigner{cosigner2, cosigner3}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigner1Config,
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

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  0,
		Type:   cometproto.ProposalType,
	}

	signBytes := comet.ProposalSignBytes(testChainID, &proposal)

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

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := privateKey[:]
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	var cosigner1, cosigner2, cosigner3 Cosigner
	cosigner1Dir := filepath.Join(tmpDir, "cosigner1")
	err = os.MkdirAll(cosigner1Dir, 0777)
	require.NoError(t, err)

	cosigner1Config := &RuntimeConfig{
		HomeDir:  cosigner1Dir,
		StateDir: cosigner1Dir,
	}

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	cosigner1 = NewLocalCosigner(
		cosigner1Config,
		key1.ID, *rsaKey1,
		peers, "", total, threshold,
	)

	key1Bz, err := key1.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner1Config.KeyFilePathCosigner(testChainID), key1Bz, 0600)
	require.NoError(t, err)
	err = os.WriteFile(cosigner1Config.KeyFilePathCosigner("different"), key1Bz, 0600)
	require.NoError(t, err)

	cosigner2Dir := filepath.Join(tmpDir, "cosigner2")
	err = os.MkdirAll(cosigner2Dir, 0777)
	require.NoError(t, err)

	cosigner2Config := &RuntimeConfig{
		HomeDir:  cosigner2Dir,
		StateDir: cosigner2Dir,
	}

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	cosigner2 = NewLocalCosigner(
		cosigner2Config,
		key2.ID, *rsaKey2,
		peers, "", total, threshold,
	)

	key2Bz, err := key2.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner2Config.KeyFilePathCosigner(testChainID), key2Bz, 0600)
	require.NoError(t, err)
	err = os.WriteFile(cosigner2Config.KeyFilePathCosigner("different"), key2Bz, 0600)
	require.NoError(t, err)

	cosigner3Dir := filepath.Join(tmpDir, "cosigner3")
	err = os.MkdirAll(cosigner3Dir, 0777)
	require.NoError(t, err)

	cosigner3Config := &RuntimeConfig{
		HomeDir:  cosigner3Dir,
		StateDir: cosigner3Dir,
	}

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	cosigner3 = NewLocalCosigner(
		cosigner3Config,
		key3.ID, *rsaKey3,
		peers, "", total, threshold,
	)

	key3Bz, err := key3.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner3Config.KeyFilePathCosigner(testChainID), key3Bz, 0600)
	require.NoError(t, err)
	err = os.WriteFile(cosigner3Config.KeyFilePathCosigner("different"), key3Bz, 0600)
	require.NoError(t, err)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := []Cosigner{cosigner2, cosigner3}

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	validator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigner1Config,
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
	err = validator.SignProposal("different", &proposal)
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigner1Config,
		int(threshold),
		cosigner1,
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
