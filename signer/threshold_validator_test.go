package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/strangelove-ventures/horcrux/signer/localthreshold"
	"github.com/strangelove-ventures/horcrux/signer/raft"
	"time"

	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func getMockRaftStore(cosigner localthreshold.Cosigner, tmpDir string) *raft.RaftStore {
	return &raft.RaftStore{
		NodeID:      "1",
		RaftDir:     tmpDir,
		RaftBind:    "127.0.0.1:0",
		RaftTimeout: 1 * time.Second,
		M:           make(map[string]string),
		Logger:      nil,
		Cosigner:    cosigner.(*localthreshold.LocalCosigner),
		Peers:       []localthreshold.Cosigner{},
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

	peers := []localthreshold.CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}}

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := localthreshold.LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())
	signState2, err := localthreshold.LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	config1 := localthreshold.LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := localthreshold.LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 localthreshold.Cosigner
	var cosigner2 localthreshold.Cosigner

	cosigner1 = localthreshold.NewLocalCosigner(config1)
	cosigner2 = localthreshold.NewLocalCosigner(config2)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)

	thresholdPeers := make([]localthreshold.Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2)

	tmpDir, _ := ioutil.TempDir("", "store_test")
	defer os.RemoveAll(tmpDir)

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: int(threshold),
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
		RaftStore: raftStore,
		Logger:    tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	err = validator.SignProposal("chain-id", &proposal)
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

	peers := []localthreshold.CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}, {
		ID:        3,
		PublicKey: rsaKey3.PublicKey,
	}}

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := localthreshold.LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := localthreshold.LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	key3 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := ioutil.TempFile("", "state3.json")
	require.NoError(t, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := localthreshold.LoadOrCreateSignState(stateFile3.Name())
	require.NoError(t, err)

	config1 := localthreshold.LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := localthreshold.LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config3 := localthreshold.LocalCosignerConfig{
		CosignerKey: key3,
		SignState:   &signState3,
		RsaKey:      *rsaKey3,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 localthreshold.Cosigner
	var cosigner2 localthreshold.Cosigner
	var cosigner3 localthreshold.Cosigner

	cosigner1 = localthreshold.NewLocalCosigner(config1)
	cosigner2 = localthreshold.NewLocalCosigner(config2)
	cosigner3 = localthreshold.NewLocalCosigner(config3)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := make([]localthreshold.Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2, cosigner3)

	tmpDir, _ := ioutil.TempDir("", "store_test")
	defer os.RemoveAll(tmpDir)

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: int(threshold),
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
		RaftStore: raftStore,
		Logger:    tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	err = validator.SignProposal("chain-id", &proposal)
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

	peers := []localthreshold.CosignerPeer{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}, {
		ID:        3,
		PublicKey: rsaKey3.PublicKey,
	}}

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := localthreshold.LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := localthreshold.LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	key3 := localthreshold.CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := ioutil.TempFile("", "state3.json")
	require.NoError(t, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := localthreshold.LoadOrCreateSignState(stateFile3.Name())
	require.NoError(t, err)

	config1 := localthreshold.LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := localthreshold.LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config3 := localthreshold.LocalCosignerConfig{
		CosignerKey: key3,
		SignState:   &signState3,
		RsaKey:      *rsaKey3,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 localthreshold.Cosigner
	var cosigner2 localthreshold.Cosigner
	var cosigner3 localthreshold.Cosigner

	cosigner1 = localthreshold.NewLocalCosigner(config1)
	cosigner2 = localthreshold.NewLocalCosigner(config2)
	cosigner3 = localthreshold.NewLocalCosigner(config3)

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)
	require.Equal(t, cosigner3.GetID(), 3)

	thresholdPeers := make([]localthreshold.Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2, cosigner3)

	tmpDir, _ := ioutil.TempDir("", "store_test")
	defer os.RemoveAll(tmpDir)

	raftStore := getMockRaftStore(cosigner1, tmpDir)

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: int(threshold),
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
		RaftStore: raftStore,
		Logger:    tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	_, err = raftStore.Open()
	require.NoError(t, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	err = validator.SignProposal("chain-id", &proposal)
	if err != nil {
		t.Logf("%v", err)
	}
	require.NoError(t, err)

	require.True(t, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))
}
