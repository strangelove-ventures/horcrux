package signer

// COMMENT: In the future differentiate test for different signers.
import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
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

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey1,
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := os.CreateTemp("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey2,
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := os.CreateTemp("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())
	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	localSigner1 := NewThresholdSignerSoft(key1, threshold, total)
	cosigner1 := NewLocalCosigner("", peers, &signState1, localSigner1)

	localSigner2 := NewThresholdSignerSoft(key2, threshold, total)
	cosigner2 := NewLocalCosigner("", peers, &signState2, localSigner2)

	thresholdPeers := make([]Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2)

	tmpDir, _ := os.MkdirTemp("", "store_test")
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

	// Introducing some 'visual' logging so you can manually inspect Cosigners,
	// an easy way to avoid easyable human caused problems.
	cosigner1JSON, err := json.MarshalIndent(cosigner1, "", "  ")
	if err != nil {
		t.Logf("cosigner1JSON error: %v", err.Error())
	}
	// Logs Cosigner 2 output
	t.Logf("Cosigner1 output \n %s\n", string(cosigner1JSON))

	cosigner2JSON, err := json.MarshalIndent(cosigner2, "", "  ")
	if err != nil {
		t.Logf("cosigner2JSON error: %v", err.Error())
	}
	// Logs Cosigner 2 output
	t.Logf("Cosigner2 output \n %s\n", string(cosigner2JSON))

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

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey1,
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := os.CreateTemp("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey2,
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := os.CreateTemp("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey3,
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := os.CreateTemp("", "state3.json")
	require.NoError(t, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := LoadOrCreateSignState(stateFile3.Name())
	require.NoError(t, err)

	localSigner1 := NewThresholdSignerSoft(key1, threshold, total)
	cosigner1 := NewLocalCosigner("", peers, &signState1, localSigner1)

	localSigner2 := NewThresholdSignerSoft(key2, threshold, total)
	cosigner2 := NewLocalCosigner("", peers, &signState2, localSigner2)

	localSigner3 := NewThresholdSignerSoft(key3, threshold, total)
	cosigner3 := NewLocalCosigner("", peers, &signState3, localSigner3)

	thresholdPeers := make([]Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2, cosigner3)

	tmpDir, _ := os.MkdirTemp("", "store_test")
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

	privateKey := tmCryptoEd25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	secretShares := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey1,
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := os.CreateTemp("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey2,
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := os.CreateTemp("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		RSAKey:   *rsaKey3,
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := os.CreateTemp("", "state3.json")
	require.NoError(t, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := LoadOrCreateSignState(stateFile3.Name())
	require.NoError(t, err)

	localSigner1 := NewThresholdSignerSoft(key1, threshold, total)
	cosigner1 := NewLocalCosigner("", peers, &signState1, localSigner1)

	localSigner2 := NewThresholdSignerSoft(key2, threshold, total)
	cosigner2 := NewLocalCosigner("", peers, &signState2, localSigner2)

	localSigner3 := NewThresholdSignerSoft(key3, threshold, total)
	cosigner3 := NewLocalCosigner("", peers, &signState3, localSigner3)

	thresholdPeers := make([]Cosigner, 0)
	thresholdPeers = append(thresholdPeers, cosigner2, cosigner3)

	tmpDir, _ := os.MkdirTemp("", "store_test")
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
