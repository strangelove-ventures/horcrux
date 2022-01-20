package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
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
		Peers:       []CosignerConfig{},
	}
}

func TestThresholdValidator2of2(test *testing.T) {

	total := uint8(2)
	threshold := uint8(2)

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

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
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(test, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(test, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(test, err)
	defer os.Remove(stateFile2.Name())
	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(test, err)

	config1 := LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 Cosigner
	var cosigner2 Cosigner

	cosigner1 = NewLocalCosigner(config1)
	cosigner2 = NewLocalCosigner(config2)

	require.Equal(test, cosigner1.GetID(), 1)
	require.Equal(test, cosigner2.GetID(), 2)

	thresholdPeers := make([]Cosigner, 0)
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
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	err = raftStore.Open()
	require.NoError(test, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	HRS := HRSKey{
		Height: proposal.Height,
		Round:  int64(proposal.Round),
		Step:   ProposalToStep(&proposal),
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigner 2 will need its ephemeral nonce part from cosigner 1.
	// During normal operation, ephemeral shares are communicated over the raft cluster after the "HRS" event is emitted.
	// Since we are using local cosigners, cosigner 2 has no path to do so. Instead we manually perform the exchange
	// for our test.
	{
		cosigner1EphSecretPart, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     2,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart.SourceSig,
			SourceID:                       cosigner1EphSecretPart.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey2_1 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 2, 1)
		err = raftStore.Set(doneSharingKey2_1, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Sign from cosigner 2 now that it has all ephemeral parts shared

		signReq := CosignerSignRequest{SignBytes: signBytes}

		signRes2, err := cosigner2.Sign(signReq)
		require.NoError(test, err)

		signKey2 := fmt.Sprintf("SignRes.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 2)

		signJSON2, err := json.Marshal(signRes2)
		require.NoError(test, err)

		err = raftStore.Set(signKey2, string(signJSON2))
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply
	}

	err = validator.SignProposal("chain-id", &proposal)
	require.NoError(test, err)

	require.True(test, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

}

func TestThresholdValidator3of3(test *testing.T) {
	total := uint8(3)
	threshold := uint8(3)

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

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
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(test, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(test, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(test, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(test, err)

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := ioutil.TempFile("", "state3.json")
	require.NoError(test, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := LoadOrCreateSignState(stateFile3.Name())
	require.NoError(test, err)

	config1 := LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config3 := LocalCosignerConfig{
		CosignerKey: key3,
		SignState:   &signState3,
		RsaKey:      *rsaKey3,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 Cosigner
	var cosigner2 Cosigner
	var cosigner3 Cosigner

	cosigner1 = NewLocalCosigner(config1)
	cosigner2 = NewLocalCosigner(config2)
	cosigner3 = NewLocalCosigner(config3)

	require.Equal(test, cosigner1.GetID(), 1)
	require.Equal(test, cosigner2.GetID(), 2)
	require.Equal(test, cosigner3.GetID(), 3)

	thresholdPeers := make([]Cosigner, 0)
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
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	err = raftStore.Open()
	require.NoError(test, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	HRS := HRSKey{
		Height: proposal.Height,
		Round:  int64(proposal.Round),
		Step:   ProposalToStep(&proposal),
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigners will need their ephemeral nonce part from the other cosigners.
	// During normal operation, ephemeral shares are communicated over the raft cluster after the "HRS" event is emitted.
	// Since we are using local cosigners, the cosigners have no path to do so. Instead we manually perform the exchange
	// for our test.
	{
		// Share Ephemeral Secret Part from 2 to 1
		cosigner2EphSecretPart1, err := cosigner2.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     1,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner1.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner2EphSecretPart1.SourceSig,
			SourceID:                       cosigner2EphSecretPart1.SourceID,
			SourceEphemeralSecretPublicKey: cosigner2EphSecretPart1.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner2EphSecretPart1.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey1_2 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 1, 2)
		err = raftStore.Set(doneSharingKey1_2, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Share Ephemeral Secret Part from 3 to 1

		cosigner3EphSecretPart1, err := cosigner3.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     1,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner1.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner3EphSecretPart1.SourceSig,
			SourceID:                       cosigner3EphSecretPart1.SourceID,
			SourceEphemeralSecretPublicKey: cosigner3EphSecretPart1.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner3EphSecretPart1.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey1_3 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 1, 3)
		err = raftStore.Set(doneSharingKey1_3, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Share Ephemeral Secret Part from 1 to 2
		cosigner1EphSecretPart2, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     2,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart2.SourceSig,
			SourceID:                       cosigner1EphSecretPart2.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart2.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart2.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey2_1 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 2, 1)
		err = raftStore.Set(doneSharingKey2_1, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Share Ephemeral Secret Part from 1 to 3

		cosigner1EphSecretPart3, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     3,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart3.SourceSig,
			SourceID:                       cosigner1EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart3.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey3_1 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 3, 1)
		err = raftStore.Set(doneSharingKey3_1, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Share Ephemeral Secret Part from 2 to 3

		cosigner2EphSecretPart3, err := cosigner2.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     3,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner2EphSecretPart3.SourceSig,
			SourceID:                       cosigner2EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner2EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner2EphSecretPart3.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey3_2 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 3, 2)
		err = raftStore.Set(doneSharingKey3_2, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Share Ephemeral Secret Part from 3 to 2

		cosigner3EphSecretPart2, err := cosigner3.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     2,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner3EphSecretPart2.SourceSig,
			SourceID:                       cosigner3EphSecretPart2.SourceID,
			SourceEphemeralSecretPublicKey: cosigner3EphSecretPart2.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner3EphSecretPart2.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey2_3 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 2, 3)
		err = raftStore.Set(doneSharingKey2_3, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Sign from cosigner 2 now that it has all ephemeral parts shared

		signReq := CosignerSignRequest{SignBytes: signBytes}

		signRes2, err := cosigner2.Sign(signReq)
		require.NoError(test, err)

		signKey2 := fmt.Sprintf("SignRes.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 2)

		signJSON2, err := json.Marshal(signRes2)
		require.NoError(test, err)

		err = raftStore.Set(signKey2, string(signJSON2))
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Sign from cosigner 3 now that it has all ephemeral parts shared

		signRes3, err := cosigner3.Sign(signReq)
		require.NoError(test, err)

		signKey3 := fmt.Sprintf("SignRes.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 3)

		signJSON3, err := json.Marshal(signRes3)
		require.NoError(test, err)

		err = raftStore.Set(signKey3, string(signJSON3))
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply
	}

	err = validator.SignProposal("chain-id", &proposal)
	if err != nil {
		test.Logf("%v", err)
	}
	require.NoError(test, err)

	require.True(test, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

}

func TestThresholdValidator2of3(test *testing.T) {
	total := uint8(3)
	threshold := uint8(2)

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

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
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(test, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(test, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(test, err)
	defer os.Remove(stateFile2.Name())

	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(test, err)

	key3 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[2],
		ID:       3,
	}

	stateFile3, err := ioutil.TempFile("", "state3.json")
	require.NoError(test, err)
	defer os.Remove(stateFile3.Name())

	signState3, err := LoadOrCreateSignState(stateFile3.Name())
	require.NoError(test, err)

	config1 := LocalCosignerConfig{
		CosignerKey: key1,
		SignState:   &signState1,
		RsaKey:      *rsaKey1,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config2 := LocalCosignerConfig{
		CosignerKey: key2,
		SignState:   &signState2,
		RsaKey:      *rsaKey2,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	config3 := LocalCosignerConfig{
		CosignerKey: key3,
		SignState:   &signState3,
		RsaKey:      *rsaKey3,
		Peers:       peers,
		Total:       total,
		Threshold:   threshold,
	}

	var cosigner1 Cosigner
	var cosigner2 Cosigner
	var cosigner3 Cosigner

	cosigner1 = NewLocalCosigner(config1)
	cosigner2 = NewLocalCosigner(config2)
	cosigner3 = NewLocalCosigner(config3)

	require.Equal(test, cosigner1.GetID(), 1)
	require.Equal(test, cosigner2.GetID(), 2)
	require.Equal(test, cosigner3.GetID(), 3)

	thresholdPeers := make([]Cosigner, 0)
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
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	raftStore.SetThresholdValidator(validator)

	err = raftStore.Open()
	require.NoError(test, err)

	time.Sleep(3 * time.Second) // Ensure there is a leader

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	HRS := HRSKey{
		Height: proposal.Height,
		Round:  int64(proposal.Round),
		Step:   ProposalToStep(&proposal),
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigner 3 will need its ephemeral nonce part from cosigner 1.
	// During normal operation, ephemeral shares are communicated over the raft cluster after the "HRS" event is emitted.
	// Since we are using local cosigners, cosigner 2 has no path to do so. Instead we manually perform the exchange
	// for our test.
	{
		cosigner1EphSecretPart3, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     3,
			Height: HRS.Height,
			Round:  HRS.Round,
			Step:   HRS.Step,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart3.SourceSig,
			SourceID:                       cosigner1EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart3.EncryptedSharePart,
			Height:                         HRS.Height,
			Round:                          HRS.Round,
			Step:                           HRS.Step,
		})
		require.NoError(test, err)

		doneSharingKey3_1 := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 3, 1)
		err = raftStore.Set(doneSharingKey3_1, "true")
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		signRes3, err := cosigner3.Sign(CosignerSignRequest{SignBytes: signBytes})
		require.NoError(test, err)

		signKey3 := fmt.Sprintf("SignRes.%d.%d.%d.%d", HRS.Height, HRS.Round, HRS.Step, 3)

		signJSON3, err := json.Marshal(signRes3)
		require.NoError(test, err)

		err = raftStore.Set(signKey3, string(signJSON3))
		require.NoError(test, err)
		time.Sleep(500 * time.Millisecond) // Wait for raft key to apply

		// Note: purposefully left out interactions with cosigner2, to test it being "down"
	}

	err = validator.SignProposal("chain-id", &proposal)
	if err != nil {
		test.Logf("%v", err)
	}
	require.NoError(test, err)

	require.True(test, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

}
