package signer

import (
	"crypto/rand"
	"crypto/rsa"

	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

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

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: 2,
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigner 2 will need its ephemeral nonce part from cosigner 1.
	// During normal operation, cosigner 2 would use an rpc call to cosigner 1 to request its part.
	// Since we are using local cosigners, cosigner 2 has no path to do so. Instead we manually perform the exchange
	// for our test.
	//
	// An enhancement could be to have Local cosigner logic directly interface their peers.
	{
		cosigner1EphSecretPart, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           2,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: true,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart.SourceSig,
			SourceID:                       cosigner1EphSecretPart.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)
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

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: int(threshold),
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigner 2 will need its ephemeral nonce part from cosigner 1.
	// During normal operation, cosigner 2 would use an rpc call to cosigner 1 to request its part.
	// Since we are using local cosigners, cosigner 2 has no path to do so. Instead we manually perform the exchange
	// for our test.
	//
	// An enhancement could be to have Local cosigner logic directly interface their peers.
	{
		cosigner1EphSecretPart2, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           2,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: true,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart2.SourceSig,
			SourceID:                       cosigner1EphSecretPart2.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart2.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart2.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)

		cosigner1EphSecretPart3, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           3,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: false,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart3.SourceSig,
			SourceID:                       cosigner1EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart3.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)

		cosigner2EphSecretPart3, err := cosigner2.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           3,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: false,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner2EphSecretPart3.SourceSig,
			SourceID:                       cosigner2EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner2EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner2EphSecretPart3.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)

		cosigner3EphSecretPart2, err := cosigner3.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           2,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: false,
		})
		require.NoError(test, err)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner3EphSecretPart2.SourceSig,
			SourceID:                       cosigner3EphSecretPart2.SourceID,
			SourceEphemeralSecretPublicKey: cosigner3EphSecretPart2.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner3EphSecretPart2.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)
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

	thresholdValidatorOpt := ThresholdValidatorOpt{
		Pubkey:    privateKey.PubKey(),
		Threshold: int(threshold),
		SignState: signState1,
		Cosigner:  cosigner1,
		Peers:     thresholdPeers,
	}

	validator := NewThresholdValidator(&thresholdValidatorOpt)

	var proposal tmProto.Proposal
	proposal.Height = 1
	proposal.Round = 0
	proposal.Type = tmProto.ProposalType

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	// To perform a sign operation, cosigner 2 will need its ephemeral nonce part from cosigner 1.
	// During normal operation, cosigner 2 would use an rpc call to cosigner 1 to request its part.
	// Since we are using local cosigners, cosigner 2 has no path to do so. Instead we manually perform the exchange
	// for our test.
	//
	// An enhancement could be to have Local cosigner logic directly interface their peers.
	{
		_, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           2,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: true,
		})
		require.NoError(test, err)

		cosigner1EphSecretPart3, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:           3,
			Height:       proposal.Height,
			Round:        int64(proposal.Round),
			Step:         ProposalToStep(&proposal),
			FindOrCreate: false,
		})
		require.NoError(test, err)

		err = cosigner3.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart3.SourceSig,
			SourceID:                       cosigner1EphSecretPart3.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart3.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart3.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
		require.NoError(test, err)

		// Note: purposefully left out interactions with cosigner2, to test it being "down"
	}

	err = validator.SignProposal("chain-id", &proposal)
	if err != nil {
		test.Logf("%v", err)
	}
	require.NoError(test, err)

	require.True(test, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

}
