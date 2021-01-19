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
			ID:     2,
			Height: proposal.Height,
			Round:  int64(proposal.Round),
			Step:   ProposalToStep(&proposal),
		})
		require.NoError(test, err)

		cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceSig:                      cosigner1EphSecretPart.SourceSig,
			SourceID:                       cosigner1EphSecretPart.SourceID,
			SourceEphemeralSecretPublicKey: cosigner1EphSecretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             cosigner1EphSecretPart.EncryptedSharePart,
			Height:                         proposal.Height,
			Round:                          int64(proposal.Round),
			Step:                           ProposalToStep(&proposal),
		})
	}

	err = validator.SignProposal("chain-id", &proposal)
	require.NoError(test, err)

	require.True(test, privateKey.PubKey().VerifySignature(signBytes, proposal.Signature))

}
