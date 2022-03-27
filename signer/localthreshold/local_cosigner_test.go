package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func TestLocalCosignerGetID(t *testing.T) {
	dummyPub := tmCryptoEd25519.PubKey{}

	bitSize := 4096
	rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key := CosignerKey{
		PubKey:   dummyPub,
		ShareKey: []byte{},
		ID:       1,
	}
	signState := SignState{
		Height: 0,
		Round:  0,
		Step:   0,
	}

	config := LocalCosignerConfig{
		CosignerKey: key,
		SignState:   &signState,
		RsaKey:      *rsaKey,
		Peers: []CosignerPeer{{
			ID:        1,
			PublicKey: rsaKey.PublicKey,
		}},
	}

	cosigner := NewLocalCosigner(config)
	require.Equal(t, cosigner.GetID(), 1)
}

func TestLocalCosignerSign2of2(t *testing.T) {
	// Test signing with a 2 of 2

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
		ShareKey: secretShares[0],
		ID:       1,
	}

	stateFile1, err := ioutil.TempFile("", "state1.json")
	require.NoError(t, err)
	defer os.Remove(stateFile1.Name())

	signState1, err := LoadOrCreateSignState(stateFile1.Name())
	require.NoError(t, err)

	key2 := CosignerKey{
		PubKey:   privateKey.PubKey(),
		ShareKey: secretShares[1],
		ID:       2,
	}

	stateFile2, err := ioutil.TempFile("", "state2.json")
	require.NoError(t, err)
	defer os.Remove(stateFile2.Name())
	signState2, err := LoadOrCreateSignState(stateFile2.Name())
	require.NoError(t, err)

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

	require.Equal(t, cosigner1.GetID(), 1)
	require.Equal(t, cosigner2.GetID(), 2)

	publicKeys := make([]tsed25519.Element, 0)

	now := time.Now()

	hrst := HRSTKey{
		Height:    1,
		Round:     0,
		Step:      2,
		Timestamp: now.UnixNano(),
	}

	ephemeralSharesFor2, err := cosigner1.GetEphemeralSecretParts(hrst)
	require.NoError(t, err)

	publicKeys = append(publicKeys, ephemeralSharesFor2.EncryptedSecrets[0].SourceEphemeralSecretPublicKey)

	ephemeralSharesFor1, err := cosigner2.GetEphemeralSecretParts(hrst)
	require.NoError(t, err)

	t.Logf("Shares from 2: %d", len(ephemeralSharesFor1.EncryptedSecrets))

	publicKeys = append(publicKeys, ephemeralSharesFor1.EncryptedSecrets[0].SourceEphemeralSecretPublicKey)

	ephemeralPublic := tsed25519.AddElements(publicKeys)

	t.Logf("public keys: %x", publicKeys)
	t.Logf("eph pub: %x", ephemeralPublic)
	// pack a vote into sign bytes
	var vote tmProto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = tmProto.PrevoteType
	vote.Timestamp = now

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	sigRes1, err := cosigner1.SetEphemeralSecretPartsAndSign(CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: ephemeralSharesFor1.EncryptedSecrets,
		HRST:             hrst,
		SignBytes:        signBytes,
	})
	require.NoError(t, err)

	sigRes2, err := cosigner2.SetEphemeralSecretPartsAndSign(CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: ephemeralSharesFor2.EncryptedSecrets,
		HRST:             hrst,
		SignBytes:        signBytes,
	})
	require.NoError(t, err)

	sigIds := []int{1, 2}
	sigArr := [][]byte{sigRes1.Signature, sigRes2.Signature}

	t.Logf("sig arr: %x", sigArr)

	combinedSig := tsed25519.CombineShares(total, sigIds, sigArr)
	signature := ephemeralPublic
	signature = append(signature, combinedSig...)

	t.Logf("signature: %x", signature)
	require.True(t, privateKey.PubKey().VerifySignature(signBytes, signature))
}

func TestLocalCosignerWatermark(t *testing.T) {
	/*
		privateKey := tm_ed25519.GenPrivKey()

		privKeyBytes := [64]byte{}
		copy(privKeyBytes[:], privateKey[:])
		secretShares := tsed25519.DealShares(privKeyBytes[:32], 2, 2)

		key1 := CosignerKey{
			PubKey:   privateKey.PubKey(),
			ShareKey: secretShares[0],
			ID:       1,
		}

		stateFile1, err := ioutil.TempFile("", "state1.json")
		require.NoError(t, err)
		defer os.Remove(stateFile1.Name())

		signState1, err := LoadOrCreateSignState(stateFile1.Name())

		cosigner1 := NewLocalCosigner(key1, &signState1)

		ephPublicKey, ephPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ephShares := tsed25519.DealShares(ephPrivateKey.Seed(), 2, 2)

		signReq1 := CosignerSignRequest{
			EphemeralPublic:      ephPublicKey,
			EphemeralShareSecret: ephShares[0],
			Height:               2,
			Round:                0,
			Step:                 0,
			SignBytes:            []byte("Hello World!"),
		}

		_, err = cosigner1.Sign(signReq1)
		require.NoError(t, err)

		// watermark should have increased after signing
		require.Equal(t, signState1.Height, int64(2))

		// revert the height to a lower number and check if signing is rejected
		signReq1.Height = 1
		_, err = cosigner1.Sign(signReq1)
		require.Error(t, err, "height regression. Got 1, last height 2")
	*/
}
