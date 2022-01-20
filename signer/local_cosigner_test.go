package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

func TestLocalCosignerGetID(test *testing.T) {
	dummyPub := tmCryptoEd25519.PubKey{}

	bitSize := 4096
	rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

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
		Peers: []CosignerPeer{CosignerPeer{
			ID:        1,
			PublicKey: rsaKey.PublicKey,
		}},
	}

	cosigner := NewLocalCosigner(config)
	require.Equal(test, cosigner.GetID(), 1)
}

func TestLocalCosignerSign2of2(test *testing.T) {
	// Test signing with a 2 of 2

	total := uint8(2)
	threshold := uint8(2)

	bitSize := 4096
	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(test, err)

	peers := []CosignerPeer{CosignerPeer{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, CosignerPeer{
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

	publicKeys := make([]tsed25519.Element, 0)

	// get part 2 from cosigner 1 and give to cosigner 2
	{
		resp, err := cosigner1.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     2,
			Height: 1,
			Round:  0,
			Step:   2,
		})
		require.NoError(test, err)

		publicKeys = append(publicKeys, resp.SourceEphemeralSecretPublicKey)

		err = cosigner2.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       resp.SourceID,
			Height:                         1,
			Round:                          0,
			Step:                           2,
			SourceEphemeralSecretPublicKey: resp.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             resp.EncryptedSharePart,
			SourceSig:                      resp.SourceSig,
		})
		require.NoError(test, err)
	}

	// get part 1 from cosigner 2 and give to cosigner 1
	{
		resp, err := cosigner2.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     1,
			Height: 1,
			Round:  0,
			Step:   2,
		})
		require.NoError(test, err)

		publicKeys = append(publicKeys, resp.SourceEphemeralSecretPublicKey)

		err = cosigner1.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       resp.SourceID,
			Height:                         1,
			Round:                          0,
			Step:                           2,
			SourceEphemeralSecretPublicKey: resp.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             resp.EncryptedSharePart,
			SourceSig:                      resp.SourceSig,
		})
		require.NoError(test, err)
	}

	ephemeralPublic := tsed25519.AddElements(publicKeys)

	fmt.Printf("public keys: %x\n", publicKeys)
	fmt.Printf("eph pub: %x\n", ephemeralPublic)

	// pack a vote into sign bytes
	var vote tmProto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = tmProto.PrevoteType

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	// sign with cosigner 1
	sigRes1, err := cosigner1.Sign(CosignerSignRequest{
		SignBytes: signBytes,
	})
	require.NoError(test, err)

	sigRes2, err := cosigner2.Sign(CosignerSignRequest{
		SignBytes: signBytes,
	})
	require.NoError(test, err)

	sigIds := []int{1, 2}
	sigArr := [][]byte{sigRes1.Signature, sigRes2.Signature}

	fmt.Printf("sig arr: %x\n", sigArr)

	combinedSig := tsed25519.CombineShares(total, sigIds, sigArr)
	signature := append(ephemeralPublic, combinedSig...)

	fmt.Printf("signature: %x\n", signature)
	require.True(test, privateKey.PubKey().VerifySignature(signBytes, signature))
}

func TestLocalCosignerWatermark(test *testing.T) {
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
		require.NoError(test, err)
		defer os.Remove(stateFile1.Name())

		signState1, err := LoadOrCreateSignState(stateFile1.Name())

		cosigner1 := NewLocalCosigner(key1, &signState1)

		ephPublicKey, ephPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(test, err)

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
		require.NoError(test, err)

		// watermark should have increased after signing
		require.Equal(test, signState1.Height, int64(2))

		// revert the height to a lower number and check if signing is rejected
		signReq1.Height = 1
		_, err = cosigner1.Sign(signReq1)
		require.Error(test, err, "height regression. Got 1, last height 2")
	*/
}
