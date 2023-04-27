package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const testChainID = "test"

func TestLocalCosignerGetID(t *testing.T) {
	dummyPub := cometcryptoed25519.PubKey{}

	bitSize := 4096
	rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key := CosignerKey{
		PubKey:   dummyPub,
		ShareKey: []byte{},
		ID:       1,
	}

	cosigner := NewLocalCosigner(
		&RuntimeConfig{},
		key,
		*rsaKey,
		[]CosignerPeer{{
			ID:        1,
			PublicKey: rsaKey.PublicKey,
		}},
		"",
		0,
		0,
	)
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

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
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

	tmpDir := t.TempDir()

	cosigner1Dir, cosigner2Dir := filepath.Join(tmpDir, "cosigner1"), filepath.Join(tmpDir, "cosigner2")
	err = os.Mkdir(cosigner1Dir, 0700)
	require.NoError(t, err)

	err = os.Mkdir(cosigner2Dir, 0700)
	require.NoError(t, err)

	cosigner1 := NewLocalCosigner(
		&RuntimeConfig{StateDir: cosigner1Dir},
		key1,
		*rsaKey1,
		peers,
		"",
		total,
		threshold,
	)
	defer cosigner1.waitForSignStatesToFlushToDisk()
	cosigner2 := NewLocalCosigner(
		&RuntimeConfig{StateDir: cosigner2Dir},
		key2,
		*rsaKey2,
		peers,
		"",
		total,
		threshold,
	)
	defer cosigner2.waitForSignStatesToFlushToDisk()

	err = cosigner1.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	err = cosigner2.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

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

	ephemeralSharesFor2, err := cosigner1.GetEphemeralSecretParts(testChainID, hrst)
	require.NoError(t, err)

	publicKeys = append(publicKeys, ephemeralSharesFor2.EncryptedSecrets[0].SourceEphemeralSecretPublicKey)

	ephemeralSharesFor1, err := cosigner2.GetEphemeralSecretParts(testChainID, hrst)
	require.NoError(t, err)

	t.Logf("Shares from 2: %d", len(ephemeralSharesFor1.EncryptedSecrets))

	publicKeys = append(publicKeys, ephemeralSharesFor1.EncryptedSecrets[0].SourceEphemeralSecretPublicKey)

	ephemeralPublic := tsed25519.AddElements(publicKeys)

	t.Logf("public keys: %x", publicKeys)
	t.Logf("eph pub: %x", ephemeralPublic)
	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = now

	signBytes := comet.VoteSignBytes("chain-id", &vote)

	sigRes1, err := cosigner1.SetEphemeralSecretPartsAndSign(CosignerSetEphemeralSecretPartsAndSignRequest{
		ChainID:          testChainID,
		EncryptedSecrets: ephemeralSharesFor1.EncryptedSecrets,
		HRST:             hrst,
		SignBytes:        signBytes,
	})
	require.NoError(t, err)

	sigRes2, err := cosigner2.SetEphemeralSecretPartsAndSign(CosignerSetEphemeralSecretPartsAndSignRequest{
		ChainID:          testChainID,
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
