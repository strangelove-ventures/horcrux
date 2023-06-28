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

const (
	testChainID  = "chain-1"
	testChainID2 = "chain-2"
	bitSize      = 4096
)

func TestLocalCosignerGetID(t *testing.T) {
	dummyPub := cometcryptoed25519.PubKey{}

	rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key := CosignerEd25519Key{
		PubKey:       dummyPub,
		PrivateShard: []byte{},
		ID:           1,
	}

	cosigner := NewLocalCosigner(
		&RuntimeConfig{},
		CosignerRSAKey{
			ID:     key.ID,
			RSAKey: *rsaKey,
		},
		[]CosignerRSAPubKey{{
			ID:        1,
			PublicKey: rsaKey.PublicKey,
		}},
		"",
		0,
	)

	require.Equal(t, 1, cosigner.GetID())
}

func TestLocalCosignerSign2of2(t *testing.T) {
	// Test signing with a 2 of 2

	total := uint8(2)
	threshold := uint8(2)

	rsaKey1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	rsaKey2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	pubKeys := []CosignerRSAPubKey{{
		ID:        1,
		PublicKey: rsaKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: rsaKey2.PublicKey,
	}}

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	key1 := CosignerEd25519Key{
		PubKey:       privateKey.PubKey(),
		PrivateShard: privShards[0],
		ID:           1,
	}

	key2 := CosignerEd25519Key{
		PubKey:       privateKey.PubKey(),
		PrivateShard: privShards[1],
		ID:           2,
	}

	tmpDir := t.TempDir()

	cosigner1Dir, cosigner2Dir := filepath.Join(tmpDir, "cosigner1"), filepath.Join(tmpDir, "cosigner2")
	err = os.Mkdir(cosigner1Dir, 0700)
	require.NoError(t, err)

	err = os.Mkdir(cosigner2Dir, 0700)
	require.NoError(t, err)

	cosigner1 := NewLocalCosigner(
		&RuntimeConfig{
			HomeDir:  cosigner1Dir,
			StateDir: cosigner1Dir,
		},
		CosignerRSAKey{
			ID:     key1.ID,
			RSAKey: *rsaKey1,
		},
		pubKeys,
		"",
		threshold,
	)

	key1Bz, err := key1.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner1.config.KeyFilePathCosigner(testChainID), key1Bz, 0600)
	require.NoError(t, err)

	defer cosigner1.waitForSignStatesToFlushToDisk()

	cosigner2 := NewLocalCosigner(
		&RuntimeConfig{
			HomeDir:  cosigner2Dir,
			StateDir: cosigner2Dir,
		},
		CosignerRSAKey{
			ID:     key2.ID,
			RSAKey: *rsaKey2,
		},
		pubKeys,
		"",
		threshold,
	)

	key2Bz, err := key2.MarshalJSON()
	require.NoError(t, err)
	err = os.WriteFile(cosigner2.config.KeyFilePathCosigner(testChainID), key2Bz, 0600)
	require.NoError(t, err)

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

	noncesFor2, err := cosigner1.GetNonces(testChainID, hrst)
	require.NoError(t, err)

	publicKeys = append(publicKeys, noncesFor2.Nonces[0].PubKey)

	noncesFor1, err := cosigner2.GetNonces(testChainID, hrst)
	require.NoError(t, err)

	t.Logf("Shares from 2: %d", len(noncesFor1.Nonces))

	publicKeys = append(publicKeys, noncesFor1.Nonces[0].PubKey)

	noncePublic := tsed25519.AddElements(publicKeys)

	t.Logf("public keys: %x", publicKeys)
	t.Logf("eph pub: %x", noncePublic)
	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = now

	signBytes := comet.VoteSignBytes("chain-id", &vote)

	sigRes1, err := cosigner1.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:   testChainID,
		Nonces:    noncesFor1.Nonces,
		HRST:      hrst,
		SignBytes: signBytes,
	})
	require.NoError(t, err)

	sigRes2, err := cosigner2.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:   testChainID,
		Nonces:    noncesFor2.Nonces,
		HRST:      hrst,
		SignBytes: signBytes,
	})
	require.NoError(t, err)

	sigIds := []int{1, 2}
	sigArr := [][]byte{sigRes1.Signature, sigRes2.Signature}

	t.Logf("sig arr: %x", sigArr)

	combinedSig := tsed25519.CombineShares(total, sigIds, sigArr)
	signature := noncePublic
	signature = append(signature, combinedSig...)

	t.Logf("signature: %x", signature)
	require.True(t, privateKey.PubKey().VerifySignature(signBytes, signature))
}
