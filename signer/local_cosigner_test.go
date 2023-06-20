package signer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	ecies "github.com/ecies/go/v2"
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

	eciesKey, err := ecies.GenerateKey()
	require.NoError(t, err)

	key := CosignerEd25519Key{
		PubKey:       dummyPub,
		PrivateShard: []byte{},
		ID:           1,
	}

	cosigner := NewLocalCosigner(
		&RuntimeConfig{},
		CosignerECIESKey{
			ID:       key.ID,
			ECIESKey: eciesKey,
		},
		[]CosignerECIESPubKey{{
			ID:        1,
			PublicKey: eciesKey.PublicKey,
		}},
		"",
		0,
	)

	require.Equal(t, 1, cosigner.GetID())
}

func TestLocalCosignerSign2of2(t *testing.T) {
	// Test signing with a 2 of 2
	threshold := uint8(2)

	eciesKey1, err := ecies.GenerateKey()
	require.NoError(t, err)

	eciesKey2, err := ecies.GenerateKey()
	require.NoError(t, err)

	pubKeys := []CosignerECIESPubKey{{
		ID:        1,
		PublicKey: eciesKey1.PublicKey,
	}, {
		ID:        2,
		PublicKey: eciesKey2.PublicKey,
	}}

	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, 2)
	pubKey := privateKey.PubKey()

	key1 := CosignerEd25519Key{
		PubKey:       pubKey,
		PrivateShard: privShards[0],
		ID:           1,
	}

	key2 := CosignerEd25519Key{
		PubKey:       pubKey,
		PrivateShard: privShards[1],
		ID:           2,
	}

	tmpDir := t.TempDir()

	cfg := Config{
		ThresholdModeConfig: &ThresholdModeConfig{
			Threshold: 2,
			Cosigners: CosignersConfig{
				{ShardID: 1},
				{ShardID: 2},
			},
		},
	}

	cosigner1Dir, cosigner2Dir := filepath.Join(tmpDir, "cosigner1"), filepath.Join(tmpDir, "cosigner2")
	err = os.Mkdir(cosigner1Dir, 0700)
	require.NoError(t, err)

	err = os.Mkdir(cosigner2Dir, 0700)
	require.NoError(t, err)

	cosigner1 := NewLocalCosigner(
		&RuntimeConfig{
			HomeDir:  cosigner1Dir,
			StateDir: cosigner1Dir,
			Config:   cfg,
		},
		CosignerECIESKey{
			ID:       key1.ID,
			ECIESKey: eciesKey1,
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
			Config:   cfg,
		},
		CosignerECIESKey{
			ID:       key2.ID,
			ECIESKey: eciesKey2,
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

	publicKeys := make([][]byte, 0)

	now := time.Now()

	hrst := HRSTKey{
		Height:    1,
		Round:     0,
		Step:      2,
		Timestamp: now.UnixNano(),
	}

	ephemeralSharesFor2, err := cosigner1.GetNonces(testChainID, hrst)
	require.NoError(t, err)

	publicKeys = append(publicKeys, ephemeralSharesFor2.EncryptedSecrets[0].SourcePubKey)

	ephemeralSharesFor1, err := cosigner2.GetNonces(testChainID, hrst)
	require.NoError(t, err)

	t.Logf("Shares from 2: %d", len(ephemeralSharesFor1.EncryptedSecrets))

	publicKeys = append(publicKeys, ephemeralSharesFor1.EncryptedSecrets[0].SourcePubKey)

	t.Logf("public keys: %x", publicKeys)
	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = now

	signBytes := comet.VoteSignBytes("chain-id", &vote)

	sigRes1, err := cosigner1.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:          testChainID,
		EncryptedSecrets: ephemeralSharesFor1.EncryptedSecrets,
		HRST:             hrst,
		SignBytes:        signBytes,
	})
	require.NoError(t, err)

	sigRes2, err := cosigner2.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:          testChainID,
		EncryptedSecrets: ephemeralSharesFor2.EncryptedSecrets,
		HRST:             hrst,
		SignBytes:        signBytes,
	})
	require.NoError(t, err)

	sigIds := []int{1, 2}
	sigArr := [][]byte{sigRes1.Signature[32:], sigRes2.Signature[32:]}

	t.Logf("sig arr: %x", sigArr)

	combinedSig := tsed25519.CombineShares(2, sigIds, sigArr)
	signature := sigRes1.Signature[:32]
	signature = append(signature, combinedSig...)

	t.Logf("signature: %x", combinedSig)
	require.True(t, pubKey.VerifySignature(signBytes, signature))
}
