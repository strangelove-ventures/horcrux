package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	testChainID  = "chain-1"
	testChainID2 = "chain-2"
	bitSize      = 4096
)

func TestLocalCosignerSignRSA2of3(t *testing.T) {
	testLocalCosignerSignRSA(t, 2, 3)
}

func TestLocalCosignerSignRSA3of5(t *testing.T) {
	testLocalCosignerSignRSA(t, 3, 5)
}

func testLocalCosignerSignRSA(t *testing.T, threshold, total uint8) {
	t.Parallel()

	security := make([]CosignerSecurity, total)

	keys := make([]*rsa.PrivateKey, total)
	pubKeys := make([]*rsa.PublicKey, total)
	for i := 0; i < int(total); i++ {
		var err error
		keys[i], err = rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		pubKeys[i] = &keys[i].PublicKey
	}

	for i, k := range keys {
		security[i] = NewCosignerSecurityRSA(
			CosignerRSAKey{
				ID:      i + 1,
				RSAKey:  *k,
				RSAPubs: pubKeys,
			},
		)
	}

	testLocalCosignerSign(t, threshold, total, security)
}

func TestLocalCosignerSignECIES2of3(t *testing.T) {
	testLocalCosignerSignECIES(t, 2, 3)
}

func TestLocalCosignerSignECIES3of5(t *testing.T) {
	testLocalCosignerSignECIES(t, 3, 5)
}

func testLocalCosignerSignECIES(t *testing.T, threshold, total uint8) {
	t.Parallel()

	security := make([]CosignerSecurity, total)

	keys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	for i := 0; i < int(total); i++ {
		var err error
		keys[i], err = ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		pubKeys[i] = &keys[i].PublicKey
	}

	for i, k := range keys {
		security[i] = NewCosignerSecurityECIES(
			CosignerECIESKey{
				ID:        i + 1,
				ECIESKey:  k,
				ECIESPubs: pubKeys,
			},
		)
	}

	testLocalCosignerSign(t, threshold, total, security)
}

func testLocalCosignerSign(t *testing.T, threshold, total uint8, security []CosignerSecurity) {
	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)
	pubKey := privateKey.PubKey()

	cfg := Config{
		ThresholdModeConfig: &ThresholdModeConfig{
			Threshold: int(threshold),
			Cosigners: make(CosignersConfig, total),
		},
	}

	ctx := context.Background()

	tmpDir := t.TempDir()

	thresholdCosigners := make([]*LocalCosigner, threshold)
	nonces := make([][]CosignerNonce, threshold)

	now := time.Now()

	hrst := HRSTKey{
		Height:    1,
		Round:     0,
		Step:      2,
		Timestamp: now.UnixNano(),
	}

	u, err := uuid.NewRandom()
	require.NoError(t, err)

	for i := 0; i < int(total); i++ {
		id := i + 1

		key := &CosignerKey{
			PubKey:       pubKey.Bytes(),
			PrivateShard: privShards[i],
			ID:           id,
		}

		cfg.ThresholdModeConfig.Cosigners[i] = CosignerConfig{
			ShardID: id,
		}

		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner%d", id))
		err := os.Mkdir(cosignerDir, 0700)
		require.NoError(t, err)

		cosigner := NewLocalCosigner(
			log.NewNopLogger(),
			&RuntimeConfig{
				HomeDir:  cosignerDir,
				StateDir: cosignerDir,
				Config:   cfg,
			},
			security[i],
			"",
		)

		keyBz, err := json.Marshal(key)
		require.NoError(t, err)
		err = os.WriteFile(cosigner.config.KeyFilePathCosigner(testChainID), keyBz, 0600)
		require.NoError(t, err)

		defer cosigner.waitForSignStatesToFlushToDisk()

		err = cosigner.LoadSignStateIfNecessary(testChainID)
		require.NoError(t, err)

		require.Equal(t, cosigner.GetID(), id)

		if i < int(threshold) {
			thresholdCosigners[i] = cosigner

			res, err := cosigner.GetNonces(ctx, []uuid.UUID{u})
			require.NoError(t, err)

			nonces[i] = res[0].Nonces
		}
	}

	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = now

	signBytes := comet.VoteSignBytes("chain-id", &vote)

	sigs := make([]PartialSignature, threshold)

	for i, cosigner := range thresholdCosigners {
		cosignerNonces := make([]CosignerNonce, 0, threshold-1)

		for j, nonce := range nonces {
			if i == j {
				continue
			}

			for _, n := range nonce {
				if n.DestinationID == cosigner.GetID() {
					cosignerNonces = append(cosignerNonces, n)
				}
			}
		}

		sigRes, err := cosigner.SetNoncesAndSign(ctx, CosignerSetNoncesAndSignRequest{
			Nonces: &CosignerUUIDNonces{
				UUID:   u,
				Nonces: cosignerNonces,
			},
			ChainID:   testChainID,
			HRST:      hrst,
			SignBytes: signBytes,
		})
		require.NoError(t, err)

		sigs[i] = PartialSignature{
			ID:        cosigner.GetID(),
			Signature: sigRes.Signature,
		}
	}

	combinedSig, err := thresholdCosigners[0].CombineSignatures(testChainID, sigs)
	require.NoError(t, err)

	require.True(t, pubKey.VerifySignature(signBytes, combinedSig))
}
