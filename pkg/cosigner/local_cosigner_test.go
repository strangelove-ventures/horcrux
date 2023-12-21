package cosigner_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/config"
	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	"github.com/strangelove-ventures/horcrux/pkg/cosigner/nodesecurity"
	"github.com/strangelove-ventures/horcrux/pkg/tss"
	"github.com/strangelove-ventures/horcrux/pkg/types"

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

	security := make([]cosigner.ICosignerSecurity, total)

	keys := make([]*rsa.PrivateKey, total)
	pubKeys := make([]*rsa.PublicKey, total)
	for i := 0; i < int(total); i++ {
		var err error
		keys[i], err = rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		pubKeys[i] = &keys[i].PublicKey
	}

	for i, k := range keys {
		security[i] = nodesecurity.NewCosignerSecurityRSA(
			nodesecurity.CosignerRSAKey{
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

	security := make([]cosigner.ICosignerSecurity, total)

	keys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	for i := 0; i < int(total); i++ {
		var err error
		keys[i], err = ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		pubKeys[i] = &keys[i].PublicKey
	}

	for i, k := range keys {
		security[i] = nodesecurity.NewCosignerSecurityECIES(
			nodesecurity.CosignerECIESKey{
				ID:        i + 1,
				ECIESKey:  k,
				ECIESPubs: pubKeys,
			},
		)
	}

	testLocalCosignerSign(t, threshold, total, security)
}

func testLocalCosignerSign(t *testing.T, threshold, total uint8, security []cosigner.ICosignerSecurity) {
	privateKey := cometcryptoed25519.GenPrivKey()

	privKeyBytes := [64]byte{}
	copy(privKeyBytes[:], privateKey[:])
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)
	pubKey := privateKey.PubKey()

	cfg := config.Config{
		ThresholdModeConfig: &config.ThresholdModeConfig{
			Threshold: int(threshold),
			Cosigners: make(config.CosignersConfig, total),
		},
	}

	ctx := context.Background()

	tmpDir := t.TempDir()

	thresholdCosigners := make([]*cosigner.LocalCosigner, threshold)
	nonces := make([][]cosigner.CosignerNonce, threshold)

	now := time.Now()

	hrst := types.HRSTKey{
		Height:    1,
		Round:     0,
		Step:      2,
		Timestamp: now.UnixNano(),
	}

	u, err := uuid.NewRandom()
	require.NoError(t, err)

	for i := 0; i < int(total); i++ {
		id := i + 1

		key := tss.CosignerEd25519Key{
			PubKey:       pubKey,
			PrivateShard: privShards[i],
			ID:           id,
		}

		cfg.ThresholdModeConfig.Cosigners[i] = config.CosignerConfig{
			ShardID: id,
		}

		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner%d", id))
		err := os.Mkdir(cosignerDir, 0700)
		require.NoError(t, err)
		runtimeconfig := &config.RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
			Config:   cfg,
		}
		cosigner := cosigner.NewLocalCosigner(
			log.NewNopLogger(),
			runtimeconfig,
			security[i],
			"",
		)

		keyBz, err := key.MarshalJSON()
		require.NoError(t, err)
		err = os.WriteFile(runtimeconfig.KeyFilePathCosigner(testChainID), keyBz, 0600)
		require.NoError(t, err)

		defer cosigner.WaitForSignStatesToFlushToDisk()

		err = cosigner.LoadSignStateIfNecessary(testChainID)
		require.NoError(t, err)

		require.Equal(t, cosigner.GetIndex(), id)

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

	sigs := make([]types.PartialSignature, threshold)

	for i, local_cosigner := range thresholdCosigners {
		cosignerNonces := make([]cosigner.CosignerNonce, 0, threshold-1)

		for j, nonce := range nonces {
			if i == j {
				continue
			}

			for _, n := range nonce {
				if n.DestinationID == local_cosigner.GetIndex() {
					cosignerNonces = append(cosignerNonces, n)
				}
			}
		}

		sigRes, err := local_cosigner.SetNoncesAndSign(ctx, cosigner.CosignerSetNoncesAndSignRequest{
			Nonces: &cosigner.CosignerUUIDNonces{
				UUID:   u,
				Nonces: cosignerNonces,
			},
			ChainID:   testChainID,
			HRST:      hrst,
			SignBytes: signBytes,
		})
		require.NoError(t, err)

		sigs[i] = types.PartialSignature{
			Index:     local_cosigner.GetIndex(),
			Signature: sigRes.Signature,
		}
	}

	combinedSig, err := thresholdCosigners[0].CombineSignatures(testChainID, sigs)
	require.NoError(t, err)

	require.True(t, pubKey.VerifySignature(signBytes, combinedSig))
}
