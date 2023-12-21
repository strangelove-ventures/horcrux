package bn254_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	horcrux_bn254 "github.com/strangelove-ventures/horcrux/v3/signer/bn254"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestBn254(t *testing.T) {
	skInt := int64(2)

	var pk bn254.G1Affine
	pk.ScalarMultiplication(&horcrux_bn254.G1Gen, big.NewInt(skInt))

	msg := []byte("payload to sign")

	digest := sha3.NewLegacyKeccak256().Sum(msg)

	hash, err := bn254.HashToG2(digest, nil)
	require.NoError(t, err)

	var sig bn254.G2Affine
	_ = sig.ScalarMultiplication(&hash, big.NewInt(skInt))

	left, err := bn254.MillerLoop([]bn254.G1Affine{horcrux_bn254.G1Gen}, []bn254.G2Affine{sig})
	require.NoError(t, err)

	left = bn254.FinalExponentiation(&left)

	right, err := bn254.MillerLoop([]bn254.G1Affine{pk}, []bn254.G2Affine{hash})
	require.NoError(t, err)

	right = bn254.FinalExponentiation(&right)

	assert.True(t, left.Equal(&right))
}

func TestThresholdBn254(t *testing.T) {
	secret := horcrux_bn254.GenPrivKey()
	secretBz := secret.Bytes()

	pubKey := secret.PubKey()

	_, shards := horcrux_bn254.GenFromSecret(secretBz, 2, 3)

	msg := []byte("payload to sign")

	digest := sha3.NewLegacyKeccak256().Sum(msg)

	signatures := make([]*bn254.G2Affine, len(shards))
	for i, shard := range shards {
		signature, err := horcrux_bn254.SignWithShard(shard, digest)
		require.NoError(t, err)

		var pubKey bn254.G1Affine
		pubKey.ScalarMultiplication(&horcrux_bn254.G1Gen, shard)

		err = horcrux_bn254.VerifyShardSignature(&pubKey, digest, signature)
		require.NoError(t, err)

		signatures[i] = signature
	}

	thresholdSignature := horcrux_bn254.CombineSignatures(signatures[:2], 1, 2)
	thresholdSignatureBz := thresholdSignature.Bytes()

	valid := pubKey.VerifySignature(digest, thresholdSignatureBz[:])
	require.True(t, valid)
}
