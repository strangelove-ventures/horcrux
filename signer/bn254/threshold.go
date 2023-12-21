package bn254

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

var genG2 = new(bn254.G2Affine)
var zeroG1 = new(bn254.G1Affine)
var zeroG2 = new(bn254.G2Affine)

func init() {
	_, _, g1, g2 := bn254.Generators()
	g1Bytes254 := g1.Bytes()
	g2Bytes254 := g2.Bytes()

	_, _ = genG2.SetBytes(g2Bytes254[:])

	_, _ = zeroG1.SetBytes(g1Bytes254[:])
	_, _ = zeroG2.SetBytes(g2Bytes254[:])

	zeroG1.Sub(zeroG1, &G1Gen)
	zeroG2.Sub(zeroG2, genG2)
}

// CombinePublicKeys combines public keys using Lagrange coefficients
func CombinePublicKeys(pks []*bn254.G1Affine, evaluationPoints ...int64) *bn254.G1Affine {
	var sum = new(bn254.G1Affine)
	zeroG1Bz := zeroG1.Bytes()
	sum.SetBytes(zeroG1Bz[:])

	for i := 0; i < len(evaluationPoints); i++ {
		var inc = new(bn254.G1Affine)
		inc.ScalarMultiplication(pks[evaluationPoints[i]-1], lagrangeCoeff(evaluationPoints[i], evaluationPoints...))
		sum.Add(sum, inc)
	}

	return sum
}

// CombineSignatures combines signatures using Lagrange coefficients
func CombineSignatures(signatures []*bn254.G2Affine, evaluationPoints ...int64) *bn254.G2Affine {
	var sum = new(bn254.G2Affine)
	zeroG2Bz := zeroG2.Bytes()
	sum.SetBytes(zeroG2Bz[:])

	var signatureIndex int
	for _, evaluationPoint := range evaluationPoints {
		var inc = new(bn254.G2Affine)
		inc.ScalarMultiplication(signatures[signatureIndex], lagrangeCoeff(evaluationPoint, evaluationPoints...))
		sum.Add(sum, inc)
		signatureIndex++
	}

	return sum
}

// SignWithShard signs a digest with a bn254 private key
func SignWithShard(sk *big.Int, digest []byte) (*bn254.G2Affine, error) {
	g2 := HashToG2(digest)
	g2.ScalarMultiplication(&g2, sk)

	return &g2, nil
}

// VerifyShardSignature verifies a bn254 signature against a digest and a public key
func VerifyShardSignature(pk *bn254.G1Affine, digest []byte, sig *bn254.G2Affine) error {
	digestOnG2 := HashToG2(digest)

	var g1Neg bn254.G1Affine
	g1Neg.Neg(&G1Gen)

	shouldBeOne, err := bn254.MillerLoop([]bn254.G1Affine{g1Neg, *pk}, []bn254.G2Affine{*sig, digestOnG2})
	if err != nil {
		return fmt.Errorf("failed MillerLoop: %w", err)
	}

	shouldBeOne = bn254.FinalExponentiation(&shouldBeOne)

	unity := bn254.GT{}
	unity.SetOne()

	if unity.Equal(&shouldBeOne) {
		return nil
	}

	return fmt.Errorf("signature mismatch")
}
