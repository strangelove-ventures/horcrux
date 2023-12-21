package bn254

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Polynomial []*big.Int

func (p Polynomial) Y(x int) *big.Int {
	sum := big.NewInt(0)
	for i := 0; i < len(p); i++ {
		exp := big.NewInt(int64(i))
		inc := big.NewInt(int64(x))
		inc.Exp(inc, exp, fr.Modulus())
		inc.Mul(inc, p[i])
		sum.Add(sum, inc)
	}
	sum.Mod(sum, fr.Modulus())
	return sum
}

type Shards []*big.Int

func GenFromSecret(secret []byte, threshold uint8, total uint8) (Polynomial, Shards) {
	polynomial := make(Polynomial, threshold)
	polynomial[0] = new(big.Int)
	polynomial[0].SetBytes(secret)

	for i := 1; i < int(threshold); i++ {
		bi, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			panic(err)
		}
		polynomial[i] = bi
	}

	shares := make([]*big.Int, total)
	for point := 1; point <= int(total); point++ {
		shares[point-1] = polynomial.Y(point)
	}

	return polynomial, shares
}

func lagrangeCoeff(point int64, points ...int64) *big.Int {
	var prodElements []*big.Int //nolint:prealloc

	for _, j := range points {
		if point == j {
			continue
		}

		iScalar := big.NewInt(point)
		jScalar := big.NewInt(j)

		nominator := jScalar // j

		var denominator = new(big.Int)
		denominator.Sub(jScalar, iScalar)
		denominator.Mod(denominator, fr.Modulus())

		denominator.ModInverse(denominator, fr.Modulus())

		division := nominator.Mul(nominator, denominator)

		prodElements = append(prodElements, division)
	}

	if len(prodElements) == 0 {
		panic("empty lagrange coeff vector")
	}

	prod := prodElements[0]
	for i := 1; i < len(prodElements); i++ {
		prod.Mul(prod, prodElements[i])
	}

	return prod
}
