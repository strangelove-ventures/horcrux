package pkg

import (
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"gitlab.com/polychainlabs/edwards25519"
	"gitlab.com/polychainlabs/threshold-ed25519/internal/util"
)

var (
	// Order of curve25519 as a big int
	// 2^252 + 27742317777372353535851937790883648493
	orderL = new(big.Int).SetBits([]big.Word{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000})

	scalarSize  = 32
	elementSize = 32
)

// Scalar type alias for byte array
type Scalar []byte

// Element type alias for byte array
type Element []byte

// ScalarMultiplyBase multiplies the scalar parameter by the ed25519 base
// and returns an element in the field.
func ScalarMultiplyBase(scalar Scalar) Element {
	var reduced [32]byte
	var orig [64]byte
	copy(orig[:], scalar)
	edwards25519.ScReduce(&reduced, &orig)

	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &reduced)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	element := make(Element, elementSize)
	copy(element, publicKeyBytes[:])
	return element
}

// AddScalars adds all scalars, mods the result by the field order, and returns the result as a scalar
func AddScalars(scalars []Scalar) Scalar {
	var result big.Int

	for _, scalar := range scalars {
		result.Add(&result, util.BytesToBig(scalar))
	}

	result.Mod(&result, orderL)
	out := make(Scalar, 32)
	copy(out, util.Reverse(result.Bytes()))
	return out
}

// AddElements adds field elements and returns a field element result
func AddElements(elements []Element) Element {
	var out edwards25519.CompletedGroupElement

	var zero edwards25519.ExtendedGroupElement
	zero.Zero()

	var zeroP edwards25519.PreComputedGroupElement
	zeroP.Zero()
	edwards25519.GeMixedAdd(&out, &zero, &zeroP)

	for _, element := range elements {
		if len(element) == 0 {
			continue
		}
		var ge edwards25519.ExtendedGroupElement
		var publicKeyBytes [32]byte
		copy(publicKeyBytes[:], element)
		ge.FromBytes(&publicKeyBytes)

		var tempE edwards25519.ExtendedGroupElement
		var tempC edwards25519.CachedGroupElement
		out.ToExtended(&tempE)
		tempE.ToCached(&tempC)
		edwards25519.GeAdd(&out, &ge, &tempC)
	}

	var temp edwards25519.ExtendedGroupElement
	out.ToExtended(&temp)

	var publicKeyBytes [32]byte
	temp.ToBytes(&publicKeyBytes)

	element := make(Element, elementSize)
	copy(element, publicKeyBytes[:])
	return element
}

// DealShares split the secret bytes into n total shares requiring t threshold of the shares
// to re-assemble the original secret.
// The return value is an array of Scalars of size `n` (total)
func DealShares(secret []byte, threshold uint8, total uint8) []Scalar {
	coeffs := make([]big.Int, threshold)
	coeffs[0].SetBytes(util.Reverse(secret))

	for i := uint8(1); i < threshold; i++ {
		random, err := rand.Int(rand.Reader, orderL)
		if err != nil {
			panic(err)
		}
		coeffs[i].Set(random)
	}

	shares := make([]Scalar, total)
	for i := uint8(0); i < total; i++ {
		// start share coeff as the last coeff
		var shareCoeff big.Int
		shareCoeff.Set(&coeffs[threshold-1])

		for j := int32(threshold) - 2; j >= 0; j-- {
			shareCoeff.Mul(&shareCoeff, big.NewInt(int64(i+1)))
			shareCoeff.Add(&shareCoeff, &coeffs[j])
			shareCoeff.Mod(&shareCoeff, orderL)
		}

		shares[i] = make(Scalar, 32)
		copy(shares[i], util.Reverse(shareCoeff.Bytes()))
	}

	return shares
}

// CombineShares merges an array of shares into an original Scalar value
func CombineShares(total uint8, cosignerIds []int, shares [][]byte) Scalar {
	var delta big.Int
	// factorial
	delta.MulRange(1, int64(total))

	var secret big.Int

	// loop over players
	for idx, cosignerID := range cosignerIds {
		omega := calcOmega(cosignerID, cosignerIds, delta)

		var shareNum big.Int
		shareNum.SetBytes(util.Reverse(shares[idx]))
		shareNum.Mul(&shareNum, big.NewInt(omega))
		shareNum.Mod(&shareNum, orderL)

		secret.Add(&secret, &shareNum)
	}

	delta.ModInverse(&delta, orderL)
	secret.Mul(&secret, &delta)
	secret.Mod(&secret, orderL)

	combined := make(Scalar, scalarSize)
	copy(combined, util.Reverse(secret.Bytes()))
	return combined
}

// SignWithShare signs a message using a secret share and an ephemeral share
func SignWithShare(message []byte, share []byte, ephemeralShare []byte, publicKey []byte, ephemeralPublic []byte) []byte {
	hash := sha512.New()
	hash.Write(ephemeralPublic[:])
	hash.Write(publicKey[:])
	hash.Write(message)

	var digest [64]byte
	hash.Sum(digest[:0])

	var digestReduced [32]byte
	edwards25519.ScReduce(&digestReduced, &digest)

	var share32 [32]byte
	copy(share32[:], share[:32])

	var eph32 [32]byte
	copy(eph32[:], ephemeralShare[:32])

	var s [32]byte
	edwards25519.ScMulAdd(&s, &digestReduced, &share32, &eph32)

	signature := make([]byte, len(s))
	copy(signature, s[:])
	return signature
}

// ExpandSecret expands a secret "seed" into an expanded secret
// Private keys (aka secrets) in RPC 8032 are actually "seeds"
// for the expanded secret. This mirrors the golang ed25519
// handling of ed25519 secrets.
func ExpandSecret(secret []byte) []byte {
	digest := sha512.Sum512(secret)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	return digest[:32]
}

func calcOmega(cosignerID int, cosigners []int, delta big.Int) (result int64) {
	result = delta.Int64()

	for _, cosigner := range cosigners {
		if cosigner != cosignerID {
			result *= int64(cosigner)
		}
	}

	for _, cosigner := range cosigners {
		if cosigner != cosignerID {
			result /= int64(cosigner) - int64(cosignerID)
		}
	}

	return
}
