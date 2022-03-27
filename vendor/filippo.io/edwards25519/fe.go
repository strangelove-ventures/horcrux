// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/subtle"
	"encoding/binary"
)

// fieldElement represents an element of the field GF(2^255-19). Note that this
// is not a cryptographically secure group, and should only be used to interact
// with Point coordinates.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is a valid zero element.
type fieldElement struct {
	// An element t represents the integer
	//     t.l0 + t.l1*2^51 + t.l2*2^102 + t.l3*2^153 + t.l4*2^204
	//
	// Between operations, all limbs are expected to be lower than 2^52.
	l0 uint64
	l1 uint64
	l2 uint64
	l3 uint64
	l4 uint64
}

const maskLow51Bits uint64 = (1 << 51) - 1

var (
	feZero     = &fieldElement{0, 0, 0, 0, 0}
	feOne      = &fieldElement{1, 0, 0, 0, 0}
	feTwo      = &fieldElement{2, 0, 0, 0, 0}
	feMinusOne = new(fieldElement).Negate(feOne)
)

// Zero sets v = 0, and returns v.
func (v *fieldElement) Zero() *fieldElement {
	*v = *feZero
	return v
}

// One sets v = 1, and returns v.
func (v *fieldElement) One() *fieldElement {
	*v = *feOne
	return v
}

// reduce reduces v modulo 2^255 - 19 and returns it.
func (v *fieldElement) reduce() *fieldElement {
	v.carryPropagate()

	// After the light reduction we now have a field element representation
	// v < 2^255 + 2^13 * 19, but need v < 2^255 - 19.

	// If v >= 2^255 - 19, then v + 19 >= 2^255, which would overflow 2^255 - 1,
	// generating a carry. That is, c will be 0 if v < 2^255 - 19, and 1 otherwise.
	c := (v.l0 + 19) >> 51
	c = (v.l1 + c) >> 51
	c = (v.l2 + c) >> 51
	c = (v.l3 + c) >> 51
	c = (v.l4 + c) >> 51

	// If v < 2^255 - 19 and c = 0, this will be a no-op. Otherwise, it's
	// effectively applying the reduction identity to the carry.
	v.l0 += 19 * c

	v.l1 += v.l0 >> 51
	v.l0 = v.l0 & maskLow51Bits
	v.l2 += v.l1 >> 51
	v.l1 = v.l1 & maskLow51Bits
	v.l3 += v.l2 >> 51
	v.l2 = v.l2 & maskLow51Bits
	v.l4 += v.l3 >> 51
	v.l3 = v.l3 & maskLow51Bits
	// no additional carry
	v.l4 = v.l4 & maskLow51Bits

	return v
}

// Add sets v = a + b, and returns v.
func (v *fieldElement) Add(a, b *fieldElement) *fieldElement {
	v.l0 = a.l0 + b.l0
	v.l1 = a.l1 + b.l1
	v.l2 = a.l2 + b.l2
	v.l3 = a.l3 + b.l3
	v.l4 = a.l4 + b.l4
	// Using the generic implementation here is actually faster than the
	// assembly. Probably because the body of this function is so simple that
	// the compiler can figure out better optimizations by inlining the carry
	// propagation.
	return v.carryPropagateGeneric()
}

// Subtract sets v = a - b, and returns v.
func (v *fieldElement) Subtract(a, b *fieldElement) *fieldElement {
	// We first add 2 * p, to guarantee the subtraction won't underflow, and
	// then subtract b (which can be up to 2^255 + 2^13 * 19).
	v.l0 = (a.l0 + 0xFFFFFFFFFFFDA) - b.l0
	v.l1 = (a.l1 + 0xFFFFFFFFFFFFE) - b.l1
	v.l2 = (a.l2 + 0xFFFFFFFFFFFFE) - b.l2
	v.l3 = (a.l3 + 0xFFFFFFFFFFFFE) - b.l3
	v.l4 = (a.l4 + 0xFFFFFFFFFFFFE) - b.l4
	return v.carryPropagate()
}

// Negate sets v = -a, and returns v.
func (v *fieldElement) Negate(a *fieldElement) *fieldElement {
	return v.Subtract(feZero, a)
}

// Invert sets v = 1/z mod p, and returns v.
//
// If z == 0, Invert returns v = 0.
func (v *fieldElement) Invert(z *fieldElement) *fieldElement {
	// Inversion is implemented as exponentiation with exponent p − 2. It uses the
	// same sequence of 255 squarings and 11 multiplications as [Curve25519].
	var z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t fieldElement

	z2.Square(z)             // 2
	t.Square(&z2)            // 4
	t.Square(&t)             // 8
	z9.Multiply(&t, z)       // 9
	z11.Multiply(&z9, &z2)   // 11
	t.Square(&z11)           // 22
	z2_5_0.Multiply(&t, &z9) // 2^5 - 2^0 = 31

	t.Square(&z2_5_0) // 2^6 - 2^1
	for i := 0; i < 4; i++ {
		t.Square(&t) // 2^10 - 2^5
	}
	z2_10_0.Multiply(&t, &z2_5_0) // 2^10 - 2^0

	t.Square(&z2_10_0) // 2^11 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^20 - 2^10
	}
	z2_20_0.Multiply(&t, &z2_10_0) // 2^20 - 2^0

	t.Square(&z2_20_0) // 2^21 - 2^1
	for i := 0; i < 19; i++ {
		t.Square(&t) // 2^40 - 2^20
	}
	t.Multiply(&t, &z2_20_0) // 2^40 - 2^0

	t.Square(&t) // 2^41 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^50 - 2^10
	}
	z2_50_0.Multiply(&t, &z2_10_0) // 2^50 - 2^0

	t.Square(&z2_50_0) // 2^51 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^100 - 2^50
	}
	z2_100_0.Multiply(&t, &z2_50_0) // 2^100 - 2^0

	t.Square(&z2_100_0) // 2^101 - 2^1
	for i := 0; i < 99; i++ {
		t.Square(&t) // 2^200 - 2^100
	}
	t.Multiply(&t, &z2_100_0) // 2^200 - 2^0

	t.Square(&t) // 2^201 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^250 - 2^50
	}
	t.Multiply(&t, &z2_50_0) // 2^250 - 2^0

	t.Square(&t) // 2^251 - 2^1
	t.Square(&t) // 2^252 - 2^2
	t.Square(&t) // 2^253 - 2^3
	t.Square(&t) // 2^254 - 2^4
	t.Square(&t) // 2^255 - 2^5

	return v.Multiply(&t, &z11) // 2^255 - 21
}

// Set sets v = a, and returns v.
func (v *fieldElement) Set(a *fieldElement) *fieldElement {
	*v = *a
	return v
}

// SetBytes sets v to x, which must be a 32 bytes little-endian encoding.
//
// Consistently with RFC 7748, the most significant bit (the high bit of the
// last byte) is ignored, and non-canonical values (2^255-19 through 2^255-1)
// are accepted. Note that this is laxer than specified by RFC 8032.
func (v *fieldElement) SetBytes(x []byte) *fieldElement {
	if len(x) != 32 {
		panic("edwards25519: invalid field element input size")
	}

	// Bits 0:51 (bytes 0:8, bits 0:64, shift 0, mask 51).
	v.l0 = binary.LittleEndian.Uint64(x[0:8])
	v.l0 &= maskLow51Bits
	// Bits 51:102 (bytes 6:14, bits 48:112, shift 3, mask 51).
	v.l1 = binary.LittleEndian.Uint64(x[6:14]) >> 3
	v.l1 &= maskLow51Bits
	// Bits 102:153 (bytes 12:20, bits 96:160, shift 6, mask 51).
	v.l2 = binary.LittleEndian.Uint64(x[12:20]) >> 6
	v.l2 &= maskLow51Bits
	// Bits 153:204 (bytes 19:27, bits 152:216, shift 1, mask 51).
	v.l3 = binary.LittleEndian.Uint64(x[19:27]) >> 1
	v.l3 &= maskLow51Bits
	// Bits 204:251 (bytes 24:32, bits 192:256, shift 12, mask 51).
	// Note: not bytes 25:33, shift 4, to avoid overread.
	v.l4 = binary.LittleEndian.Uint64(x[24:32]) >> 12
	v.l4 &= maskLow51Bits

	return v
}

// Bytes returns the canonical 32 bytes little-endian encoding of v.
func (v *fieldElement) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [32]byte
	return v.bytes(&out)
}

func (v *fieldElement) bytes(out *[32]byte) []byte {
	t := *v
	t.reduce()

	var buf [8]byte
	for i, l := range [5]uint64{t.l0, t.l1, t.l2, t.l3, t.l4} {
		bitsOffset := i * 51
		binary.LittleEndian.PutUint64(buf[:], l<<uint(bitsOffset%8))
		for i, bb := range buf {
			off := bitsOffset/8 + i
			if off >= len(out) {
				break
			}
			out[off] |= bb
		}
	}

	return out[:]
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *fieldElement) Equal(u *fieldElement) int {
	sa, sv := u.Bytes(), v.Bytes()
	return subtle.ConstantTimeCompare(sa, sv)
}

const mask64Bits uint64 = (1 << 64) - 1

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *fieldElement) Select(a, b *fieldElement, cond int) *fieldElement {
	m := uint64(cond) * mask64Bits
	v.l0 = (m & a.l0) | (^m & b.l0)
	v.l1 = (m & a.l1) | (^m & b.l1)
	v.l2 = (m & a.l2) | (^m & b.l2)
	v.l3 = (m & a.l3) | (^m & b.l3)
	v.l4 = (m & a.l4) | (^m & b.l4)
	return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0, and returns v.
func (v *fieldElement) Swap(u *fieldElement, cond int) {
	m := uint64(cond) * mask64Bits
	t := m & (v.l0 ^ u.l0)
	v.l0 ^= t
	u.l0 ^= t
	t = m & (v.l1 ^ u.l1)
	v.l1 ^= t
	u.l1 ^= t
	t = m & (v.l2 ^ u.l2)
	v.l2 ^= t
	u.l2 ^= t
	t = m & (v.l3 ^ u.l3)
	v.l3 ^= t
	u.l3 ^= t
	t = m & (v.l4 ^ u.l4)
	v.l4 ^= t
	u.l4 ^= t
}

// condNeg sets v to -u if cond == 1, and to u if cond == 0.
func (v *fieldElement) condNeg(u *fieldElement, cond int) *fieldElement {
	tmp := new(fieldElement).Negate(u)
	return v.Select(tmp, u, cond)
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *fieldElement) IsNegative() int {
	b := v.Bytes()
	return int(b[0] & 1)
}

// Absolute sets v to |u|, and returns v.
func (v *fieldElement) Absolute(u *fieldElement) *fieldElement {
	return v.condNeg(u, u.IsNegative())
}

// Multiply sets v = x * y, and returns v.
func (v *fieldElement) Multiply(x, y *fieldElement) *fieldElement {
	feMul(v, x, y)
	return v
}

// Square sets v = x * x, and returns v.
func (v *fieldElement) Square(x *fieldElement) *fieldElement {
	feSquare(v, x)
	return v
}

// Mult32 sets v = x * y, and returns v.
func (v *fieldElement) Mult32(x *fieldElement, y uint32) *fieldElement {
	x0lo, x0hi := mul51(x.l0, y)
	x1lo, x1hi := mul51(x.l1, y)
	x2lo, x2hi := mul51(x.l2, y)
	x3lo, x3hi := mul51(x.l3, y)
	x4lo, x4hi := mul51(x.l4, y)
	v.l0 = x0lo + 19*x4hi // carried over per the reduction identity
	v.l1 = x1lo + x0hi
	v.l2 = x2lo + x1hi
	v.l3 = x3lo + x2hi
	v.l4 = x4lo + x3hi
	// The hi portions are going to be only 32 bits, plus any previous excess,
	// so we can skip the carry propagation.
	return v
}

// Pow22523 set v = x^((p-5)/8), and returns v. (p-5)/8 is 2^252-3.
func (v *fieldElement) Pow22523(x *fieldElement) *fieldElement {
	var t0, t1, t2 fieldElement

	t0.Square(x)
	for i := 1; i < 1; i++ {
		t0.Square(&t0)
	}
	t1.Square(&t0)
	for i := 1; i < 2; i++ {
		t1.Square(&t1)
	}
	t1.Multiply(x, &t1)
	t0.Multiply(&t0, &t1)
	t0.Square(&t0)
	for i := 1; i < 1; i++ {
		t0.Square(&t0)
	}
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 5; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 10; i++ {
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)
	t2.Square(&t1)
	for i := 1; i < 20; i++ {
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)
	t1.Square(&t1)
	for i := 1; i < 10; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 50; i++ {
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)
	t2.Square(&t1)
	for i := 1; i < 100; i++ {
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)
	t1.Square(&t1)
	for i := 1; i < 50; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t0.Square(&t0)
	for i := 1; i < 2; i++ {
		t0.Square(&t0)
	}
	return v.Multiply(&t0, x)
}

// sqrtM1 is 2^((p-1)/4), which squared is equal to -1 by Euler's Criterion.
var sqrtM1 = &fieldElement{1718705420411056, 234908883556509,
	2233514472574048, 2117202627021982, 765476049583133}

// feSqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, SqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 4.3 of draft-irtf-cfrg-ristretto255-decaf448-00,
// and returns r and 0.
func (r *fieldElement) SqrtRatio(u, v *fieldElement) (rr *fieldElement, wasSquare int) {
	var a, b fieldElement

	v3 := a.Multiply(a.Square(v), v)  // v^3 = v^2 * v
	v7 := b.Multiply(b.Square(v3), v) // v^7 = (v^3)^2 * v

	// r = (u * v3) * (u * v7)^((p-5)/8)
	uv3 := a.Multiply(u, v3) // (u * v3)
	uv7 := b.Multiply(u, v7) // (u * v7)
	r.Multiply(uv3, r.Pow22523(uv7))

	check := a.Multiply(v, a.Square(r)) // check = v * r^2

	uNeg := b.Negate(u)
	correctSignSqrt := check.Equal(u)
	flippedSignSqrt := check.Equal(uNeg)
	flippedSignSqrtI := check.Equal(uNeg.Multiply(uNeg, sqrtM1))

	rPrime := b.Multiply(r, sqrtM1) // r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	r.Select(rPrime, r, flippedSignSqrt|flippedSignSqrtI)

	r.Absolute(r) // Choose the nonnegative square root.
	return r, correctSignSqrt | flippedSignSqrt
}
