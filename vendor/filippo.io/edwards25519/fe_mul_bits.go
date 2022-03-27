// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13

package edwards25519

import "math/bits"

// madd64 returns ol + oh * 2⁶⁴ = lo + hi * 2⁶⁴ + a * b. That is, it multiplies
// a and b, and adds the result to the split uint128 [lo,hi].
func madd64(lo, hi, a, b uint64) (ol uint64, oh uint64) {
	oh, ol = bits.Mul64(a, b)
	var c uint64
	ol, c = bits.Add64(ol, lo, 0)
	oh, _ = bits.Add64(oh, hi, c)
	return
}

// mul51 returns lo + hi * 2⁵¹ = a * b.
func mul51(a uint64, b uint32) (lo uint64, hi uint64) {
	mh, ml := bits.Mul64(a, uint64(b))
	lo = ml & maskLow51Bits
	hi = (mh << 13) | (ml >> 51)
	return
}
