// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.13

package edwards25519

import "unsafe"

// madd64 returns ol + oh * 2⁶⁴ = lo + hi * 2⁶⁴ + a * b. That is, it multiplies
// a and b, and adds the result to the split uint128 [lo,hi].
func madd64(lo, hi, a, b uint64) (ol uint64, oh uint64) {
	t1 := (a>>32)*(b&0xFFFFFFFF) + ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF) >> 32)
	t2 := (a&0xFFFFFFFF)*(b>>32) + (t1 & 0xFFFFFFFF)
	ol = (a * b) + lo
	cmp := ol < lo
	oh = hi + (a>>32)*(b>>32) + t1>>32 + t2>>32 + uint64(*(*byte)(unsafe.Pointer(&cmp)))
	return
}

const mask32 = 1<<32 - 1

// mul51 returns lo + hi * 2⁵¹ = a * b.
func mul51(a uint64, b uint32) (lo uint64, hi uint64) {
	w0 := (a & mask32) * uint64(b)
	t := (a>>32)*uint64(b) + w0>>32
	w1 := t & mask32
	w2 := t >> 32
	mh := w2 + w1>>32
	ml := a * uint64(b)

	lo = ml & maskLow51Bits
	hi = (mh << 13) | (ml >> 51)
	return
}
