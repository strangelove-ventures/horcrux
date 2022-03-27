// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

func feMulGeneric(v, x, y *fieldElement) {
	x0 := x.l0
	x1 := x.l1
	x2 := x.l2
	x3 := x.l3
	x4 := x.l4

	y0 := y.l0
	y1 := y.l1
	y2 := y.l2
	y3 := y.l3
	y4 := y.l4

	// Reduction can be carried out simultaneously to multiplication. For
	// example, we do not compute a coefficient r_5 . Whenever the result of a
	// mul instruction belongs to r_5 , for example in the multiplication of
	// x_3*y_2 , we multiply one of the inputs by 19 and add the result to r_0.

	x1_19 := x1 * 19
	x2_19 := x2 * 19
	x3_19 := x3 * 19
	x4_19 := x4 * 19

	// calculate r0 = x0*y0 + 19*(x1*y4 + x2*y3 + x3*y2 + x4*y1)
	r00, r01 := madd64(0, 0, x0, y0)
	r00, r01 = madd64(r00, r01, x1_19, y4)
	r00, r01 = madd64(r00, r01, x2_19, y3)
	r00, r01 = madd64(r00, r01, x3_19, y2)
	r00, r01 = madd64(r00, r01, x4_19, y1)

	// calculate r1 = x0*y1 + x1*y0 + 19*(x2*y4 + x3*y3 + x4*y2)
	r10, r11 := madd64(0, 0, x0, y1)
	r10, r11 = madd64(r10, r11, x1, y0)
	r10, r11 = madd64(r10, r11, x2_19, y4)
	r10, r11 = madd64(r10, r11, x3_19, y3)
	r10, r11 = madd64(r10, r11, x4_19, y2)

	// calculate r2 = x0*y2 + x1*y1 + x2*y0 + 19*(x3*y4 + x4*y3)
	r20, r21 := madd64(0, 0, x0, y2)
	r20, r21 = madd64(r20, r21, x1, y1)
	r20, r21 = madd64(r20, r21, x2, y0)
	r20, r21 = madd64(r20, r21, x3_19, y4)
	r20, r21 = madd64(r20, r21, x4_19, y3)

	// calculate r3 = x0*y3 + x1*y2 + x2*y1 + x3*y0 + 19*x4*y4
	r30, r31 := madd64(0, 0, x0, y3)
	r30, r31 = madd64(r30, r31, x1, y2)
	r30, r31 = madd64(r30, r31, x2, y1)
	r30, r31 = madd64(r30, r31, x3, y0)
	r30, r31 = madd64(r30, r31, x4_19, y4)

	// calculate r4 = x0*y4 + x1*y3 + x2*y2 + x3*y1 + x4*y0
	r40, r41 := madd64(0, 0, x0, y4)
	r40, r41 = madd64(r40, r41, x1, y3)
	r40, r41 = madd64(r40, r41, x2, y2)
	r40, r41 = madd64(r40, r41, x3, y1)
	r40, r41 = madd64(r40, r41, x4, y0)

	// After the multiplication we need to reduce (carry) the 5 coefficients to
	// obtain a result with coefficients that are at most slightly larger than
	// 2^51 . Denote the two registers holding coefficient r_0 as r_00 and r_01
	// with r_0 = 2^64*r_01 + r_00 . Similarly denote the two registers holding
	// coefficient r_1 as r_10 and r_11 . We first shift r_01 left by 13, while
	// shifting in the most significant bits of r_00 (shld instruction) and
	// then compute the logical and of r_00 with 2^51 − 1. We do the same with
	// r_10 and r_11 and add r_01 into r_10 after the logical and with 2^51 −
	// 1. We proceed this way for coefficients r_2,...,r_4; register r_41 is
	// multiplied by 19 before adding it to r_00 .

	r01 = (r01 << 13) | (r00 >> 51)
	r00 &= maskLow51Bits

	r11 = (r11 << 13) | (r10 >> 51)
	r10 &= maskLow51Bits
	r10 += r01

	r21 = (r21 << 13) | (r20 >> 51)
	r20 &= maskLow51Bits
	r20 += r11

	r31 = (r31 << 13) | (r30 >> 51)
	r30 &= maskLow51Bits
	r30 += r21

	r41 = (r41 << 13) | (r40 >> 51)
	r40 &= maskLow51Bits
	r40 += r31

	r41 *= 19
	r00 += r41

	// Now all 5 coefficients fit into 64-bit registers but are still too large
	// to be used as input to another multiplication. We therefore carry from
	// r_0 to r_1 , from r_1 to r_2 , from r_2 to r_3 , from r_3 to r_4 , and
	// finally from r_4 to r_0 . Each of these carries is done as one copy, one
	// right shift by 51, one logical and with 2^51 − 1, and one addition.
	*v = fieldElement{r00, r10, r20, r30, r40}
	v.carryPropagate()
}

func feSquareGeneric(v, x *fieldElement) {
	// Squaring needs only 15 mul instructions. Some inputs are multiplied by 2;
	// this is combined with multiplication by 19 where possible. The coefficient
	// reduction after squaring is the same as for multiplication.

	x0 := x.l0
	x1 := x.l1
	x2 := x.l2
	x3 := x.l3
	x4 := x.l4

	x0_2 := x0 << 1
	x1_2 := x1 << 1

	x1_38 := x1 * 38
	x2_38 := x2 * 38
	x3_38 := x3 * 38

	x3_19 := x3 * 19
	x4_19 := x4 * 19

	// r0 = x0*x0 + x1*38*x4 + x2*38*x3
	r00, r01 := madd64(0, 0, x0, x0)
	r00, r01 = madd64(r00, r01, x1_38, x4)
	r00, r01 = madd64(r00, r01, x2_38, x3)

	// r1 = x0*2*x1 + x2*38*x4 + x3*19*x3
	r10, r11 := madd64(0, 0, x0_2, x1)
	r10, r11 = madd64(r10, r11, x2_38, x4)
	r10, r11 = madd64(r10, r11, x3_19, x3)

	// r2 = x0*2*x2 + x1*x1 + x3*38*x4
	r20, r21 := madd64(0, 0, x0_2, x2)
	r20, r21 = madd64(r20, r21, x1, x1)
	r20, r21 = madd64(r20, r21, x3_38, x4)

	// r3 = x0*2*x3 + x1*2*x2 + x4*19*x4
	r30, r31 := madd64(0, 0, x0_2, x3)
	r30, r31 = madd64(r30, r31, x1_2, x2)
	r30, r31 = madd64(r30, r31, x4_19, x4)

	// r4 = x0*2*x4 + x1*2*x3 + x2*x2
	r40, r41 := madd64(0, 0, x0_2, x4)
	r40, r41 = madd64(r40, r41, x1_2, x3)
	r40, r41 = madd64(r40, r41, x2, x2)

	// Same reduction

	r01 = (r01 << 13) | (r00 >> 51)
	r00 &= maskLow51Bits

	r11 = (r11 << 13) | (r10 >> 51)
	r10 &= maskLow51Bits
	r10 += r01

	r21 = (r21 << 13) | (r20 >> 51)
	r20 &= maskLow51Bits
	r20 += r11

	r31 = (r31 << 13) | (r30 >> 51)
	r30 &= maskLow51Bits
	r30 += r21

	r41 = (r41 << 13) | (r40 >> 51)
	r40 &= maskLow51Bits
	r40 += r31

	r41 *= 19
	r00 += r41

	*v = fieldElement{r00, r10, r20, r30, r40}
	v.carryPropagate()
}

// carryPropagate brings the limbs below 52 bits by applying the reduction
// identity to the l4 carry.
func (v *fieldElement) carryPropagateGeneric() *fieldElement {
	c0 := v.l0 >> 51
	c1 := v.l1 >> 51
	c2 := v.l2 >> 51
	c3 := v.l3 >> 51
	c4 := v.l4 >> 51

	v.l0 = v.l0&maskLow51Bits + c4*19
	v.l1 = v.l1&maskLow51Bits + c0
	v.l2 = v.l2&maskLow51Bits + c1
	v.l3 = v.l3&maskLow51Bits + c2
	v.l4 = v.l4&maskLow51Bits + c3

	return v
}
