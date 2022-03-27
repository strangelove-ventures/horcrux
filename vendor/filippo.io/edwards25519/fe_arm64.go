// Copyright (c) 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,gc,!purego

package edwards25519

func feMul(v, x, y *fieldElement) { feMulGeneric(v, x, y) }

func feSquare(v, x *fieldElement) { feSquareGeneric(v, x) }

//go:noescape
func carryPropagate(v *fieldElement)

func (v *fieldElement) carryPropagate() *fieldElement {
	carryPropagate(v)
	return v
}
