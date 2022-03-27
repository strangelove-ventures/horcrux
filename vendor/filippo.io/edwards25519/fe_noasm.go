// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64,!arm64 !gc purego

package edwards25519

func feMul(v, x, y *fieldElement) { feMulGeneric(v, x, y) }

func feSquare(v, x *fieldElement) { feSquareGeneric(v, x) }

func (v *fieldElement) carryPropagate() *fieldElement {
	return v.carryPropagateGeneric()
}
