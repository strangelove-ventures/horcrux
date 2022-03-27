// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,gc,!purego

package edwards25519

//go:noescape
func feMul(out, a, b *fieldElement)

//go:noescape
func feSquare(out, x *fieldElement)

func (v *fieldElement) carryPropagate() *fieldElement {
	return v.carryPropagateGeneric()
}
