// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package curve25519

import "crypto/ecdh"

const (
	ScalarSize = 32
	PointSize  = 32
)

var Basepoint []byte
var basePoint = [32]byte{9}

func init() { Basepoint = basePoint[:] }

func X25519(scalar, point []byte) ([]byte, error) {
	var dst [32]byte
	return x25519(&dst, scalar, point)
}

func x25519(dst *[32]byte, scalar, point []byte) ([]byte, error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	priv, err := curve.NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	out, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	copy(dst[:], out)
	return dst[:], nil
}
