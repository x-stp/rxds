// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf

import (
	"crypto/hmac"
	"errors"
	"hash"
	"io"
)

func Extract(hash func() hash.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash().Size())
	}
	extractor := hmac.New(hash, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}

type hkdf struct {
	expander hash.Hash
	size     int

	info    []byte
	counter byte

	prev []byte
	buf  []byte
}

func (f *hkdf) Read(p []byte) (int, error) {
	need := len(p)
	remains := len(f.buf) + int(255-f.counter+1)*f.size
	if remains < need {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	n := copy(p, f.buf)
	p = p[n:]

	for len(p) > 0 {
		if f.counter > 1 {
			f.expander.Reset()
		}
		f.expander.Write(f.prev)
		f.expander.Write(f.info)
		f.expander.Write([]byte{f.counter})
		f.prev = f.expander.Sum(f.prev[:0])
		f.counter++

		f.buf = f.prev
		n = copy(p, f.buf)
		p = p[n:]
	}
	f.buf = f.buf[n:]

	return need, nil
}

func Expand(hash func() hash.Hash, pseudorandomKey, info []byte) io.Reader {
	expander := hmac.New(hash, pseudorandomKey)
	return &hkdf{expander, expander.Size(), info, 1, nil, nil}
}

func New(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	prk := Extract(hash, secret, salt)
	return Expand(hash, prk, info)
}
