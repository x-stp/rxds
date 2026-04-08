// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/x-stp/rxds/internal/cryptobyte/asn1"
)

// A Builder builds byte strings from fixed-length and length-prefixed values.
type Builder struct {
	err            error
	result         []byte
	fixedSize      bool
	child          *Builder
	offset         int
	pendingLenLen  int
	pendingIsASN1  bool
	inContinuation *bool
}

func NewBuilder(buffer []byte) *Builder {
	return &Builder{
		result: buffer,
	}
}

func NewFixedBuilder(buffer []byte) *Builder {
	return &Builder{
		result:    buffer,
		fixedSize: true,
	}
}

func (b *Builder) SetError(err error) {
	b.err = err
}

func (b *Builder) Bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.result[b.offset:], nil
}

func (b *Builder) BytesOrPanic() []byte {
	if b.err != nil {
		panic(b.err)
	}
	return b.result[b.offset:]
}

func (b *Builder) AddUint8(v uint8) {
	b.add(byte(v))
}

func (b *Builder) AddUint16(v uint16) {
	b.add(byte(v>>8), byte(v))
}

func (b *Builder) AddUint24(v uint32) {
	b.add(byte(v>>16), byte(v>>8), byte(v))
}

func (b *Builder) AddUint32(v uint32) {
	b.add(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (b *Builder) AddUint48(v uint64) {
	b.add(byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (b *Builder) AddUint64(v uint64) {
	b.add(byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (b *Builder) AddBytes(v []byte) {
	b.add(v...)
}

type BuilderContinuation func(child *Builder)

type BuildError struct {
	Err error
}

func (b *Builder) AddUint8LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(1, false, f)
}

func (b *Builder) AddUint16LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(2, false, f)
}

func (b *Builder) AddUint24LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(3, false, f)
}

func (b *Builder) AddUint32LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(4, false, f)
}

func (b *Builder) callContinuation(f BuilderContinuation, arg *Builder) {
	if !*b.inContinuation {
		*b.inContinuation = true

		defer func() {
			*b.inContinuation = false

			r := recover()
			if r == nil {
				return
			}

			if buildError, ok := r.(BuildError); ok {
				b.err = buildError.Err
			} else {
				panic(r)
			}
		}()
	}

	f(arg)
}

func (b *Builder) addLengthPrefixed(lenLen int, isASN1 bool, f BuilderContinuation) {
	if b.err != nil {
		return
	}

	offset := len(b.result)
	b.add(make([]byte, lenLen)...)

	if b.inContinuation == nil {
		b.inContinuation = new(bool)
	}

	b.child = &Builder{
		result:         b.result,
		fixedSize:      b.fixedSize,
		offset:         offset,
		pendingLenLen:  lenLen,
		pendingIsASN1:  isASN1,
		inContinuation: b.inContinuation,
	}

	b.callContinuation(f, b.child)
	b.flushChild()
	if b.child != nil {
		panic("cryptobyte: internal error")
	}
}

func (b *Builder) flushChild() {
	if b.child == nil {
		return
	}
	b.child.flushChild()
	child := b.child
	b.child = nil

	if child.err != nil {
		b.err = child.err
		return
	}

	length := len(child.result) - child.pendingLenLen - child.offset

	if length < 0 {
		panic("cryptobyte: internal error")
	}

	if child.pendingIsASN1 {
		if child.pendingLenLen != 1 {
			panic("cryptobyte: internal error")
		}
		var lenLen, lenByte uint8
		if int64(length) > 0xfffffffe {
			b.err = errors.New("pending ASN.1 child too long")
			return
		} else if length > 0xffffff {
			lenLen = 5
			lenByte = 0x80 | 4
		} else if length > 0xffff {
			lenLen = 4
			lenByte = 0x80 | 3
		} else if length > 0xff {
			lenLen = 3
			lenByte = 0x80 | 2
		} else if length > 0x7f {
			lenLen = 2
			lenByte = 0x80 | 1
		} else {
			lenLen = 1
			lenByte = uint8(length)
			length = 0
		}

		child.result[child.offset] = lenByte
		extraBytes := int(lenLen - 1)
		if extraBytes != 0 {
			child.add(make([]byte, extraBytes)...)
			childStart := child.offset + child.pendingLenLen
			copy(child.result[childStart+extraBytes:], child.result[childStart:])
		}
		child.offset++
		child.pendingLenLen = extraBytes
	}

	l := length
	for i := child.pendingLenLen - 1; i >= 0; i-- {
		child.result[child.offset+i] = uint8(l)
		l >>= 8
	}
	if l != 0 {
		b.err = fmt.Errorf("cryptobyte: pending child length %d exceeds %d-byte length prefix", length, child.pendingLenLen)
		return
	}

	if b.fixedSize && &b.result[0] != &child.result[0] {
		panic("cryptobyte: BuilderContinuation reallocated a fixed-size buffer")
	}

	b.result = child.result
}

func (b *Builder) add(bytes ...byte) {
	if b.err != nil {
		return
	}
	if b.child != nil {
		panic("cryptobyte: attempted write while child is pending")
	}
	if len(b.result)+len(bytes) < len(bytes) {
		b.err = errors.New("cryptobyte: length overflow")
	}
	if b.fixedSize && len(b.result)+len(bytes) > cap(b.result) {
		b.err = errors.New("cryptobyte: Builder is exceeding its fixed-size buffer")
		return
	}
	b.result = append(b.result, bytes...)
}

func (b *Builder) Unwrite(n int) {
	if b.err != nil {
		return
	}
	if b.child != nil {
		panic("cryptobyte: attempted unwrite while child is pending")
	}
	length := len(b.result) - b.pendingLenLen - b.offset
	if length < 0 {
		panic("cryptobyte: internal error")
	}
	if n < 0 {
		panic("cryptobyte: attempted to unwrite negative number of bytes")
	}
	if n > length {
		panic("cryptobyte: attempted to unwrite more than was written")
	}
	b.result = b.result[:len(b.result)-n]
}

type MarshalingValue interface {
	Marshal(b *Builder) error
}

func (b *Builder) AddValue(v MarshalingValue) {
	err := v.Marshal(b)
	if err != nil {
		b.err = err
	}
}

// ASN.1 helpers from builder.go (merged or from original file)

func (b *Builder) AddASN1Int64(v int64) {
	b.addASN1Signed(asn1.INTEGER, v)
}

func (b *Builder) AddASN1Int64WithTag(v int64, tag asn1.Tag) {
	b.addASN1Signed(tag, v)
}

func (b *Builder) AddASN1Enum(v int64) {
	b.addASN1Signed(asn1.ENUM, v)
}

func (b *Builder) addASN1Signed(tag asn1.Tag, v int64) {
	b.AddASN1(tag, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80 || i < -0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
}

func (b *Builder) AddASN1Uint64(v uint64) {
	b.AddASN1(asn1.INTEGER, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
}

var bigOne = big.NewInt(1)

func (b *Builder) AddASN1BigInt(n *big.Int) {
	if b.err != nil {
		return
	}

	b.AddASN1(asn1.INTEGER, func(c *Builder) {
		if n.Sign() < 0 {
			nMinus1 := new(big.Int).Neg(n)
			nMinus1.Sub(nMinus1, bigOne)
			bytes := nMinus1.Bytes()
			for i := range bytes {
				bytes[i] ^= 0xff
			}
			if len(bytes) == 0 || bytes[0]&0x80 == 0 {
				c.add(0xff)
			}
			c.add(bytes...)
		} else if n.Sign() == 0 {
			c.add(0)
		} else {
			bytes := n.Bytes()
			if bytes[0]&0x80 != 0 {
				c.add(0)
			}
			c.add(bytes...)
		}
	})
}

func (b *Builder) AddASN1OctetString(bytes []byte) {
	b.AddASN1(asn1.OCTET_STRING, func(c *Builder) {
		c.AddBytes(bytes)
	})
}

const generalizedTimeFormatStr = "20060102150405Z0700"

func (b *Builder) AddASN1GeneralizedTime(t time.Time) {
	if t.Year() < 0 || t.Year() > 9999 {
		b.err = fmt.Errorf("cryptobyte: cannot represent %v as a GeneralizedTime", t)
		return
	}
	b.AddASN1(asn1.GeneralizedTime, func(c *Builder) {
		c.AddBytes([]byte(t.Format(generalizedTimeFormatStr)))
	})
}

const defaultUTCTimeFormatStr = "060102150405Z0700"

func (b *Builder) AddASN1UTCTime(t time.Time) {
	b.AddASN1(asn1.UTCTime, func(c *Builder) {
		if t.Year() < 1950 || t.Year() >= 2050 {
			b.err = fmt.Errorf("cryptobyte: cannot represent %v as a UTCTime", t)
			return
		}
		c.AddBytes([]byte(t.Format(defaultUTCTimeFormatStr)))
	})
}

func (b *Builder) AddASN1BitString(data []byte) {
	b.AddASN1(asn1.BIT_STRING, func(b *Builder) {
		b.AddUint8(0)
		b.AddBytes(data)
	})
}

func (b *Builder) addBase128Int(n int64) {
	var length int
	if n == 0 {
		length = 1
	} else {
		for i := n; i > 0; i >>= 7 {
			length++
		}
	}

	for i := length - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		b.add(o)
	}
}

func isValidOID(oid encoding_asn1.ObjectIdentifier) bool {
	if len(oid) < 2 {
		return false
	}

	if oid[0] > 2 || (oid[0] <= 1 && oid[1] >= 40) {
		return false
	}

	for _, v := range oid {
		if v < 0 {
			return false
		}
	}

	return true
}

func (b *Builder) AddASN1ObjectIdentifier(oid encoding_asn1.ObjectIdentifier) {
	b.AddASN1(asn1.OBJECT_IDENTIFIER, func(b *Builder) {
		if !isValidOID(oid) {
			b.err = fmt.Errorf("cryptobyte: invalid OID: %v", oid)
			return
		}

		b.addBase128Int(int64(oid[0])*40 + int64(oid[1]))
		for _, v := range oid[2:] {
			b.addBase128Int(int64(v))
		}
	})
}

func (b *Builder) AddASN1Boolean(v bool) {
	b.AddASN1(asn1.BOOLEAN, func(b *Builder) {
		if v {
			b.AddUint8(0xff)
		} else {
			b.AddUint8(0)
		}
	})
}

func (b *Builder) AddASN1NULL() {
	b.add(uint8(asn1.NULL), 0)
}

func (b *Builder) MarshalASN1(v interface{}) {
	if b.err != nil {
		return
	}
	bytes, err := encoding_asn1.Marshal(v)
	if err != nil {
		b.err = err
		return
	}
	b.AddBytes(bytes)
}

func (b *Builder) AddASN1(tag asn1.Tag, f BuilderContinuation) {
	if b.err != nil {
		return
	}
	if tag&0x1f == 0x1f {
		b.err = fmt.Errorf("cryptobyte: high-tag number identifier octets not supported: 0x%x", tag)
		return
	}
	b.AddUint8(uint8(tag))
	b.addLengthPrefixed(1, true, f)
}
