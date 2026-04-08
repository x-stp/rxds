// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	encoding_asn1 "encoding/asn1"
	"math/big"
	"reflect"
	"time"

	"github.com/x-stp/rxds/cryptobyte/asn1"
)

// String represents a string of bytes.
type String []byte

func (s *String) read(n int) []byte {
	if len(*s) < n || n < 0 {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}

func (s *String) Skip(n int) bool {
	return s.read(n) != nil
}

func (s *String) ReadUint8(out *uint8) bool {
	v := s.read(1)
	if v == nil {
		return false
	}
	*out = uint8(v[0])
	return true
}

func (s *String) ReadUint16(out *uint16) bool {
	v := s.read(2)
	if v == nil {
		return false
	}
	*out = uint16(v[0])<<8 | uint16(v[1])
	return true
}

func (s *String) ReadUint24(out *uint32) bool {
	v := s.read(3)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	return true
}

func (s *String) ReadUint32(out *uint32) bool {
	v := s.read(4)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return true
}

func (s *String) ReadUint48(out *uint64) bool {
	v := s.read(6)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<40 | uint64(v[1])<<32 | uint64(v[2])<<24 | uint64(v[3])<<16 | uint64(v[4])<<8 | uint64(v[5])
	return true
}

func (s *String) ReadUint64(out *uint64) bool {
	v := s.read(8)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<56 | uint64(v[1])<<48 | uint64(v[2])<<40 | uint64(v[3])<<32 | uint64(v[4])<<24 | uint64(v[5])<<16 | uint64(v[6])<<8 | uint64(v[7])
	return true
}

func (s *String) readUnsigned(out *uint32, length int) bool {
	v := s.read(length)
	if v == nil {
		return false
	}
	var result uint32
	for i := 0; i < length; i++ {
		result <<= 8
		result |= uint32(v[i])
	}
	*out = result
	return true
}

func (s *String) readLengthPrefixed(lenLen int, outChild *String) bool {
	lenBytes := s.read(lenLen)
	if lenBytes == nil {
		return false
	}
	var length uint32
	for _, b := range lenBytes {
		length = length << 8
		length = length | uint32(b)
	}
	v := s.read(int(length))
	if v == nil {
		return false
	}
	*outChild = v
	return true
}

func (s *String) ReadUint8LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(1, out)
}

func (s *String) ReadUint16LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(2, out)
}

func (s *String) ReadUint24LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(3, out)
}

func (s *String) ReadBytes(out *[]byte, n int) bool {
	v := s.read(n)
	if v == nil {
		return false
	}
	*out = v
	return true
}

func (s *String) CopyBytes(out []byte) bool {
	n := len(out)
	v := s.read(n)
	if v == nil {
		return false
	}
	return copy(out, v) == n
}

func (s String) Empty() bool {
	return len(s) == 0
}

// ASN.1 parsing

func (s *String) ReadASN1Boolean(out *bool) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.BOOLEAN) || len(bytes) != 1 {
		return false
	}

	switch bytes[0] {
	case 0:
		*out = false
	case 0xff:
		*out = true
	default:
		return false
	}

	return true
}

func (s *String) ReadASN1Integer(out interface{}) bool {
	switch out := out.(type) {
	case *int, *int8, *int16, *int32, *int64:
		var i int64
		if !s.readASN1Int64(&i) || reflect.ValueOf(out).Elem().OverflowInt(i) {
			return false
		}
		reflect.ValueOf(out).Elem().SetInt(i)
		return true
	case *uint, *uint8, *uint16, *uint32, *uint64:
		var u uint64
		if !s.readASN1Uint64(&u) || reflect.ValueOf(out).Elem().OverflowUint(u) {
			return false
		}
		reflect.ValueOf(out).Elem().SetUint(u)
		return true
	case *big.Int:
		return s.readASN1BigInt(out)
	case *[]byte:
		return s.readASN1Bytes(out)
	default:
		panic("out does not point to an integer type")
	}
}

func checkASN1Integer(bytes []byte) bool {
	if len(bytes) == 0 {
		return false
	}
	if len(bytes) == 1 {
		return true
	}
	if bytes[0] == 0 && bytes[1]&0x80 == 0 || bytes[0] == 0xff && bytes[1]&0x80 == 0x80 {
		return false
	}
	return true
}

func (s *String) readASN1BigInt(out *big.Int) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.INTEGER) || !checkASN1Integer(bytes) {
		return false
	}
	if bytes[0]&0x80 == 0x80 {
		neg := make([]byte, len(bytes))
		for i, b := range bytes {
			neg[i] = ^b
		}
		out.SetBytes(neg)
		out.Add(out, bigOne)
		out.Neg(out)
	} else {
		out.SetBytes(bytes)
	}
	return true
}

func (s *String) readASN1Bytes(out *[]byte) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.INTEGER) || !checkASN1Integer(bytes) {
		return false
	}
	if bytes[0]&0x80 == 0x80 {
		return false
	}
	for len(bytes) > 1 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	*out = bytes
	return true
}

func (s *String) readASN1Int64(out *int64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.INTEGER) || !checkASN1Integer(bytes) || !asn1Signed(out, bytes) {
		return false
	}
	return true
}

func asn1Signed(out *int64, n []byte) bool {
	length := len(n)
	if length > 8 {
		return false
	}
	for i := range length {
		*out <<= 8
		*out |= int64(n[i])
	}
	*out <<= 64 - uint8(length)*8
	*out >>= 64 - uint8(length)*8
	return true
}

func (s *String) readASN1Uint64(out *uint64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.INTEGER) || !checkASN1Integer(bytes) || !asn1Unsigned(out, bytes) {
		return false
	}
	return true
}

func asn1Unsigned(out *uint64, n []byte) bool {
	length := len(n)
	if length > 9 || length == 9 && n[0] != 0 {
		return false
	}
	if n[0]&0x80 != 0 {
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= uint64(n[i])
	}
	return true
}

func (s *String) ReadASN1Int64WithTag(out *int64, tag asn1.Tag) bool {
	var bytes String
	return s.ReadASN1(&bytes, tag) && checkASN1Integer(bytes) && asn1Signed(out, bytes)
}

func (s *String) ReadASN1Enum(out *int) bool {
	var bytes String
	var i int64
	if !s.ReadASN1(&bytes, asn1.ENUM) || !checkASN1Integer(bytes) || !asn1Signed(&i, bytes) {
		return false
	}
	if int64(int(i)) != i {
		return false
	}
	*out = int(i)
	return true
}

func (s *String) readBase128Int(out *int) bool {
	ret := 0
	for i := 0; len(*s) > 0; i++ {
		if i == 5 {
			return false
		}
		if ret >= 1<<(31-7) {
			return false
		}
		ret <<= 7
		b := s.read(1)[0]

		if i == 0 && b == 0x80 {
			return false
		}

		ret |= int(b & 0x7f)
		if b&0x80 == 0 {
			*out = ret
			return true
		}
	}
	return false
}

func (s *String) ReadASN1ObjectIdentifier(out *encoding_asn1.ObjectIdentifier) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.OBJECT_IDENTIFIER) || len(bytes) == 0 {
		return false
	}

	components := make([]int, len(bytes)+1)

	var v int
	if !bytes.readBase128Int(&v) {
		return false
	}
	if v < 80 {
		components[0] = v / 40
		components[1] = v % 40
	} else {
		components[0] = 2
		components[1] = v - 80
	}

	i := 2
	for ; len(bytes) > 0; i++ {
		if !bytes.readBase128Int(&v) {
			return false
		}
		components[i] = v
	}
	*out = components[:i]
	return true
}

func (s *String) ReadASN1GeneralizedTime(out *time.Time) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.GeneralizedTime) {
		return false
	}
	t := string(bytes)
	res, err := time.Parse(generalizedTimeFormatStr, t)
	if err != nil {
		return false
	}
	if serialized := res.Format(generalizedTimeFormatStr); serialized != t {
		return false
	}
	*out = res
	return true
}

func (s *String) ReadASN1UTCTime(out *time.Time) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.UTCTime) {
		return false
	}
	t := string(bytes)

	formatStr := defaultUTCTimeFormatStr
	var err error
	res, err := time.Parse(formatStr, t)
	if err != nil {
		formatStr = "0601021504Z0700"
		res, err = time.Parse(formatStr, t)
	}
	if err != nil {
		return false
	}

	if serialized := res.Format(formatStr); serialized != t {
		return false
	}

	if res.Year() >= 2050 {
		res = res.AddDate(-100, 0, 0)
	}
	*out = res
	return true
}

func (s *String) ReadASN1BitString(out *encoding_asn1.BitString) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.BIT_STRING) || len(bytes) == 0 ||
		len(bytes)*8/8 != len(bytes) {
		return false
	}

	paddingBits := bytes[0]
	bytes = bytes[1:]
	if paddingBits > 7 ||
		len(bytes) == 0 && paddingBits != 0 ||
		len(bytes) > 0 && bytes[len(bytes)-1]&(1<<paddingBits-1) != 0 {
		return false
	}

	out.BitLength = len(bytes)*8 - int(paddingBits)
	out.Bytes = bytes
	return true
}

func (s *String) ReadASN1BitStringAsBytes(out *[]byte) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.BIT_STRING) || len(bytes) == 0 {
		return false
	}

	paddingBits := bytes[0]
	if paddingBits != 0 {
		return false
	}
	*out = bytes[1:]
	return true
}

func (s *String) ReadASN1Bytes(out *[]byte, tag asn1.Tag) bool {
	return s.ReadASN1((*String)(out), tag)
}

func (s *String) ReadASN1(out *String, tag asn1.Tag) bool {
	var t asn1.Tag
	if !s.ReadAnyASN1(out, &t) || t != tag {
		return false
	}
	return true
}

func (s *String) ReadASN1Element(out *String, tag asn1.Tag) bool {
	var t asn1.Tag
	if !s.ReadAnyASN1Element(out, &t) || t != tag {
		return false
	}
	return true
}

func (s *String) ReadAnyASN1(out *String, outTag *asn1.Tag) bool {
	return s.readASN1(out, outTag, true)
}

func (s *String) ReadAnyASN1Element(out *String, outTag *asn1.Tag) bool {
	return s.readASN1(out, outTag, false)
}

func (s String) PeekASN1Tag(tag asn1.Tag) bool {
	if len(s) == 0 {
		return false
	}
	return asn1.Tag(s[0]) == tag
}

func (s *String) SkipASN1(tag asn1.Tag) bool {
	var unused String
	return s.ReadASN1(&unused, tag)
}

func (s *String) ReadOptionalASN1(out *String, outPresent *bool, tag asn1.Tag) bool {
	present := s.PeekASN1Tag(tag)
	if outPresent != nil {
		*outPresent = present
	}
	if present && !s.ReadASN1(out, tag) {
		return false
	}
	return true
}

func (s *String) SkipOptionalASN1(tag asn1.Tag) bool {
	if !s.PeekASN1Tag(tag) {
		return true
	}
	var unused String
	return s.ReadASN1(&unused, tag)
}

func (s *String) ReadOptionalASN1Integer(out interface{}, tag asn1.Tag, defaultValue interface{}) bool {
	var present bool
	var i String
	if !s.ReadOptionalASN1(&i, &present, tag) {
		return false
	}
	if !present {
		switch out.(type) {
		case *int, *int8, *int16, *int32, *int64,
			*uint, *uint8, *uint16, *uint32, *uint64, *[]byte:
			reflect.ValueOf(out).Elem().Set(reflect.ValueOf(defaultValue))
		case *big.Int:
			if defaultValue, ok := defaultValue.(*big.Int); ok {
				out.(*big.Int).Set(defaultValue)
			} else {
				panic("out points to big.Int, but defaultValue does not")
			}
		default:
			panic("invalid integer type")
		}
		return true
	}
	if !i.ReadASN1Integer(out) || !i.Empty() {
		return false
	}
	return true
}

func (s *String) ReadOptionalASN1OctetString(out *[]byte, outPresent *bool, tag asn1.Tag) bool {
	var present bool
	var child String
	if !s.ReadOptionalASN1(&child, &present, tag) {
		return false
	}
	if outPresent != nil {
		*outPresent = present
	}
	if present {
		var oct String
		if !child.ReadASN1(&oct, asn1.OCTET_STRING) || !child.Empty() {
			return false
		}
		*out = oct
	} else {
		*out = nil
	}
	return true
}

func (s *String) ReadOptionalASN1Boolean(out *bool, tag asn1.Tag, defaultValue bool) bool {
	var present bool
	var child String
	if !s.ReadOptionalASN1(&child, &present, tag) {
		return false
	}

	if !present {
		*out = defaultValue
		return true
	}

	return child.ReadASN1Boolean(out)
}

func (s *String) readASN1(out *String, outTag *asn1.Tag, skipHeader bool) bool {
	if len(*s) < 2 {
		return false
	}
	tag, lenByte := (*s)[0], (*s)[1]

	if tag&0x1f == 0x1f {
		return false
	}

	if outTag != nil {
		*outTag = asn1.Tag(tag)
	}

	var length, headerLen uint32
	if lenByte&0x80 == 0 {
		length = uint32(lenByte) + 2
		headerLen = 2
	} else {
		lenLen := lenByte & 0x7f
		var len32 uint32

		if lenLen == 0 || lenLen > 4 || len(*s) < int(2+lenLen) {
			return false
		}

		lenBytes := String((*s)[2 : 2+lenLen])
		if !lenBytes.readUnsigned(&len32, int(lenLen)) {
			return false
		}

		if len32 < 128 {
			return false
		}
		if len32>>((lenLen-1)*8) == 0 {
			return false
		}

		headerLen = 2 + uint32(lenLen)
		if headerLen+len32 < len32 {
			return false
		}
		length = headerLen + len32
	}

	if int(length) < 0 || !s.ReadBytes((*[]byte)(out), int(length)) {
		return false
	}
	if skipHeader && !out.Skip(int(headerLen)) {
		panic("cryptobyte: internal error")
	}

	return true
}
