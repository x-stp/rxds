// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package jarm

import (
	"crypto/rand"
	"encoding/binary"
)

type cipherOrder int

const (
	orderForward cipherOrder = iota
	orderReverse
	orderTopHalf
	orderBottomHalf
	orderMiddleOut
)

type alpnMode int

const (
	alpnStandard alpnMode = iota
	alpnRare
	alpnNone
)

type versionMode int

const (
	verNone versionMode = iota
	ver12Support
	ver13Support
)

type probeSpec struct {
	recordVersion uint16
	helloVersion  uint16
	order         cipherOrder
	grease        bool
	alpn          alpnMode
	versions      versionMode
	noTLS13Suites bool
}

// probeSpecs matches the queue array from reference jarm.py(salesforce, main().)
var probeSpecs = [probeCount]probeSpec{
	{0x0303, 0x0303, orderForward, false, alpnStandard, ver12Support, false},  // tls1_2_forward
	{0x0303, 0x0303, orderReverse, false, alpnStandard, ver12Support, false},  // tls1_2_reverse
	{0x0303, 0x0303, orderTopHalf, false, alpnStandard, verNone, false},       // tls1_2_top_half
	{0x0303, 0x0303, orderBottomHalf, false, alpnRare, verNone, false},        // tls1_2_bottom_half
	{0x0303, 0x0303, orderMiddleOut, true, alpnRare, verNone, false},          // tls1_2_middle_out
	{0x0302, 0x0302, orderForward, false, alpnStandard, verNone, false},       // tls1_1_middle_out (actually TLS 1.1 forward)
	{0x0301, 0x0303, orderForward, false, alpnStandard, ver13Support, false},  // tls1_3_forward
	{0x0301, 0x0303, orderReverse, false, alpnStandard, ver13Support, false},  // tls1_3_reverse
	{0x0301, 0x0303, orderForward, false, alpnStandard, ver13Support, true},   // tls1_3_invalid
	{0x0301, 0x0303, orderMiddleOut, true, alpnStandard, ver13Support, false}, // tls1_3_middle_out
}

// Probes returns the 10 raw ClientHello packets for the given hostname.
func Probes(host string) [probeCount][]byte {
	var out [probeCount][]byte
	for i, spec := range probeSpecs {
		out[i] = buildProbe(spec, host)
	}
	return out
}

// allCiphers matches the "ALL" cipher list from reference jarm.py get_ciphers.
var allCiphers = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b,
	0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
	0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
	0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301,
	0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028,
	0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
	0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0,
	0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba,
	0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
}

var tls13Ciphers = map[uint16]bool{
	0x1301: true, 0x1302: true, 0x1303: true, 0x1304: true, 0x1305: true,
}

func reorderCiphers(ciphers []uint16, order cipherOrder) []uint16 {
	out := make([]uint16, len(ciphers))
	copy(out, ciphers)
	switch order {
	case orderReverse:
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	case orderTopHalf:
		mid := len(out) / 2
		top := make([]uint16, len(out)-mid)
		copy(top, out[mid:])
		for i, j := 0, len(top)-1; i < j; i, j = i+1, j-1 {
			top[i], top[j] = top[j], top[i]
		}
		result := make([]uint16, 0, len(out))
		result = append(result, out[mid])
		result = append(result, top...)
		out = result
	case orderBottomHalf:
		mid := len(out) / 2
		out = out[mid:]
	case orderMiddleOut:
		result := make([]uint16, 0, len(out))
		mid := len(out) / 2
		result = append(result, out[mid])
		for i := 1; i <= mid; i++ {
			if mid+i < len(out) {
				result = append(result, out[mid+i])
			}
			if mid-i >= 0 {
				result = append(result, out[mid-i])
			}
		}
		out = result
	}
	return out
}

func buildProbe(spec probeSpec, host string) []byte {
	ciphers := make([]uint16, 0, len(allCiphers))
	for _, c := range allCiphers {
		if spec.noTLS13Suites && tls13Ciphers[c] {
			continue
		}
		ciphers = append(ciphers, c)
	}
	ciphers = reorderCiphers(ciphers, spec.order)

	var random [32]byte
	rand.Read(random[:])
	var sessionID [32]byte
	rand.Read(sessionID[:])

	var greaseVal uint16
	if spec.grease {
		var g [2]byte
		rand.Read(g[:])
		greaseVal = (uint16(g[0]&0x0f) << 8) | 0x0a0a
		ciphers = append([]uint16{greaseVal}, ciphers...)
	}

	// Build extensions
	var exts []byte
	if spec.grease {
		exts = appendExtension(exts, greaseVal, nil)
	}
	exts = appendSNI(exts, host)
	exts = appendExtension(exts, 0x0017, nil) // extended master secret
	exts = appendExtension(exts, 0x0001, []byte{0x01})
	exts = appendExtension(exts, 0xff01, []byte{0x00}) // renegotiation info

	// Supported groups: x25519, P-256, P-384, P-521
	groups := []uint16{0x001d, 0x0017, 0x0018, 0x0019}
	if spec.grease {
		groups = append([]uint16{greaseVal}, groups...)
	}
	exts = appendSupportedGroups(exts, groups)
	exts = appendExtension(exts, 0x000b, []byte{0x01, 0x00}) // EC point formats
	exts = appendExtension(exts, 0x0023, nil)                // session ticket

	if spec.alpn != alpnNone {
		exts = appendALPN(exts, spec.alpn)
	}

	// Signature algorithms
	sigAlgs := []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
		0x0806, 0x0601, 0x0201,
	}
	exts = appendSigAlgs(exts, sigAlgs)

	// Key share (x25519 with random public key)
	var keyShareData []byte
	ksPub := make([]byte, 32)
	rand.Read(ksPub)
	ks := appendUint16(nil, 0x001d) // x25519
	ks = appendUint16(ks, uint16(len(ksPub)))
	ks = append(ks, ksPub...)
	if spec.grease {
		gks := appendUint16(nil, greaseVal)
		gks = appendUint16(gks, 1)
		gks = append(gks, 0x00)
		ks = append(gks, ks...)
	}
	keyShareData = appendUint16(nil, uint16(len(ks)))
	keyShareData = append(keyShareData, ks...)
	exts = appendExtension(exts, 0x0033, keyShareData)

	exts = appendExtension(exts, 0x002d, []byte{0x01, 0x01}) // PSK key exchange modes

	if spec.versions != verNone {
		exts = appendSupportedVersions(exts, spec.versions, spec.grease, greaseVal)
	}

	// ClientHello body
	var hello []byte
	hello = appendUint16(hello, spec.helloVersion)
	hello = append(hello, random[:]...)
	hello = append(hello, byte(len(sessionID)))
	hello = append(hello, sessionID[:]...)

	hello = appendUint16(hello, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		hello = appendUint16(hello, c)
	}
	hello = append(hello, 0x01, 0x00) // compression methods: null

	hello = appendUint16(hello, uint16(len(exts)))
	hello = append(hello, exts...)

	// Handshake header (type 0x01 = ClientHello)
	var hs []byte
	hs = append(hs, 0x01)
	hs = appendUint24(hs, uint32(len(hello)))
	hs = append(hs, hello...)

	// TLS record header
	var record []byte
	record = append(record, 0x16) // handshake
	record = appendUint16(record, spec.recordVersion)
	record = appendUint16(record, uint16(len(hs)))
	record = append(record, hs...)

	return record
}

func appendSNI(exts []byte, host string) []byte {
	hostBytes := []byte(host)
	// SNI list: type(1) + length(2) + hostname
	entry := []byte{0x00} // host_name type
	entry = appendUint16(entry, uint16(len(hostBytes)))
	entry = append(entry, hostBytes...)
	data := appendUint16(nil, uint16(len(entry)))
	data = append(data, entry...)
	return appendExtension(exts, 0x0000, data)
}

func appendSupportedGroups(exts []byte, groups []uint16) []byte {
	data := appendUint16(nil, uint16(len(groups)*2))
	for _, g := range groups {
		data = appendUint16(data, g)
	}
	return appendExtension(exts, 0x000a, data)
}

func appendALPN(exts []byte, mode alpnMode) []byte {
	var protocols []string
	switch mode {
	case alpnStandard:
		protocols = []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq"}
	case alpnRare:
		protocols = []string{"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"}
	}
	var list []byte
	for _, p := range protocols {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	data := appendUint16(nil, uint16(len(list)))
	data = append(data, list...)
	return appendExtension(exts, 0x0010, data)
}

func appendSigAlgs(exts []byte, algs []uint16) []byte {
	data := appendUint16(nil, uint16(len(algs)*2))
	for _, a := range algs {
		data = appendUint16(data, a)
	}
	return appendExtension(exts, 0x000d, data)
}

func appendSupportedVersions(exts []byte, mode versionMode, grease bool, greaseVal uint16) []byte {
	var versions []uint16
	if grease {
		versions = append(versions, greaseVal)
	}
	switch mode {
	case ver12Support:
		versions = append(versions, 0x0303, 0x0302, 0x0301)
	case ver13Support:
		versions = append(versions, 0x0304, 0x0303, 0x0302, 0x0301)
	}
	data := []byte{byte(len(versions) * 2)}
	for _, v := range versions {
		data = appendUint16(data, v)
	}
	return appendExtension(exts, 0x002b, data)
}

func appendExtension(exts []byte, extType uint16, data []byte) []byte {
	exts = appendUint16(exts, extType)
	exts = appendUint16(exts, uint16(len(data)))
	return append(exts, data...)
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint24(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[1], buf[2], buf[3])
}
