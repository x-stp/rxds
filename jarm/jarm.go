// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp
//
// JARM TLS server fingerprinting.
// Protocol: https://github.com/salesforce/jarm (Salesforce, 2020)
// Ported from hdm/jarm-go (BSD-2-Clause, archived).

package jarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	jarmReadSize = 1484
	probeCount   = 10
	rawEmpty     = "|||"
	zeroHash     = "00000000000000000000000000000000000000000000000000000000000000"
)

// Fingerprint runs all 10 JARM probes against host:port and returns the
// 62-character fingerprint hash. A target that refuses every probe returns
// 62 zeroes.
func Fingerprint(ctx context.Context, host string, port uint16, timeout time.Duration) (string, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	probes := Probes(host)

	raw := make([]string, probeCount)
	for i, p := range probes {
		r, err := sendProbe(ctx, addr, p, timeout)
		if err != nil {
			raw[i] = rawEmpty
			continue
		}
		raw[i] = r
	}
	return HashRaw(raw), nil
}

func sendProbe(ctx context.Context, addr string, probe []byte, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(probe); err != nil {
		return "", err
	}

	buf := make([]byte, jarmReadSize)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	buf = buf[:n]

	if buf[0] == 21 {
		return rawEmpty, nil
	}

	return parseServerHello(buf), nil
}

// parseServerHello extracts cipher|version|alpn|extensions from a raw
// ServerHello response. Matches the reference jarm.py read_packet + extract_extension_info.
func parseServerHello(data []byte) string {
	if len(data) < 6 || data[0] != 22 || data[5] != 2 {
		return rawEmpty
	}

	if len(data) < 11 {
		return rawEmpty
	}
	serverHelloLen := int(data[3])<<8 | int(data[4])
	serverVersion := fmt.Sprintf("%02x%02x", data[9], data[10])

	if len(data) < 44 {
		return rawEmpty
	}
	counter := int(data[43]) // session ID length

	cipherOffset := counter + 44
	if len(data) < cipherOffset+2 {
		return rawEmpty
	}
	selectedCipher := fmt.Sprintf("%02x%02x", data[cipherOffset], data[cipherOffset+1])

	// Reference: counter+47 is the start of extensions length
	if counter+42 >= serverHelloLen {
		return selectedCipher + "|" + serverVersion + "|"
	}

	// Reference edge-case guards from extract_extension_info
	if len(data) > counter+47 && data[counter+47] == 11 {
		return selectedCipher + "|" + serverVersion + "|"
	}
	if len(data) > counter+52 {
		if data[counter+50] == 0x0e && data[counter+51] == 0xac && data[counter+52] == 0x0b {
			return selectedCipher + "|" + serverVersion + "|"
		}
	}
	if len(data) > 84 {
		if data[82] == 0x0f && data[83] == 0xf0 && data[84] == 0x0b {
			return selectedCipher + "|" + serverVersion + "|"
		}
	}

	extLenOffset := counter + 47
	if len(data) < extLenOffset+2 {
		return selectedCipher + "|" + serverVersion + "|"
	}
	extTotalLen := int(data[extLenOffset])<<8 | int(data[extLenOffset+1])

	pos := counter + 49
	maximum := pos + extTotalLen - 1

	var types []string
	var values [][]byte

	for pos < maximum && pos+4 <= len(data) {
		extType := fmt.Sprintf("%02x%02x", data[pos], data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		if extLen == 0 {
			types = append(types, extType)
			values = append(values, nil)
			pos += 4
		} else {
			end := pos + 4 + extLen
			if end > len(data) {
				break
			}
			types = append(types, extType)
			values = append(values, data[pos+4:end])
			pos = end
		}
	}

	var alpn string
	for i, t := range types {
		if t == "0010" && values[i] != nil && len(values[i]) >= 3 {
			alpn = string(values[i][3:])
			break
		}
	}

	result := alpn + "|" + strings.Join(types, "-")
	return selectedCipher + "|" + serverVersion + "|" + result
}

// HashRaw computes the 62-character JARM fingerprint from 10 raw probe results.
// First 30 chars: 3 per probe (2-char cipher index + 1-char version code).
// Last 32 chars: truncated SHA-256 of concatenated ALPN+extensions.
func HashRaw(rawResults []string) string {
	if len(rawResults) != probeCount {
		return zeroHash
	}

	var fuzzy strings.Builder
	var hashInput strings.Builder

	allEmpty := true
	for _, r := range rawResults {
		parts := strings.SplitN(r, "|", 4)
		if len(parts) != 4 {
			fuzzy.WriteString("000")
			continue
		}

		cipher, version, alpnStr, extensions := parts[0], parts[1], parts[2], parts[3]

		if cipher == "" && version == "" {
			fuzzy.WriteString("000")
		} else {
			allEmpty = false
			fuzzy.WriteString(cipherBytes(cipher))
			fuzzy.WriteByte(versionByte(version))
		}

		hashInput.WriteString(alpnStr)
		hashInput.WriteString(extensions)
	}

	if allEmpty {
		return zeroHash
	}

	sum := sha256.Sum256([]byte(hashInput.String()))
	return fuzzy.String() + hex.EncodeToString(sum[:])[:32]
}

// canonicalCipherList matches the cipher_bytes table in the reference jarm.py.
// 69 entries, TLS 1.3 suites at the end (positions 65-69).
var canonicalCipherList = []string{
	"0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035",
	"0039", "003c", "003d", "0041", "0045", "0067", "006b", "0084",
	"0088", "009a", "009c", "009d", "009e", "009f", "00ba", "00be",
	"00c0", "00c4",
	"c007", "c008", "c009", "c00a", "c011", "c012", "c013", "c014",
	"c023", "c024", "c027", "c028", "c02b", "c02c", "c02f", "c030",
	"c060", "c061", "c072", "c073", "c076", "c077", "c09c", "c09d",
	"c09e", "c09f", "c0a0", "c0a1", "c0a2", "c0a3", "c0ac", "c0ad",
	"c0ae", "c0af",
	"cc13", "cc14", "cca8", "cca9",
	"1301", "1302", "1303", "1304", "1305",
}

func cipherBytes(h string) string {
	h = strings.ToLower(h)
	for i, c := range canonicalCipherList {
		if c == h {
			return fmt.Sprintf("%02x", i+1)
		}
	}
	return "00"
}

func versionByte(ver string) byte {
	if ver == "" {
		return '0'
	}
	// Reference: options = "abcdef"; byte = options[int(version[3:4])]
	// 0x0300 -> [3:4] = "0" -> 'a'; 0x0301 -> "1" -> 'b'; etc.
	if len(ver) == 4 {
		d := ver[3] - '0'
		if d <= 5 {
			return "abcdef"[d]
		}
	}
	return '0'
}
