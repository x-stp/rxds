// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

func readTargets(r io.Reader, defaultPort uint16, emit func(ip netip.Addr, port uint16)) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip, port, ok := parseIPPort(line, defaultPort)
		if !ok {
			continue
		}
		emit(ip, port)
	}
	return sc.Err()
}

func parseIPPort(s string, defaultPort uint16) (netip.Addr, uint16, bool) {
	if strings.Count(s, ":") == 0 {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		return addr, defaultPort, true
	}
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	pp := parsePort(p, defaultPort)
	if pp == 0 {
		return netip.Addr{}, 0, false
	}
	return addr, pp, true
}

func readCIDRFile(ctx context.Context, path string, seed uint32, emit func(netip.Addr)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			expandCIDR(ctx, line, seed, emit)
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		emit(addr)
	}
	return sc.Err()
}

func expandCIDR(ctx context.Context, cidr string, seed uint32, emit func(netip.Addr)) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		log.Warn().Str("cidr", cidr).Err(err).Msg("skipping invalid CIDR")
		return
	}
	if !prefix.Addr().Is4() {
		log.Warn().Str("cidr", cidr).Msg("IPv6 CIDR expansion not supported, skipping")
		return
	}
	prefix = prefix.Masked()
	b4 := prefix.Addr().As4()
	base := binary.BigEndian.Uint32(b4[:])
	bits := prefix.Bits()
	if bits <= 0 || bits > 32 {
		return
	}
	size := uint32(1) << uint32(32-bits)
	for i := uint32(0); i < size; i++ {
		if i&0xffff == 0 && ctx.Err() != nil {
			return
		}
		j := permuteIndex(i, size, seed^base)
		v := base + j
		emit(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
	}
}

func parsePort(s string, def uint16) uint16 {
	if s == "" {
		return def
	}
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
		if n > 65535 {
			return 0
		}
	}
	if n == 0 {
		return 0
	}
	return uint16(n)
}

func isGlobalIP(addr netip.Addr) bool {
	return addr.IsValid() && addr.Unmap().IsGlobalUnicast()
}
