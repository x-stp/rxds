// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

type denylist struct {
	prefixes []netip.Prefix
}

func loadDenylist(path string) (*denylist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var prefixes []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			p, err := netip.ParsePrefix(line)
			if err != nil {
				continue
			}
			prefixes = append(prefixes, p.Masked())
		} else {
			addr, err := netip.ParseAddr(line)
			if err != nil {
				continue
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return &denylist{prefixes: prefixes}, nil
}

func (d *denylist) Contains(addr netip.Addr) bool {
	if d == nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range d.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (d *denylist) Len() int {
	if d == nil {
		return 0
	}
	return len(d.prefixes)
}
