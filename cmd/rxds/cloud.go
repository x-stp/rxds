// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func emitCloudSamples(
	ctx context.Context,
	sources []string,
	n int,
	seed uint32,
	port uint16,
	emit func(ip netip.Addr, p uint16),
) error {
	var prefixes []netip.Prefix
	for _, s := range sources {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		switch s {
		case "cf", "cloudflare":
			ps, err := fetchCloudflareIPv4Prefixes(ctx)
			if err != nil {
				return err
			}
			prefixes = append(prefixes, ps...)
		default:
			return fmt.Errorf("unsupported cloud source: %s", s)
		}
	}
	if len(prefixes) == 0 || n <= 0 {
		return nil
	}

	type wp struct {
		prefix netip.Prefix
		weight uint32
	}
	weighted := make([]wp, 0, len(prefixes))
	var total uint64
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		bits := p.Bits()
		if bits < 0 || bits > 32 {
			continue
		}
		w := uint32(1) << uint32(32-bits)
		weighted = append(weighted, wp{prefix: p, weight: w})
		total += uint64(w)
	}
	if total == 0 {
		return nil
	}

	rng := rand.New(rand.NewSource(int64(seed)))
	for i := 0; i < n; i++ {
		r := uint64(rng.Uint32()) % total
		var chosen netip.Prefix
		for _, w := range weighted {
			if r < uint64(w.weight) {
				chosen = w.prefix
				break
			}
			r -= uint64(w.weight)
		}
		if !chosen.IsValid() {
			continue
		}
		base := binary.BigEndian.Uint32(chosen.Addr().AsSlice())
		span := uint32(1) << uint32(32-chosen.Bits())
		off := rng.Uint32() % span
		v := base + off
		emit(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), port)
	}
	return nil
}

const cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"

func fetchCloudflareIPv4Prefixes(ctx context.Context) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareIPv4URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", cloudflareIPv4URL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(body), "\n")
	out := make([]netip.Prefix, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
