// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import "math/bits"

// permuteIndex maps i to a unique index in [0,size) via cycle-walking a Feistel
// permutation. The Feistel domain is the smallest 2^(2b) >= size, so cycle-walking
// averages well under two iterations regardless of size. Permuting over a fixed
// 2^32 domain (as before) needed ~2^32/size retries to land in range — millions
// per index for a /24 — which made small-CIDR scans crawl.
func permuteIndex(i, size, key uint32) uint32 {
	if size <= 1 {
		return 0
	}
	half := feistelHalfBits(size)
	x := feistel(i, key, half)
	for x >= size {
		x = feistel(x, key, half)
	}
	return x
}

// feistelHalfBits returns the per-half bit width b such that 2^(2b) is the
// smallest power of four >= size (b >= 1), keeping the cycle-walk domain within
// a factor of four of size.
func feistelHalfBits(size uint32) uint32 {
	total := uint32(bits.Len32(size - 1)) // ceil(log2(size)) for size >= 2
	half := (total + 1) / 2               // round up so 2*half >= total
	if half == 0 {
		half = 1
	}
	return half
}

// feistel applies a 4-round balanced Feistel permutation over a 2*half-bit
// domain. It is a bijection on [0, 2^(2*half)) for any round function.
func feistel(x, key, half uint32) uint32 {
	mask := uint32(1)<<half - 1
	l := (x >> half) & mask
	r := x & mask
	for round := range uint32(4) {
		f := feistelF(r, key+round*0x9e37) & mask
		l, r = r, l^f
	}
	return l<<half | r
}

func feistelF(x, k uint32) uint32 {
	v := x ^ k
	v ^= v >> 13
	v *= 0x85ebca6b
	v ^= v >> 16
	return v
}
