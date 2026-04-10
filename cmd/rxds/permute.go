// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

func permuteIndex(i, size, key uint32) uint32 {
	if size == 0 {
		return 0
	}
	x := feistel32(i, key)
	for x >= size {
		x = feistel32(x, key)
	}
	return x
}

func feistel32(x, key uint32) uint32 {
	l := uint16(x >> 16)
	r := uint16(x)
	for round := range uint32(4) {
		f := feistelF(r, key+round*0x9e37)
		l, r = r, l^f
	}
	return uint32(l)<<16 | uint32(r)
}

func feistelF(x uint16, k uint32) uint16 {
	v := uint32(x) ^ k
	v ^= v >> 13
	v *= 0x85ebca6b
	v ^= v >> 16
	return uint16(v)
}
