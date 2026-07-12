package main

import "testing"

func TestPermuteIndexSingleSizeTerminates(t *testing.T) {
	// size 1 (a /32 or single IP) previously could spin forever.
	for key := range uint32(1000) {
		if got := permuteIndex(0, 1, key); got != 0 {
			t.Fatalf("permuteIndex(0,1,%d) = %d, want 0", key, got)
		}
	}
}

func TestPermuteIndexIsBijection(t *testing.T) {
	// Sizes straddle power-of-four boundaries (e.g. 17, 257, 4097, 65537) so the
	// cycle-walk domain exceeds size and the walk actually iterates.
	sizes := []uint32{1, 2, 3, 7, 16, 17, 255, 256, 257, 1000, 4095, 4096, 4097, 65535, 65536, 65537, 100000}
	for _, size := range sizes {
		seen := make([]bool, size)
		for i := range size {
			idx := permuteIndex(i, size, 0x9e3779b1)
			if idx >= size {
				t.Fatalf("permuteIndex(%d,%d) = %d out of range", i, size, idx)
			}
			if seen[idx] {
				t.Fatalf("permuteIndex produced duplicate %d for size %d", idx, size)
			}
			seen[idx] = true
		}
	}
}
