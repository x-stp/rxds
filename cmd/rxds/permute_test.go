package main

import "testing"

func TestPermuteIndexSingleSizeTerminates(t *testing.T) {
	// size 1 (a /32 or single IP) previously could spin forever.
	for key := uint32(0); key < 1000; key++ {
		if got := permuteIndex(0, 1, key); got != 0 {
			t.Fatalf("permuteIndex(0,1,%d) = %d, want 0", key, got)
		}
	}
}

func TestPermuteIndexIsBijection(t *testing.T) {
	for _, size := range []uint32{1, 2, 3, 7, 16, 17, 255, 256, 1000} {
		seen := make([]bool, size)
		for i := uint32(0); i < size; i++ {
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
