// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/x-stp/rxds/internal/cpu"
	"golang.org/x/crypto/chacha20poly1305"
)

// PreHeatCPU warms up CPU crypto units by performing a small round of
// AES-GCM (when AES-NI is present) and/or ChaCha20-Poly1305 (always,
// as the fast-path on non-AES-NI hardware). This reduces latency on
// the first few handshakes in a scan.
func PreHeatCPU() {
	data := make([]byte, 256)
	if _, err := rand.Read(data); err != nil {
		return
	}

	if cpu.X86.HasAES || cpu.ARM64.HasAES {
		preheatAESGCM(data)
	}

	preheatChaCha20(data)
}

func preheatAESGCM(data []byte) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	sealed := gcm.Seal(nil, nonce, data, nil)
	_, _ = gcm.Open(nil, nonce, sealed, nil)
}

func preheatChaCha20(data []byte) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	sealed := c.Seal(nil, nonce, data, nil)
	_, _ = c.Open(nil, nonce, sealed, nil)
}
