// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x-stp/rxds"
	"github.com/x-stp/rxds/tls"
)

// These are intentionally opt-in: leak tests can be slow/flaky on shared CI.
// Run with:
//
//	SCRYPTO_LEAK=1 go test -run TestLeak -count=1 -v
//
// If you want a heap profile file:
//
//	SCRYPTO_LEAK=1 SCRYPTO_HEAP_PROFILE=heap.out go test -run TestLeak -count=1 -v
func TestLeak(t *testing.T) {
	if os.Getenv("SCRYPTO_LEAK") != "1" {
		t.Skip("set SCRYPTO_LEAK=1 to run leak checks")
	}

	// Soak parameters.
	// Defaults are intentionally "hard": 25 minutes at 64-way parallelism.
	seconds := envInt("SCRYPTO_LEAK_SECONDS", 25*60)
	par := envInt("SCRYPTO_LEAK_PAR", 64)
	intervalSeconds := envInt("SCRYPTO_LEAK_INTERVAL_SECONDS", 10)
	maxInuseGrowthBytes := envInt64("SCRYPTO_LEAK_MAX_INUSE_GROWTH_BYTES", 64<<20) // 64 MiB
	maxGoroutineGrowth := envInt("SCRYPTO_LEAK_MAX_GOROUTINE_GROWTH", 50)
	transport := os.Getenv("SCRYPTO_LEAK_TRANSPORT")
	if transport == "" {
		transport = "pipe" // default avoids TIME_WAIT/ephemeral port exhaustion
	}

	if seconds < 1 {
		t.Fatalf("SCRYPTO_LEAK_SECONDS must be >= 1")
	}
	if par < 1 {
		t.Fatalf("SCRYPTO_LEAK_PAR must be >= 1")
	}
	if intervalSeconds < 1 {
		t.Fatalf("SCRYPTO_LEAK_INTERVAL_SECONDS must be >= 1")
	}

	var (
		addr12, addr13 string
		stop12, stop13 func()
	)
	if transport == "tcp" {
		addr12, stop12 = startTLSServer(t, 0x0303 /*TLS1.2*/, 0x0303 /*TLS1.2*/)
		defer stop12()
		addr13, stop13 = startTLSServer(t, 0x0304 /*TLS1.3*/, 0x0304 /*TLS1.3*/)
		defer stop13()
	}
	serverCert := generateSelfSignedCertLeak(t)

	cfg := &tls.Config{
		ServerName:         "localhost",
		CertsOnly:          true,
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warmup to populate sync.Pools and runtime caches.
	for i := 0; i < 50; i++ {
		_ = soakOnce(ctx, transport, addr12, 0x0303, cfg, serverCert)
		_ = soakOnce(ctx, transport, addr13, 0x0304, cfg, serverCert)
	}

	// Force GC and release OS memory before baseline.
	runtime.GC()
	debug.FreeOSMemory()

	baseG := runtime.NumGoroutine()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	t.Logf("baseline: goroutines=%d heap_alloc=%d heap_inuse=%d heap_objects=%d",
		baseG, base.HeapAlloc, base.HeapInuse, base.HeapObjects)

	t.Logf("soak: seconds=%d par=%d interval=%ds max_inuse_growth=%dB max_goroutine_growth=%d",
		seconds, par, intervalSeconds, maxInuseGrowthBytes, maxGoroutineGrowth)
	t.Logf("soak transport=%s (use SCRYPTO_LEAK_TRANSPORT=tcp to include OS/network effects)", transport)

	soakCtx, soakCancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer soakCancel()

	var ops uint64
	var errs uint64
	errCh := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(par)
	for w := 0; w < par; w++ {
		go func(worker int) {
			defer wg.Done()
			for {
				select {
				case <-soakCtx.Done():
					return
				default:
				}
				// Alternate TLS12/TLS13 to hit both paths.
				if err := soakOnce(soakCtx, transport, addr12, 0x0303, cfg, serverCert); err != nil {
					atomic.AddUint64(&errs, 1)
					select {
					case errCh <- fmt.Errorf("worker=%d soakOnce(TLS12): %w", worker, err):
					default:
					}
					return
				}
				atomic.AddUint64(&ops, 1)
				if err := soakOnce(soakCtx, transport, addr13, 0x0304, cfg, serverCert); err != nil {
					atomic.AddUint64(&errs, 1)
					select {
					case errCh <- fmt.Errorf("worker=%d soakOnce(TLS13): %w", worker, err):
					default:
					}
					return
				}
				atomic.AddUint64(&ops, 1)
			}
		}(w)
	}

	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	maxG := baseG
	maxInuse := base.HeapInuse
	maxObjs := base.HeapObjects

sampleLoop:
	for {
		select {
		case err := <-errCh:
			t.Fatalf("soak failed: %v", err)
		case <-soakCtx.Done():
			break sampleLoop
		case <-ticker.C:
			runtime.GC()
			debug.FreeOSMemory()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			g := runtime.NumGoroutine()
			if g > maxG {
				maxG = g
			}
			if ms.HeapInuse > maxInuse {
				maxInuse = ms.HeapInuse
			}
			if ms.HeapObjects > maxObjs {
				maxObjs = ms.HeapObjects
			}
			t.Logf("tick ops=%d errs=%d goroutines=%d heap_inuse=%d heap_objects=%d",
				atomic.LoadUint64(&ops), atomic.LoadUint64(&errs), g, ms.HeapInuse, ms.HeapObjects)
		}
	}

	soakCancel()
	wg.Wait()

	// Force GC and release OS memory before measuring.
	runtime.GC()
	debug.FreeOSMemory()

	afterG := runtime.NumGoroutine()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	t.Logf("after: goroutines=%d heap_alloc=%d heap_inuse=%d heap_objects=%d",
		afterG, after.HeapAlloc, after.HeapInuse, after.HeapObjects)
	t.Logf("max: goroutines=%d heap_inuse=%d heap_objects=%d ops=%d errs=%d",
		maxG, maxInuse, maxObjs, atomic.LoadUint64(&ops), atomic.LoadUint64(&errs))

	// Goroutine leak check: allow a little slack for testing runtime.
	if afterG > baseG+maxGoroutineGrowth {
		t.Fatalf("goroutine leak suspected: baseline=%d after=%d (growth=%d > %d)",
			baseG, afterG, afterG-baseG, maxGoroutineGrowth)
	}

	// Heap leak check: inuse should not grow without bound. Allow slack for
	// fragmentation and caches. This is a smoke test, not a proof.
	if int64(after.HeapInuse-base.HeapInuse) > maxInuseGrowthBytes {
		t.Fatalf("heap leak suspected: baseline_inuse=%d after_inuse=%d (growth=%d > %d)",
			base.HeapInuse, after.HeapInuse, after.HeapInuse-base.HeapInuse, maxInuseGrowthBytes)
	}

	// Optional: write a heap profile after load.
	if path := os.Getenv("SCRYPTO_HEAP_PROFILE"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create heap profile: %v", err)
		}
		defer f.Close()
		if err := pprof.WriteHeapProfile(f); err != nil {
			t.Fatalf("write heap profile: %v", err)
		}
		t.Logf("wrote heap profile: %s", path)
	}
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func soakOnce(ctx context.Context, transport, addr string, vers uint16, cfg *tls.Config, serverCert stdtls.Certificate) error {
	switch transport {
	case "tcp":
		certs, err := rxds.DialForCert(ctx, "tcp", addr, cfg)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return errors.New("no certs returned")
		}
		return nil
	case "pipe":
		// net.Pipe avoids TIME_WAIT/ephemeral port exhaustion and is ideal for leak soaks.
		clientNet, serverNet := net.Pipe()

		_ = clientNet.SetDeadline(time.Now().Add(2 * time.Second))
		_ = serverNet.SetDeadline(time.Now().Add(2 * time.Second))

		go func() {
			defer serverNet.Close()
			srv := stdtls.Server(serverNet, &stdtls.Config{
				Certificates: []stdtls.Certificate{serverCert},
				MinVersion:   vers,
				MaxVersion:   vers,
			})
			_ = srv.Handshake() // client will stop early; ignore server error
			_ = srv.Close()
		}()

		c := tls.Client(clientNet, cfg)
		err := c.Handshake()
		_ = clientNet.Close()
		if err != nil && !errors.Is(err, tls.ErrExpected) {
			return err
		}
		if len(c.ConnectionState().PeerCertificates) == 0 {
			return errors.New("no certs returned")
		}
		return nil
	default:
		return fmt.Errorf("unknown transport: %q", transport)
	}
}

func generateSelfSignedCertLeak(tb testing.TB) stdtls.Certificate {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("rand.Int: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("CreateCertificate: %v", err)
	}

	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}
