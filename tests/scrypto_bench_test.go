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
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/x-stp/rxds"
	"github.com/x-stp/rxds/tls"
)

func generateSelfSignedCert(tb testing.TB) stdtls.Certificate {
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

func startTLSServer(tb testing.TB, min, max uint16) (addr string, stop func()) {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}

	cert := generateSelfSignedCert(tb)
	tlsLn := stdtls.NewListener(ln, &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   min,
		MaxVersion:   max,
		NextProtos:   []string{"h2", "http/1.1"},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				tc, _ := c.(*stdtls.Conn)
				if tc != nil {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(c)
		}
	}()

	return tlsLn.Addr().String(), func() {
		_ = tlsLn.Close()
		<-done
	}
}

func BenchmarkDialForCert_TLS12(b *testing.B) {
	addr, stop := startTLSServer(b, stdtls.VersionTLS12, stdtls.VersionTLS12)
	defer stop()

	cfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		CertsOnly:          true,
	}

	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		certs, err := rxds.DialForCert(ctx, "tcp", addr, cfg)
		if err != nil {
			b.Fatalf("DialForCert: %v", err)
		}
		if len(certs) == 0 {
			b.Fatalf("no certs returned")
		}
	}
}

func BenchmarkDialForCert_TLS13(b *testing.B) {
	addr, stop := startTLSServer(b, stdtls.VersionTLS13, stdtls.VersionTLS13)
	defer stop()

	cfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		CertsOnly:          true,
	}

	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		certs, err := rxds.DialForCert(ctx, "tcp", addr, cfg)
		if err != nil {
			b.Fatalf("DialForCert: %v", err)
		}
		if len(certs) == 0 {
			b.Fatalf("no certs returned")
		}
	}
}
