// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/x-stp/rxds/tls"
)

// This is a local-only unit test that validates we can parse an SSLv2 ServerHello
// and extract the embedded X.509 certificate. It does not implement SSLv2 ciphers.
func TestSSLv2ServerHelloCertHarvest(t *testing.T) {
	clientNet, serverNet := netPipe(t)
	defer clientNet.Close()
	defer serverNet.Close()

	cert := generateSelfSignedCert(t) // from scrypto_bench_test.go (same package)
	if len(cert.Certificate) == 0 {
		t.Fatalf("missing cert DER")
	}
	certDER := cert.Certificate[0]

	// Fake SSLv2 server: read some bytes (client hello), then send SSLv2 ServerHello with cert.
	go func() {
		defer serverNet.Close()
		_ = serverNet.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		_, _ = serverNet.Read(buf)

		// Build SSLv2 ServerHello:
		// header(2) + msg_type(1)=4 + session_id_hit(1) + cert_type(1)=1 + version(2)=0x0300 +
		// cert_len(2) + cipher_specs_len(2)=0 + conn_id_len(2)=0 + cert
		bodyLen := 1 + 1 + 1 + 2 + 2 + 2 + 2 + len(certDER)
		rec := make([]byte, 2+bodyLen)
		rec[0] = 0x80 | byte(bodyLen>>8)
		rec[1] = byte(bodyLen)
		rec[2] = 4 // SERVER_HELLO
		rec[3] = 0 // session_id_hit
		rec[4] = 1 // X.509
		rec[5] = 0x03
		rec[6] = 0x00 // SSLv3
		rec[7] = byte(len(certDER) >> 8)
		rec[8] = byte(len(certDER))
		// cipher_specs_len
		rec[9] = 0
		rec[10] = 0
		// connection_id_len
		rec[11] = 0
		rec[12] = 0
		copy(rec[13:], certDER)
		_, _ = serverNet.Write(rec)
	}()

	cfg := &tls.Config{
		CertsOnly:          true,
		InsecureSkipVerify: true,
		SSLv2ClientHello:   true,
		ServerName:         "localhost",
	}

	c := tls.Client(clientNet, cfg)
	err := c.Handshake()
	if err != nil && !errors.Is(err, tls.ErrExpected) {
		t.Fatalf("handshake: %v", err)
	}
	cs := c.ConnectionState()
	if len(cs.PeerCertificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(cs.PeerCertificates))
	}
	if cs.PeerCertificates[0] == nil || len(cs.PeerCertificates[0].Raw) == 0 {
		t.Fatalf("empty parsed cert")
	}

	// Sanity: parsed cert DER matches what server sent.
	if string(cs.PeerCertificates[0].Raw) != string(certDER) {
		t.Fatalf("parsed cert does not match sent cert")
	}
}

func netPipe(tb testing.TB) (c1, c2 net.Conn) {
	tb.Helper()
	c1, c2 = net.Pipe()
	_ = c1.SetDeadline(time.Now().Add(2 * time.Second))
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	return
}
