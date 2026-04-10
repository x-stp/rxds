// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/x-stp/rxds"
	"github.com/x-stp/rxds/tls"
)

func TestDialForCertLiveTarget(t *testing.T) {
	if os.Getenv("SCRYPTO_INTEGRATION") != "1" {
		t.Skip("set SCRYPTO_INTEGRATION=1 to run integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := "85.25.186.48:443"
	if v := os.Getenv("SCRYPTO_TARGET"); v != "" {
		target = v
	}
	sni := os.Getenv("SCRYPTO_SNI")

	// SNI matters; many servers will send a handshake failure without it (or
	// return an unrelated default certificate).
	// Provide `SCRYPTO_SNI=hostname` when targeting raw IPs.

	tryOnce := func(v2 bool) ([]*x509.Certificate, error) {
		cfg := &tls.Config{
			ServerName:         sni, // empty disables SNI
			CertsOnly:          true,
			InsecureSkipVerify: true,
			SSLv2ClientHello:   v2,
		}
		return rxds.DialForCert(ctx, "tcp", target, cfg)
	}

	// Try modern TLS framing first, then SSLv2-framed ClientHello.
	certs, err := tryOnce(false)
	if err != nil {
		certs, err = tryOnce(true)
		if err != nil {
			if sni == "" {
				t.Fatalf("DialForCert(%s): %v (try setting SCRYPTO_SNI=the_hostname_for_this_ip)", target, err)
			}
			t.Fatalf("DialForCert(%s, sni=%q): %v", target, sni, err)
		}
	}
	if len(certs) == 0 {
		t.Fatalf("no certificates returned")
	}

	t.Logf("got %d certs", len(certs))
	for i, c := range certs {
		t.Logf("cert[%d] Subject=%q Issuer=%q Serial=%s NotBefore=%s NotAfter=%s DNSNames=%q",
			i,
			c.Subject.String(),
			c.Issuer.String(),
			c.SerialNumber.String(),
			c.NotBefore.UTC().Format(time.RFC3339),
			c.NotAfter.UTC().Format(time.RFC3339),
			strings.Join(c.DNSNames, ","),
		)
		t.Logf("cert[%d] SHA256=%s", i, sha256Fingerprint(c))
	}
}

// sha256Fingerprint returns sha256 of DER bytes.
func sha256Fingerprint(c *x509.Certificate) string {
	return hex.EncodeToString(c.Raw)
}
