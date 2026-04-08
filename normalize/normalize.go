// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package normalize

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	"golang.org/x/net/idna"
)

// NormalizedCert holds normalized certificate data ready for indexing.
//
// The normalization rules are:
//   - CN is deduplicated against SANs for hashing stability.
//   - Names without a valid PSL eTLD+1 (bare TLDs, .onion, localhost) are dropped.
//   - Root domains use CN-first insertion order; SAN order follows the cert's ASN.1 SEQUENCE.
//   - FuzzyHash is order-independent over the unique DNS domain set.
//   - May add jarm and such. Not a normalize task; just 2d fingerprintin'.
type NormalizedCert struct {
	FuzzyHash   string   `json:"fuzzy_hash"`
	CN          string   `json:"cn"`
	SANs        []string `json:"sans"`
	Org         string   `json:"org"`
	ApexDomain  string   `json:"apex_domain"`
	RootDomains []string `json:"root_domains"`
}

var profile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false), // cert SANs sometimes contain underscores :shrug:
)

// NormalizeCert normalizes a certificate's identity fields. It never returns an error;
// unusable names are silently dropped.
func NormalizeCert(cert *x509.Certificate) NormalizedCert {
	if cert == nil {
		return empty()
	}

	out := empty()

	if len(cert.Subject.Organization) > 0 {
		out.Org = strings.TrimSpace(cert.Subject.Organization[0])
	}

	out.CN, _ = normalizeAndValidate(cert.Subject.CommonName)

	// Collect unique DNS names (CN first) and IP SANs separately.
	// dns feeds into root-domain extraction and fuzzy hashing; IPs only appear in SANs.
	seen := make(map[string]struct{}, 1+len(cert.DNSNames)+len(cert.IPAddresses))
	var dns []string

	add := func(name string) {
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		dns = append(dns, name)
		out.SANs = append(out.SANs, name)
	}

	// Seed CN into the dedup set so a duplicate SAN entry won't produce a double hash,
	// but don't add it to SANs (it lives in its own field).
	if out.CN != "" {
		seen[out.CN] = struct{}{}
		dns = append(dns, out.CN)
	}

	for _, d := range cert.DNSNames {
		if n, ok := normalizeAndValidate(d); ok {
			add(n)
		}
	}

	for _, ip := range cert.IPAddresses {
		if ip == nil {
			continue
		}
		s := ip.String()
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out.SANs = append(out.SANs, s)
		}
	}

	slices.Sort(out.SANs)

	// Root domains (eTLD+1). Only DNS names participate.
	rootSeen := make(map[string]struct{}, len(dns))
	for _, name := range dns {
		apex, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil || apex == "" {
			continue
		}
		if _, dup := rootSeen[apex]; dup {
			continue
		}
		rootSeen[apex] = struct{}{}
		out.RootDomains = append(out.RootDomains, apex)
	}

	if len(out.RootDomains) > 0 {
		out.ApexDomain = out.RootDomains[0]
	}

	out.FuzzyHash = fuzzyHash(dns)

	return out
}

func empty() NormalizedCert {
	return NormalizedCert{
		SANs:        []string{},
		RootDomains: []string{},
	}
}

// normalizeAndValidate canonicalizes a hostname and ensures it has a valid PSL entry.
func normalizeAndValidate(hostname string) (string, bool) {
	h := strings.TrimSpace(hostname)
	if h == "" {
		return "", false
	}

	for strings.HasPrefix(h, "*.") {
		h = h[2:]
	}
	h = strings.Trim(h, ".")

	if h == "" {
		return "", false
	}

	ascii, err := profile.ToASCII(h)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", false
	}
	ascii = strings.ToLower(ascii)

	if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
		return "", false
	}

	return ascii, true
}

// fuzzyHash produces an order-independent fingerprint:
// SHA-256 each domain → sort digests → SHA-256 the concatenation → hex.
func fuzzyHash(domains []string) string {
	digests := make([][]byte, 0, len(domains))
	for _, d := range domains {
		if d == "" {
			continue
		}
		h := sha256.Sum256([]byte(d))
		digests = append(digests, h[:])
	}

	if len(digests) == 0 {
		return ""
	}

	slices.SortFunc(digests, bytes.Compare)

	h := sha256.New()
	for _, d := range digests {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}
