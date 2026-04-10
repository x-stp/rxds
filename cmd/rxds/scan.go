// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"time"

	"github.com/x-stp/rxds"
	"github.com/x-stp/rxds/jarm"
	"github.com/x-stp/rxds/normalize"
	"github.com/x-stp/rxds/tls"
)

type worker struct {
	dialer  *net.Dialer
	cfg     *tls.Config
	timeout time.Duration
}

func newWorker(baseCfg *tls.Config, timeout time.Duration) *worker {
	cfg := baseCfg.Clone()
	cfg.CertsOnly = true
	cfg.InsecureSkipVerify = true
	cfg.WarmHelloTemplate()
	return &worker{
		dialer:  rxds.ScanDialer(),
		cfg:     cfg,
		timeout: timeout,
	}
}

type target struct {
	IP   netip.Addr
	Port uint16
}

type result struct {
	IP                string   `json:"ip"`
	Port              uint16   `json:"port"`
	SNI               string   `json:"sni,omitempty"`
	CN                string   `json:"cn"`
	SANs              []string `json:"sans"`
	Org               string   `json:"org"`
	ApexDomain        string   `json:"apex_domain"`
	RootDomains       []string `json:"root_domains"`
	FuzzyHash         string   `json:"fuzzy_hash"`
	SHA256Fingerprint string   `json:"sha256,omitempty"`
	JARM              string   `json:"jarm,omitempty"`
	Err               string   `json:"err,omitempty"`
}

var emptyStrings = []string{}

func (w *worker) scanOne(ctx context.Context, t target, doJARM bool) result {
	ipStr := t.IP.String()
	r := result{
		IP:   ipStr,
		Port: t.Port,
		SNI:  w.cfg.ServerName,
	}

	dialCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	addr := netip.AddrPortFrom(t.IP, t.Port).String()
	certs, err := rxds.DialForCertRaw(dialCtx, w.dialer, "tcp", addr, w.cfg)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if len(certs) == 0 {
		r.Err = "no_certs"
		return r
	}

	leaf := certs[0]
	n := normalize.NormalizeCert(leaf)
	r.CN = n.CN
	r.SANs = n.SANs
	if r.SANs == nil {
		r.SANs = emptyStrings
	}
	r.Org = n.Org
	r.ApexDomain = n.ApexDomain
	r.RootDomains = n.RootDomains
	if r.RootDomains == nil {
		r.RootDomains = emptyStrings
	}
	r.FuzzyHash = n.FuzzyHash
	sum := sha256.Sum256(leaf.Raw)
	r.SHA256Fingerprint = hex.EncodeToString(sum[:])

	if doJARM {
		host := w.cfg.ServerName
		if host == "" {
			host = ipStr
		}
		if fp, err := jarm.Fingerprint(dialCtx, host, t.Port, w.timeout); err == nil {
			r.JARM = fp
		}
	}

	return r
}

func shouldEmit(r result, printErrors, printEmpty bool) bool {
	if r.Err != "" {
		return printErrors
	}
	if printEmpty {
		return true
	}
	return r.CN != "" || len(r.SANs) > 0
}
