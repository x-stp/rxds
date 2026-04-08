// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds

import (
	"context"
	"crypto/x509"
	"errors"
	"net"

	"github.com/x-stp/rxds/tls"
)

// DialForCert connects to the given address and performs a TLS handshake
// just far enough to receive the server's certificate chain.
func DialForCert(ctx context.Context, network, addr string, config *tls.Config) ([]*x509.Certificate, error) {
	if config == nil {
		config = &tls.Config{}
	}

	// Warm the hello template on the original Config so clones inherit it.
	config.WarmHelloTemplate()

	conf := config.Clone()

	conf.CertsOnly = true
	conf.InsecureSkipVerify = true

	if conf.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
			c := conf.Clone()
			c.ServerName = host
			conf = c
		}
	}

	rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, conf)
	defer conn.Close()
	err = conn.Handshake()
	if err != nil && !errors.Is(err, tls.ErrExpected) {
		return nil, err
	}

	state := conn.ConnectionState()
	return state.PeerCertificates, nil
}
