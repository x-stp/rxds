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

func DialForCert(ctx context.Context, network, addr string, config *tls.Config) ([]*x509.Certificate, error) {
	if config == nil {
		config = &tls.Config{}
	}

	config.WarmHelloTemplate()

	conf := config
	if conf.ServerName == "" {
		conf = config.Clone()
		conf.InsecureSkipVerify = true
		if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
			conf.ServerName = host
		}
	}

	rawConn, err := scanDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		rawConn.SetDeadline(deadline)
	}

	conn := tls.Client(rawConn, conf)
	defer conn.Close()

	if err := conn.Handshake(); err != nil && !errors.Is(err, tls.ErrExpected) {
		return nil, err
	}

	return conn.ConnectionState().PeerCertificates, nil
}
