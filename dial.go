// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds

import (
	"context"
	"crypto/x509"
	"errors"
	"net"

	"github.com/rs/zerolog/log"

	"github.com/x-stp/rxds/tls"
)

func dialForCertConn(
	ctx context.Context,
	dialer *net.Dialer,
	network, addr string,
	config *tls.Config,
) ([]*x509.Certificate, error) {
	if dialer == nil {
		dialer = scanDialer
	}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer func(rawConn net.Conn) {
		// crypto/tls's own handshake-interrupt goroutine closes the underlying
		// conn on ctx cancel/timeout (see tls.Conn.HandshakeContext), so a
		// stalled-handshake target is already closed here. Don't log that race.
		if err := rawConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debug().Err(err).Msg("failed to close raw connection")
		}
	}(rawConn)

	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	conn := tls.Client(rawConn, config)
	err = conn.HandshakeContext(ctx)
	if err != nil && !errors.Is(err, tls.ErrExpected) {
		tls.PutConn(conn)
		return nil, err
	}

	certs := conn.ConnectionState().PeerCertificates
	tls.PutConn(conn)
	return certs, nil
}

func DialForCert(ctx context.Context, network, addr string, config *tls.Config) ([]*x509.Certificate, error) {
	if config == nil {
		config = &tls.Config{}
	}

	config.WarmHelloTemplate()

	conf := config
	if conf.ServerName == "" {
		conf = config.Clone()
		conf.InsecureSkipVerify = true // this ain't GRC
		if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
			conf.ServerName = host
		}
	}

	return dialForCertConn(ctx, scanDialer, network, addr, conf)
}

// DialForCertRaw is like DialForCert, but assumes config is already prepared
// for cert harvesting and owned by the caller.
func DialForCertRaw(
	ctx context.Context, dialer *net.Dialer, network, addr string, config *tls.Config) ([]*x509.Certificate, error) {
	if config == nil {
		config = &tls.Config{}
	}

	return dialForCertConn(ctx, dialer, network, addr, config)
}
