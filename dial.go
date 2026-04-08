// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"syscall"

	"github.com/x-stp/rxds/tls"
)

var scanDialer = &net.Dialer{
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4096)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 32768)
		})
	},
}

func DialForCert(ctx context.Context, network, addr string, config *tls.Config) ([]*x509.Certificate, error) {
	if config == nil {
		config = &tls.Config{}
	}

	config.WarmHelloTemplate()

	conf := config
	needsClone := conf.ServerName == ""
	if needsClone {
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
