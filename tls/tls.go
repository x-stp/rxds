// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	if config == nil {
		config = defaultConfig()
	}
	// This library is cert-harvest-only: always stop after receiving the server
	// certificate chain.
	if !config.CertsOnly {
		c := config.Clone()
		c.CertsOnly = true
		config = c
	}
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := netDialer.Timeout

	if !netDialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(netDialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	// hsErrCh is non-nil if we might not wait for Handshake to complete.
	var hsErrCh chan error
	if timeout != 0 || ctx.Done() != nil {
		hsErrCh = make(chan error, 2)
	}
	if timeout != 0 {
		timer := time.AfterFunc(timeout, func() {
			hsErrCh <- timeoutError{}
		})
		defer timer.Stop()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := len(addr)
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			colonPos = i
			break
		}
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)

	if hsErrCh == nil {
		err = conn.Handshake()
	} else {
		go func() {
			hsErrCh <- conn.Handshake()
		}()

		select {
		case <-ctx.Done():
			err = ctx.Err()
		case err = <-hsErrCh:
			if err != nil {
				if e := ctx.Err(); e != nil {
					err = e
				}
			}
		}
	}

	if err != nil && !errors.Is(err, ErrExpected) {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	return Certificate{}, errors.New("LoadX509KeyPair not implemented in rxds")
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	stdCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return Certificate{}, err
	}

	c := Certificate{
		Certificate:                 stdCert.Certificate,
		PrivateKey:                  stdCert.PrivateKey,
		OCSPStaple:                  stdCert.OCSPStaple,
		SignedCertificateTimestamps: stdCert.SignedCertificateTimestamps,
		Leaf:                        stdCert.Leaf,
	}
	for _, s := range stdCert.SupportedSignatureAlgorithms {
		c.SupportedSignatureAlgorithms = append(c.SupportedSignatureAlgorithms, SignatureScheme(s))
	}

	return c, nil
}
