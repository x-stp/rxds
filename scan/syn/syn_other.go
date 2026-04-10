//go:build !linux

// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package syn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

var errUnsupported = errors.New("syn scanner requires Linux")

// Scanner is unavailable on non-Linux platforms.
type Scanner struct{}

// New reports that the SYN scanner is unsupported on this platform.
func New(
	iface string,
	srcIP netip.Addr,
	srcMAC, gwMAC net.HardwareAddr,
	port uint16,
	rate int,
	grace time.Duration,
) (*Scanner, error) {
	return nil, errUnsupported
}

// NewForInterface reports that the SYN scanner is unsupported on this platform.
func NewForInterface(
	ifaceName string,
	port uint16,
	rate int,
	grace time.Duration,
) (*Scanner, error) {
	return nil, errUnsupported
}

// Run reports that the SYN scanner is unsupported on this platform.
func (s *Scanner) Run(ctx context.Context, targets <-chan netip.Addr) (<-chan netip.Addr, error) {
	return nil, errUnsupported
}

// Stats reports zero values on unsupported platforms.
func (s *Scanner) Stats() (sent, received uint64) {
	return 0, 0
}
