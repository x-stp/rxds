// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

//go:build !linux

package rxds

import "net"

// ScanDialer returns the default dialer on non-Linux platforms.
func ScanDialer() *net.Dialer {
	return &net.Dialer{}
}

var scanDialer = ScanDialer()
