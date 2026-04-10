// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package rxds

import (
	"net"
	"syscall"
)

// scanDialer for proper OS.
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
