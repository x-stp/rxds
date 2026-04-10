// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

//go:build linux

package rxds

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func setScanSocketOptions(fd int) error {
	if err := syscall.SetsockoptLinger(
		fd,
		syscall.SOL_SOCKET,
		syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0},
	); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, syscall.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1); err != nil &&
		!errors.Is(err, unix.ENOPROTOOPT) &&
		!errors.Is(err, unix.EOPNOTSUPP) &&
		!errors.Is(err, unix.ENOTSUP) {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4096); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 32768); err != nil {
		return err
	}
	return nil
}

// ScanDialer returns a dialer configured for high-throughput Linux scans.
func ScanDialer() *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = setScanSocketOptions(int(fd))
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
}

var scanDialer = ScanDialer()
