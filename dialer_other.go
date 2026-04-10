// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

//go:build !linux

package rxds

import "net"

var scanDialer = &net.Dialer{} // hi plan9, aix, and such.
