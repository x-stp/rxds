// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"context"
	"net/netip"
	"time"

	"github.com/x-stp/rxds/scan/syn"
)

func setupScanTargets(
	ctx context.Context,
	source chan target,
	synEnabled bool,
	iface string,
	port uint16,
	rate int,
	grace time.Duration,
) (<-chan target, *syn.Scanner, error) {
	if !synEnabled {
		return source, nil, nil
	}

	scanner, err := syn.NewForInterface(iface, port, rate, grace)
	if err != nil {
		return nil, nil, err
	}

	filtered, err := startSYNPrefilter(ctx, scanner, source, port)
	if err != nil {
		return nil, nil, err
	}
	return filtered, scanner, nil
}

func startSYNPrefilter(
	ctx context.Context,
	scanner *syn.Scanner,
	source <-chan target,
	port uint16,
) (<-chan target, error) {
	synTargets := make(chan netip.Addr, 1024)
	responsive, err := scanner.Run(ctx, synTargets)
	if err != nil {
		return nil, err
	}

	filtered := make(chan target, 1024)

	go func() {
		defer close(synTargets)
		for t := range source {
			select {
			case synTargets <- t.IP:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		defer close(filtered)
		for ip := range responsive {
			select {
			case filtered <- target{IP: ip, Port: port}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return filtered, nil
}
