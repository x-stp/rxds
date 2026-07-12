// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package syn

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func sendInterval(rate int) time.Duration {
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// synAckFilter is a classic BPF program accepting only IPv4 TCP SYN-ACKs that
// are addressed to srcIP and sourced from port.
func synAckFilter(srcIP netip.Addr, port uint16) []bpf.Instruction {
	src4 := srcIP.As4()
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeIPv4), SkipFalse: 10},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.IPProtocolTCP), SkipFalse: 8},
		bpf.LoadAbsolute{Off: 30, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(src4[:]), SkipFalse: 6},
		bpf.LoadMemShift{Off: 14},
		bpf.LoadIndirect{Off: 14, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipFalse: 3},
		bpf.LoadIndirect{Off: 27, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x12, SkipFalse: 1},
		bpf.RetConstant{Val: 96},
		bpf.RetConstant{Val: 0},
	}
}

type defaultRoute struct {
	gateway netip.Addr
	metric  uint64
}

// defaultGatewayIPv4From returns the lowest-metric default-route gateway for
// ifaceName from a /proc/net/route stream.
func defaultGatewayIPv4From(r io.Reader, ifaceName string) (netip.Addr, error) {
	sc := bufio.NewScanner(r)
	first := true
	var best netip.Addr
	bestMetric := ^uint64(0)
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		route, ok := parseDefaultRoute(strings.Fields(sc.Text()), ifaceName)
		if !ok || route.metric >= bestMetric {
			continue
		}
		best = route.gateway
		bestMetric = route.metric
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, err
	}
	if best.IsValid() {
		return best, nil
	}
	return netip.Addr{}, errors.New("default route not found")
}

// defaultIfaceFrom returns the interface owning the lowest-metric default route
// from a /proc/net/route stream. It mirrors defaultGatewayIPv4From's metric
// preference so the discovered interface and its gateway agree on multi-homed
// hosts (rather than taking whichever default route appears first).
func defaultIfaceFrom(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	first := true
	var best string
	bestMetric := ^uint64(0)
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 || flags&0x2 == 0 {
			continue
		}
		metric, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil || metric >= bestMetric {
			continue
		}
		bestMetric = metric
		best = fields[0]
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if best != "" {
		return best, nil
	}
	return "", errors.New("no default route found in /proc/net/route")
}

func parseDefaultRoute(fields []string, ifaceName string) (defaultRoute, bool) {
	if len(fields) < 7 || fields[0] != ifaceName || fields[1] != "00000000" {
		return defaultRoute{}, false
	}
	flags, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil || flags&0x1 == 0 || flags&0x2 == 0 {
		return defaultRoute{}, false
	}
	gateway, err := routeHexIPv4(fields[2])
	if err != nil || !gateway.Is4() || gateway == netip.IPv4Unspecified() {
		return defaultRoute{}, false
	}
	metric, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return defaultRoute{}, false
	}
	return defaultRoute{gateway: gateway, metric: metric}, true
}

// arpHardwareAddrFrom scans a /proc/net/arp stream for the resolved hardware
// address of ip on ifaceName. It reports ok=false (nil error) when no complete
// entry exists yet.
func arpHardwareAddrFrom(r io.Reader, ifaceName string, ip netip.Addr) (net.HardwareAddr, bool, error) {
	sc := bufio.NewScanner(r)
	first := true
	target := ip.String()
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || fields[0] != target || fields[5] != ifaceName {
			continue
		}
		// ATF_COM (0x2) means the entry is resolved. Without it the HW addr is
		// typically 00:00:00:00:00:00 (incomplete/failed NUD state).
		// /proc/net/arp prints flags with a "0x" prefix (e.g. "0x2"), which
		// strconv.ParseUint rejects at an explicit base — strip it first.
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			return nil, false, err
		}
		return mac, true, nil
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func routeHexIPv4(raw string) (netip.Addr, error) {
	value, err := strconv.ParseUint(raw, 16, 32)
	if err != nil {
		return netip.Addr{}, err
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(value))
	return netip.AddrFrom4(b), nil
}
