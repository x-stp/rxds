//go:build linux

// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Package syn provides a raw SYN pre-filter for IPv4 host discovery.
package syn

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Scanner sends raw SYNs and reports the IPv4 addresses that answer with SYN-ACK.
type Scanner struct {
	iface    string
	srcIP    netip.Addr
	srcMAC   net.HardwareAddr
	gwMAC    net.HardwareAddr
	port     uint16
	rate     int
	secret   uint32
	grace    time.Duration
	sent     atomic.Uint64
	received atomic.Uint64
}

type RouteOverrides struct {
	SrcIP      netip.Addr
	SrcMAC     net.HardwareAddr
	GatewayIP  netip.Addr
	GatewayMAC net.HardwareAddr
}

// New creates a scanner from explicit interface parameters.
func New(
	iface string,
	srcIP netip.Addr,
	srcMAC, gwMAC net.HardwareAddr,
	port uint16,
	rate int,
	grace time.Duration,
) (*Scanner, error) {
	if !srcIP.Is4() {
		return nil, errors.New("syn scanner requires an IPv4 source address")
	}
	if len(srcMAC) == 0 {
		return nil, errors.New("syn scanner requires a source MAC address")
	}
	if len(gwMAC) == 0 {
		return nil, errors.New("syn scanner requires a gateway MAC address")
	}
	if port == 0 {
		return nil, errors.New("syn scanner requires a non-zero port")
	}
	if rate <= 0 {
		return nil, errors.New("syn scanner requires a positive rate")
	}

	var secret [4]byte
	if _, err := io.ReadFull(crand.Reader, secret[:]); err != nil {
		return nil, err
	}

	return &Scanner{
		iface:  iface,
		srcIP:  srcIP,
		srcMAC: append(net.HardwareAddr(nil), srcMAC...),
		gwMAC:  append(net.HardwareAddr(nil), gwMAC...),
		port:   port,
		rate:   rate,
		secret: binary.BigEndian.Uint32(secret[:]),
		grace:  grace,
	}, nil
}

// NewForInterface discovers the source IPv4, source MAC, and default gateway MAC
// for ifaceName, then builds a scanner. An empty ifaceName triggers auto-detection
// via /proc/net/route.
func NewForInterface(
	ifaceName string,
	port uint16,
	rate int,
	grace time.Duration,
) (*Scanner, error) {
	return NewForInterfaceWithOverrides(ifaceName, port, rate, grace, RouteOverrides{})
}

func NewForInterfaceWithOverrides(
	ifaceName string,
	port uint16,
	rate int,
	grace time.Duration,
	overrides RouteOverrides,
) (*Scanner, error) {
	if ifaceName == "" {
		detected, err := DiscoverDefaultIface()
		if err != nil {
			return nil, err
		}
		ifaceName = detected
	}
	srcIP, srcMAC, gwMAC, err := discoverRoute(ifaceName, overrides)
	if err != nil {
		return nil, err
	}
	return New(ifaceName, srcIP, srcMAC, gwMAC, port, rate, grace)
}

// DiscoverDefaultIface returns the first interface in /proc/net/route that has a
// default route (Destination=0.0.0.0) with RTF_UP and RTF_GATEWAY flags set.
func DiscoverDefaultIface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()

	return defaultIfaceFrom(f)
}

func (s *Scanner) cookieISN(dstIP netip.Addr) uint32 {
	if !dstIP.Is4() {
		return 0
	}
	b := dstIP.As4()
	v := binary.BigEndian.Uint32(b[:])
	v ^= s.secret
	v ^= v >> 16
	v *= 0x85ebca6b
	v ^= v >> 13
	v *= 0xc2b2ae35
	v ^= v >> 16
	return v
}

// Run starts the pre-filter. Targets are IPv4 addresses only; non-IPv4 targets are
// ignored. The returned channel yields targets that answered with SYN-ACK.
func (s *Scanner) Run(ctx context.Context, targets <-chan netip.Addr) (<-chan netip.Addr, error) {
	handle, err := openPacketSocket(s.iface, s.srcIP, s.port)
	if err != nil {
		return nil, err
	}

	responsive := make(chan netip.Addr, 4096)
	runCtx, cancel := context.WithCancel(ctx)

	var loops sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		s.recvLoop(runCtx, handle, responsive)
	}()
	go func() {
		defer loops.Done()
		s.sendLoop(runCtx, cancel, handle, targets)
	}()

	go func() {
		loops.Wait()
		handle.Close()
	}()

	return responsive, nil
}

// Stats returns the number of SYN packets sent and SYN-ACKs received.
func (s *Scanner) Stats() (sent, received uint64) {
	return s.sent.Load(), s.received.Load()
}

func (s *Scanner) recvLoop(ctx context.Context, handle *packetSocket, responsive chan<- netip.Addr) {
	defer close(responsive)

	buf := make([]byte, 2048)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := handle.ReadPacketData(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if tcpLayer == nil || ipLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			continue
		}
		if !tcp.SYN || !tcp.ACK {
			continue
		}

		addr, ok := netip.AddrFromSlice(ip.SrcIP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if tcp.Ack == 0 {
			continue
		}
		if uint32(tcp.Ack)-1 != s.cookieISN(addr) {
			continue
		}

		s.received.Add(1)
		select {
		case responsive <- addr:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scanner) sendLoop(
	ctx context.Context,
	cancel context.CancelFunc,
	handle *packetSocket,
	targets <-chan netip.Addr,
) {
	defer cancel()

	interval := sendInterval(s.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	src4 := s.srcIP.As4()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for {
		select {
		case <-ctx.Done():
			return
		case dstIP, ok := <-targets:
			if !ok {
				timer := time.NewTimer(s.grace)
				defer timer.Stop()
				select {
				case <-ctx.Done():
				case <-timer.C:
				}
				return
			}
			if !dstIP.Is4() {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			dst4 := dstIP.As4()
			eth := &layers.Ethernet{
				SrcMAC:       s.srcMAC,
				DstMAC:       s.gwMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}
			ipv4 := &layers.IPv4{
				Version:  4,
				Id:       uint16(1 + rand.IntN(65534)),
				Flags:    layers.IPv4DontFragment,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    net.IP(src4[:]),
				DstIP:    net.IP(dst4[:]),
			}
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(32768 + rand.IntN(28232)),
				DstPort: layers.TCPPort(s.port),
				Seq:     s.cookieISN(dstIP),
				SYN:     true,
				Window:  64240,
				Options: []layers.TCPOption{
					{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
				},
			}
			tcp.SetNetworkLayerForChecksum(ipv4)

			if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, tcp); err != nil {
				buf.Clear()
				continue
			}
			if err := handle.WritePacketData(buf.Bytes(), s.gwMAC); err != nil {
				buf.Clear()
				continue
			}

			s.sent.Add(1)
			buf.Clear()
		}
	}
}

type packetSocket struct {
	fd      int
	ifindex int
}

func openPacketSocket(ifaceName string, srcIP netip.Addr, port uint16) (*packetSocket, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	ps := &packetSocket{fd: fd, ifindex: iface.Index}
	if err := ps.bind(); err != nil {
		ps.Close()
		return nil, err
	}
	if err := ps.setReadTimeout(100 * time.Millisecond); err != nil {
		ps.Close()
		return nil, err
	}
	if err := ps.attachFilter(srcIP, port); err != nil {
		ps.Close()
		return nil, err
	}
	return ps, nil
}

func (ps *packetSocket) bind() error {
	return unix.Bind(ps.fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ps.ifindex,
	})
}

func (ps *packetSocket) setReadTimeout(timeout time.Duration) error {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	return unix.SetsockoptTimeval(ps.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

func (ps *packetSocket) attachFilter(srcIP netip.Addr, port uint16) error {
	raw, err := bpf.Assemble(synAckFilter(srcIP, port))
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filters[i] = unix.SockFilter{
			Code: ins.Op,
			Jt:   ins.Jt,
			Jf:   ins.Jf,
			K:    ins.K,
		}
	}
	prog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	return unix.SetsockoptSockFprog(ps.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

func (ps *packetSocket) ReadPacketData(buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(ps.fd, buf, 0)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (ps *packetSocket) WritePacketData(data []byte, dst net.HardwareAddr) error {
	var addr [8]byte
	copy(addr[:], dst)
	return unix.Sendto(ps.fd, data, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ps.ifindex,
		Halen:    uint8(len(dst)),
		Addr:     addr,
	})
}

func (ps *packetSocket) Close() {
	_ = unix.Close(ps.fd)
}

func discoverRoute(ifaceName string, overrides RouteOverrides) (netip.Addr, net.HardwareAddr, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}

	srcIP, err := sourceIPv4Addr(iface, overrides.SrcIP)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	srcMAC, err := sourceHardwareAddr(iface, overrides.SrcMAC)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	gatewayIP, err := gatewayIPv4(ifaceName, overrides.GatewayIP)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	gwMAC, err := gatewayHardwareAddr(ifaceName, srcIP, gatewayIP, overrides.GatewayMAC)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	return srcIP, srcMAC, gwMAC, nil
}

func sourceIPv4Addr(iface *net.Interface, override netip.Addr) (netip.Addr, error) {
	if override.IsValid() {
		if !override.Is4() {
			return netip.Addr{}, errors.New("SYN source address must be IPv4")
		}
		return override, nil
	}
	return interfaceIPv4Addr(iface)
}

func sourceHardwareAddr(iface *net.Interface, override net.HardwareAddr) (net.HardwareAddr, error) {
	if len(override) > 0 {
		return append(net.HardwareAddr(nil), override...), nil
	}
	if len(iface.HardwareAddr) == 0 {
		return nil, errors.New("interface has no hardware address")
	}
	return iface.HardwareAddr, nil
}

func gatewayIPv4(ifaceName string, override netip.Addr) (netip.Addr, error) {
	if override.IsValid() {
		if !override.Is4() {
			return netip.Addr{}, errors.New("SYN gateway address must be IPv4")
		}
		return override, nil
	}
	return defaultGatewayIPv4(ifaceName)
}

func gatewayHardwareAddr(
	ifaceName string,
	srcIP, gatewayIP netip.Addr,
	override net.HardwareAddr,
) (net.HardwareAddr, error) {
	if len(override) > 0 {
		return append(net.HardwareAddr(nil), override...), nil
	}
	mac, ok, err := arpCacheHardwareAddr(ifaceName, gatewayIP)
	if err != nil {
		return nil, err
	}
	if ok {
		return mac, nil
	}
	if err := warmARPEntry(srcIP, gatewayIP); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mac, ok, err = arpCacheHardwareAddr(ifaceName, gatewayIP)
		if err != nil {
			return nil, err
		}
		if ok {
			return mac, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("gateway MAC not found in ARP cache")
}

func interfaceIPv4Addr(iface *net.Interface) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		var raw net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			raw = a.IP
		case *net.IPAddr:
			raw = a.IP
		}
		ip, ok := netip.AddrFromSlice(raw)
		if ok && ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, errors.New("interface has no IPv4 address")
}

func defaultGatewayIPv4(ifaceName string) (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()

	return defaultGatewayIPv4From(f, ifaceName)
}

func arpCacheHardwareAddr(
	ifaceName string,
	ip netip.Addr,
) (net.HardwareAddr, bool, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	return arpHardwareAddrFrom(f, ifaceName, ip)
}

func warmARPEntry(srcIP, gatewayIP netip.Addr) error {
	conn, err := net.DialUDP(
		"udp4",
		&net.UDPAddr{IP: srcIP.AsSlice()},
		&net.UDPAddr{IP: gatewayIP.AsSlice(), Port: 9},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0})
	return err
}
