//go:build linux

// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Package syn provides a raw SYN pre-filter for IPv4 host discovery.
package syn

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	if ifaceName == "" {
		detected, err := DiscoverDefaultIface()
		if err != nil {
			return nil, err
		}
		ifaceName = detected
	}
	srcIP, srcMAC, gwMAC, err := discoverRoute(ifaceName)
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

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			continue
		}
		if flags&0x1 == 0 || flags&0x2 == 0 {
			continue
		}
		return fields[0], nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no default route found in /proc/net/route")
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
	handle, err := pcap.OpenLive(s.iface, 96, false, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	bpf := "tcp and dst host " + s.srcIP.String() +
		" and src port " + strconv.Itoa(int(s.port)) +
		" and tcp[13] == 18"
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
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

func (s *Scanner) recvLoop(ctx context.Context, handle *pcap.Handle, responsive chan<- netip.Addr) {
	defer close(responsive)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

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
		// per RFC 793 and RFC 9293, a SYN-ACK acknowledges our ISN plus one.
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
	handle *pcap.Handle,
	targets <-chan netip.Addr,
) {
	defer cancel()

	interval := time.Second / time.Duration(s.rate)
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
			if err := handle.WritePacketData(buf.Bytes()); err != nil {
				buf.Clear()
				continue
			}

			s.sent.Add(1)
			buf.Clear()
		}
	}
}

func discoverRoute(ifaceName string) (netip.Addr, net.HardwareAddr, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	if len(iface.HardwareAddr) == 0 {
		return netip.Addr{}, nil, nil, errors.New("interface has no hardware address")
	}
	srcIP, err := interfaceIPv4Addr(iface)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	gatewayIP, err := defaultGatewayIPv4(ifaceName)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	gwMAC, err := gatewayHardwareAddr(ifaceName, srcIP, gatewayIP)
	if err != nil {
		return netip.Addr{}, nil, nil, err
	}
	return srcIP, iface.HardwareAddr, gwMAC, nil
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

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] != ifaceName || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		gateway, err := routeHexIPv4(fields[2])
		if err != nil {
			continue
		}
		return gateway, nil
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, err
	}
	return netip.Addr{}, errors.New("default route not found")
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

func gatewayHardwareAddr(
	ifaceName string,
	srcIP, gatewayIP netip.Addr,
) (net.HardwareAddr, error) {
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

func arpCacheHardwareAddr(
	ifaceName string,
	ip netip.Addr,
) (net.HardwareAddr, bool, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
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
		flags, err := strconv.ParseUint(fields[2], 16, 32)
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
