//go:build linux

package syn

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func TestSynAckFilter(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	vm, err := bpf.NewVM(synAckFilter(src, 443))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		tcp  layers.TCP
		ip   layers.IPv4
		want bool
	}{
		{
			name: "syn ack",
			tcp:  layers.TCP{SrcPort: 443, DstPort: 44444, SYN: true, ACK: true},
			ip:   layers.IPv4{SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP(src.AsSlice()), Protocol: layers.IPProtocolTCP},
			want: true,
		},
		{
			name: "wrong port",
			tcp:  layers.TCP{SrcPort: 8443, DstPort: 44444, SYN: true, ACK: true},
			ip:   layers.IPv4{SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP(src.AsSlice()), Protocol: layers.IPProtocolTCP},
		},
		{
			name: "wrong flags",
			tcp:  layers.TCP{SrcPort: 443, DstPort: 44444, SYN: true},
			ip:   layers.IPv4{SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP(src.AsSlice()), Protocol: layers.IPProtocolTCP},
		},
		{
			name: "wrong destination",
			tcp:  layers.TCP{SrcPort: 443, DstPort: 44444, SYN: true, ACK: true},
			ip:   layers.IPv4{SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{192, 0, 2, 11}, Protocol: layers.IPProtocolTCP},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := synAckPacket(t, tt.ip, tt.tcp)
			got, err := vm.Run(packet)
			if err != nil {
				t.Fatal(err)
			}
			if (got != 0) != tt.want {
				t.Fatalf("filter result = %d, want accepted=%v", got, tt.want)
			}
		})
	}
}

func synAckPacket(t *testing.T, ip layers.IPv4, tcp layers.TCP) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip.Version = 4
	ip.IHL = 5
	ip.TTL = 64
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, &ip, &tcp)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
