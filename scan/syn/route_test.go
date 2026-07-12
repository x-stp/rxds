package syn

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

func TestSendIntervalNeverZero(t *testing.T) {
	tests := []struct {
		rate int
		want time.Duration
	}{
		{1, time.Second},
		{1000, time.Millisecond},
		{2_000_000_000, time.Nanosecond},
		{1 << 30, time.Nanosecond},
	}
	for _, tt := range tests {
		if got := sendInterval(tt.rate); got != tt.want {
			t.Fatalf("sendInterval(%d) = %v, want %v", tt.rate, got, tt.want)
		}
		if sendInterval(tt.rate) <= 0 {
			t.Fatalf("sendInterval(%d) returned non-positive interval", tt.rate)
		}
	}
}

func TestDefaultGatewayPrefersLowestMetricAndRequiresGateway(t *testing.T) {
	const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
	// eth0 has two default routes; the 0x0003 (UP|GATEWAY) one at metric 100
	// must win over the higher-metric 600 entry. The 0x0001 (UP only, no
	// GATEWAY) line and the on-link 00000000 gateway must be ignored.
	body := strings.Join([]string{
		"eth0\t00000000\t0100000A\t0001\t0\t0\t50\t00000000",  // UP only, no GATEWAY -> skip
		"eth0\t00000000\t0202000A\t0003\t0\t0\t600\t00000000", // valid, metric 600
		"eth0\t00000000\tFE02000A\t0003\t0\t0\t100\t00000000", // valid, metric 100 -> winner
		"eth1\t00000000\t0103000A\t0003\t0\t0\t10\t00000000",  // other iface -> skip
		"eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF",   // not default dest -> skip
	}, "\n")

	gw, err := defaultGatewayIPv4From(strings.NewReader(header+body), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gw.String(), "10.0.2.254"; got != want {
		t.Fatalf("gateway = %s, want %s", got, want)
	}
}

func TestDefaultGatewayMissing(t *testing.T) {
	const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
	body := "eth0\t00000000\t0100000A\t0001\t0\t0\t50\t00000000"
	if _, err := defaultGatewayIPv4From(strings.NewReader(header+body), "eth0"); err == nil {
		t.Fatal("expected error when no default gateway route exists")
	}
}

func TestARPHardwareAddrParsesPrefixedFlags(t *testing.T) {
	// /proc/net/arp writes Flags with a "0x" prefix (0x2 = ATF_COM). The parser
	// must accept it; base-16 strconv.ParseUint rejects the prefix outright,
	// which previously made gateway MAC auto-detection always fail.
	const header = "IP address       HW type     Flags       HW address            Mask     Device\n"
	body := strings.Join([]string{
		"10.88.0.9        0x1         0x2         00:00:5e:00:53:aa     *        eth1", // wrong iface -> skip
		"10.88.0.5        0x1         0x0         00:00:00:00:00:00     *        eth0", // incomplete -> skip
		"10.88.0.1        0x1         0x2         aa:ed:79:eb:df:a7     *        eth0", // resolved -> hit
	}, "\n")

	mac, ok, err := arpHardwareAddrFrom(strings.NewReader(header+body), "eth0", netip.MustParseAddr("10.88.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a resolved ARP entry, got ok=false")
	}
	if got, want := mac.String(), "aa:ed:79:eb:df:a7"; got != want {
		t.Fatalf("mac = %s, want %s", got, want)
	}
}

func TestARPHardwareAddrIncompleteEntry(t *testing.T) {
	const header = "IP address       HW type     Flags       HW address            Mask     Device\n"
	body := "10.88.0.1        0x1         0x0         00:00:00:00:00:00     *        eth0"
	_, ok, err := arpHardwareAddrFrom(strings.NewReader(header+body), "eth0", netip.MustParseAddr("10.88.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected ok=false for an incomplete (0x0) ARP entry")
	}
}

func TestDefaultIfacePrefersLowestMetric(t *testing.T) {
	const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
	// Two valid default routes on different ifaces; the metric-100 eth1 must win
	// over the metric-700 ppp0. UP-only (no GATEWAY) and non-default lines skip.
	body := strings.Join([]string{
		"eth0\t00000000\t0100000A\t0001\t0\t0\t50\t00000000",  // UP only, no GATEWAY -> skip
		"ppp0\t00000000\t0202000A\t0003\t0\t0\t700\t00000000", // valid, metric 700
		"eth1\t00000000\tFE02000A\t0003\t0\t0\t100\t00000000", // valid, metric 100 -> winner
		"eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF",   // not default dest -> skip
	}, "\n")

	iface, err := defaultIfaceFrom(strings.NewReader(header + body))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := iface, "eth1"; got != want {
		t.Fatalf("iface = %s, want %s", got, want)
	}
}

func TestDefaultIfaceMissing(t *testing.T) {
	const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
	body := "eth0\t00000000\t0100000A\t0001\t0\t0\t50\t00000000" // UP only, no GATEWAY
	if _, err := defaultIfaceFrom(strings.NewReader(header + body)); err == nil {
		t.Fatal("expected error when no default route exists")
	}
}

func TestRouteHexIPv4LittleEndian(t *testing.T) {
	gw, err := routeHexIPv4("0102000A")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gw.String(), "10.0.2.1"; got != want {
		t.Fatalf("routeHexIPv4 = %s, want %s", got, want)
	}
}

func TestSynAckFilterAssembles(t *testing.T) {
	gw, err := routeHexIPv4("0102000A")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bpf.Assemble(synAckFilter(gw, 443)); err != nil {
		t.Fatalf("synAckFilter did not assemble: %v", err)
	}
}
