package syn

import (
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
