package jarm

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestReorderCiphersMatchesReference(t *testing.T) {
	tests := []struct {
		name  string
		in    []uint16
		order cipherOrder
		want  []uint16
	}{
		{"reverse", []uint16{1, 2, 3, 4}, orderReverse, []uint16{4, 3, 2, 1}},
		{"top odd", []uint16{1, 2, 3, 4, 5}, orderTopHalf, []uint16{3, 2, 1}},
		{"top even", []uint16{1, 2, 3, 4}, orderTopHalf, []uint16{2, 1}},
		{"bottom odd", []uint16{1, 2, 3, 4, 5}, orderBottomHalf, []uint16{4, 5}},
		{"bottom even", []uint16{1, 2, 3, 4}, orderBottomHalf, []uint16{3, 4}},
		{"middle odd", []uint16{1, 2, 3, 4, 5}, orderMiddleOut, []uint16{3, 4, 2, 5, 1}},
		{"middle even", []uint16{1, 2, 3, 4}, orderMiddleOut, []uint16{3, 2, 4, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reorderCiphers(tt.in, tt.order); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("reorderCiphers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeSpecsMatchReferenceExtensionOrder(t *testing.T) {
	want := [probeCount]cipherOrder{
		orderReverse,
		orderForward,
		orderForward,
		orderForward,
		orderReverse,
		orderForward,
		orderReverse,
		orderForward,
		orderForward,
		orderReverse,
	}
	for i, spec := range probeSpecs {
		if spec.extOrder != want[i] {
			t.Fatalf("probe %d extension order = %v, want %v", i, spec.extOrder, want[i])
		}
	}
}

func TestSupportedVersionsUsesReferenceOrder(t *testing.T) {
	got := appendSupportedVersions(nil, ver13Support, orderReverse, false)
	want := []byte{0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("supported_versions = %x, want %x", got, want)
	}
}

func TestParseServerHelloWithoutExtensionsKeepsCipherVersion(t *testing.T) {
	raw := serverHelloRecord(nil)
	if got, want := parseServerHello(raw), "1301|0303||"; got != want {
		t.Fatalf("parseServerHello() = %q, want %q", got, want)
	}

	rawResults := [probeCount]string{}
	for i := range rawResults {
		rawResults[i] = "|||"
	}
	rawResults[0] = "1301|0303||"

	if got := HashRaw(rawResults[:]); got[:3] != "41d" {
		t.Fatalf("HashRaw fuzzy prefix = %q, want %q", got[:3], "41d")
	}
}

func TestReadProbeResponseEmptyRead(t *testing.T) {
	got, err := readProbeResponse(emptyReadConn{})
	if err != nil {
		t.Fatal(err)
	}
	if got != rawEmpty {
		t.Fatalf("readProbeResponse() = %q, want %q", got, rawEmpty)
	}
}

func serverHelloRecord(extensions []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body, 0x00, 0x13, 0x01, 0x00)
	if extensions != nil {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
	}
	handshake := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{0x16, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

type emptyReadConn struct{}

func (emptyReadConn) Read([]byte) (int, error)         { return 0, nil }
func (emptyReadConn) Write([]byte) (int, error)        { return 0, nil }
func (emptyReadConn) Close() error                     { return nil }
func (emptyReadConn) LocalAddr() net.Addr              { return nil }
func (emptyReadConn) RemoteAddr() net.Addr             { return nil }
func (emptyReadConn) SetDeadline(time.Time) error      { return nil }
func (emptyReadConn) SetReadDeadline(time.Time) error  { return nil }
func (emptyReadConn) SetWriteDeadline(time.Time) error { return nil }
