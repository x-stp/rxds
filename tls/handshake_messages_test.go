package tls

import (
	"bytes"
	"testing"
)

func TestServerHelloUnknownExtensionWithBody(t *testing.T) {
	body := []byte{
		0x03, 0x03,
	}
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body,
		0x00,
		byte(TLS_AES_128_GCM_SHA256>>8), byte(TLS_AES_128_GCM_SHA256&0xff),
		0x00,
		0x00, 0x06,
		0xaa, 0xaa, 0x00, 0x02, 0x01, 0x02,
	)

	msg := append([]byte{typeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	var hello serverHelloMsg
	if !hello.unmarshal(msg) {
		t.Fatal("ServerHello with non-empty unknown extension did not parse")
	}
	if got, want := len(hello.unknownExtensions), 1; got != want {
		t.Fatalf("unknown extension count = %d, want %d", got, want)
	}
	if got, want := hello.unknownExtensions[0], []byte{0xaa, 0xaa, 0x00, 0x02, 0x01, 0x02}; !bytes.Equal(got, want) {
		t.Fatalf("unknown extension = %x, want %x", got, want)
	}
}
