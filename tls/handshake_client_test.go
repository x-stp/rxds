package tls

import (
	"bytes"
	"testing"
)

func TestHandshakeLogCopiesHelloBytes(t *testing.T) {
	clientRaw := []byte{typeClientHello, 0, 0, 1, 0xaa}
	serverRaw := []byte{typeServerHello, 0, 0, 1, 0xbb}
	serverRandom := bytes.Repeat([]byte{0xcc}, 32)

	hello := &clientHelloMsg{raw: clientRaw}
	serverHello := &serverHelloMsg{
		raw:         serverRaw,
		random:      serverRandom,
		cipherSuite: TLS_AES_128_GCM_SHA256,
	}

	log := newHandshakeLog(hello, serverHello, VersionTLS13)
	clientRaw[4] = 0x11
	serverRaw[4] = 0x22
	serverRandom[0] = 0x33

	if got, want := log.ClientHelloRaw, []byte{typeClientHello, 0, 0, 1, 0xaa}; !bytes.Equal(got, want) {
		t.Fatalf("ClientHelloRaw alias changed: got %x want %x", got, want)
	}
	if got, want := log.ServerHelloRaw, []byte{typeServerHello, 0, 0, 1, 0xbb}; !bytes.Equal(got, want) {
		t.Fatalf("ServerHelloRaw alias changed: got %x want %x", got, want)
	}
	if log.ServerRandom[0] != 0xcc {
		t.Fatalf("ServerRandom alias changed: got %x", log.ServerRandom[0])
	}
}
