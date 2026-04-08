// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package tls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"crypto/x509"
)

type Conn struct {
	conn        net.Conn
	isClient    bool
	handshakeFn func() error

	handshakeStatus     uint32
	handshakeMutex      sync.Mutex
	handshakeErr        error
	vers                uint16
	haveVers            bool
	config              *Config
	handshakes          int
	didResume           bool
	cipherSuite         uint16
	ocspResponse        []byte
	scts                [][]byte
	peerCertificates    []*x509.Certificate
	verifiedChains      []CertificateChain
	serverName          string
	secureRenegotiation bool
	ekm                 func(label string, context []byte, length int) ([]byte, error)
	resumptionSecret    []byte
	handshakeLog        *HandshakeLog

	ticketKeys []ticketKey

	clientFinishedIsFirst bool

	closeNotifyErr  error
	closeNotifySent bool

	clientFinished [12]byte
	serverFinished [12]byte

	clientProtocol string

	in, out   halfConn
	rawInput  bytes.Buffer
	input     bytes.Reader
	hand      bytes.Buffer
	buffering bool
	sendBuf   []byte

	helloBuf    []byte
	bytesSent   int64
	packetsSent int64

	retryCount int

	activeCall int32

	tmp [16]byte
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) NetConn() net.Conn {
	return c.conn
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}
	return new(Certificate), nil
}

type halfConn struct {
	sync.Mutex

	err     error
	version uint16
	cipher  any
	mac     hash.Hash
	seq     [8]byte

	scratchBuf [13]byte

	nextCipher any
	nextMac    hash.Hash

	trafficSecret []byte
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}

func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil || hc.version == VersionTLS13 {
		return AlertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) setTrafficSecret(suite *cipherSuiteTLS13, secret []byte) {
	hc.trafficSecret = secret
	key, iv := suite.trafficKey(secret)
	hc.cipher = suite.aead(key, iv)
	for i := range hc.seq {
		hc.seq[i] = 0
	}
}

func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}
	panic("TLS: sequence number wraparound")
}

func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case aead:
		return c.explicitNonceLen()
	case cbcMode:
		if hc.version >= VersionTLS11 {
			return c.BlockSize()
		}
		return 0
	default:
		panic("unknown cipher type")
	}
}

func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	good = byte(int32(^t) >> 31)

	toCheck := 256
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	paddingLen &= good
	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	if hc.version == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, AlertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]

			var additionalData []byte
			if hc.version == VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
				additionalData = append(additionalData, record[:3]...)
				n := len(payload) - c.Overhead()
				additionalData = append(additionalData, byte(n>>8), byte(n))
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, AlertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, AlertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

		if hc.version == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, AlertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, AlertRecordOverflow
			}
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, AlertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		macSize := hc.mac.Size()
		if len(payload) < macSize {
			return nil, 0, AlertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n)
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, AlertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	hc.incSeq()
	return plaintext, typ, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	var dst []byte
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}

		if hc.version == VersionTLS13 {
			record = append(record, payload...)
			record = append(record, record[0])
			record[0] = byte(recordTypeApplicationData)
			n := len(payload) + 1 + c.Overhead()
			record[3] = byte(n >> 8)
			record[4] = byte(n)
			record = c.Seal(record[:recordHeaderLen],
				nonce, record[recordHeaderLen:], record[:recordHeaderLen])
		} else {
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:recordHeaderLen]...)
			record = c.Seal(record, nonce, payload, additionalData)
		}
	case cbcMode:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		blockSize := c.BlockSize()
		plaintextLen := len(payload) + len(mac)
		paddingLen := blockSize - plaintextLen%blockSize
		record, dst = sliceForAppend(record, plaintextLen+paddingLen)
		copy(dst, payload)
		copy(dst[len(payload):], mac)
		for i := plaintextLen; i < len(dst); i++ {
			dst[i] = byte(paddingLen - 1)
		}
		if len(explicitNonce) > 0 {
			c.SetIV(explicitNonce)
		}
		c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	hc.incSeq()

	return record, nil
}

type RecordHeaderError struct {
	Msg          string
	RecordHeader [5]byte
	Conn         net.Conn
}

func (e RecordHeaderError) Error() string { return "tls: " + e.Msg }

func (c *Conn) newRecordHeaderError(conn net.Conn, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Conn = conn
	copy(err.RecordHeader[:], c.rawInput.Bytes())
	return err
}

type readRecordMode uint8

const (
	readRecordNormal readRecordMode = iota
	readRecordExpectChangeCipherSpec
)

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(readRecordNormal)
}

func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(readRecordExpectChangeCipherSpec)
}

func (c *Conn) readRecordOrCCS(mode readRecordMode) error {
	if c.in.err != nil {
		return c.in.err
	}
	expectChangeCipherSpec := mode == readRecordExpectChangeCipherSpec
	handshakeComplete := c.handshakeComplete()

	if c.input.Len() != 0 {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with pending application data"))
	}
	c.input.Reset(nil)

	if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil {
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}
	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has the high bit set in the first byte. SSLv2 records,
	// however, start with a 2-byte length header where the MSB is set.
	//
	// We accept SSLv2 ServerHello in cert-only mode in order to harvest the
	// embedded X.509 certificate (RFC 6101 Appendix E.2.2).
	if !handshakeComplete && (hdr[0]&0x80) == 0x80 {
		// Cert-harvest support: some servers reply to an SSLv2-framed ClientHello
		// with an SSLv2 ServerHello (RFC 6101 Appendix E.2.2). That message embeds
		// the server certificate in clear and is sufficient for scanning.
		//
		// We only implement enough parsing to extract the X.509 certificate.
		if c.config == nil || !c.config.CertsOnly {
			c.sendAlert(AlertProtocolVersion)
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
		}

		// SSLv2 2-byte header: MSB set indicates 2-byte length header (no padding).
		if c.rawInput.Len() < 2 {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "short SSLv2 record header"))
		}
		h := c.rawInput.Bytes()
		bodyLen := int(h[0]&0x7f)<<8 | int(h[1])
		// SSLv2 2-byte header encodes a 15-bit length (max 32767).
		if bodyLen > 0x7fff {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "invalid SSLv2 record length"))
		}
		totalLen := 2 + bodyLen
		if bodyLen <= 0 || totalLen > maxHandshake {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "invalid SSLv2 record length"))
		}
		if err := c.readFromUntil(c.conn, totalLen); err != nil {
			if e, ok := err.(net.Error); !ok || !e.Temporary() {
				c.in.setErrorLocked(err)
			}
			return err
		}
		rec := c.rawInput.Next(totalLen)
		if len(rec) < 2+1+1+1+2+2+2+2 {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "short SSLv2 ServerHello"))
		}

		// Body starts at rec[2].
		msgType := rec[2]
		// 4 == SSL2_MT_SERVER_HELLO
		if msgType != 4 {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 message type"))
		}

		// rec[3] session_id_hit (ignored)
		certType := rec[4]
		// rec[5:7] server_version (ignored; could be SSLv3/TLS)
		certLen := int(rec[7])<<8 | int(rec[8])
		cipherSpecsLen := int(rec[9])<<8 | int(rec[10])
		connIDLen := int(rec[11])<<8 | int(rec[12])

		off := 13
		if certLen <= 0 || off+certLen > len(rec) {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "invalid SSLv2 certificate length"))
		}
		// 1 == X.509 certificate
		if certType != 1 {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 certificate type"))
		}
		certDER := append([]byte(nil), rec[off:off+certLen]...)
		off += certLen

		// Skip cipher_specs and connection_id if present.
		if off+cipherSpecsLen+connIDLen > len(rec) {
			return c.in.setErrorLocked(c.newRecordHeaderError(nil, "invalid SSLv2 ServerHello trailing lengths"))
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return c.in.setErrorLocked(err)
		}
		c.peerCertificates = []*x509.Certificate{cert}

		// Stop immediately: cert-only scanning mode.
		return ErrExpected
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])
	if c.haveVers && c.vers != VersionTLS13 && vers != c.vers {
		c.sendAlert(AlertProtocolVersion)
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, c.vers)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	if (c.vers == VersionTLS13 && n > maxCiphertextTLS13) || n > maxCiphertext {
		c.sendAlert(AlertRecordOverflow)
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	record := c.rawInput.Next(recordHeaderLen + n)
	data, typ, err := c.in.decrypt(record)
	if err != nil {
		if a, ok := err.(Alert); ok {
			return c.in.setErrorLocked(c.sendAlert(a))
		}
		return c.in.setErrorLocked(c.sendAlert(AlertInternalError))
	}
	if len(data) > maxPlaintext {
		return c.in.setErrorLocked(c.sendAlert(AlertRecordOverflow))
	}

	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		c.retryCount = 0
	}

	if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
		return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
	}

	switch typ {
	default:
		return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))

	case recordTypeAlert:
		if len(data) != 2 {
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}
		if Alert(data[1]) == AlertCloseNotify {
			return c.in.setErrorLocked(io.EOF)
		}
		if c.vers == VersionTLS13 {
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: Alert(data[1])})
		}
		switch data[0] {
		case AlertLevelWarning:
			return c.retryReadRecord(mode)
		case AlertLevelError:
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: Alert(data[1])})
		default:
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}

	case recordTypeChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 {
			return c.in.setErrorLocked(c.sendAlert(AlertDecodeError))
		}
		if c.hand.Len() > 0 {
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}
		if c.vers == VersionTLS13 {
			return c.retryReadRecord(mode)
		}
		if !expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}
		if err := c.in.changeCipherSpec(); err != nil {
			if a, ok := err.(Alert); ok {
				return c.in.setErrorLocked(c.sendAlert(a))
			}
			return c.in.setErrorLocked(c.sendAlert(AlertInternalError))
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}
		if len(data) == 0 {
			return c.retryReadRecord(mode)
		}
		c.input.Reset(data)

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
		}
		c.hand.Write(data)
	}

	return nil
}

func (c *Conn) retryReadRecord(mode readRecordMode) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(AlertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many ignored records"))
	}
	return c.readRecordOrCCS(mode)
}

type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n)
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

func (c *Conn) sendAlertLocked(err Alert) error {
	switch err {
	case AlertNoRenegotiation, AlertCloseNotify:
		c.tmp[0] = AlertLevelWarning
	default:
		c.tmp[0] = AlertLevelError
	}
	c.tmp[1] = byte(err)

	_, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
	if err == AlertCloseNotify {
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

func (c *Conn) sendAlert(err Alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	return c.sendAlertLocked(err)
}

const (
	tcpMSSEstimate           = 1208
	recordSizeBoostThreshold = 128 * 1024
)

func (c *Conn) maxPayloadSizeForWrite(typ recordType) int {
	if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
		return maxPlaintext
	}

	if c.bytesSent >= recordSizeBoostThreshold {
		return maxPlaintext
	}

	payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case cipher.Stream:
			payloadBytes -= c.out.mac.Size()
		case cipher.AEAD:
			payloadBytes -= ciph.Overhead()
		case cbcMode:
			blockSize := ciph.BlockSize()
			payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
			payloadBytes -= c.out.mac.Size()
		default:
			panic("unknown cipher type")
		}
	}
	if c.vers == VersionTLS13 {
		payloadBytes-- // encrypted ContentType
	}

	pkt := c.packetsSent
	c.packetsSent++
	if pkt > 1000 {
		return maxPlaintext
	}

	n := payloadBytes * int(pkt+1)
	if n > maxPlaintext {
		n = maxPlaintext
	}
	return n
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent += int64(n)
	return n, err
}

func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}

	n, err := c.conn.Write(c.sendBuf)
	c.bytesSent += int64(n)
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

// outBufPool stores pointers to slice headers so callers can reuse and resize the
// same buffer across writes without copying the header back out of the pool value.
var outBufPool = sync.Pool{
	New: func() any {
		return new([]byte)
	},
}

func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		const maxPoolBuf = 32 * 1024
		if cap(outBuf) > maxPoolBuf {
			outBuf = nil
		}
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Initial ClientHello record version:
			// - default to TLS1.0 for maximum compatibility (RFC 5246 legacy behavior)
			// - but if the caller explicitly capped MaxVersion to SSLv3, use SSLv3.
			vers = VersionTLS10
			if c.config != nil && c.config.MaxVersion == VersionSSL30 {
				vers = VersionSSL30
			}
		} else if vers == VersionTLS13 {
			vers = VersionTLS12
		}
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		var err error
		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}
		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			if a, ok := err.(Alert); ok {
				return n, c.sendAlertLocked(a)
			}
			return n, c.sendAlertLocked(AlertInternalError)
		}
	}

	return n, nil
}

func (c *Conn) writeRecord(typ recordType, data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writeRecordLocked(typ, data)
}

func (c *Conn) readHandshake() (any, error) {
	for c.hand.Len() < 4 {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}

	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		c.sendAlert(AlertInternalError)
		return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake))
	}
	for c.hand.Len() < 4+n {
		if err := c.readRecord(); err != nil {
			return nil, err
		}
	}
	data = c.hand.Next(4 + n)
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		if c.vers == VersionTLS13 {
			m = new(newSessionTicketMsgTLS13)
		} else {
			m = new(newSessionTicketMsg)
		}
	case typeCertificate:
		if c.vers == VersionTLS13 {
			m = new(certificateMsgTLS13)
		} else {
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if c.vers == VersionTLS13 {
			m = new(certificateRequestMsgTLS13)
		} else {
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: c.vers >= VersionTLS12,
			}
		}
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
	}

	// Always copy handshake messages.
	//
	// Most message structs keep references to the backing bytes (slices/fields and m.raw).
	// The handshake buffer can be re-used/overwritten by subsequent reads, so aliasing it
	// is unsafe and can cause corruption/panics under load.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, c.in.setErrorLocked(c.sendAlert(AlertUnexpectedMessage))
	}
	return m, nil
}

var errShutdown = errors.New("tls: protocol is shutdown")

func (c *Conn) Write(b []byte) (int, error) {
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			break
		}
	}
	defer atomic.AddInt32(&c.activeCall, -2)

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete() {
		return 0, AlertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n, c.out.setErrorLocked(err)
}

func (c *Conn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(AlertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(AlertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(AlertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		c.sendAlert(AlertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	atomic.StoreUint32(&c.handshakeStatus, 0)
	return c.handshakeErr
}

func (c *Conn) handlePostHandshakeMessage() error {
	if c.vers != VersionTLS13 {
		return c.handleRenegotiation()
	}
	// TLS 1.3 post handshake stub
	return errors.New("tls: post handshake not implemented")
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)

	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (c *Conn) Close() error {
	var x int32
	for {
		x = atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return net.ErrClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}

	if c.helloBuf != nil {
		helloBufPool.Put(c.helloBuf)
		c.helloBuf = nil
	}

	if x != 0 {
		return c.conn.Close()
	}

	var alertErr error
	if c.handshakeComplete() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

var errEarlyCloseWrite = errors.New("tls: CloseWrite called before handshake complete")

func (c *Conn) CloseWrite() error {
	if !c.handshakeComplete() {
		return errEarlyCloseWrite
	}

	return c.closeNotify()
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		c.closeNotifyErr = c.sendAlertLocked(AlertCloseNotify)
		c.closeNotifySent = true
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshake(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	return c.handshake(ctx)
}

func (c *Conn) Handshake() error {
	return c.handshake(context.Background())
}

func (c *Conn) handshake(ctx context.Context) (ret error) {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.isClient {
		if c.handshakeFn == nil {
			c.handshakeErr = errors.New("tls: internal error: missing handshake function")
		} else {
			c.handshakeErr = c.handshakeFn()
		}
	} else {
		// Server handshake removed
		c.handshakeErr = errors.New("tls: server handshake not implemented")
	}

	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		c.flush()
	}

	// ErrExpected is a cert-only early stop signal: not a completed handshake,
	// but also not an internal error.
	if c.handshakeErr == nil && !c.handshakeComplete() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr == ErrExpected {
		// Expected early-stop: keep it as the return value but don't treat it as a
		// missing-handshake-result internal error.
		return c.handshakeErr
	}

	return c.handshakeErr
}

func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.connectionStateLocked()
}

func (c *Conn) connectionStateLocked() ConnectionState {
	var state ConnectionState
	state.HandshakeComplete = c.handshakeComplete()
	state.Version = c.vers
	state.NegotiatedProtocol = c.clientProtocol
	state.DidResume = c.didResume
	state.NegotiatedProtocolIsMutual = true
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.SignedCertificateTimestamps = c.scts
	state.OCSPResponse = c.ocspResponse
	state.HandshakeLog = c.handshakeLog
	if !c.didResume && c.vers != VersionTLS13 {
		if c.clientFinishedIsFirst {
			state.TLSUnique = c.clientFinished[:]
		} else {
			state.TLSUnique = c.serverFinished[:]
		}
	}
	if c.config.Renegotiation != RenegotiateNever {
		// state.ekm = noExportedKeyingMaterial // Stub
	} else {
		state.ekm = c.ekm
	}
	return state
}

func (c *Conn) OCSPResponse() []byte {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	return c.ocspResponse
}

func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("tls: VerifyHostname called on TLS server connection")
	}
	if !c.handshakeComplete() {
		return errors.New("tls: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("tls: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}

func (c *Conn) handshakeComplete() bool {
	return atomic.LoadUint32(&c.handshakeStatus) == 1
}

func (c *Conn) Config() *Config {
	return c.config
}
