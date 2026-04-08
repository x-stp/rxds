// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"crypto/x509"
)

type clientHandshakeState struct {
	c               *Conn
	serverHello     *serverHelloMsg
	hello           *clientHelloMsg
	suite           *cipherSuite
	finishedHash    finishedHash
	masterSecret    []byte
	preMasterSecret []byte
	session         *ClientSessionState
}

// Helper to write V2 ClientHello
// RFC 6101 Appendix E.2.1 specifies the V2 ClientHello format.
// We use this to trigger legacy servers that might not respond to a modern TLS ClientHello,
// or to identify themselves as SSLv2/v3 capable.
//
// V2Msg = <Header> <Msg>
// Header = <1 byte: 0x80 | len_high> <1 byte: len_low>
// Msg = <1 byte: msg_type(1)> <2 bytes: version> <2 bytes: cipher_spec_len> <2 bytes: session_id_len> <2 bytes: challenge_len> ...
func (c *Conn) writeV2ClientHello(hello *clientHelloMsg) error {
	cipherSpecsLen := len(hello.cipherSuites) * 3
	sessionIdLen := 0 // RFC 6101 E.1: V2 ClientHello session_id_length must be 0
	challengeLen := len(hello.random)

	bodyLen := 1 + 2 + 2 + 2 + 2 + cipherSpecsLen + sessionIdLen + challengeLen
	v2Hello := make([]byte, 2+bodyLen)

	v2Hello[0] = 0x80 | uint8(bodyLen>>8)
	v2Hello[1] = uint8(bodyLen)

	v2Hello[2] = 1
	v2Hello[3] = uint8(hello.vers >> 8)
	v2Hello[4] = uint8(hello.vers)
	v2Hello[5] = uint8(cipherSpecsLen >> 8)
	v2Hello[6] = uint8(cipherSpecsLen)
	v2Hello[7] = uint8(sessionIdLen >> 8)
	v2Hello[8] = uint8(sessionIdLen)
	v2Hello[9] = uint8(challengeLen >> 8)
	v2Hello[10] = uint8(challengeLen)

	offset := 11
	for _, suite := range hello.cipherSuites {
		v2Hello[offset] = 0
		v2Hello[offset+1] = uint8(suite >> 8)
		v2Hello[offset+2] = uint8(suite)
		offset += 3
	}

	copy(v2Hello[offset:], hello.random)

	_, err := c.conn.Write(v2Hello)
	return err
}

func (c *Conn) makeClientHello() (*clientHelloMsg, ecdheParameters, error) {
	// Slow path: builds a full ClientHello from scratch. The fast path
	// (Config.patchHello via helloTemplateCache) skips this entirely after
	// the first dial by patching a pre-built template.
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions()
	if len(supportedVersions) == 0 {
		return nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	clientHelloVersion := config.maxSupportedVersion()
	if clientHelloVersion > VersionTLS12 {
		clientHelloVersion = VersionTLS12
	}

	hello := &clientHelloMsg{
		vers:                         clientHelloVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(),
		supportedPoints:              []uint8{uint8(pointFormatUncompressed)}, // Cast fixed
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	possibleCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

	for _, suiteId := range possibleCipherSuites {
		for _, suite := range implementedCipherSuites {
			if suite.id != suiteId {
				continue
			}
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				break
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			break
		}
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: short read from Rand: %w", err)
	}

	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
		return nil, nil, fmt.Errorf("tls: short read from Rand: %w", err)
	}

	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	if config.ExtendedMasterSecret {
		hello.extendedMasterSecret = true
	}

	var params ecdheParameters
	if hello.supportedVersions[0] == VersionTLS13 {
		hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13()...)

		curveID := config.curvePreferences()[0]
		if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
			return nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		}
		params, err = generateECDHEParameters(config.rand(), curveID)
		if err != nil {
			return nil, nil, err
		}
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	return hello, params, nil
}

// clientHandshake performs the client side of the TLS handshake.
// RFC 8446 Section 4.4.2 (Certificate) and Section 4.4.3 (CertificateVerify) are key here.
// For scanning, we implement an early exit mechanism via ErrExpected.
func (c *Conn) clientHandshake() (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}
	var hello *clientHelloMsg
	var ecdheParams ecdheParameters
	var session *ClientSessionState
	var cacheKey string
	var earlySecret, binderKey []byte

	c.didResume = false

	if c.config.ExternalClientHello != nil {
		hello = new(clientHelloMsg)
		if !hello.unmarshal(c.config.ExternalClientHello) {
			return errors.New("could not read the ClientHello provided")
		}
		hello.raw = nil
		session = nil

		if len(hello.supportedVersions) > 0 && hello.supportedVersions[0] == VersionTLS13 || len(hello.keyShares) > 0 {
			return errors.New("tls: ExternalClientHello is not supported for TLS 1.3 (missing key share private key)")
		}
	} else if raw, h, params, err := c.config.patchHello(); err == nil {
		hello = h
		hello.raw = raw
		ecdheParams = params
	} else {
		var err error
		hello, ecdheParams, err = c.makeClientHello()
		if err != nil {
			return err
		}
	}
	c.serverName = hello.serverName

	cacheKey, session, earlySecret, binderKey = c.loadSession(hello)
	if cacheKey != "" && session != nil {
		defer func() {
			if err != nil {
				c.config.ClientSessionCache.Put(cacheKey, nil)
			}
		}()
	}

	if c.config.ForceSessionTicketExt {
		hello.ticketSupported = true
	}

	if c.config.SignedCertificateTimestampExt {
		hello.sctEnabled = true
	}

	if c.config.SSLv2ClientHello {
		if err := c.writeV2ClientHello(hello); err != nil {
			return err
		}
	} else {
		if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
			return err
		}
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	if c.config.CertsOnly {
		c.handshakeLog = &HandshakeLog{
			ClientHelloRaw: hello.marshal(),
			ServerHelloRaw: serverHello.marshal(),
			ServerVersion:  c.vers,
			ServerRandom:   serverHello.random,
			ServerCipher:   serverHello.cipherSuite,
		}
	}

	// Downgrade canary checks. RFC 8446 Section 4.1.3.
	maxVers := c.config.maxSupportedVersion()
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(AlertIllegalParameter)
		return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	}

	if c.vers == VersionTLS13 {
		hs13 := &clientHandshakeStateTLS13{
			c:           c,
			serverHello: serverHello,
			hello:       hello,
			ecdheParams: ecdheParams,
			session:     session,
			earlySecret: earlySecret,
			binderKey:   binderKey,
		}
		// In TLS 1.3, session tickets are delivered after the handshake.
		return hs13.handshake()
	}

	hs := &clientHandshakeState{
		c:           c,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}

	if err := hs.handshake(); err != nil {
		return err
	}

	if cacheKey != "" && hs.session != nil && session != hs.session {
		c.config.ClientSessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

func (c *Conn) loadSession(hello *clientHelloMsg) (string, *ClientSessionState, []byte, []byte) {
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return "", nil, nil, nil
	}

	hello.ticketSupported = true

	if c.handshakes != 0 {
		return "", nil, nil, nil
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	session, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || session == nil {
		return cacheKey, nil, nil, nil
	}

	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.vers {
			versOk = true
			break
		}
	}
	if !versOk {
		return cacheKey, nil, nil, nil
	}

	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			return cacheKey, nil, nil, nil
		}
		serverCert := session.serverCertificates[0]
		if c.config.time().After(serverCert.NotAfter) {
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return cacheKey, nil, nil, nil
		}
		if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
			return cacheKey, nil, nil, nil
		}
	}

	if session.vers != VersionTLS13 {
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return cacheKey, nil, nil, nil
		}

		hello.sessionTicket = session.sessionTicket
		return cacheKey, session, nil, nil
	}

	return cacheKey, session, nil, nil
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion([]uint16{peerVersion})
	if !ok {
		c.sendAlert(AlertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion)
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(AlertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(AlertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		if !hs.serverHello.ocspStapling {
			c.sendAlert(AlertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}
		hs.finishedHash.Write(cs.marshal())
		c.ocspResponse = cs.response
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(AlertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(AlertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := certificateRequestInfoFromMsg(c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(AlertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	var ckx *clientKeyExchangeMsg
	hs.preMasterSecret, ckx, err = keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(AlertInternalError)
		return err
	}

	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(AlertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(AlertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(AlertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(AlertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(AlertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, hs.preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(AlertInternalError)
		return fmt.Errorf("tls: failed to write to key log: %w", err)
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(AlertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(AlertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(AlertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(AlertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(AlertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(AlertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		lifetimeHint:       sessionTicketMsg.lifetimeHint,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())

	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(AlertBadCertificate)
			return fmt.Errorf("tls: failed to parse certificate from server: %w", err)
		}
		certs[i] = cert
	}

	// Cert-only scanning default: avoid costly path building unless the caller
	// explicitly requested verification (InsecureSkipVerify=false).
	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(AlertBadCertificate)
			return err
		}

		if chains != nil {
			c.verifiedChains = make([]CertificateChain, len(chains))
			for i, chain := range chains {
				c.verifiedChains[i] = CertificateChain(chain)
			}
		}
	}

	// Scanner mode: when CertsOnly is enabled we want to accept *any* key type so
	// we can harvest certificates from exotic/legacy PKIs (e.g. SM2, GOST, etc.).
	// In normal TLS mode we keep the key-type gate to fail early before the
	// handshake tries to verify signatures using an unsupported public key type.
	if !c.config.CertsOnly {
		switch certs[0].PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *dsa.PublicKey:
			// supported
		default:
			c.sendAlert(AlertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
		}
	}

	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			if err == ErrExpected {
				c.sendAlert(AlertCloseNotify)
				return err
			}
			c.sendAlert(AlertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(AlertBadCertificate)
			return err
		}
	}

	// Cert-only scanner mode: stop as soon as we have the peer certificates
	// (and optional OCSP/SCT already parsed by the handshake).
	if c.config.CertsOnly {
		return ErrExpected
	}

	return nil
}

func certificateRequestInfoFromMsg(vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

func mutualProtocol(protos, preferenceProtos []string) string {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s
			}
		}
	}
	return ""
}

func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
