// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync"
	"time"

	"crypto/x509"
	"github.com/x-stp/rxds/internal/cpu"
)

var ErrExpected = errors.New("rxds: expected early exit")

type CertificateChain []*x509.Certificate

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	VersionSSL30 = 0x0300
	VersionSSL20 = 0x0002 // there we go again
)

const (
	maxPlaintext        = 16384        // maximum plaintext payload length
	maxCiphertext       = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13  = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen     = 5            // record header length
	dtlsRecordHeaderLen = 13
	maxHandshake        = 65536 // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords   = 16    // maximum number of consecutive non-advancing records

	minVersion = VersionSSL30
	maxVersion = VersionTLS13
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeHelloVerifyRequest  uint8 = 3
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionExtendedRandom          uint16 = 0x0028 // not IANA assigned
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
)

func (curveID *CurveID) String() string {
	switch *curveID {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case X25519:
		return "X25519"
	default:
		return fmt.Sprintf("CurveID(%d)", *curveID)
	}
}

type PointFormat uint8

const (
	pointFormatUncompressed PointFormat = 0
)

func (pFormat *PointFormat) String() string {
	switch *pFormat {
	case pointFormatUncompressed:
		return "uncompressed"
	default:
		return fmt.Sprintf("PointFormat(%d)", *pFormat)
	}
}

// TLS 1.3 Key Share.
type keyShare struct {
	group CurveID
	data  []byte
}

// TLS 1.3 PSK Key Exchange Modes.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

const (
	statusTypeOCSP uint8 = 1
)

const (
	certTypeRSASign        = 1
	certTypeDSSSign        = 2
	certTypeRSAFixedDH     = 3
	certTypeDSSFixedDH     = 4
	certTypeECDSASign      = 64
	certTypeRSAFixedECDH   = 65
	certTypeECDSAFixedECDH = 66
)

const (
	hashNone      uint8 = 0
	hashMD5       uint8 = 1
	hashSHA1      uint8 = 2
	hashSHA224    uint8 = 3
	hashSHA256    uint8 = 4
	hashSHA384    uint8 = 5
	hashSHA512    uint8 = 6
	hashIntrinsic uint8 = 8
)

var supportedHashFunc = map[uint8]crypto.Hash{
	hashMD5:    crypto.MD5,
	hashSHA1:   crypto.SHA1,
	hashSHA224: crypto.SHA224,
	hashSHA256: crypto.SHA256,
	hashSHA384: crypto.SHA384,
	hashSHA512: crypto.SHA512,
}

const (
	// signatureRSA is the legacy value used in the TLS 1.0–1.2 ServerKeyExchange
	// hash-and-signature encoding (RFC 5246 Section 7.4.1.4.1, value 1).
	// It is NOT the same as signaturePKCS1v15 which is an internal rxds enum
	// used in TLS 1.3 CertificateVerify / auth.go dispatch.
	signatureRSA      uint8 = 1
	signatureDSA      uint8 = 2
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
)

type SigAndHash struct {
	Signature, Hash uint8
}

var supportedSKXSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA512},
	{signatureECDSA, hashSHA512},
	{signatureDSA, hashSHA512},
	{signatureRSA, hashSHA384},
	{signatureECDSA, hashSHA384},
	{signatureDSA, hashSHA384},
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureDSA, hashSHA256},
	{signatureRSA, hashSHA224},
	{signatureECDSA, hashSHA224},
	{signatureDSA, hashSHA224},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
	{signatureDSA, hashSHA1},
	{signatureRSA, hashMD5},
	{signatureECDSA, hashMD5},
	{signatureDSA, hashMD5},
}

var defaultSKXSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
	{signatureRSA, hashSHA1},
	{signatureECDSA, hashSHA1},
	{signatureRSA, hashSHA256},
	{signatureRSA, hashSHA384},
	{signatureRSA, hashSHA512},
}

var supportedClientCertSignatureAlgorithms = []SigAndHash{
	{signatureRSA, hashSHA256},
	{signatureECDSA, hashSHA256},
}

var directSigning crypto.Hash = 0

// SignatureScheme identifies a signature algorithm supported by TLS.
type SignatureScheme uint16

const (
	PKCS1WithSHA256        SignatureScheme = 0x0401
	PKCS1WithSHA384        SignatureScheme = 0x0501
	PKCS1WithSHA512        SignatureScheme = 0x0601
	PSSWithSHA256          SignatureScheme = 0x0804
	PSSWithSHA384          SignatureScheme = 0x0805
	PSSWithSHA512          SignatureScheme = 0x0806
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	Ed25519                SignatureScheme = 0x0807
	EdDSAWithEd25519       SignatureScheme = 0x0807
	EdDSAWithEd448         SignatureScheme = 0x0808
	PKCS1WithSHA1          SignatureScheme = 0x0201
	ECDSAWithSHA1          SignatureScheme = 0x0203
)

var supportedSignatureAlgorithms = []SignatureScheme{
	PSSWithSHA256,
	ECDSAWithP256AndSHA256,
	Ed25519,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,
	PKCS1WithSHA1,
	ECDSAWithSHA1,
}

var signatureAlgorithms = map[SignatureScheme]SigAndHash{
	PSSWithSHA256:          {signatureRSA, hashSHA256},
	ECDSAWithP256AndSHA256: {signatureECDSA, hashSHA256},
	Ed25519:                {signatureEd25519, hashSHA256},
	PSSWithSHA384:          {signatureRSA, hashSHA384},
	PSSWithSHA512:          {signatureRSA, hashSHA512},
	PKCS1WithSHA256:        {signatureRSA, hashSHA256},
	PKCS1WithSHA384:        {signatureRSA, hashSHA384},
	PKCS1WithSHA512:        {signatureRSA, hashSHA512},
	ECDSAWithP384AndSHA384: {signatureECDSA, hashSHA384},
	ECDSAWithP521AndSHA512: {signatureECDSA, hashSHA512},
	PKCS1WithSHA1:          {signatureRSA, hashSHA1},
	ECDSAWithSHA1:          {signatureECDSA, hashSHA1},
}

var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// HandshakeLog captures structured handshake metadata for scan analysis.
// Populated only when Config.CertsOnly is true and the handshake reaches
// the relevant messages. Inspired by zcrypto-style transcript logging.
type HandshakeLog struct {
	ClientHelloRaw []byte `json:"client_hello_raw,omitempty"`
	ServerHelloRaw []byte `json:"server_hello_raw,omitempty"`
	ServerVersion  uint16 `json:"server_version,omitempty"`
	ServerRandom   []byte `json:"server_random,omitempty"`
	ServerCipher   uint16 `json:"server_cipher,omitempty"`
}

type ConnectionState struct {
	Version                     uint16
	HandshakeComplete           bool
	DidResume                   bool
	CipherSuite                 uint16
	NegotiatedProtocol          string
	NegotiatedProtocolIsMutual  bool
	ServerName                  string
	PeerCertificates            []*x509.Certificate
	VerifiedChains              []CertificateChain
	SignedCertificateTimestamps [][]byte
	OCSPResponse                []byte
	TLSUnique                   []byte
	HandshakeLog                *HandshakeLog
	ekm                         func(label string, context []byte, length int) ([]byte, error)
}

func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if cs.ekm == nil {
		return nil, errors.New("tls: ExportKeyingMaterial is not available")
	}
	return cs.ekm(label, context, length)
}

type ClientSessionState struct {
	sessionTicket      []uint8
	lifetimeHint       uint32
	vers               uint16
	cipherSuite        uint16
	masterSecret       []byte
	serverCertificates []*x509.Certificate
	verifiedChains     []CertificateChain
	receivedAt         time.Time
	ocspResponse       []byte
	scts               [][]byte
	nonce              []byte
	useBy              time.Time
	ageAdd             uint32
}

type ClientSessionCache interface {
	Get(sessionKey string) (session *ClientSessionState, ok bool)
	Put(sessionKey string, cs *ClientSessionState)
}

type ClientHelloInfo struct {
	CipherSuites      []uint16
	ServerName        string
	SupportedCurves   []CurveID
	SupportedPoints   []uint8
	SignatureSchemes  []SignatureScheme
	SupportedProtos   []string
	SupportedVersions []uint16
	Conn              net.Conn
	config            *Config
}

type CertificateRequestInfo struct {
	AcceptableCAs    [][]byte
	SignatureSchemes []SignatureScheme
	Version          uint16
}

type RenegotiationSupport int

const (
	RenegotiateNever RenegotiationSupport = iota
	RenegotiateOnceAsClient
	RenegotiateFreelyAsClient
)

type Config struct {
	Rand                          io.Reader
	Time                          func() time.Time
	Certificates                  []Certificate
	NameToCertificate             map[string]*Certificate
	GetCertificate                func(*ClientHelloInfo) (*Certificate, error)
	GetClientCertificate          func(*CertificateRequestInfo) (*Certificate, error)
	GetConfigForClient            func(*ClientHelloInfo) (*Config, error)
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains []CertificateChain) error
	VerifyConnection              func(ConnectionState) error
	RootCAs                       *x509.CertPool
	NextProtos                    []string
	ServerName                    string
	ClientAuth                    int
	ClientCAs                     *x509.CertPool
	InsecureSkipVerify            bool
	CipherSuites                  []uint16
	PreferServerCipherSuites      bool
	SessionTicketsDisabled        bool
	SessionTicketKey              [32]byte
	ClientSessionCache            ClientSessionCache
	MinVersion                    uint16
	MaxVersion                    uint16
	CurvePreferences              []CurveID
	ExplicitCurvePreferences      bool
	SupportedPoints               []uint8
	NoOcspStapling                bool
	CompressionMethods            []uint8
	SignatureAndHashes            []SigAndHash
	ForceSuites                   bool
	ExportRSAKey                  *rsa.PrivateKey
	HeartbeatEnabled              bool
	ClientDSAEnabled              bool
	ExtendedRandom                bool
	ForceSessionTicketExt         bool
	ExtendedMasterSecret          bool
	SignedCertificateTimestampExt bool
	ClientRandom                  []byte
	ServerRandom                  []byte
	ExternalClientHello           []byte
	CertsOnly                     bool
	DontBufferHandshakes          bool
	DynamicRecordSizingDisabled   bool
	Renegotiation                 RenegotiationSupport
	KeyLogWriter                  io.Writer
	SSLv2ClientHello              bool

	mutex                 sync.RWMutex
	sessionTicketKeys     []ticketKey
	autoSessionTicketKeys []ticketKey

	helloCache *helloTemplateCache
}

type helloFieldOffsets struct {
	random   int // 32 bytes
	session  int // 32 bytes
	keyShare int // 32 bytes; 0 if no TLS 1.3
}

type helloTemplateCache struct {
	once     sync.Once
	template []byte
	msg      *clientHelloMsg
	offsets  helloFieldOffsets
	err      error
}

const (
	ticketKeyNameLen  = 16
	ticketKeyLifetime = 7 * 24 * time.Hour
	ticketKeyRotation = 24 * time.Hour
)

type ticketKey struct {
	keyName [ticketKeyNameLen]byte
	aesKey  [16]byte
	hmacKey [16]byte
	created time.Time
}

func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	copy(key.keyName[:], hashed[:ticketKeyNameLen])
	copy(key.aesKey[:], hashed[ticketKeyNameLen:ticketKeyNameLen+16])
	copy(key.hmacKey[:], hashed[ticketKeyNameLen+16:ticketKeyNameLen+32])
	key.created = c.time()
	return key
}

const maxSessionTicketLifetime = 7 * 24 * time.Hour

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Deep-copy internal mutable slices to avoid aliasing between clones.
	var stk []ticketKey
	if len(c.sessionTicketKeys) > 0 {
		stk = append([]ticketKey(nil), c.sessionTicketKeys...)
	}
	var astk []ticketKey
	if len(c.autoSessionTicketKeys) > 0 {
		astk = append([]ticketKey(nil), c.autoSessionTicketKeys...)
	}
	return &Config{
		Rand:                          c.Rand,
		Time:                          c.Time,
		Certificates:                  c.Certificates,
		NameToCertificate:             c.NameToCertificate,
		GetCertificate:                c.GetCertificate,
		GetClientCertificate:          c.GetClientCertificate,
		GetConfigForClient:            c.GetConfigForClient,
		VerifyPeerCertificate:         c.VerifyPeerCertificate,
		VerifyConnection:              c.VerifyConnection,
		RootCAs:                       c.RootCAs,
		NextProtos:                    c.NextProtos,
		ServerName:                    c.ServerName,
		ClientAuth:                    c.ClientAuth,
		ClientCAs:                     c.ClientCAs,
		InsecureSkipVerify:            c.InsecureSkipVerify,
		CipherSuites:                  c.CipherSuites,
		PreferServerCipherSuites:      c.PreferServerCipherSuites,
		SessionTicketsDisabled:        c.SessionTicketsDisabled,
		SessionTicketKey:              c.SessionTicketKey,
		ClientSessionCache:            c.ClientSessionCache,
		MinVersion:                    c.MinVersion,
		MaxVersion:                    c.MaxVersion,
		CurvePreferences:              c.CurvePreferences,
		DynamicRecordSizingDisabled:   c.DynamicRecordSizingDisabled,
		Renegotiation:                 c.Renegotiation,
		KeyLogWriter:                  c.KeyLogWriter,
		ExplicitCurvePreferences:      c.ExplicitCurvePreferences,
		SignatureAndHashes:            c.SignatureAndHashes,
		ForceSuites:                   c.ForceSuites,
		ExportRSAKey:                  c.ExportRSAKey,
		HeartbeatEnabled:              c.HeartbeatEnabled,
		ClientDSAEnabled:              c.ClientDSAEnabled,
		ExtendedRandom:                c.ExtendedRandom,
		ForceSessionTicketExt:         c.ForceSessionTicketExt,
		ExtendedMasterSecret:          c.ExtendedMasterSecret,
		SignedCertificateTimestampExt: c.SignedCertificateTimestampExt,
		ClientRandom:                  c.ClientRandom,
		ExternalClientHello:           c.ExternalClientHello,
		CertsOnly:                     c.CertsOnly,
		DontBufferHandshakes:          c.DontBufferHandshakes,
		sessionTicketKeys:             stk,
		autoSessionTicketKeys:         astk,
		SupportedPoints:               c.SupportedPoints,
		NoOcspStapling:                c.NoOcspStapling,
		CompressionMethods:            c.CompressionMethods,
		ServerRandom:                  c.ServerRandom,
		SSLv2ClientHello:              c.SSLv2ClientHello,
		helloCache:                    c.helloCache,
	}
}

var deprecatedSessionTicketKey = []byte("DEPRECATED")

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
	// Deprecated/broken but useful for cert harvesting against ancient endpoints.
	VersionSSL30,
}

func (c *Config) supportedVersions() []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) minSupportedVersion() uint16 {
	supportedVersions := c.supportedVersions()
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[len(supportedVersions)-1]
}

func (c *Config) maxSupportedVersion() uint16 {
	supportedVersions := c.supportedVersions()
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

var defaultCurvePreferences = []CurveID{X25519, CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	if c.ExplicitCurvePreferences {
		return c.CurvePreferences
	}
	return c.CurvePreferences
}

func (c *Config) supportsCurve(curve CurveID) bool {
	for _, cc := range c.curvePreferences() {
		if cc == curve {
			return true
		}
	}
	return false
}

func (c *Config) mutualVersion(peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions()
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

var errNoCertificates = errors.New("tls: no certificates configured")

func (c *Config) signatureAndHashesForClient() []SigAndHash {
	if c != nil && c.SignatureAndHashes != nil {
		return c.SignatureAndHashes
	}
	if c.ClientDSAEnabled {
		return supportedSKXSignatureAlgorithms
	}
	return defaultSKXSignatureAlgorithms
}

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := []byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret))

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

var writerMutex sync.Mutex

type Certificate struct {
	Certificate                  [][]byte          `json:"certificate_chain,omitempty"`
	PrivateKey                   crypto.PrivateKey `json:"-"`
	SupportedSignatureAlgorithms []SignatureScheme `json:"supported_sig_algos,omitempty"`
	OCSPStaple                   []byte            `json:"ocsp_staple,omitempty"`
	SignedCertificateTimestamps  [][]byte          `json:"signed_cert_timestamps,omitempty"`
	Leaf                         *x509.Certificate `json:"leaf,omitempty"`
}

func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, errNoCertificates
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var emptyConfig = Config{
	// Cert-only scanning defaults.
	// - CertsOnly: stop after receiving the server certificate chain.
	// - InsecureSkipVerify: avoid x509.Verify path building by default.
	CertsOnly:          true,
	InsecureSkipVerify: true,
}

func defaultConfig() *Config {
	return emptyConfig.Clone()
}

var (
	once                        sync.Once
	varDefaultCipherSuites      []uint16
	varDefaultCipherSuitesTLS13 []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func defaultCipherSuitesTLS13() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuitesTLS13
}

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

func initDefaultCipherSuites() {
	var topCipherSuites []uint16

	if hasAESGCMHardwareSupport {
		topCipherSuites = []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_256_GCM_SHA384,
		}
	} else {
		topCipherSuites = []uint16{
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
		}
	}

	varDefaultCipherSuites = make([]uint16, 0, len(implementedCipherSuites))
	varDefaultCipherSuites = append(varDefaultCipherSuites, topCipherSuites...)

NextCipherSuite:
	for _, suite := range implementedCipherSuites {
		if suite.flags&suiteDefaultOff != 0 {
			continue
		}
		for _, existing := range varDefaultCipherSuites {
			if existing == suite.id {
				continue NextCipherSuite
			}
		}
		varDefaultCipherSuites = append(varDefaultCipherSuites, suite.id)
	}
}

func unexpectedMessageError(wanted, got any) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func isSupportedSignatureAlgorithm(sigAlg SignatureScheme, supportedSignatureAlgorithms []SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}

func isSupportedSignatureAndHash(sigHash SigAndHash, sigHashes []SigAndHash) bool {
	for _, s := range sigHashes {
		if s == sigHash {
			return true
		}
	}
	return false
}

var aesgcmCiphers = map[uint16]bool{
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	TLS_AES_128_GCM_SHA256:                  true,
	TLS_AES_256_GCM_SHA384:                  true,
}

var nonAESGCMAEADCiphers = map[uint16]bool{
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:   true,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: true,
	TLS_CHACHA20_POLY1305_SHA256:           true,
}
