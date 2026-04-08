// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"crypto/x509"
)

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// hashForServerKeyExchange hashes the given slices and returns their digest using
// the given hash function (for >= TLS 1.2) or using a default based on the sigType
// (for earlier TLS versions). For Ed25519 signatures, which don't do pre-hashing,
// it returns the concatenation of the slices.
func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if version >= VersionTLS12 {
		h := hashFunc.New()
		for _, slice := range slices {
			h.Write(slice)
		}
		return h.Sum(nil)
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	return md5SHA1Hash(slices)
}

type keyAgreementAuthentication interface {
	verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error)
}

type signedKeyAgreement struct {
	version uint16
	sigType uint8
	raw     []byte
	valid   bool
	sh      SigAndHash
}

func (ka *signedKeyAgreement) verifyParameters(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, params []byte, sig []byte) ([]byte, error) {
	if len(sig) < 2 {
		return nil, errServerKeyExchange
	}

	var tls12HashId uint8
	if ka.version >= VersionTLS12 {
		var sigAndHash []uint8
		sigAndHash, sig = sig[:2], sig[2:]
		tls12HashId = sigAndHash[0]
		ka.sh.Hash = tls12HashId
		ka.sh.Signature = sigAndHash[1]
		if sigAndHash[1] != ka.sigType {
			return nil, errServerKeyExchange
		}
		if len(sig) < 2 {
			return nil, errServerKeyExchange
		}

		if !isSupportedSignatureAndHash(SigAndHash{ka.sigType, tls12HashId}, config.signatureAndHashesForClient()) {
			return nil, errors.New("tls: unsupported hash function for ServerKeyExchange")
		}
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return nil, errServerKeyExchange
	}
	sig = sig[2:]
	ka.raw = sig

	hashFunc := supportedHashFunc[tls12HashId]
	digest := hashForServerKeyExchange(ka.sigType, hashFunc, ka.version, clientHello.random, serverHello.random, params)
	switch ka.sigType {
	case signatureECDSA:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return digest, errors.New("ECDHE ECDSA: certificate key is not ECDSA")
		}
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return digest, err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return digest, errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return digest, errors.New("ECDSA verification failure")
		}
	case signatureRSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return digest, errors.New("ECDHE RSA requires a RSA server public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, sig); err != nil {
			return digest, err
		}
	case signatureDSA:
		pubKey, ok := cert.PublicKey.(*dsa.PublicKey)
		if !ok {
			return digest, errors.New("DSS ciphers require a DSA server public key")
		}
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(sig, dsaSig); err != nil {
			return digest, err
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return digest, errors.New("DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pubKey, digest, dsaSig.R, dsaSig.S) {
			return digest, errors.New("DSA verification failure")
		}
	default:
		return digest, errors.New("unknown ECDHE signature algorithm")
	}
	ka.valid = true
	return digest, nil
}

type rsaKeyAgreement struct {
	auth        keyAgreementAuthentication
	verifyError error
}

func (ka *rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka *rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, nil
}

func (ka *rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

func (ka *rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errClientKeyExchange
	}
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), publicKey, preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

type ecdheKeyAgreement struct {
	auth    keyAgreementAuthentication
	version uint16
	isRSA   bool
	params  ecdheParameters

	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte

	verifyError error
}

func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 {
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	params, err := generateECDHEParameters(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.params = params

	ka.preMasterSecret = params.SharedKey(publicKey)
	if ka.preMasterSecret == nil {
		return errServerKeyExchange
	}

	ourPublicKey := params.PublicKey()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= VersionTLS12 {
		signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])

		if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
			return errors.New("tls: certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errServerKeyExchange
	}

	// Calculate signed hash to store in digest
	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	skx.digest = signed

	_, ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverECDHEParams, sig)

	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}

type dheKeyAgreement struct {
	auth        keyAgreementAuthentication
	p, g        *big.Int
	yTheirs     *big.Int
	yOurs       *big.Int
	xOurs       *big.Int
	yServer     *big.Int
	yClient     *big.Int
	verifyError error
}

func (ka *dheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka *dheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, nil
}

func (ka *dheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	k := skx.key
	if len(k) < 2 {
		return errServerKeyExchange
	}
	pLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < pLen {
		return errServerKeyExchange
	}
	ka.p = new(big.Int).SetBytes(k[:pLen])
	k = k[pLen:]

	if len(k) < 2 {
		return errServerKeyExchange
	}
	gLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < gLen {
		return errServerKeyExchange
	}
	ka.g = new(big.Int).SetBytes(k[:gLen])
	k = k[gLen:]

	if len(k) < 2 {
		return errServerKeyExchange
	}
	yLen := (int(k[0]) << 8) | int(k[1])
	k = k[2:]
	if len(k) < yLen {
		return errServerKeyExchange
	}
	ka.yTheirs = new(big.Int).SetBytes(k[:yLen])
	ka.yServer = new(big.Int).Set(ka.yTheirs)
	k = k[yLen:]
	if ka.yTheirs.Sign() <= 0 || ka.yTheirs.Cmp(ka.p) >= 0 {
		return errServerKeyExchange
	}

	sig := k
	serverDHParams := skx.key[:len(skx.key)-len(sig)]

	_, ka.verifyError = ka.auth.verifyParameters(config, clientHello, serverHello, cert, serverDHParams, sig)
	if config.InsecureSkipVerify {
		return nil
	}
	return ka.verifyError
}

func (ka *dheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.p == nil || ka.g == nil || ka.yTheirs == nil {
		return nil, nil, errors.New("missing ServerKeyExchange message")
	}

	xOurs, err := rand.Int(config.rand(), ka.p)
	if err != nil {
		return nil, nil, err
	}
	preMasterSecret := new(big.Int).Exp(ka.yTheirs, xOurs, ka.p).Bytes()

	yOurs := new(big.Int).Exp(ka.g, xOurs, ka.p)
	ka.yOurs = yOurs
	ka.xOurs = xOurs
	ka.yClient = new(big.Int).Set(yOurs)
	yBytes := yOurs.Bytes()
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 2+len(yBytes))
	ckx.ciphertext[0] = byte(len(yBytes) >> 8)
	ckx.ciphertext[1] = byte(len(yBytes))
	copy(ckx.ciphertext[2:], yBytes)

	return preMasterSecret, ckx, nil
}
