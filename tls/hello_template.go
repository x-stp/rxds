// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package tls

import (
	"bytes"
	"errors"
	"io"
)

var errNoTemplate = errors.New("tls: hello template not available")

// WarmHelloTemplate pre-builds the ClientHello template so clones of this
// Config inherit the cached wire bytes. Safe to call concurrently.
func (c *Config) WarmHelloTemplate() {
	tc := c.getHelloCache()
	tc.once.Do(func() { tc.build(c) })
}

func (c *Config) getHelloCache() *helloTemplateCache {
	c.mutex.RLock()
	tc := c.helloCache
	c.mutex.RUnlock()
	if tc != nil {
		return tc
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.helloCache == nil {
		c.helloCache = new(helloTemplateCache)
	}
	return c.helloCache
}

func (tc *helloTemplateCache) build(cfg *Config) {
	dummy := &Conn{
		config:   cfg,
		isClient: true,
	}

	hello, _, err := dummy.makeClientHello()
	if err != nil {
		tc.err = err
		return
	}

	raw := hello.marshal()
	if raw == nil {
		tc.err = errors.New("tls: failed to marshal template ClientHello")
		return
	}

	randomOff := bytes.Index(raw, hello.random)
	if randomOff < 0 || randomOff+32 > len(raw) {
		tc.err = errors.New("tls: could not locate random in template")
		return
	}

	sessionOff := bytes.Index(raw, hello.sessionId)
	if sessionOff < 0 || sessionOff+32 > len(raw) {
		tc.err = errors.New("tls: could not locate sessionId in template")
		return
	}

	var keyShareOff int
	if len(hello.keyShares) > 0 && len(hello.keyShares[0].data) == 32 {
		keyShareOff = bytes.Index(raw, hello.keyShares[0].data)
		if keyShareOff < 0 || keyShareOff+32 > len(raw) {
			tc.err = errors.New("tls: could not locate keyShare in template")
			return
		}
	}

	hello.raw = nil

	tc.template = raw
	tc.msg = hello
	tc.offsets = helloFieldOffsets{
		random:   randomOff,
		session:  sessionOff,
		keyShare: keyShareOff,
	}
}

// patchHello copies the pre-built template and patches the per-connection
// random, session ID, and key share. Returns the wire bytes, a clientHelloMsg
// with patched fields, and the ECDHE parameters for TLS 1.3.
func (c *Config) patchHello() ([]byte, *clientHelloMsg, ecdheParameters, error) {
	tc := c.getHelloCache()
	tc.once.Do(func() { tc.build(c) })
	if tc.template == nil {
		return nil, nil, nil, errNoTemplate
	}

	tmpl := tc.template
	off := tc.offsets

	raw := make([]byte, len(tmpl))
	copy(raw, tmpl)

	r := c.rand()

	if _, err := io.ReadFull(r, raw[off.random:off.random+32]); err != nil {
		return nil, nil, nil, err
	}
	if _, err := io.ReadFull(r, raw[off.session:off.session+32]); err != nil {
		return nil, nil, nil, err
	}

	hello := tc.msg.cloneForPatch()
	hello.random = raw[off.random : off.random+32]
	hello.sessionId = raw[off.session : off.session+32]
	hello.raw = raw

	var params ecdheParameters
	if off.keyShare > 0 {
		curveID := c.curvePreferences()[0]
		var err error
		params, err = generateECDHEParameters(r, curveID)
		if err != nil {
			return nil, nil, nil, err
		}
		pub := params.PublicKey()
		copy(raw[off.keyShare:off.keyShare+32], pub)
		hello.keyShares = []keyShare{{group: curveID, data: pub}}
	}

	return raw, hello, params, nil
}

func (m *clientHelloMsg) cloneForPatch() *clientHelloMsg {
	c := *m
	c.raw = nil
	c.random = nil
	c.sessionId = nil
	c.keyShares = nil
	return &c
}
