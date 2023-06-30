// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
)

type UConn struct {
	Conn *Conn

	_Extensions    []TLSExtension
	_ClientHelloID _ClientHelloID

	_ClientHelloBuilt bool
	_HandshakeState   _ClientHandshakeState

	// sessionID may or may not depend on ticket; nil => random
	_GetSessionID func(ticket []byte) [32]byte

	greaseSeed [ssl_grease_last_index]uint16

	omitSNIExtension bool
}

// UClient returns a new uTLS client, with behavior depending on clientHelloID.
// Config CAN be nil, but make sure to eventually specify ServerName.
func UClient(conn net.Conn, config *_Config, clientHelloID _ClientHelloID) *UConn {
	if config == nil {
		config = &_Config{}
	}
	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := _ClientHandshakeState{_C: &tlsConn, _Hello: &_ClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, _ClientHelloID: clientHelloID, _HandshakeState: handshakeState}
	uconn._HandshakeState.uconn = &uconn
	return &uconn
}

// _BuildHandshakeState behavior varies based on ClientHelloID and
// whether it was already called before.
// If HelloGolang:
//
//	[only once] make default ClientHello and overwrite existing state
//
// If any other mimicking ClientHelloID is used:
//
//	[only once] make ClientHello based on ID and overwrite existing state
//	[each call] apply uconn.Extensions config to internal crypto/tls structures
//	[each call] marshal ClientHello.
//
// _BuildHandshakeState is automatically called before uTLS performs handshake,
// amd should only be called explicitly to inspect/change fields of
// default/mimicked ClientHello.
func (uconn *UConn) _BuildHandshakeState() error {
	if uconn._ClientHelloID == _HelloGolang {
		if uconn._ClientHelloBuilt {
			return nil
		}

		// use default Golang ClientHello.
		hello, ecdheParams, err := uconn.Conn.makeClientHello()
		if err != nil {
			return err
		}

		uconn._HandshakeState._Hello = hello.getPublicPtr()
		uconn._HandshakeState._State13._EcdheParams = ecdheParams
		uconn._HandshakeState._C = uconn.Conn
	} else {
		if !uconn._ClientHelloBuilt {
			err := uconn.applyPresetByID(uconn._ClientHelloID)
			if err != nil {
				return err
			}
			if uconn.omitSNIExtension {
				uconn.removeSNIExtension()
			}
		}

		err := uconn._ApplyConfig()
		if err != nil {
			return err
		}
		err = uconn._MarshalClientHello()
		if err != nil {
			return err
		}
	}
	uconn._ClientHelloBuilt = true
	return nil
}

// _SetSessionState sets the session ticket, which may be preshared or fake.
// If session is nil, the body of session ticket extension will be unset,
// but the extension itself still MAY be present for mimicking purposes.
// Session tickets to be reused - use same cache on following connections.
func (uconn *UConn) _SetSessionState(session *_ClientSessionState) error {
	uconn._HandshakeState._Session = session
	var sessionTicket []uint8
	if session != nil {
		sessionTicket = session.sessionTicket
	}
	uconn._HandshakeState._Hello._TicketSupported = true
	uconn._HandshakeState._Hello._SessionTicket = sessionTicket

	for _, ext := range uconn._Extensions {
		st, ok := ext.(*SessionTicketExtension)
		if !ok {
			continue
		}
		st._Session = session
		if session != nil {
			if len(session._SessionTicket()) > 0 {
				if uconn._GetSessionID != nil {
					sid := uconn._GetSessionID(session._SessionTicket())
					uconn._HandshakeState._Hello._SessionId = sid[:]
					return nil
				}
			}
			var sessionID [32]byte
			_, err := io.ReadFull(uconn.Conn.config.rand(), sessionID[:])
			if err != nil {
				return err
			}
			uconn._HandshakeState._Hello._SessionId = sessionID[:]
		}
		return nil
	}
	return nil
}

func (uconn *UConn) removeSNIExtension() {
	filteredExts := make([]TLSExtension, 0, len(uconn._Extensions))
	for _, e := range uconn._Extensions {
		if _, ok := e.(*SNIExtension); !ok {
			filteredExts = append(filteredExts, e)
		}
	}
	uconn._Extensions = filteredExts
}

// _Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (c *UConn) _Handshake() error {
	c.Conn.handshakeMutex.Lock()
	defer c.Conn.handshakeMutex.Unlock()

	if err := c.Conn.handshakeErr; err != nil {
		return err
	}
	if c.Conn.handshakeComplete() {
		return nil
	}

	c.Conn.in.Lock()
	defer c.Conn.in.Unlock()

	if c.Conn.isClient {
		// [uTLS section begins]
		err := c._BuildHandshakeState()
		if err != nil {
			return err
		}
		// [uTLS section ends]

		c.Conn.handshakeErr = c.clientHandshake()
	} else {
		c.Conn.handshakeErr = c.Conn.serverHandshake()
	}
	if c.Conn.handshakeErr == nil {
		c.Conn.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.Conn.flush()
	}

	if c.Conn.handshakeErr == nil && !c.Conn.handshakeComplete() {
		c.Conn.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}

	return c.Conn.handshakeErr
}

// Copy-pasted from tls.Conn in its entirety. But c.Handshake() is now utls' one, not tls.
// Write writes data to the connection.
func (c *UConn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.Conn.activeCall)
		if x&1 != 0 {
			return 0, errClosed
		}
		if atomic.CompareAndSwapInt32(&c.Conn.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.Conn.activeCall, -2)
			break
		}
	}

	if err := c._Handshake(); err != nil {
		return 0, err
	}

	c.Conn.out.Lock()
	defer c.Conn.out.Unlock()

	if err := c.Conn.out.err; err != nil {
		return 0, err
	}

	if !c.Conn.handshakeComplete() {
		return 0, alertInternalError
	}

	if c.Conn.closeNotifySent {
		return 0, errShutdown
	}

	// SSL 3.0 and TLS 1.0 are susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.Conn.vers <= VersionTLS10 {
		if _, ok := c.Conn.out.cipher.(cipher.BlockMode); ok {
			n, err := c.Conn.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.Conn.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := c.Conn.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.Conn.out.setErrorLocked(err)
}

// clientHandshakeWithOneState checks that exactly one expected state is set (1.2 or 1.3)
// and performs client TLS handshake with that state
func (c *UConn) clientHandshake() (err error) {
	// [uTLS section begins]
	hello := c._HandshakeState._Hello.getPrivatePtr()
	defer func() { c._HandshakeState._Hello = hello.getPublicPtr() }()

	sessionIsAlreadySet := c._HandshakeState._Session != nil

	// after this point exactly 1 out of 2 HandshakeState pointers is non-nil,
	// useTLS13 variable tells which pointer
	// [uTLS section ends]

	if c.Conn.config == nil {
		c.Conn.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.Conn.didResume = false

	// [uTLS section begins]
	// don't make new ClientHello, use hs.hello
	// preserve the checks from beginning and end of makeClientHello()
	if len(c.Conn.config._ServerName) == 0 && !c.Conn.config._InsecureSkipVerify {
		return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.Conn.config._NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}

	if c.Conn.handshakes > 0 {
		hello.secureRenegotiation = c.Conn.clientFinished[:]
	}
	// [uTLS section ends]

	cacheKey, session, earlySecret, binderKey := c.Conn.loadSession(hello)
	if cacheKey != "" && session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				c.Conn.config._ClientSessionCache._Put(cacheKey, nil)
			}
		}()
	}

	if !sessionIsAlreadySet { // uTLS: do not overwrite already set session
		err = c._SetSessionState(session)
		if err != nil {
			return
		}
	}

	if _, err := c.Conn.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}

	msg, err := c.Conn.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.Conn.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.Conn.pickTLSVersion(serverHello); err != nil {
		return err
	}

	// uTLS: do not create new handshakeState, use existing one
	if c.Conn.vers == VersionTLS13 {
		hs13 := c._HandshakeState.toPrivate13()
		hs13.serverHello = serverHello
		hs13.hello = hello
		if !sessionIsAlreadySet {
			hs13.earlySecret = earlySecret
			hs13.binderKey = binderKey
		}
		// In TLS 1.3, session tickets are delivered after the handshake.
		err = hs13.handshake()
		if handshakeState := hs13.toPublic13(); handshakeState != nil {
			c._HandshakeState = *handshakeState
		}
		return err
	}

	hs12 := c._HandshakeState.toPrivate12()
	hs12.serverHello = serverHello
	hs12.hello = hello
	err = hs12.handshake()
	if handshakeState := hs12.toPublic12(); handshakeState != nil {
		c._HandshakeState = *handshakeState
	}
	if err != nil {
		return err
	}

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one.
	if cacheKey != "" && hs12.session != nil && session != hs12.session {
		c.Conn.config._ClientSessionCache._Put(cacheKey, hs12.session)
	}
	return nil
}

func (uconn *UConn) _ApplyConfig() error {
	for _, ext := range uconn._Extensions {
		err := ext.writeToUConn(uconn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uconn *UConn) _MarshalClientHello() error {
	hello := uconn._HandshakeState._Hello
	headerLength := 2 + 32 + 1 + len(hello._SessionId) +
		2 + len(hello._CipherSuites)*2 +
		1 + len(hello._CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension
	for _, ext := range uconn._Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			// If not padding - just add length of extension to total length
			extensionsLen += ext.Len()
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("Multiple padding extensions!")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uconn._Extensions) > 0 {
		helloLen += 2 + extensionsLen // 2 bytes for extensions' length
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4) // 1 byte for tls record type, 3 for length
	// We use buffered Writer to avoid checking write errors after every Write(): whenever first error happens
	// Write() will become noop, and error will be accessible via Flush(), which is called once in the end

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)} // poor man's uint24
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello._Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello._Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello._SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello._SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello._CipherSuites)<<1))
	for _, suite := range hello._CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello._CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello._CompressionMethods)

	if len(uconn._Extensions) > 0 {
		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uconn._Extensions {
			bufferedWriter.ReadFrom(ext)
		}
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("utls: unexpected ClientHello length. Expected: " + strconv.Itoa(4+helloLen) +
			". Got: " + strconv.Itoa(helloBuffer.Len()))
	}

	hello._Raw = helloBuffer.Bytes()
	return nil
}

// _SetTLSVers sets min and max TLS version in all appropriate places.
// Function will use first non-zero version parsed in following order:
//  1. Provided minTLSVers, maxTLSVers
//  2. specExtensions may have SupportedVersionsExtension
//  3. [default] min = TLS 1.0, max = TLS 1.2
//
// Error is only returned if things are in clearly undesirable state
// to help user fix them.
func (uconn *UConn) _SetTLSVers(minTLSVers, maxTLSVers uint16, specExtensions []TLSExtension) error {
	if minTLSVers == 0 && maxTLSVers == 0 {
		// if version is not set explicitly in the ClientHelloSpec, check the SupportedVersions extension
		supportedVersionsExtensionsPresent := 0
		for _, e := range specExtensions {
			switch ext := e.(type) {
			case *SupportedVersionsExtension:
				findVersionsInSupportedVersionsExtensions := func(versions []uint16) (uint16, uint16) {
					// returns (minVers, maxVers)
					minVers := uint16(0)
					maxVers := uint16(0)
					for _, vers := range versions {
						if vers == _GREASE_PLACEHOLDER {
							continue
						}
						if maxVers < vers || maxVers == 0 {
							maxVers = vers
						}
						if minVers > vers || minVers == 0 {
							minVers = vers
						}
					}
					return minVers, maxVers
				}

				supportedVersionsExtensionsPresent += 1
				minTLSVers, maxTLSVers = findVersionsInSupportedVersionsExtensions(ext.Versions)
				if minTLSVers == 0 && maxTLSVers == 0 {
					return fmt.Errorf("SupportedVersions extension has invalid Versions field")
				} // else: proceed
			}
		}
		switch supportedVersionsExtensionsPresent {
		case 0:
			// if mandatory for TLS 1.3 extension is not present, just default to 1.2
			minTLSVers = VersionTLS10
			maxTLSVers = VersionTLS12
		case 1:
		default:
			return fmt.Errorf("uconn.Extensions contains %v separate SupportedVersions extensions",
				supportedVersionsExtensionsPresent)
		}
	}

	if minTLSVers < VersionTLS10 || minTLSVers > VersionTLS12 {
		return fmt.Errorf("uTLS does not support 0x%X as min version", minTLSVers)
	}

	if maxTLSVers < VersionTLS10 || maxTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as max version", maxTLSVers)
	}

	uconn._HandshakeState._Hello._SupportedVersions = makeSupportedVersions(minTLSVers, maxTLSVers)
	uconn.Conn.config._MinVersion = minTLSVers
	uconn.Conn.config._MaxVersion = maxTLSVers

	return nil
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}
