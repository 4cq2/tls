// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
)

type _Transport struct {
	_Conn *_UConn
	_Spec _ClientHelloSpec
}

func (t *_Transport) _RoundTrip(req *http.Request) (*http.Response, error) {
	conf := _Config{_ServerName: req.URL.Host}
	conn, err := net.Dial("tcp", req.URL.Host+":443")
	if err != nil {
		return nil, err
	}
	t._Conn = _UClient(conn, &conf, _HelloCustom)
	if err := t._Conn._ApplyPreset(&t._Spec); err != nil {
		return nil, err
	}
	if err := req.Write(t._Conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(t._Conn.Conn), req)
}

var _Android_API_26 = _ClientHelloSpec{
	_CipherSuites: []uint16{
		_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		_TLS_RSA_WITH_AES_128_GCM_SHA256,
		_TLS_RSA_WITH_AES_256_GCM_SHA384,
		_TLS_RSA_WITH_AES_128_CBC_SHA,
		_TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	_Extensions: []TLSExtension{
		&RenegotiationInfoExtension{},
		&SNIExtension{},
		&UtlsExtendedMasterSecretExtension{},
		&SessionTicketExtension{},
		&SignatureAlgorithmsExtension{
			_SupportedSignatureAlgorithms: []_SignatureScheme{
				_ECDSAWithP256AndSHA256,
			},
		},
		&StatusRequestExtension{},
		&_ALPNExtension{
			_AlpnProtocols: []string{"http/1.1"},
		},
		&SupportedPointsExtension{
			_SupportedPoints: []uint8{pointFormatUncompressed},
		},
		&SupportedCurvesExtension{
			_Curves: []_CurveID{
				_X25519,
				_CurveP256,
				_CurveP384,
			},
		},
	},
}

type builder []byte

func (b *builder) _Add_Bytes(v []byte) {
	*b = append(*b, v...)
}

func (b *builder) _Add_String(v string) {
	*b = append(*b, v...)
}

func (b *builder) add_uint16(v uint16) {
	*b = binary.BigEndian.AppendUint16(*b, v)
}

func (b *builder) add_uint16_prefixed(f continuation) {
	var child builder
	f(&child)
	length := uint16(len(child))
	b.add_uint16(length)
	*b = append(*b, child...)
}

func (b *builder) add_uint24(v uint32) {
	child := binary.BigEndian.AppendUint32(nil, v)
	*b = append(*b, child[1:]...)
}

func (b *builder) add_uint24_prefixed(f continuation) {
	var child builder
	f(&child)
	length := uint32(len(child))
	b.add_uint24(length)
	*b = append(*b, child...)
}

func (b *builder) add_uint32(v uint32) {
	*b = binary.BigEndian.AppendUint32(*b, v)
}

func (b *builder) _Add_Uint64(v uint64) {
	*b = binary.BigEndian.AppendUint64(*b, v)
}

func (b *builder) add_uint32_prefixed(f continuation) {
	var child builder
	f(&child)
	length := uint32(len(child))
	b.add_uint32(length)
	*b = append(*b, child...)
}

func (b *builder) add_uint8(v uint8) {
	*b = append(*b, v)
}

func (b *builder) add_uint8_prefixed(f continuation) {
	var child builder
	f(&child)
	length := uint8(len(child))
	b.add_uint8(length)
	*b = append(*b, child...)
}

type continuation func(*builder)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	utlsExtensionPadding              uint16 = 21
	utlsExtensionExtendedMasterSecret uint16 = 23 // https://tools.ietf.org/html/rfc7627

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionChannelID uint16 = 30032 // not IANA assigned

	fakeCertCompressionAlgs uint16 = 0x001b
	fakeRecordSizeLimit     uint16 = 0x001c
)

const (
	_OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	_OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	_DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	_DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	_DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	_FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	_FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	_FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	_FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	_FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)
)

// fake curves(groups)
var (
	_FakeFFDHE2048 = uint16(0x0100)
	_FakeFFDHE3072 = uint16(0x0101)
)

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type _CertCompressionAlgo uint16

const (
	_CertCompressionZlib   _CertCompressionAlgo = 0x0001
	_CertCompressionBrotli _CertCompressionAlgo = 0x0002
)

const (
	_PskModePlain uint8 = pskModePlain
	_PskModeDHE   uint8 = pskModeDHE
)

type _ClientHelloID struct {
	_Client string

	// _Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	_Version string

	// _Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	_Seed *_PRNGSeed
}

func (p *_ClientHelloID) _Str() string {
	return fmt.Sprintf("%s-%s", p._Client, p._Version)
}

const (
	// clients
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustom           = "Custom"
	helloFirefox          = "Firefox"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloAndroid          = "Android"

	// versions
	helloAutoVers = "0"
)

type _ClientHelloSpec struct {
	_CipherSuites       []uint16       // nil => default
	_CompressionMethods []uint8        // nil => no compression
	_Extensions         []TLSExtension // nil => no extensions

	_TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	_TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	_GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var (
	// _HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	_HelloGolang = _ClientHelloID{helloGolang, helloAutoVers, nil}

	// _HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	_HelloCustom = _ClientHelloID{helloCustom, helloAutoVers, nil}

	// The rest will will parrot given browser.
	_HelloFirefox_55 = _ClientHelloID{helloFirefox, "55", nil}
	_HelloFirefox_56 = _ClientHelloID{helloFirefox, "56", nil}
	_HelloFirefox_63 = _ClientHelloID{helloFirefox, "63", nil}
	_HelloFirefox_65 = _ClientHelloID{helloFirefox, "65", nil}

	_HelloChrome_58 = _ClientHelloID{helloChrome, "58", nil}
	_HelloChrome_62 = _ClientHelloID{helloChrome, "62", nil}
	_HelloChrome_70 = _ClientHelloID{helloChrome, "70", nil}
	_HelloChrome_72 = _ClientHelloID{helloChrome, "72", nil}
	_HelloChrome_83 = _ClientHelloID{helloChrome, "83", nil}

	_HelloIOS_11_1 = _ClientHelloID{helloIOS, "111", nil} // legacy "111" means 11.1
	_HelloIOS_12_1 = _ClientHelloID{helloIOS, "12.1", nil}
)

// based on spec's GreaseStyle, _GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const _GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return _GREASE_PLACEHOLDER
	} else {
		return v
	}
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{_OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
		{_OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
	}...)
}
