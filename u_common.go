// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
)

type Transport struct {
	Conn *UConn
	Spec ClientHelloSpec
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	conf := Config{ServerName: req.URL.Host}
	conn, err := net.Dial("tcp", req.URL.Host+":443")
	if err != nil {
		return nil, err
	}
	t.Conn = UClient(conn, &conf, HelloCustom)
	if err := t.Conn.ApplyPreset(&t.Spec); err != nil {
		return nil, err
	}
	if err := req.Write(t.Conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(t.Conn), req)
}

var Android_API_26 = ClientHelloSpec{
	CipherSuites: []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	Extensions: []TLSExtension{
		&RenegotiationInfoExtension{},
		&SNIExtension{},
		&UtlsExtendedMasterSecretExtension{},
		&SessionTicketExtension{},
		&SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
			},
		},
		&StatusRequestExtension{},
		&ALPNExtension{
			_AlpnProtocols: []string{"http/1.1"},
		},
		&SupportedPointsExtension{
			SupportedPoints: []uint8{pointFormatUncompressed},
		},
		&SupportedCurvesExtension{
			Curves: []CurveID{
				X25519,
				CurveP256,
				CurveP384,
			},
		},
	},
}

type builder []byte

func (b *builder) Add_Bytes(v []byte) {
	*b = append(*b, v...)
}

func (b *builder) Add_String(v string) {
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

func (b *builder) Add_Uint64(v uint64) {
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
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// fake curves(groups)
var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type _CertCompressionAlgo uint16

const (
	_CertCompressionZlib   _CertCompressionAlgo = 0x0001
	_CertCompressionBrotli _CertCompressionAlgo = 0x0002
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	Version string

	// Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	Seed *PRNGSeed
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
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

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustom, helloAutoVers, nil}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers, nil}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, helloAutoVers, nil}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, helloAutoVers, nil}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_65
	HelloFirefox_55   = ClientHelloID{helloFirefox, "55", nil}
	HelloFirefox_56   = ClientHelloID{helloFirefox, "56", nil}
	HelloFirefox_63   = ClientHelloID{helloFirefox, "63", nil}
	HelloFirefox_65   = ClientHelloID{helloFirefox, "65", nil}

	HelloChrome_Auto = HelloChrome_83
	HelloChrome_58   = ClientHelloID{helloChrome, "58", nil}
	HelloChrome_62   = ClientHelloID{helloChrome, "62", nil}
	HelloChrome_70   = ClientHelloID{helloChrome, "70", nil}
	HelloChrome_72   = ClientHelloID{helloChrome, "72", nil}
	HelloChrome_83   = ClientHelloID{helloChrome, "83", nil}

	HelloIOS_Auto = HelloIOS_12_1
	HelloIOS_11_1 = ClientHelloID{helloIOS, "111", nil} // legacy "111" means 11.1
	HelloIOS_12_1 = ClientHelloID{helloIOS, "12.1", nil}
)

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

// utlsMacSHA384 returns a SHA-384 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func utlsMacSHA384(version uint16, key []byte) macFunction {
	return tls10MAC{h: hmac.New(sha512.New384, key)}
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
// Must be called before establishing any connections.
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}
