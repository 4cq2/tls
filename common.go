// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	_VersionSSL30 = 0x0300
	_VersionTLS10 = 0x0301
	_VersionTLS11 = 0x0302
	_VersionTLS12 = 0x0303
	_VersionTLS13 = 0x0304
)

const (
	maxPlaintext       = 16384        // maximum plaintext payload length
	maxCiphertext      = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13 = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen    = 5            // record header length
	maxHandshake       = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords  = 16           // maximum number of consecutive non-advancing records
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
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionNextProtoNeg            uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo       uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// _CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type _CurveID uint16

const (
	_CurveP256 _CurveID = 23
	_CurveP384 _CurveID = 24
	_CurveP521 _CurveID = 25
	_X25519    _CurveID = 29
)

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group _CurveID
	data  []byte
}

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // RFC 4492, Section 5.5
)

// Signature algorithms (for internal signaling use). Starting at 16 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	signaturePKCS1v15 uint8 = iota + 16
	signatureECDSA
	signatureRSAPSS
)

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
var supportedSignatureAlgorithms = []_SignatureScheme{
	_PSSWithSHA256,
	_PSSWithSHA384,
	_PSSWithSHA512,
	_PKCS1WithSHA256,
	_ECDSAWithP256AndSHA256,
	_PKCS1WithSHA384,
	_ECDSAWithP384AndSHA384,
	_PKCS1WithSHA512,
	_ECDSAWithP521AndSHA512,
	_PKCS1WithSHA1,
	_ECDSAWithSHA1,
}

// helloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// _ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type _ClientAuthType int

const (
	_NoClientCert _ClientAuthType = iota
	_RequestClientCert
	_RequireAnyClientCert
	_VerifyClientCertIfGiven
	_RequireAndVerifyClientCert
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c _ClientAuthType) bool {
	switch c {
	case _RequireAnyClientCert, _RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// _ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type _ClientSessionState struct {
	sessionTicket      []uint8               // Encrypted ticket used for session resumption with server
	vers               uint16                // SSL/TLS version negotiated for the session
	cipherSuite        uint16                // Ciphersuite negotiated for the session
	masterSecret       []byte                // Full handshake MasterSecret, or TLS 1.3 resumption_master_secret
	serverCertificates []*x509.Certificate   // Certificate chain presented by the server
	verifiedChains     [][]*x509.Certificate // Certificate chains we built for verification
	receivedAt         time.Time             // When the session ticket was received from the server

	// TLS 1.3 fields.
	nonce  []byte    // Ticket nonce sent by the server, to derive PSK
	useBy  time.Time // Expiration of the ticket lifetime as set by the server
	ageAdd uint32    // Random obfuscation factor for sending the ticket age
}

// _ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. _ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type _ClientSessionCache interface {
	// _Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	_Get(sessionKey string) (session *_ClientSessionState, ok bool)

	// _Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	_Put(sessionKey string, cs *_ClientSessionState)
}

// _SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type _SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	_PKCS1WithSHA256 _SignatureScheme = 0x0401
	_PKCS1WithSHA384 _SignatureScheme = 0x0501
	_PKCS1WithSHA512 _SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	_PSSWithSHA256 _SignatureScheme = 0x0804
	_PSSWithSHA384 _SignatureScheme = 0x0805
	_PSSWithSHA512 _SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	_ECDSAWithP256AndSHA256 _SignatureScheme = 0x0403
	_ECDSAWithP384AndSHA384 _SignatureScheme = 0x0503
	_ECDSAWithP521AndSHA512 _SignatureScheme = 0x0603

	// Legacy signature and hash algorithms for TLS 1.2.
	_PKCS1WithSHA1 _SignatureScheme = 0x0201
	_ECDSAWithSHA1 _SignatureScheme = 0x0203
)

// _ClientHelloInfo contains information from a ClientHello message in order to
// guide certificate selection in the GetCertificate callback.
type _ClientHelloInfo struct {
	// _CipherSuites lists the _CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	_CipherSuites []uint16

	// _ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. _ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	_ServerName string

	// _SupportedCurves lists the elliptic curves supported by the client.
	// _SupportedCurves is set only if the Supported Elliptic Curves
	// Extension is being used (see RFC 4492, Section 5.1.1).
	_SupportedCurves []_CurveID

	// _SupportedPoints lists the point formats supported by the client.
	// _SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	_SupportedPoints []uint8

	// _SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. _SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	_SignatureSchemes []_SignatureScheme

	// _SupportedProtos lists the application protocols supported by the client.
	// _SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	_SupportedProtos []string

	// _SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	_SupportedVersions []uint16

	// _Conn is the underlying net._Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	_Conn net.Conn
}

// _CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type _CertificateRequestInfo struct {
	// _AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	_AcceptableCAs [][]byte

	// _SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	_SignatureSchemes []_SignatureScheme
}

// _RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type _RenegotiationSupport int

const (
	// _RenegotiateNever disables renegotiation.
	_RenegotiateNever _RenegotiationSupport = iota

	// _RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	_RenegotiateOnceAsClient

	// _RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	_RenegotiateFreelyAsClient
)

// A _Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A _Config may be reused; the tls package will also not
// modify it.
type _Config struct {
	// _Rand provides the source of entropy for nonces and RSA blinding.
	// If _Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	_Rand io.Reader

	// _Time returns the current time as the number of seconds since the epoch.
	// If _Time is nil, TLS uses time.Now.
	_Time func() time.Time

	// _Certificates contains one or more certificate chains to present to
	// the other side of the connection. Server configurations must include
	// at least one certificate or else set GetCertificate. Clients doing
	// client-authentication may set either _Certificates or
	// GetClientCertificate.
	_Certificates []_Certificate

	// _NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	// See Config.BuildNameToCertificate
	// The nil value causes the first element of Certificates to be used
	// for all connections.
	_NameToCertificate map[string]*_Certificate

	// _GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If _GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// first element of Certificates will be used.
	_GetCertificate func(*_ClientHelloInfo) (*_Certificate, error)

	// _GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If _GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// _GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// _GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	_GetClientCertificate func(*_CertificateRequestInfo) (*_Certificate, error)

	// _GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If _GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// Uniquely for the fields in the returned Config, session ticket keys
	// will be duplicated from the original Config if not set.
	// Specifically, if SetSessionTicketKeys was called on the original
	// config but not on the returned config then the ticket keys from the
	// original config will be copied into the new config before use.
	// Otherwise, if SessionTicketKey was set in the original config but
	// not in the returned config then it will be copied into the returned
	// config before use. If neither of those cases applies then the key
	// material from the returned config will be used for session tickets.
	_GetConfigForClient func(*_ClientHelloInfo) (*_Config, error)

	// _VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains argument will always be nil.
	_VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// _RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If _RootCAs is nil, TLS uses the host's root CA set.
	_RootCAs *x509.CertPool

	// _NextProtos is a list of supported application level protocols, in
	// order of preference.
	_NextProtos []string

	// _ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	_ServerName string

	// _ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	_ClientAuth _ClientAuthType

	// _ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	_ClientCAs *x509.CertPool

	// _InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If _InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	_InsecureSkipVerify bool

	// _CipherSuites is a list of supported cipher suites for TLS versions up to
	// TLS 1.2. If _CipherSuites is nil, a default list of secure cipher suites
	// is used, with a preference order based on hardware performance. The
	// default cipher suites might change over Go versions. Note that TLS 1.3
	// ciphersuites are not configurable.
	_CipherSuites []uint16

	// _PreferServerCipherSuites controls whether the server selects the
	// client's most preferred ciphersuite, or the server's most preferred
	// ciphersuite. If true then the server's preference, as expressed in
	// the order of elements in CipherSuites, is used.
	_PreferServerCipherSuites bool

	// _SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil.
	_SessionTicketsDisabled bool

	// _SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// If multiple servers are terminating connections for the same host
	// they should all have the same _SessionTicketKey. If the
	// _SessionTicketKey leaks, previously recorded and future TLS
	// connections using that key might be compromised.
	_SessionTicketKey [32]byte

	// _ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	_ClientSessionCache _ClientSessionCache

	// _MinVersion contains the minimum SSL/TLS version that is acceptable.
	// If zero, then TLS 1.0 is taken as the minimum.
	_MinVersion uint16

	// _MaxVersion contains the maximum SSL/TLS version that is acceptable.
	// If zero, then the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	_MaxVersion uint16

	// _CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used. The client will use the first preference as the type for
	// its key share in TLS 1.3. This may change in the future.
	_CurvePreferences []_CurveID

	// _DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	_DynamicRecordSizingDisabled bool

	// _Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	_Renegotiation _RenegotiationSupport

	// _KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of _KeyLogWriter compromises security and should only be
	// used for debugging.
	_KeyLogWriter io.Writer

	serverInitOnce sync.Once // guards calling (*Config).serverInit

	// mutex protects sessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If the length
	// is zero, SessionTicketsDisabled must be true. The first key is used
	// for new tickets and any subsequent keys can be used to decrypt old
	// tickets.
	sessionTicketKeys []ticketKey
}

// ticketKeyNameLen is the number of bytes of identifier that is prepended to
// an encrypted session ticket in order to identify the key used to encrypt it.
const ticketKeyNameLen = 16

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	// keyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	keyName [ticketKeyNameLen]byte
	aesKey  [16]byte
	hmacKey [16]byte
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	copy(key.keyName[:], hashed[:ticketKeyNameLen])
	copy(key.aesKey[:], hashed[ticketKeyNameLen:ticketKeyNameLen+16])
	copy(key.hmacKey[:], hashed[ticketKeyNameLen+16:ticketKeyNameLen+32])
	return key
}

// maxSessionTicketLifetime is the maximum allowed lifetime of a TLS 1.3 session
// ticket, and the lifetime we set for tickets we send.
const maxSessionTicketLifetime = 7 * 24 * time.Hour

// serverInit is run under c.serverInitOnce to do initialization of c. If c was
// returned by a GetConfigForClient callback then the argument should be the
// Config that was passed to Server, otherwise it should be nil.
func (c *_Config) serverInit(originalConfig *_Config) {
	if c._SessionTicketsDisabled || len(c.ticketKeys()) != 0 {
		return
	}

	alreadySet := false
	for _, b := range c._SessionTicketKey {
		if b != 0 {
			alreadySet = true
			break
		}
	}

	if !alreadySet {
		if originalConfig != nil {
			copy(c._SessionTicketKey[:], originalConfig._SessionTicketKey[:])
		} else if _, err := io.ReadFull(c.rand(), c._SessionTicketKey[:]); err != nil {
			c._SessionTicketsDisabled = true
			return
		}
	}

	if originalConfig != nil {
		originalConfig.mutex.RLock()
		c.sessionTicketKeys = originalConfig.sessionTicketKeys
		originalConfig.mutex.RUnlock()
	} else {
		c.sessionTicketKeys = []ticketKey{ticketKeyFromBytes(c._SessionTicketKey)}
	}
}

func (c *_Config) ticketKeys() []ticketKey {
	c.mutex.RLock()
	// c.sessionTicketKeys is constant once created. SetSessionTicketKeys
	// will only update it by replacing it with a new value.
	ret := c.sessionTicketKeys
	c.mutex.RUnlock()
	return ret
}

func (c *_Config) rand() io.Reader {
	r := c._Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *_Config) time() time.Time {
	t := c._Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *_Config) cipherSuites() []uint16 {
	s := c._CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

var supportedVersions = []uint16{
	_VersionTLS13,
	_VersionTLS12,
	_VersionTLS11,
	_VersionTLS10,
	_VersionSSL30,
}

func (c *_Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c._MinVersion != 0 && v < c._MinVersion {
			continue
		}
		if c != nil && c._MaxVersion != 0 && v > c._MaxVersion {
			continue
		}
		// TLS 1.0 is the minimum version supported as a client.
		if isClient && v < _VersionTLS10 {
			continue
		}
		// TLS 1.3 is opt-out in Go 1.13.
		if v == _VersionTLS13 && !isTLS13Supported() {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

// tls13Support caches the result for isTLS13Supported.
var tls13Support struct {
	sync.Once
	cached bool
}

// isTLS13Supported returns whether the program enabled TLS 1.3 by not opting
// out with GODEBUG=tls13=0. It's cached after the first execution.
func isTLS13Supported() bool {
	tls13Support.Do(func() {
		tls13Support.cached = goDebugString("tls13") != "0"
	})
	return tls13Support.cached
}

// goDebugString returns the value of the named GODEBUG key.
// GODEBUG is of the form "key=val,key2=val2".
func goDebugString(key string) string {
	s := os.Getenv("GODEBUG")
	for i := 0; i < len(s)-len(key)-1; i++ {
		if i > 0 && s[i-1] != ',' {
			continue
		}
		afterKey := s[i+len(key):]
		if afterKey[0] != '=' || s[i:i+len(key)] != key {
			continue
		}
		val := afterKey[1:]
		for i, b := range val {
			if b == ',' {
				return val[:i]
			}
		}
		return val
	}
	return ""
}

func (c *_Config) maxSupportedVersion(isClient bool) uint16 {
	supportedVersions := c.supportedVersions(isClient)
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

var defaultCurvePreferences = []_CurveID{_X25519, _CurveP256, _CurveP384, _CurveP521}

func (c *_Config) curvePreferences() []_CurveID {
	if c == nil || len(c._CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	return c._CurvePreferences
}

// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *_Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *_Config) getCertificate(clientHello *_ClientHelloInfo) (*_Certificate, error) {
	if c._GetCertificate != nil &&
		(len(c._Certificates) == 0 || len(clientHello._ServerName) > 0) {
		cert, err := c._GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c._Certificates) == 0 {
		return nil, errors.New("tls: no certificates configured")
	}

	if len(c._Certificates) == 1 || c._NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &c._Certificates[0], nil
	}

	name := strings.ToLower(clientHello._ServerName)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := c._NameToCertificate[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c._NameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c._Certificates[0], nil
}

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *_Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c._KeyLogWriter == nil {
		return nil
	}

	logLine := []byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret))

	writerMutex.Lock()
	_, err := c._KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// A _Certificate is a chain of one or more certificates, leaf first.
type _Certificate struct {
	_Certificate [][]byte
	// _PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA or ECDSA PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	_PrivateKey crypto.PrivateKey
	// _OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	_OCSPStaple []byte
	// _SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	_SignedCertificateTimestamps [][]byte
	// _Leaf is the parsed form of the leaf certificate, which may be
	// initialized using x509.ParseCertificate to reduce per-handshake
	// processing for TLS clients doing client authentication. If nil, the
	// leaf certificate will be parsed as needed.
	_Leaf *x509.Certificate
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

// TODO(jsing): Make these available to both crypto/x509 and crypto/tls.
type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

var emptyConfig _Config

func defaultConfig() *_Config {
	return &emptyConfig
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

func initDefaultCipherSuites() {
	// Without AES-GCM hardware, we put the ChaCha20-Poly1305
	// cipher suites first.
	topCipherSuites := []uint16{
		_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
	varDefaultCipherSuitesTLS13 = []uint16{
		_TLS_CHACHA20_POLY1305_SHA256,
		_TLS_AES_128_GCM_SHA256,
		_TLS_AES_256_GCM_SHA384,
	}

	varDefaultCipherSuites = make([]uint16, 0, len(cipherSuites))
	varDefaultCipherSuites = append(varDefaultCipherSuites, topCipherSuites...)

NextCipherSuite:
	for _, suite := range cipherSuites {
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

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

func isSupportedSignatureAlgorithm(sigAlg _SignatureScheme, supportedSignatureAlgorithms []_SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}

// signatureFromSignatureScheme maps a signature algorithm to the underlying
// signature method (without hash function).
func signatureFromSignatureScheme(signatureAlgorithm _SignatureScheme) uint8 {
	switch signatureAlgorithm {
	case _PKCS1WithSHA1, _PKCS1WithSHA256, _PKCS1WithSHA384, _PKCS1WithSHA512:
		return signaturePKCS1v15
	case _PSSWithSHA256, _PSSWithSHA384, _PSSWithSHA512:
		return signatureRSAPSS
	case _ECDSAWithSHA1, _ECDSAWithP256AndSHA256, _ECDSAWithP384AndSHA384, _ECDSAWithP521AndSHA512:
		return signatureECDSA
	default:
		return 0
	}
}
