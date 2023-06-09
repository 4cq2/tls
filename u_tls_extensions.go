// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
)

type _TLSExtension interface {
	writeToUConn(*_UConn) error

	_Len() int // includes header

	// Read reads up to len(p) bytes into p.
	// It returns the number of bytes read (0 <= n <= len(p)) and any error encountered.
	Read(p []byte) (n int, err error) // implements io.Reader
}

type _NPNExtension struct {
	_NextProtos []string
}

func (e *_NPNExtension) writeToUConn(uc *_UConn) error {
	uc._Conn.config._NextProtos = e._NextProtos
	uc._HandshakeState._Hello._NextProtoNeg = true
	return nil
}

func (e *_NPNExtension) _Len() int {
	return 4
}

func (e *_NPNExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionNextProtoNeg >> 8)
	b[1] = byte(extensionNextProtoNeg & 0xff)
	// The length is always 0
	return e._Len(), io.EOF
}

type _SNIExtension struct {
	_ServerName string // not an array because go crypto/tls doesn't support multiple SNIs
}

func (e *_SNIExtension) writeToUConn(uc *_UConn) error {
	uc._Conn.config._ServerName = e._ServerName
	uc._HandshakeState._Hello._ServerName = e._ServerName
	return nil
}

func (e *_SNIExtension) _Len() int {
	return 4 + 2 + 1 + 2 + len(e._ServerName)
}

func (e *_SNIExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 3546, section 3.1
	b[0] = byte(extensionServerName >> 8)
	b[1] = byte(extensionServerName)
	b[2] = byte((len(e._ServerName) + 5) >> 8)
	b[3] = byte((len(e._ServerName) + 5))
	b[4] = byte((len(e._ServerName) + 3) >> 8)
	b[5] = byte(len(e._ServerName) + 3)
	// b[6] Server Name Type: host_name (0)
	b[7] = byte(len(e._ServerName) >> 8)
	b[8] = byte(len(e._ServerName))
	copy(b[9:], []byte(e._ServerName))
	return e._Len(), io.EOF
}

type _StatusRequestExtension struct {
}

func (e *_StatusRequestExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._OcspStapling = true
	return nil
}

func (e *_StatusRequestExtension) _Len() int {
	return 9
}

func (e *_StatusRequestExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 4366, section 3.6
	b[0] = byte(extensionStatusRequest >> 8)
	b[1] = byte(extensionStatusRequest)
	b[2] = 0
	b[3] = 5
	b[4] = 1 // OCSP type
	// Two zero valued uint16s for the two lengths.
	return e._Len(), io.EOF
}

type _SupportedCurvesExtension struct {
	_Curves []_CurveID
}

func (e *_SupportedCurvesExtension) writeToUConn(uc *_UConn) error {
	uc._Conn.config._CurvePreferences = e._Curves
	uc._HandshakeState._Hello._SupportedCurves = e._Curves
	return nil
}

func (e *_SupportedCurvesExtension) _Len() int {
	return 6 + 2*len(e._Curves)
}

func (e *_SupportedCurvesExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// http://tools.ietf.org/html/rfc4492#section-5.5.1
	b[0] = byte(extensionSupportedCurves >> 8)
	b[1] = byte(extensionSupportedCurves)
	b[2] = byte((2 + 2*len(e._Curves)) >> 8)
	b[3] = byte((2 + 2*len(e._Curves)))
	b[4] = byte((2 * len(e._Curves)) >> 8)
	b[5] = byte((2 * len(e._Curves)))
	for i, curve := range e._Curves {
		b[6+2*i] = byte(curve >> 8)
		b[7+2*i] = byte(curve)
	}
	return e._Len(), io.EOF
}

type _SupportedPointsExtension struct {
	_SupportedPoints []uint8
}

func (e *_SupportedPointsExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._SupportedPoints = e._SupportedPoints
	return nil
}

func (e *_SupportedPointsExtension) _Len() int {
	return 5 + len(e._SupportedPoints)
}

func (e *_SupportedPointsExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// http://tools.ietf.org/html/rfc4492#section-5.5.2
	b[0] = byte(extensionSupportedPoints >> 8)
	b[1] = byte(extensionSupportedPoints)
	b[2] = byte((1 + len(e._SupportedPoints)) >> 8)
	b[3] = byte((1 + len(e._SupportedPoints)))
	b[4] = byte((len(e._SupportedPoints)))
	for i, pointFormat := range e._SupportedPoints {
		b[5+i] = pointFormat
	}
	return e._Len(), io.EOF
}

type _SignatureAlgorithmsExtension struct {
	_SupportedSignatureAlgorithms []_SignatureScheme
}

func (e *_SignatureAlgorithmsExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._SupportedSignatureAlgorithms = e._SupportedSignatureAlgorithms
	return nil
}

func (e *_SignatureAlgorithmsExtension) _Len() int {
	return 6 + 2*len(e._SupportedSignatureAlgorithms)
}

func (e *_SignatureAlgorithmsExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
	b[0] = byte(extensionSignatureAlgorithms >> 8)
	b[1] = byte(extensionSignatureAlgorithms)
	b[2] = byte((2 + 2*len(e._SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte((2 + 2*len(e._SupportedSignatureAlgorithms)))
	b[4] = byte((2 * len(e._SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte((2 * len(e._SupportedSignatureAlgorithms)))
	for i, sigAndHash := range e._SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigAndHash >> 8)
		b[7+2*i] = byte(sigAndHash)
	}
	return e._Len(), io.EOF
}

type _RenegotiationInfoExtension struct {
	// _Renegotiation field limits how many times client will perform renegotiation: no limit, once, or never.
	// The extension still will be sent, even if _Renegotiation is set to RenegotiateNever.
	_Renegotiation _RenegotiationSupport
}

func (e *_RenegotiationInfoExtension) writeToUConn(uc *_UConn) error {
	uc._Conn.config._Renegotiation = e._Renegotiation
	switch e._Renegotiation {
	case _RenegotiateOnceAsClient:
		fallthrough
	case _RenegotiateFreelyAsClient:
		uc._HandshakeState._Hello._SecureRenegotiationSupported = true
	case _RenegotiateNever:
	default:
	}
	return nil
}

func (e *_RenegotiationInfoExtension) _Len() int {
	return 5
}

func (e *_RenegotiationInfoExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	var extInnerBody []byte // inner body is empty
	innerBodyLen := len(extInnerBody)
	extBodyLen := innerBodyLen + 1

	b[0] = byte(extensionRenegotiationInfo >> 8)
	b[1] = byte(extensionRenegotiationInfo & 0xff)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	b[4] = byte(innerBodyLen)
	copy(b[5:], extInnerBody)

	return e._Len(), io.EOF
}

type _ALPNExtension struct {
	_AlpnProtocols []string
}

func (e *_ALPNExtension) writeToUConn(uc *_UConn) error {
	uc._Conn.config._NextProtos = e._AlpnProtocols
	uc._HandshakeState._Hello._AlpnProtocols = e._AlpnProtocols
	return nil
}

func (e *_ALPNExtension) _Len() int {
	bLen := 2 + 2 + 2
	for _, s := range e._AlpnProtocols {
		bLen += 1 + len(s)
	}
	return bLen
}

func (e *_ALPNExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionALPN >> 8)
	b[1] = byte(extensionALPN & 0xff)
	lengths := b[2:]
	b = b[6:]

	stringsLength := 0
	for _, s := range e._AlpnProtocols {
		l := len(s)
		b[0] = byte(l)
		copy(b[1:], s)
		b = b[1+l:]
		stringsLength += 1 + l
	}

	lengths[2] = byte(stringsLength >> 8)
	lengths[3] = byte(stringsLength)
	stringsLength += 2
	lengths[0] = byte(stringsLength >> 8)
	lengths[1] = byte(stringsLength)

	return e._Len(), io.EOF
}

type _SCTExtension struct {
}

func (e *_SCTExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._Scts = true
	return nil
}

func (e *_SCTExtension) _Len() int {
	return 4
}

func (e *_SCTExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc6962#section-3.3.1
	b[0] = byte(extensionSCT >> 8)
	b[1] = byte(extensionSCT)
	// zero uint16 for the zero-length extension_data
	return e._Len(), io.EOF
}

type _SessionTicketExtension struct {
	_Session *_ClientSessionState
}

func (e *_SessionTicketExtension) writeToUConn(uc *_UConn) error {
	if e._Session != nil {
		uc._HandshakeState._Session = e._Session
		uc._HandshakeState._Hello._SessionTicket = e._Session.sessionTicket
	}
	return nil
}

func (e *_SessionTicketExtension) _Len() int {
	if e._Session != nil {
		return 4 + len(e._Session.sessionTicket)
	}
	return 4
}

func (e *_SessionTicketExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	extBodyLen := e._Len() - 4

	b[0] = byte(extensionSessionTicket >> 8)
	b[1] = byte(extensionSessionTicket)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	if extBodyLen > 0 {
		copy(b[4:], e._Session.sessionTicket)
	}
	return e._Len(), io.EOF
}

// _GenericExtension allows to include in ClientHello arbitrary unsupported extensions.
type _GenericExtension struct {
	_Id   uint16
	_Data []byte
}

func (e *_GenericExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_GenericExtension) _Len() int {
	return 4 + len(e._Data)
}

func (e *_GenericExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(e._Id >> 8)
	b[1] = byte(e._Id)
	b[2] = byte(len(e._Data) >> 8)
	b[3] = byte(len(e._Data))
	if len(e._Data) > 0 {
		copy(b[4:], e._Data)
	}
	return e._Len(), io.EOF
}

type _UtlsExtendedMasterSecretExtension struct {
}

// TODO: update when this extension is implemented in crypto/tls
// but we probably won't have to enable it in Config
func (e *_UtlsExtendedMasterSecretExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._Ems = true
	return nil
}

func (e *_UtlsExtendedMasterSecretExtension) _Len() int {
	return 4
}

func (e *_UtlsExtendedMasterSecretExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(utlsExtensionExtendedMasterSecret >> 8)
	b[1] = byte(utlsExtensionExtendedMasterSecret)
	// The length is 0
	return e._Len(), io.EOF
}

var extendedMasterSecretLabel = []byte("extended master secret")

// extendedMasterFromPreMasterSecret generates the master secret from the pre-master
// secret and session hash. See https://tools.ietf.org/html/rfc7627#section-4
func extendedMasterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret []byte, fh finishedHash) []byte {
	sessionHash := fh._Sum()
	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, extendedMasterSecretLabel, sessionHash)
	return masterSecret
}

// GREASE stinks with dead parrots, have to be super careful, and, if possible, not include GREASE
// https://github.com/google/boringssl/blob/1c68fa2350936ca5897a66b430ebaf333a0e43f5/ssl/internal.h
const (
	ssl_grease_cipher = iota
	ssl_grease_group
	ssl_grease_extension1
	ssl_grease_extension2
	ssl_grease_version
	ssl_grease_ticket_extension
	ssl_grease_last_index = ssl_grease_ticket_extension
)

// it is responsibility of user not to generate multiple grease extensions with same value
type _UtlsGREASEExtension struct {
	_Value uint16
	_Body  []byte // in Chrome first grease has empty body, second grease has a single zero byte
}

func (e *_UtlsGREASEExtension) writeToUConn(uc *_UConn) error {
	return nil
}

// will panic if ssl_grease_last_index[index] is out of bounds.
func _GetBoringGREASEValue(greaseSeed [ssl_grease_last_index]uint16, index int) uint16 {
	// GREASE value is back from deterministic to random.
	// https://github.com/google/boringssl/blob/a365138ac60f38b64bfc608b493e0f879845cb88/ssl/handshake_client.c#L530
	ret := uint16(greaseSeed[index])
	/* This generates a random value of the form 0xωaωa, for all 0 ≤ ω < 16. */
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func (e *_UtlsGREASEExtension) _Len() int {
	return 4 + len(e._Body)
}

func (e *_UtlsGREASEExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(e._Value >> 8)
	b[1] = byte(e._Value)
	b[2] = byte(len(e._Body) >> 8)
	b[3] = byte(len(e._Body))
	if len(e._Body) > 0 {
		copy(b[4:], e._Body)
	}
	return e._Len(), io.EOF
}

type _UtlsPaddingExtension struct {
	_PaddingLen int
	_WillPad    bool // set to false to disable extension

	// Functor for deciding on padding length based on unpadded ClientHello length.
	// If willPad is false, then this extension should not be included.
	_GetPaddingLen func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool)
}

func (e *_UtlsPaddingExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_UtlsPaddingExtension) _Len() int {
	if e._WillPad {
		return 4 + e._PaddingLen
	} else {
		return 0
	}
}

func (e *_UtlsPaddingExtension) _Update(clientHelloUnpaddedLen int) {
	if e._GetPaddingLen != nil {
		e._PaddingLen, e._WillPad = e._GetPaddingLen(clientHelloUnpaddedLen)
	}
}

func (e *_UtlsPaddingExtension) Read(b []byte) (int, error) {
	if !e._WillPad {
		return 0, io.EOF
	}
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(utlsExtensionPadding >> 8)
	b[1] = byte(utlsExtensionPadding)
	b[2] = byte(e._PaddingLen >> 8)
	b[3] = byte(e._PaddingLen)
	return e._Len(), io.EOF
}

// https://github.com/google/boringssl/blob/7d7554b6b3c79e707e25521e61e066ce2b996e4c/ssl/t1_lib.c#L2803
func _BoringPaddingStyle(unpaddedLen int) (int, bool) {
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 0, false
}

/* TLS 1.3 */
type _KeyShareExtension struct {
	_KeyShares []_KeyShare
}

func (e *_KeyShareExtension) _Len() int {
	return 4 + 2 + e.keySharesLen()
}

func (e *_KeyShareExtension) keySharesLen() int {
	extLen := 0
	for _, ks := range e._KeyShares {
		extLen += 4 + len(ks._Data)
	}
	return extLen
}

func (e *_KeyShareExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionKeyShare >> 8)
	b[1] = byte(extensionKeyShare)
	keySharesLen := e.keySharesLen()
	b[2] = byte((keySharesLen + 2) >> 8)
	b[3] = byte((keySharesLen + 2))
	b[4] = byte((keySharesLen) >> 8)
	b[5] = byte((keySharesLen))

	i := 6
	for _, ks := range e._KeyShares {
		b[i] = byte(ks._Group >> 8)
		b[i+1] = byte(ks._Group)
		b[i+2] = byte(len(ks._Data) >> 8)
		b[i+3] = byte(len(ks._Data))
		copy(b[i+4:], ks._Data)
		i += 4 + len(ks._Data)
	}

	return e._Len(), io.EOF
}

func (e *_KeyShareExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._KeyShares = e._KeyShares
	return nil
}

type _PSKKeyExchangeModesExtension struct {
	_Modes []uint8
}

func (e *_PSKKeyExchangeModesExtension) _Len() int {
	return 4 + 1 + len(e._Modes)
}

func (e *_PSKKeyExchangeModesExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	if len(e._Modes) > 255 {
		return 0, errors.New("too many PSK Key Exchange modes")
	}

	b[0] = byte(extensionPSKModes >> 8)
	b[1] = byte(extensionPSKModes)

	modesLen := len(e._Modes)
	b[2] = byte((modesLen + 1) >> 8)
	b[3] = byte((modesLen + 1))
	b[4] = byte(modesLen)

	if len(e._Modes) > 0 {
		copy(b[5:], e._Modes)
	}

	return e._Len(), io.EOF
}

func (e *_PSKKeyExchangeModesExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._PskModes = e._Modes
	return nil
}

type _SupportedVersionsExtension struct {
	_Versions []uint16
}

func (e *_SupportedVersionsExtension) writeToUConn(uc *_UConn) error {
	uc._HandshakeState._Hello._SupportedVersions = e._Versions
	return nil
}

func (e *_SupportedVersionsExtension) _Len() int {
	return 4 + 1 + (2 * len(e._Versions))
}

func (e *_SupportedVersionsExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	extLen := 2 * len(e._Versions)
	if extLen > 255 {
		return 0, errors.New("too many supported versions")
	}

	b[0] = byte(extensionSupportedVersions >> 8)
	b[1] = byte(extensionSupportedVersions)
	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1))
	b[4] = byte(extLen)

	i := 5
	for _, sv := range e._Versions {
		b[i] = byte(sv >> 8)
		b[i+1] = byte(sv)
		i += 2
	}
	return e._Len(), io.EOF
}

// MUST NOT be part of initial ClientHello
type _CookieExtension struct {
	_Cookie []byte
}

func (e *_CookieExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_CookieExtension) _Len() int {
	return 4 + len(e._Cookie)
}

func (e *_CookieExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionCookie >> 8)
	b[1] = byte(extensionCookie)
	b[2] = byte(len(e._Cookie) >> 8)
	b[3] = byte(len(e._Cookie))
	if len(e._Cookie) > 0 {
		copy(b[4:], e._Cookie)
	}
	return e._Len(), io.EOF
}

/*
FAKE EXTENSIONS
*/

type _FakeChannelIDExtension struct {
}

func (e *_FakeChannelIDExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_FakeChannelIDExtension) _Len() int {
	return 4
}

func (e *_FakeChannelIDExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
	b[0] = byte(fakeExtensionChannelID >> 8)
	b[1] = byte(fakeExtensionChannelID & 0xff)
	// The length is 0
	return e._Len(), io.EOF
}

type _FakeCertCompressionAlgsExtension struct {
	_Methods []_CertCompressionAlgo
}

func (e *_FakeCertCompressionAlgsExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_FakeCertCompressionAlgsExtension) _Len() int {
	return 4 + 1 + (2 * len(e._Methods))
}

func (e *_FakeCertCompressionAlgsExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
	b[0] = byte(fakeCertCompressionAlgs >> 8)
	b[1] = byte(fakeCertCompressionAlgs & 0xff)

	extLen := 2 * len(e._Methods)
	if extLen > 255 {
		return 0, errors.New("too many certificate compression methods")
	}

	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1) & 0xff)
	b[4] = byte(extLen)

	i := 5
	for _, compMethod := range e._Methods {
		b[i] = byte(compMethod >> 8)
		b[i+1] = byte(compMethod)
		i += 2
	}
	return e._Len(), io.EOF
}

type _FakeRecordSizeLimitExtension struct {
	_Limit uint16
}

func (e *_FakeRecordSizeLimitExtension) writeToUConn(uc *_UConn) error {
	return nil
}

func (e *_FakeRecordSizeLimitExtension) _Len() int {
	return 6
}

func (e *_FakeRecordSizeLimitExtension) Read(b []byte) (int, error) {
	if len(b) < e._Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
	b[0] = byte(fakeRecordSizeLimit >> 8)
	b[1] = byte(fakeRecordSizeLimit & 0xff)

	b[2] = byte(0)
	b[3] = byte(2)

	b[4] = byte(e._Limit >> 8)
	b[5] = byte(e._Limit & 0xff)
	return e._Len(), io.EOF
}
