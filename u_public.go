// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"hash"
)

// _ClientHandshakeState includes both TLS 1.3-only and TLS 1.2-only states,
// only one of them will be used, depending on negotiated version.
//
// _ClientHandshakeState will be converted into and from either
//   - clientHandshakeState      (TLS 1.2)
//   - clientHandshakeStateTLS13 (TLS 1.3)
//
// uTLS will call .handshake() on one of these private internal states,
// to perform TLS handshake using standard crypto/tls implementation.
type _ClientHandshakeState struct {
	_C            *Conn
	_ServerHello  *ServerHelloMsg
	_Hello        *ClientHelloMsg
	_MasterSecret []byte
	_Session      *ClientSessionState

	_State12 TLS12OnlyState
	_State13 TLS13OnlyState

	uconn *UConn
}

// TLS 1.3 only
type TLS13OnlyState struct {
	Suite         *_CipherSuiteTLS13
	EcdheParams   EcdheParameters
	EarlySecret   []byte
	BinderKey     []byte
	CertReq       *_CertificateRequestMsgTLS13
	UsingPSK      bool
	SentDummyCCS  bool
	Transcript    hash.Hash
	TrafficSecret []byte // client_application_traffic_secret_0
}

// TLS 1.2 and before only
type TLS12OnlyState struct {
	FinishedHash FinishedHash
	Suite        _CipherSuite
}

func (chs *_ClientHandshakeState) toPrivate13() *clientHandshakeStateTLS13 {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeStateTLS13{
			c:           chs._C,
			serverHello: chs._ServerHello.getPrivatePtr(),
			hello:       chs._Hello.getPrivatePtr(),
			ecdheParams: chs._State13.EcdheParams,

			session:     chs._Session,
			earlySecret: chs._State13.EarlySecret,
			binderKey:   chs._State13.BinderKey,

			certReq:       chs._State13.CertReq.toPrivate(),
			usingPSK:      chs._State13.UsingPSK,
			sentDummyCCS:  chs._State13.SentDummyCCS,
			suite:         chs._State13.Suite.toPrivate(),
			transcript:    chs._State13.Transcript,
			masterSecret:  chs._MasterSecret,
			trafficSecret: chs._State13.TrafficSecret,

			uconn: chs.uconn,
		}
	}
}

func (chs13 *clientHandshakeStateTLS13) toPublic13() *_ClientHandshakeState {
	if chs13 == nil {
		return nil
	} else {
		tls13State := TLS13OnlyState{
			EcdheParams:   chs13.ecdheParams,
			EarlySecret:   chs13.earlySecret,
			BinderKey:     chs13.binderKey,
			CertReq:       chs13.certReq.toPublic(),
			UsingPSK:      chs13.usingPSK,
			SentDummyCCS:  chs13.sentDummyCCS,
			Suite:         chs13.suite.toPublic(),
			TrafficSecret: chs13.trafficSecret,
			Transcript:    chs13.transcript,
		}
		return &_ClientHandshakeState{
			_C:           chs13.c,
			_ServerHello: chs13.serverHello.getPublicPtr(),
			_Hello:       chs13.hello.getPublicPtr(),

			_Session: chs13.session,

			_MasterSecret: chs13.masterSecret,

			_State13: tls13State,

			uconn: chs13.uconn,
		}
	}
}

func (chs *_ClientHandshakeState) toPrivate12() *clientHandshakeState {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeState{
			c:           chs._C,
			serverHello: chs._ServerHello.getPrivatePtr(),
			hello:       chs._Hello.getPrivatePtr(),
			suite:       chs._State12.Suite.getPrivatePtr(),
			session:     chs._Session,

			masterSecret: chs._MasterSecret,

			finishedHash: chs._State12.FinishedHash.getPrivateObj(),

			uconn: chs.uconn,
		}
	}
}

func (chs12 *clientHandshakeState) toPublic12() *_ClientHandshakeState {
	if chs12 == nil {
		return nil
	} else {
		tls12State := TLS12OnlyState{
			Suite:        chs12.suite.getPublicObj(),
			FinishedHash: chs12.finishedHash.getPublicObj(),
		}
		return &_ClientHandshakeState{
			_C:           chs12.c,
			_ServerHello: chs12.serverHello.getPublicPtr(),
			_Hello:       chs12.hello.getPublicPtr(),

			_Session: chs12.session,

			_MasterSecret: chs12.masterSecret,

			_State12: tls12State,

			uconn: chs12.uconn,
		}
	}
}

type EcdheParameters interface {
	ecdheParameters
}

type _CertificateRequestMsgTLS13 struct {
	_Raw                              []byte
	_OcspStapling                     bool
	_Scts                             bool
	_SupportedSignatureAlgorithms     []SignatureScheme
	_SupportedSignatureAlgorithmsCert []SignatureScheme
	_CertificateAuthorities           [][]byte
}

func (crm *certificateRequestMsgTLS13) toPublic() *_CertificateRequestMsgTLS13 {
	if crm == nil {
		return nil
	} else {
		return &_CertificateRequestMsgTLS13{
			_Raw:                              crm.raw,
			_OcspStapling:                     crm.ocspStapling,
			_Scts:                             crm.scts,
			_SupportedSignatureAlgorithms:     crm.supportedSignatureAlgorithms,
			_SupportedSignatureAlgorithmsCert: crm.supportedSignatureAlgorithmsCert,
			_CertificateAuthorities:           crm.certificateAuthorities,
		}
	}
}

func (crm *_CertificateRequestMsgTLS13) toPrivate() *certificateRequestMsgTLS13 {
	if crm == nil {
		return nil
	} else {
		return &certificateRequestMsgTLS13{
			raw:                              crm._Raw,
			ocspStapling:                     crm._OcspStapling,
			scts:                             crm._Scts,
			supportedSignatureAlgorithms:     crm._SupportedSignatureAlgorithms,
			supportedSignatureAlgorithmsCert: crm._SupportedSignatureAlgorithmsCert,
			certificateAuthorities:           crm._CertificateAuthorities,
		}
	}
}

type _CipherSuiteTLS13 struct {
	_Id     uint16
	_KeyLen int
	_Aead   func(key, fixedNonce []byte) aead
	_Hash   crypto.Hash
}

func (c *cipherSuiteTLS13) toPublic() *_CipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &_CipherSuiteTLS13{
			_Id:     c.id,
			_KeyLen: c.keyLen,
			_Aead:   c.aead,
			_Hash:   c.hash,
		}
	}
}

func (c *_CipherSuiteTLS13) toPrivate() *cipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &cipherSuiteTLS13{
			id:     c._Id,
			keyLen: c._KeyLen,
			aead:   c._Aead,
			hash:   c._Hash,
		}
	}
}

type ServerHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	Ems                          bool
	TicketSupported              bool
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string

	// 1.3
	SupportedVersion        uint16
	ServerShare             keyShare
	SelectedIdentityPresent bool
	SelectedIdentity        uint16
	Cookie                  []byte  // HelloRetryRequest extension
	SelectedGroup           CurveID // HelloRetryRequest extension

}

func (shm *ServerHelloMsg) getPrivatePtr() *serverHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &serverHelloMsg{
			raw:                          shm.Raw,
			vers:                         shm.Vers,
			random:                       shm.Random,
			sessionId:                    shm.SessionId,
			cipherSuite:                  shm.CipherSuite,
			compressionMethod:            shm.CompressionMethod,
			nextProtoNeg:                 shm.NextProtoNeg,
			nextProtos:                   shm.NextProtos,
			ocspStapling:                 shm.OcspStapling,
			scts:                         shm.Scts,
			ems:                          shm.Ems,
			ticketSupported:              shm.TicketSupported,
			secureRenegotiation:          shm.SecureRenegotiation,
			secureRenegotiationSupported: shm.SecureRenegotiationSupported,
			alpnProtocol:                 shm.AlpnProtocol,
			supportedVersion:             shm.SupportedVersion,
			serverShare:                  shm.ServerShare,
			selectedIdentityPresent:      shm.SelectedIdentityPresent,
			selectedIdentity:             shm.SelectedIdentity,
			cookie:                       shm.Cookie,
			selectedGroup:                shm.SelectedGroup,
		}
	}
}

func (shm *serverHelloMsg) getPublicPtr() *ServerHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &ServerHelloMsg{
			Raw:                          shm.raw,
			Vers:                         shm.vers,
			Random:                       shm.random,
			SessionId:                    shm.sessionId,
			CipherSuite:                  shm.cipherSuite,
			CompressionMethod:            shm.compressionMethod,
			NextProtoNeg:                 shm.nextProtoNeg,
			NextProtos:                   shm.nextProtos,
			OcspStapling:                 shm.ocspStapling,
			Scts:                         shm.scts,
			Ems:                          shm.ems,
			TicketSupported:              shm.ticketSupported,
			SecureRenegotiation:          shm.secureRenegotiation,
			SecureRenegotiationSupported: shm.secureRenegotiationSupported,
			AlpnProtocol:                 shm.alpnProtocol,
			SupportedVersion:             shm.supportedVersion,
			ServerShare:                  shm.serverShare,
			SelectedIdentityPresent:      shm.selectedIdentityPresent,
			SelectedIdentity:             shm.selectedIdentity,
			Cookie:                       shm.cookie,
			SelectedGroup:                shm.selectedGroup,
		}
	}
}

type ClientHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	_CipherSuites                []uint16
	CompressionMethods           []uint8
	NextProtoNeg                 bool
	ServerName                   string
	OcspStapling                 bool
	Scts                         bool
	Ems                          bool // [UTLS] actually implemented due to its prevalence
	SupportedCurves              []CurveID
	SupportedPoints              []uint8
	TicketSupported              bool
	SessionTicket                []uint8
	SupportedSignatureAlgorithms []SignatureScheme
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	_AlpnProtocols               []string

	// 1.3
	SupportedSignatureAlgorithmsCert []SignatureScheme
	SupportedVersions                []uint16
	Cookie                           []byte
	KeyShares                        []KeyShare
	EarlyData                        bool
	PskModes                         []uint8
	PskIdentities                    []pskIdentity
	PskBinders                       [][]byte
}

func (chm *ClientHelloMsg) getPrivatePtr() *clientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &clientHelloMsg{
			raw:                          chm.Raw,
			vers:                         chm.Vers,
			random:                       chm.Random,
			sessionId:                    chm.SessionId,
			cipherSuites:                 chm._CipherSuites,
			compressionMethods:           chm.CompressionMethods,
			nextProtoNeg:                 chm.NextProtoNeg,
			serverName:                   chm.ServerName,
			ocspStapling:                 chm.OcspStapling,
			scts:                         chm.Scts,
			ems:                          chm.Ems,
			supportedCurves:              chm.SupportedCurves,
			supportedPoints:              chm.SupportedPoints,
			ticketSupported:              chm.TicketSupported,
			sessionTicket:                chm.SessionTicket,
			supportedSignatureAlgorithms: chm.SupportedSignatureAlgorithms,
			secureRenegotiation:          chm.SecureRenegotiation,
			secureRenegotiationSupported: chm.SecureRenegotiationSupported,
			alpnProtocols:                chm._AlpnProtocols,

			supportedSignatureAlgorithmsCert: chm.SupportedSignatureAlgorithmsCert,
			supportedVersions:                chm.SupportedVersions,
			cookie:                           chm.Cookie,
			keyShares:                        KeyShares(chm.KeyShares).ToPrivate(),
			earlyData:                        chm.EarlyData,
			pskModes:                         chm.PskModes,
			pskIdentities:                    chm.PskIdentities,
			pskBinders:                       chm.PskBinders,
		}
	}
}

func (chm *clientHelloMsg) getPublicPtr() *ClientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &ClientHelloMsg{
			Raw:                          chm.raw,
			Vers:                         chm.vers,
			Random:                       chm.random,
			SessionId:                    chm.sessionId,
			_CipherSuites:                chm.cipherSuites,
			CompressionMethods:           chm.compressionMethods,
			NextProtoNeg:                 chm.nextProtoNeg,
			ServerName:                   chm.serverName,
			OcspStapling:                 chm.ocspStapling,
			Scts:                         chm.scts,
			Ems:                          chm.ems,
			SupportedCurves:              chm.supportedCurves,
			SupportedPoints:              chm.supportedPoints,
			TicketSupported:              chm.ticketSupported,
			SessionTicket:                chm.sessionTicket,
			SupportedSignatureAlgorithms: chm.supportedSignatureAlgorithms,
			SecureRenegotiation:          chm.secureRenegotiation,
			SecureRenegotiationSupported: chm.secureRenegotiationSupported,
			_AlpnProtocols:               chm.alpnProtocols,

			SupportedSignatureAlgorithmsCert: chm.supportedSignatureAlgorithmsCert,
			SupportedVersions:                chm.supportedVersions,
			Cookie:                           chm.cookie,
			KeyShares:                        keyShares(chm.keyShares).ToPublic(),
			EarlyData:                        chm.earlyData,
			PskModes:                         chm.pskModes,
			PskIdentities:                    chm.pskIdentities,
			PskBinders:                       chm.pskBinders,
		}
	}
}

// UnmarshalClientHello allows external code to parse raw client hellos.
// It returns nil on failure.
func UnmarshalClientHello(data []byte) *ClientHelloMsg {
	m := &clientHelloMsg{}
	if m.unmarshal(data) {
		return m.getPublicPtr()
	}
	return nil
}

// A _CipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type _CipherSuite struct {
	_Id uint16
	// the lengths, in bytes, of the key material needed for each component.
	_KeyLen int
	_MacLen int
	_IvLen  int
	_Ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	_Flags  int
	_Cipher func(key, iv []byte, isRead bool) interface{}
	_Mac    func(version uint16, macKey []byte) macFunction
	_Aead   func(key, fixedNonce []byte) aead
}

func (cs *_CipherSuite) getPrivatePtr() *cipherSuite {
	if cs == nil {
		return nil
	} else {
		return &cipherSuite{
			id:     cs._Id,
			keyLen: cs._KeyLen,
			macLen: cs._MacLen,
			ivLen:  cs._IvLen,
			ka:     cs._Ka,
			flags:  cs._Flags,
			cipher: cs._Cipher,
			mac:    cs._Mac,
			aead:   cs._Aead,
		}
	}
}

func (cs *cipherSuite) getPublicObj() _CipherSuite {
	if cs == nil {
		return _CipherSuite{}
	} else {
		return _CipherSuite{
			_Id:     cs.id,
			_KeyLen: cs.keyLen,
			_MacLen: cs.macLen,
			_IvLen:  cs.ivLen,
			_Ka:     cs.ka,
			_Flags:  cs.flags,
			_Cipher: cs.cipher,
			_Mac:    cs.mac,
			_Aead:   cs.aead,
		}
	}
}

// A FinishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type FinishedHash struct {
	Client hash.Hash
	Server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	ClientMD5 hash.Hash
	ServerMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	Buffer []byte

	Version uint16
	Prf     func(result, secret, label, seed []byte)
}

func (fh *FinishedHash) getPrivateObj() finishedHash {
	if fh == nil {
		return finishedHash{}
	} else {
		return finishedHash{
			client:    fh.Client,
			server:    fh.Server,
			clientMD5: fh.ClientMD5,
			serverMD5: fh.ServerMD5,
			buffer:    fh.Buffer,
			version:   fh.Version,
			prf:       fh.Prf,
		}
	}
}

func (fh *finishedHash) getPublicObj() FinishedHash {
	if fh == nil {
		return FinishedHash{}
	} else {
		return FinishedHash{
			Client:    fh.client,
			Server:    fh.server,
			ClientMD5: fh.clientMD5,
			ServerMD5: fh.serverMD5,
			Buffer:    fh.buffer,
			Version:   fh.version,
			Prf:       fh.prf}
	}
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type KeyShare struct {
	Group CurveID
	Data  []byte
}

type KeyShares []KeyShare
type keyShares []keyShare

func (kss keyShares) ToPublic() []KeyShare {
	var KSS []KeyShare
	for _, ks := range kss {
		KSS = append(KSS, KeyShare{Data: ks.data, Group: ks.group})
	}
	return KSS
}
func (KSS KeyShares) ToPrivate() []keyShare {
	var kss []keyShare
	for _, KS := range KSS {
		kss = append(kss, keyShare{data: KS.Data, group: KS.Group})
	}
	return kss
}

// ClientSessionState is public, but all its fields are private. Let's add setters, getters and constructor

// ClientSessionState contains the state needed by clients to resume TLS sessions.
func MakeClientSessionState(
	SessionTicket []uint8,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	ServerCertificates []*x509.Certificate,
	VerifiedChains [][]*x509.Certificate) *ClientSessionState {
	css := ClientSessionState{sessionTicket: SessionTicket,
		vers:               Vers,
		cipherSuite:        CipherSuite,
		masterSecret:       MasterSecret,
		serverCertificates: ServerCertificates,
		verifiedChains:     VerifiedChains}
	return &css
}

// Encrypted ticket used for session resumption with server
func (css *ClientSessionState) SessionTicket() []uint8 {
	return css.sessionTicket
}

// SSL/TLS version negotiated for the session
func (css *ClientSessionState) Vers() uint16 {
	return css.vers
}

// Ciphersuite negotiated for the session
func (css *ClientSessionState) CipherSuite() uint16 {
	return css.cipherSuite
}

// MasterSecret generated by client on a full handshake
func (css *ClientSessionState) MasterSecret() []byte {
	return css.masterSecret
}

// Certificate chain presented by the server
func (css *ClientSessionState) ServerCertificates() []*x509.Certificate {
	return css.serverCertificates
}

// Certificate chains we built for verification
func (css *ClientSessionState) VerifiedChains() [][]*x509.Certificate {
	return css.verifiedChains
}

func (css *ClientSessionState) SetSessionTicket(SessionTicket []uint8) {
	css.sessionTicket = SessionTicket
}
func (css *ClientSessionState) SetVers(Vers uint16) {
	css.vers = Vers
}
func (css *ClientSessionState) SetCipherSuite(CipherSuite uint16) {
	css.cipherSuite = CipherSuite
}
func (css *ClientSessionState) SetMasterSecret(MasterSecret []byte) {
	css.masterSecret = MasterSecret
}
func (css *ClientSessionState) SetServerCertificates(ServerCertificates []*x509.Certificate) {
	css.serverCertificates = ServerCertificates
}
func (css *ClientSessionState) SetVerifiedChains(VerifiedChains [][]*x509.Certificate) {
	css.verifiedChains = VerifiedChains
}

// TicketKey is the internal representation of a session ticket key.
type TicketKey struct {
	// KeyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	KeyName [ticketKeyNameLen]byte
	AesKey  [16]byte
	HmacKey [16]byte
}

type TicketKeys []TicketKey
type ticketKeys []ticketKey

func TicketKeyFromBytes(b [32]byte) TicketKey {
	tk := ticketKeyFromBytes(b)
	return tk.ToPublic()
}

func (tk ticketKey) ToPublic() TicketKey {
	return TicketKey{
		KeyName: tk.keyName,
		AesKey:  tk.aesKey,
		HmacKey: tk.hmacKey,
	}
}

func (TK TicketKey) ToPrivate() ticketKey {
	return ticketKey{
		keyName: TK.KeyName,
		aesKey:  TK.AesKey,
		hmacKey: TK.HmacKey,
	}
}

func (tks ticketKeys) ToPublic() []TicketKey {
	var TKS []TicketKey
	for _, ks := range tks {
		TKS = append(TKS, ks.ToPublic())
	}
	return TKS
}

func (TKS TicketKeys) ToPrivate() []ticketKey {
	var tks []ticketKey
	for _, TK := range TKS {
		tks = append(tks, TK.ToPrivate())
	}
	return tks
}
