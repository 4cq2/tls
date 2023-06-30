// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
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
	_C            *_Conn
	_ServerHello  *_ServerHelloMsg
	_Hello        *_ClientHelloMsg
	_MasterSecret []byte
	_Session      *_ClientSessionState

	_State12 _TLS12OnlyState
	_State13 _TLS13OnlyState

	uconn *_UConn
}

// TLS 1.3 only
type _TLS13OnlyState struct {
	_Suite         *_CipherSuiteTLS13
	_EcdheParams   _EcdheParameters
	_EarlySecret   []byte
	_BinderKey     []byte
	_CertReq       *_CertificateRequestMsgTLS13
	_UsingPSK      bool
	_SentDummyCCS  bool
	_Transcript    hash.Hash
	_TrafficSecret []byte // client_application_traffic_secret_0
}

// TLS 1.2 and before only
type _TLS12OnlyState struct {
	_FinishedHash _FinishedHash
	_Suite        _CipherSuite
}

func (chs *_ClientHandshakeState) toPrivate13() *clientHandshakeStateTLS13 {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeStateTLS13{
			c:           chs._C,
			serverHello: chs._ServerHello.getPrivatePtr(),
			hello:       chs._Hello.getPrivatePtr(),
			ecdheParams: chs._State13._EcdheParams,

			session:     chs._Session,
			earlySecret: chs._State13._EarlySecret,
			binderKey:   chs._State13._BinderKey,

			certReq:       chs._State13._CertReq.toPrivate(),
			usingPSK:      chs._State13._UsingPSK,
			sentDummyCCS:  chs._State13._SentDummyCCS,
			suite:         chs._State13._Suite.toPrivate(),
			transcript:    chs._State13._Transcript,
			masterSecret:  chs._MasterSecret,
			trafficSecret: chs._State13._TrafficSecret,

			uconn: chs.uconn,
		}
	}
}

func (chs13 *clientHandshakeStateTLS13) toPublic13() *_ClientHandshakeState {
	if chs13 == nil {
		return nil
	} else {
		tls13State := _TLS13OnlyState{
			_EcdheParams:   chs13.ecdheParams,
			_EarlySecret:   chs13.earlySecret,
			_BinderKey:     chs13.binderKey,
			_CertReq:       chs13.certReq.toPublic(),
			_UsingPSK:      chs13.usingPSK,
			_SentDummyCCS:  chs13.sentDummyCCS,
			_Suite:         chs13.suite.toPublic(),
			_TrafficSecret: chs13.trafficSecret,
			_Transcript:    chs13.transcript,
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
			suite:       chs._State12._Suite.getPrivatePtr(),
			session:     chs._Session,

			masterSecret: chs._MasterSecret,

			finishedHash: chs._State12._FinishedHash.getPrivateObj(),

			uconn: chs.uconn,
		}
	}
}

func (chs12 *clientHandshakeState) toPublic12() *_ClientHandshakeState {
	if chs12 == nil {
		return nil
	} else {
		tls12State := _TLS12OnlyState{
			_Suite:        chs12.suite.getPublicObj(),
			_FinishedHash: chs12.finishedHash.getPublicObj(),
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

type _EcdheParameters interface {
	ecdheParameters
}

type _CertificateRequestMsgTLS13 struct {
	_Raw                              []byte
	_OcspStapling                     bool
	_Scts                             bool
	_SupportedSignatureAlgorithms     []_SignatureScheme
	_SupportedSignatureAlgorithmsCert []_SignatureScheme
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

type _ServerHelloMsg struct {
	_Raw                          []byte
	_Vers                         uint16
	_Random                       []byte
	_SessionId                    []byte
	_CipherSuite                  uint16
	_CompressionMethod            uint8
	_NextProtoNeg                 bool
	_NextProtos                   []string
	_OcspStapling                 bool
	_Scts                         [][]byte
	_Ems                          bool
	_TicketSupported              bool
	_SecureRenegotiation          []byte
	_SecureRenegotiationSupported bool
	_AlpnProtocol                 string

	// 1.3
	_SupportedVersion        uint16
	_ServerShare             keyShare
	_SelectedIdentityPresent bool
	_SelectedIdentity        uint16
	_Cookie                  []byte   // HelloRetryRequest extension
	_SelectedGroup           _CurveID // HelloRetryRequest extension

}

func (shm *_ServerHelloMsg) getPrivatePtr() *serverHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &serverHelloMsg{
			raw:                          shm._Raw,
			vers:                         shm._Vers,
			random:                       shm._Random,
			sessionId:                    shm._SessionId,
			cipherSuite:                  shm._CipherSuite,
			compressionMethod:            shm._CompressionMethod,
			nextProtoNeg:                 shm._NextProtoNeg,
			nextProtos:                   shm._NextProtos,
			ocspStapling:                 shm._OcspStapling,
			scts:                         shm._Scts,
			ems:                          shm._Ems,
			ticketSupported:              shm._TicketSupported,
			secureRenegotiation:          shm._SecureRenegotiation,
			secureRenegotiationSupported: shm._SecureRenegotiationSupported,
			alpnProtocol:                 shm._AlpnProtocol,
			supportedVersion:             shm._SupportedVersion,
			serverShare:                  shm._ServerShare,
			selectedIdentityPresent:      shm._SelectedIdentityPresent,
			selectedIdentity:             shm._SelectedIdentity,
			cookie:                       shm._Cookie,
			selectedGroup:                shm._SelectedGroup,
		}
	}
}

func (shm *serverHelloMsg) getPublicPtr() *_ServerHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &_ServerHelloMsg{
			_Raw:                          shm.raw,
			_Vers:                         shm.vers,
			_Random:                       shm.random,
			_SessionId:                    shm.sessionId,
			_CipherSuite:                  shm.cipherSuite,
			_CompressionMethod:            shm.compressionMethod,
			_NextProtoNeg:                 shm.nextProtoNeg,
			_NextProtos:                   shm.nextProtos,
			_OcspStapling:                 shm.ocspStapling,
			_Scts:                         shm.scts,
			_Ems:                          shm.ems,
			_TicketSupported:              shm.ticketSupported,
			_SecureRenegotiation:          shm.secureRenegotiation,
			_SecureRenegotiationSupported: shm.secureRenegotiationSupported,
			_AlpnProtocol:                 shm.alpnProtocol,
			_SupportedVersion:             shm.supportedVersion,
			_ServerShare:                  shm.serverShare,
			_SelectedIdentityPresent:      shm.selectedIdentityPresent,
			_SelectedIdentity:             shm.selectedIdentity,
			_Cookie:                       shm.cookie,
			_SelectedGroup:                shm.selectedGroup,
		}
	}
}

type _ClientHelloMsg struct {
	_Raw                          []byte
	_Vers                         uint16
	_Random                       []byte
	_SessionId                    []byte
	_CipherSuites                 []uint16
	_CompressionMethods           []uint8
	_NextProtoNeg                 bool
	_ServerName                   string
	_OcspStapling                 bool
	_Scts                         bool
	_Ems                          bool // [UTLS] actually implemented due to its prevalence
	_SupportedCurves              []_CurveID
	_SupportedPoints              []uint8
	_TicketSupported              bool
	_SessionTicket                []uint8
	_SupportedSignatureAlgorithms []_SignatureScheme
	_SecureRenegotiation          []byte
	_SecureRenegotiationSupported bool
	_AlpnProtocols                []string

	// 1.3
	_SupportedSignatureAlgorithmsCert []_SignatureScheme
	_SupportedVersions                []uint16
	_Cookie                           []byte
	_KeyShares                        []_KeyShare
	_EarlyData                        bool
	_PskModes                         []uint8
	_PskIdentities                    []pskIdentity
	_PskBinders                       [][]byte
}

func (chm *_ClientHelloMsg) getPrivatePtr() *clientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &clientHelloMsg{
			raw:                          chm._Raw,
			vers:                         chm._Vers,
			random:                       chm._Random,
			sessionId:                    chm._SessionId,
			cipherSuites:                 chm._CipherSuites,
			compressionMethods:           chm._CompressionMethods,
			nextProtoNeg:                 chm._NextProtoNeg,
			serverName:                   chm._ServerName,
			ocspStapling:                 chm._OcspStapling,
			scts:                         chm._Scts,
			ems:                          chm._Ems,
			supportedCurves:              chm._SupportedCurves,
			supportedPoints:              chm._SupportedPoints,
			ticketSupported:              chm._TicketSupported,
			sessionTicket:                chm._SessionTicket,
			supportedSignatureAlgorithms: chm._SupportedSignatureAlgorithms,
			secureRenegotiation:          chm._SecureRenegotiation,
			secureRenegotiationSupported: chm._SecureRenegotiationSupported,
			alpnProtocols:                chm._AlpnProtocols,

			supportedSignatureAlgorithmsCert: chm._SupportedSignatureAlgorithmsCert,
			supportedVersions:                chm._SupportedVersions,
			cookie:                           chm._Cookie,
			keyShares:                        _KeyShares(chm._KeyShares)._ToPrivate(),
			earlyData:                        chm._EarlyData,
			pskModes:                         chm._PskModes,
			pskIdentities:                    chm._PskIdentities,
			pskBinders:                       chm._PskBinders,
		}
	}
}

func (chm *clientHelloMsg) getPublicPtr() *_ClientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &_ClientHelloMsg{
			_Raw:                          chm.raw,
			_Vers:                         chm.vers,
			_Random:                       chm.random,
			_SessionId:                    chm.sessionId,
			_CipherSuites:                 chm.cipherSuites,
			_CompressionMethods:           chm.compressionMethods,
			_NextProtoNeg:                 chm.nextProtoNeg,
			_ServerName:                   chm.serverName,
			_OcspStapling:                 chm.ocspStapling,
			_Scts:                         chm.scts,
			_Ems:                          chm.ems,
			_SupportedCurves:              chm.supportedCurves,
			_SupportedPoints:              chm.supportedPoints,
			_TicketSupported:              chm.ticketSupported,
			_SessionTicket:                chm.sessionTicket,
			_SupportedSignatureAlgorithms: chm.supportedSignatureAlgorithms,
			_SecureRenegotiation:          chm.secureRenegotiation,
			_SecureRenegotiationSupported: chm.secureRenegotiationSupported,
			_AlpnProtocols:                chm.alpnProtocols,

			_SupportedSignatureAlgorithmsCert: chm.supportedSignatureAlgorithmsCert,
			_SupportedVersions:                chm.supportedVersions,
			_Cookie:                           chm.cookie,
			_KeyShares:                        keyShares(chm.keyShares)._ToPublic(),
			_EarlyData:                        chm.earlyData,
			_PskModes:                         chm.pskModes,
			_PskIdentities:                    chm.pskIdentities,
			_PskBinders:                       chm.pskBinders,
		}
	}
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

// A _FinishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type _FinishedHash struct {
	_Client hash.Hash
	_Server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	_ClientMD5 hash.Hash
	_ServerMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	_Buffer []byte

	_Version uint16
	_Prf     func(result, secret, label, seed []byte)
}

func (fh *_FinishedHash) getPrivateObj() finishedHash {
	if fh == nil {
		return finishedHash{}
	} else {
		return finishedHash{
			client:    fh._Client,
			server:    fh._Server,
			clientMD5: fh._ClientMD5,
			serverMD5: fh._ServerMD5,
			buffer:    fh._Buffer,
			version:   fh._Version,
			prf:       fh._Prf,
		}
	}
}

func (fh *finishedHash) getPublicObj() _FinishedHash {
	if fh == nil {
		return _FinishedHash{}
	} else {
		return _FinishedHash{
			_Client:    fh.client,
			_Server:    fh.server,
			_ClientMD5: fh.clientMD5,
			_ServerMD5: fh.serverMD5,
			_Buffer:    fh.buffer,
			_Version:   fh.version,
			_Prf:       fh.prf}
	}
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type _KeyShare struct {
	_Group _CurveID
	_Data  []byte
}

type _KeyShares []_KeyShare
type keyShares []keyShare

func (kss keyShares) _ToPublic() []_KeyShare {
	var KSS []_KeyShare
	for _, ks := range kss {
		KSS = append(KSS, _KeyShare{_Data: ks.data, _Group: ks.group})
	}
	return KSS
}
func (KSS _KeyShares) _ToPrivate() []keyShare {
	var kss []keyShare
	for _, KS := range KSS {
		kss = append(kss, keyShare{data: KS._Data, group: KS._Group})
	}
	return kss
}

// ClientSessionState is public, but all its fields are private. Let's add setters, getters and constructor

// Encrypted ticket used for session resumption with server
func (css *_ClientSessionState) _SessionTicket() []uint8 {
	return css.sessionTicket
}

// _TicketKey is the internal representation of a session ticket key.
type _TicketKey struct {
	// _KeyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	_KeyName [ticketKeyNameLen]byte
	_AesKey  [16]byte
	_HmacKey [16]byte
}

type _TicketKeys []_TicketKey
type ticketKeys []ticketKey

func (tk ticketKey) _ToPublic() _TicketKey {
	return _TicketKey{
		_KeyName: tk.keyName,
		_AesKey:  tk.aesKey,
		_HmacKey: tk.hmacKey,
	}
}

func (TK _TicketKey) _ToPrivate() ticketKey {
	return ticketKey{
		keyName: TK._KeyName,
		aesKey:  TK._AesKey,
		hmacKey: TK._HmacKey,
	}
}

func (tks ticketKeys) _ToPublic() []_TicketKey {
	var TKS []_TicketKey
	for _, ks := range tks {
		TKS = append(TKS, ks._ToPublic())
	}
	return TKS
}

func (TKS _TicketKeys) _ToPrivate() []ticketKey {
	var tks []ticketKey
	for _, TK := range TKS {
		tks = append(tks, TK._ToPrivate())
	}
	return tks
}
