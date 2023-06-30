// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

func utlsIdToSpec(id _ClientHelloID) (_ClientHelloSpec, error) {
	switch id {
	case _HelloChrome_58, _HelloChrome_62:
		return _ClientHelloSpec{
			_TLSVersMax: _VersionTLS12,
			_TLSVersMin: _VersionTLS10,
			_CipherSuites: []uint16{
				_GREASE_PLACEHOLDER,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{compressionNone},
			_Extensions: []_TLSExtension{
				&UtlsGREASEExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
					_PKCS1WithSHA1},
				},
				&_StatusRequestExtension{},
				&SCTExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_FakeChannelIDExtension{},
				&_SupportedPointsExtension{_SupportedPoints: []byte{pointFormatUncompressed}},
				&_SupportedCurvesExtension{[]_CurveID{_CurveID(_GREASE_PLACEHOLDER),
					_X25519, _CurveP256, _CurveP384}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			},
			_GetSessionID: sha256.Sum256,
		}, nil
	case _HelloChrome_70:
		return _ClientHelloSpec{
			_TLSVersMin: _VersionTLS10,
			_TLSVersMax: _VersionTLS13,
			_CipherSuites: []uint16{
				_GREASE_PLACEHOLDER,
				_TLS_AES_128_GCM_SHA256,
				_TLS_AES_256_GCM_SHA384,
				_TLS_CHACHA20_POLY1305_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{
				compressionNone,
			},
			_Extensions: []_TLSExtension{
				&UtlsGREASEExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
					_PKCS1WithSHA1,
				}},
				&_StatusRequestExtension{},
				&SCTExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_FakeChannelIDExtension{},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&_KeyShareExtension{[]_KeyShare{
					{_Group: _CurveID(_GREASE_PLACEHOLDER), _Data: []byte{0}},
					{_Group: _X25519},
				}},
				&_PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&SupportedVersionsExtension{[]uint16{
					_GREASE_PLACEHOLDER,
					_VersionTLS13,
					_VersionTLS12,
					_VersionTLS11,
					_VersionTLS10}},
				&_SupportedCurvesExtension{[]_CurveID{
					_CurveID(_GREASE_PLACEHOLDER),
					_X25519,
					_CurveP256,
					_CurveP384,
				}},
				&_FakeCertCompressionAlgsExtension{[]_CertCompressionAlgo{_CertCompressionBrotli}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			},
		}, nil
	case _HelloChrome_72:
		return _ClientHelloSpec{
			_CipherSuites: []uint16{
				_GREASE_PLACEHOLDER,
				_TLS_AES_128_GCM_SHA256,
				_TLS_AES_256_GCM_SHA384,
				_TLS_CHACHA20_POLY1305_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{
				0x00, // compressionNone
			},
			_Extensions: []_TLSExtension{
				&UtlsGREASEExtension{},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SupportedCurvesExtension{[]_CurveID{
					_CurveID(_GREASE_PLACEHOLDER),
					_X25519,
					_CurveP256,
					_CurveP384,
				}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_StatusRequestExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
					_PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&_KeyShareExtension{[]_KeyShare{
					{_Group: _CurveID(_GREASE_PLACEHOLDER), _Data: []byte{0}},
					{_Group: _X25519},
				}},
				&_PSKKeyExchangeModesExtension{[]uint8{
					_PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					_GREASE_PLACEHOLDER,
					_VersionTLS13,
					_VersionTLS12,
					_VersionTLS11,
					_VersionTLS10,
				}},
				&_FakeCertCompressionAlgsExtension{[]_CertCompressionAlgo{
					_CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			},
		}, nil
	case _HelloChrome_83:
		return _ClientHelloSpec{
			_CipherSuites: []uint16{
				_GREASE_PLACEHOLDER,
				_TLS_AES_128_GCM_SHA256,
				_TLS_AES_256_GCM_SHA384,
				_TLS_CHACHA20_POLY1305_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			_CompressionMethods: []byte{
				0x00, // compressionNone
			},
			_Extensions: []_TLSExtension{
				&UtlsGREASEExtension{},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SupportedCurvesExtension{[]_CurveID{
					_CurveID(_GREASE_PLACEHOLDER),
					_X25519,
					_CurveP256,
					_CurveP384,
				}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_StatusRequestExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&_KeyShareExtension{[]_KeyShare{
					{_Group: _CurveID(_GREASE_PLACEHOLDER), _Data: []byte{0}},
					{_Group: _X25519},
				}},
				&_PSKKeyExchangeModesExtension{[]uint8{
					_PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					_GREASE_PLACEHOLDER,
					_VersionTLS13,
					_VersionTLS12,
					_VersionTLS11,
					_VersionTLS10,
				}},
				&_FakeCertCompressionAlgsExtension{[]_CertCompressionAlgo{
					_CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			},
		}, nil
	case _HelloFirefox_55, _HelloFirefox_56:
		return _ClientHelloSpec{
			_TLSVersMax: _VersionTLS12,
			_TLSVersMin: _VersionTLS10,
			_CipherSuites: []uint16{
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				_FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{compressionNone},
			_Extensions: []_TLSExtension{
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SupportedCurvesExtension{[]_CurveID{_X25519, _CurveP256, _CurveP384, _CurveP521}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{pointFormatUncompressed}},
				&SessionTicketExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_StatusRequestExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_ECDSAWithP384AndSHA384,
					_ECDSAWithP521AndSHA512,
					_PSSWithSHA256,
					_PSSWithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA256,
					_PKCS1WithSHA384,
					_PKCS1WithSHA512,
					_ECDSAWithSHA1,
					_PKCS1WithSHA1},
				},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			},
			_GetSessionID: nil,
		}, nil
	case _HelloFirefox_63, _HelloFirefox_65:
		return _ClientHelloSpec{
			_TLSVersMin: _VersionTLS10,
			_TLSVersMax: _VersionTLS13,
			_CipherSuites: []uint16{
				_TLS_AES_128_GCM_SHA256,
				_TLS_CHACHA20_POLY1305_SHA256,
				_TLS_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				_FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{
				compressionNone,
			},
			_Extensions: []_TLSExtension{
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SupportedCurvesExtension{[]_CurveID{
					_X25519,
					_CurveP256,
					_CurveP384,
					_CurveP521,
					_CurveID(_FakeFFDHE2048),
					_CurveID(_FakeFFDHE3072),
				}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "http/1.1"}},
				&_StatusRequestExtension{},
				&_KeyShareExtension{[]_KeyShare{
					{_Group: _X25519},
					{_Group: _CurveP256},
				}},
				&SupportedVersionsExtension{[]uint16{
					_VersionTLS13,
					_VersionTLS12,
					_VersionTLS11,
					_VersionTLS10}},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_ECDSAWithP384AndSHA384,
					_ECDSAWithP521AndSHA512,
					_PSSWithSHA256,
					_PSSWithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA256,
					_PKCS1WithSHA384,
					_PKCS1WithSHA512,
					_ECDSAWithSHA1,
					_PKCS1WithSHA1,
				}},
				&_PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&_FakeRecordSizeLimitExtension{0x4001},
				&UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle},
			}}, nil
	case _HelloIOS_11_1:
		return _ClientHelloSpec{
			_TLSVersMax: _VersionTLS12,
			_TLSVersMin: _VersionTLS10,
			_CipherSuites: []uint16{
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				_TLS_RSA_WITH_AES_128_CBC_SHA256,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			_CompressionMethods: []byte{
				compressionNone,
			},
			_Extensions: []_TLSExtension{
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
					_PKCS1WithSHA1,
				}},
				&_StatusRequestExtension{},
				&_NPNExtension{},
				&SCTExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&_SupportedCurvesExtension{_Curves: []_CurveID{
					_X25519,
					_CurveP256,
					_CurveP384,
					_CurveP521,
				}},
			},
		}, nil
	case _HelloIOS_12_1:
		return _ClientHelloSpec{
			_CipherSuites: []uint16{
				_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				_TLS_RSA_WITH_AES_256_GCM_SHA384,
				_TLS_RSA_WITH_AES_128_GCM_SHA256,
				_DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				_TLS_RSA_WITH_AES_128_CBC_SHA256,
				_TLS_RSA_WITH_AES_256_CBC_SHA,
				_TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			_CompressionMethods: []byte{
				compressionNone,
			},
			_Extensions: []_TLSExtension{
				&_RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient},
				&_SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&_SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: []_SignatureScheme{
					_ECDSAWithP256AndSHA256,
					_PSSWithSHA256,
					_PKCS1WithSHA256,
					_ECDSAWithP384AndSHA384,
					_ECDSAWithSHA1,
					_PSSWithSHA384,
					_PSSWithSHA384,
					_PKCS1WithSHA384,
					_PSSWithSHA512,
					_PKCS1WithSHA512,
					_PKCS1WithSHA1,
				}},
				&_StatusRequestExtension{},
				&_NPNExtension{},
				&SCTExtension{},
				&_ALPNExtension{_AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&_SupportedPointsExtension{_SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&_SupportedCurvesExtension{[]_CurveID{
					_X25519,
					_CurveP256,
					_CurveP384,
					_CurveP521,
				}},
			},
		}, nil
	default:
		return _ClientHelloSpec{}, errors.New("ClientHello ID " + id._Str() + " is unknown")
	}
}

func (uconn *_UConn) applyPresetByID(id _ClientHelloID) (err error) {
	var spec _ClientHelloSpec
	uconn._ClientHelloID = id
	// choose/generate the spec
	switch id._Client {
	case helloRandomized, helloRandomizedNoALPN, helloRandomizedALPN:
		spec, err = uconn.generateRandomizedSpec()
		if err != nil {
			return err
		}
	case helloCustom:
		return nil

	default:
		spec, err = utlsIdToSpec(id)
		if err != nil {
			return err
		}
	}

	return uconn._ApplyPreset(&spec)
}

// _ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Fields of TLSExtensions that are slices/pointers are shared across different connections with
// same ClientHelloSpec. It is advised to use different specs and avoid any shared state.
func (uconn *_UConn) _ApplyPreset(p *_ClientHelloSpec) error {
	var err error

	err = uconn._SetTLSVers(p._TLSVersMin, p._TLSVersMax, p._Extensions)
	if err != nil {
		return err
	}

	privateHello, ecdheParams, err := uconn.Conn.makeClientHello()
	if err != nil {
		return err
	}
	uconn._HandshakeState._Hello = privateHello.getPublicPtr()
	uconn._HandshakeState._State13._EcdheParams = ecdheParams
	hello := uconn._HandshakeState._Hello
	session := uconn._HandshakeState._Session

	switch len(hello._Random) {
	case 0:
		hello._Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.Conn.config.rand(), hello._Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
	// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello._Random)) + " bytes")
	}
	if len(hello._CipherSuites) == 0 {
		hello._CipherSuites = defaultCipherSuites()
	}
	if len(hello._CompressionMethods) == 0 {
		hello._CompressionMethods = []uint8{compressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_bytes := make([]byte, 2*ssl_grease_last_index)
	grease_extensions_seen := 0
	_, err = io.ReadFull(uconn.Conn.config.rand(), grease_bytes)
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	for i := range uconn.greaseSeed {
		uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
	}
	if _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1) == _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2) {
		uconn.greaseSeed[ssl_grease_extension2] ^= 0x1010
	}

	hello._CipherSuites = make([]uint16, len(p._CipherSuites))
	copy(hello._CipherSuites, p._CipherSuites)
	for i := range hello._CipherSuites {
		if hello._CipherSuites[i] == _GREASE_PLACEHOLDER {
			hello._CipherSuites[i] = _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
		}
	}
	uconn._GetSessionID = p._GetSessionID
	uconn._Extensions = make([]_TLSExtension, len(p._Extensions))
	copy(uconn._Extensions, p._Extensions)

	// Check whether NPN extension actually exists
	var haveNPN bool

	// reGrease, and point things to each other
	for _, e := range uconn._Extensions {
		switch ext := e.(type) {
		case *_SNIExtension:
			if ext._ServerName == "" {
				ext._ServerName = uconn.Conn.config._ServerName
			}
		case *UtlsGREASEExtension:
			switch grease_extensions_seen {
			case 0:
				ext._Value = _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1)
			case 1:
				ext._Value = _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2)
				ext._Body = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
			}
			grease_extensions_seen += 1
		case *SessionTicketExtension:
			if session == nil && uconn.Conn.config._ClientSessionCache != nil {
				cacheKey := clientSessionCacheKey(uconn.Conn._RemoteAddr(), uconn.Conn.config)
				session, _ = uconn.Conn.config._ClientSessionCache._Get(cacheKey)
				// TODO: use uconn.loadSession(hello.getPrivateObj()) to support TLS 1.3 PSK-style resumption
			}
			err := uconn._SetSessionState(session)
			if err != nil {
				return err
			}
		case *_SupportedCurvesExtension:
			for i := range ext._Curves {
				if ext._Curves[i] == _GREASE_PLACEHOLDER {
					ext._Curves[i] = _CurveID(_GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
				}
			}
		case *_KeyShareExtension:
			preferredCurveIsSet := false
			for i := range ext._KeyShares {
				curveID := ext._KeyShares[i]._Group
				if curveID == _GREASE_PLACEHOLDER {
					ext._KeyShares[i]._Group = _CurveID(_GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
					continue
				}
				if len(ext._KeyShares[i]._Data) > 1 {
					continue
				}

				ecdheParams, err := generateECDHEParameters(uconn.Conn.config.rand(), curveID)
				if err != nil {
					return fmt.Errorf("unsupported Curve in KeyShareExtension: %v."+
						"To mimic it, fill the Data(key) field manually.", curveID)
				}
				ext._KeyShares[i]._Data = ecdheParams.PublicKey()
				if !preferredCurveIsSet {
					// only do this once for the first non-grease curve
					uconn._HandshakeState._State13._EcdheParams = ecdheParams
					preferredCurveIsSet = true
				}
			}
		case *SupportedVersionsExtension:
			for i := range ext._Versions {
				if ext._Versions[i] == _GREASE_PLACEHOLDER {
					ext._Versions[i] = _GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_version)
				}
			}
		case *_NPNExtension:
			haveNPN = true
		}
	}

	// The default golang behavior in makeClientHello always sets NextProtoNeg if NextProtos is set,
	// but NextProtos is also used by ALPN and our spec nmay not actually have a NPN extension
	hello._NextProtoNeg = haveNPN

	return nil
}

func (uconn *_UConn) generateRandomizedSpec() (_ClientHelloSpec, error) {
	p := _ClientHelloSpec{}

	if uconn._ClientHelloID._Seed == nil {
		seed, err := _NewPRNGSeed()
		if err != nil {
			return p, err
		}
		uconn._ClientHelloID._Seed = seed
	}

	r, err := newPRNGWithSeed(uconn._ClientHelloID._Seed)
	if err != nil {
		return p, err
	}

	id := uconn._ClientHelloID

	var WithALPN bool
	switch id._Client {
	case helloRandomizedALPN:
		WithALPN = true
	case helloRandomizedNoALPN:
		WithALPN = false
	case helloRandomized:
		if r._FlipWeightedCoin(0.7) {
			WithALPN = true
		} else {
			WithALPN = false
		}
	default:
		return p, fmt.Errorf("using non-randomized ClientHelloID %v to generate randomized spec", id._Client)
	}

	p._CipherSuites = make([]uint16, len(defaultCipherSuites()))
	copy(p._CipherSuites, defaultCipherSuites())
	shuffledSuites, err := shuffledCiphers(r)
	if err != nil {
		return p, err
	}

	if r._FlipWeightedCoin(0.4) {
		p._TLSVersMin = _VersionTLS10
		p._TLSVersMax = _VersionTLS13
		tls13ciphers := make([]uint16, len(defaultCipherSuitesTLS13()))
		copy(tls13ciphers, defaultCipherSuitesTLS13())
		r.rand.Shuffle(len(tls13ciphers), func(i, j int) {
			tls13ciphers[i], tls13ciphers[j] = tls13ciphers[j], tls13ciphers[i]
		})
		// appending TLS 1.3 ciphers before TLS 1.2, since that's what popular implementations do
		shuffledSuites = append(tls13ciphers, shuffledSuites...)

		// TLS 1.3 forbids RC4 in any configurations
		shuffledSuites = removeRC4Ciphers(shuffledSuites)
	} else {
		p._TLSVersMin = _VersionTLS10
		p._TLSVersMax = _VersionTLS12
	}

	p._CipherSuites = removeRandomCiphers(r, shuffledSuites, 0.4)

	sni := _SNIExtension{uconn.Conn.config._ServerName}
	sessionTicket := SessionTicketExtension{_Session: uconn._HandshakeState._Session}

	sigAndHashAlgos := []_SignatureScheme{
		_ECDSAWithP256AndSHA256,
		_PKCS1WithSHA256,
		_ECDSAWithP384AndSHA384,
		_PKCS1WithSHA384,
		_PKCS1WithSHA1,
		_PKCS1WithSHA512,
	}

	if r._FlipWeightedCoin(0.63) {
		sigAndHashAlgos = append(sigAndHashAlgos, _ECDSAWithSHA1)
	}
	if r._FlipWeightedCoin(0.59) {
		sigAndHashAlgos = append(sigAndHashAlgos, _ECDSAWithP521AndSHA512)
	}
	if r._FlipWeightedCoin(0.51) || p._TLSVersMax == _VersionTLS13 {
		// https://tools.ietf.org/html/rfc8446 says "...RSASSA-PSS (which is mandatory in TLS 1.3)..."
		sigAndHashAlgos = append(sigAndHashAlgos, _PSSWithSHA256)
		if r._FlipWeightedCoin(0.9) {
			// these usually go together
			sigAndHashAlgos = append(sigAndHashAlgos, _PSSWithSHA384)
			sigAndHashAlgos = append(sigAndHashAlgos, _PSSWithSHA512)
		}
	}

	r.rand.Shuffle(len(sigAndHashAlgos), func(i, j int) {
		sigAndHashAlgos[i], sigAndHashAlgos[j] = sigAndHashAlgos[j], sigAndHashAlgos[i]
	})
	sigAndHash := _SignatureAlgorithmsExtension{_SupportedSignatureAlgorithms: sigAndHashAlgos}

	status := _StatusRequestExtension{}
	sct := SCTExtension{}
	ems := UtlsExtendedMasterSecretExtension{}
	points := _SupportedPointsExtension{_SupportedPoints: []byte{pointFormatUncompressed}}

	curveIDs := []_CurveID{}
	if r._FlipWeightedCoin(0.71) || p._TLSVersMax == _VersionTLS13 {
		curveIDs = append(curveIDs, _X25519)
	}
	curveIDs = append(curveIDs, _CurveP256, _CurveP384)
	if r._FlipWeightedCoin(0.46) {
		curveIDs = append(curveIDs, _CurveP521)
	}

	curves := _SupportedCurvesExtension{curveIDs}

	padding := UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle}
	reneg := _RenegotiationInfoExtension{_Renegotiation: _RenegotiateOnceAsClient}

	p._Extensions = []_TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if WithALPN {
		if len(uconn.Conn.config._NextProtos) == 0 {
			// if user didn't specify alpn yet, choose something popular
			uconn.Conn.config._NextProtos = []string{"h2", "http/1.1"}
		}
		alpn := _ALPNExtension{_AlpnProtocols: uconn.Conn.config._NextProtos}
		p._Extensions = append(p._Extensions, &alpn)
	}

	if r._FlipWeightedCoin(0.62) || p._TLSVersMax == _VersionTLS13 {
		// always include for TLS 1.3, since TLS 1.3 ClientHellos are often over 256 bytes
		// and that's when padding is required to work around buggy middleboxes
		p._Extensions = append(p._Extensions, &padding)
	}
	if r._FlipWeightedCoin(0.74) {
		p._Extensions = append(p._Extensions, &status)
	}
	if r._FlipWeightedCoin(0.46) {
		p._Extensions = append(p._Extensions, &sct)
	}
	if r._FlipWeightedCoin(0.75) {
		p._Extensions = append(p._Extensions, &reneg)
	}
	if r._FlipWeightedCoin(0.77) {
		p._Extensions = append(p._Extensions, &ems)
	}
	if p._TLSVersMax == _VersionTLS13 {
		ks := _KeyShareExtension{[]_KeyShare{
			{_Group: _X25519}, // the key for the group will be generated later
		}}
		if r._FlipWeightedCoin(0.25) {
			// do not ADD second keyShare because crypto/tls does not support multiple ecdheParams
			// TODO: add it back when they implement multiple keyShares, or implement it oursevles
			// ks.KeyShares = append(ks.KeyShares, KeyShare{Group: CurveP256})
			ks._KeyShares[0]._Group = _CurveP256
		}
		pskExchangeModes := _PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}}
		supportedVersionsExt := SupportedVersionsExtension{
			_Versions: makeSupportedVersions(p._TLSVersMin, p._TLSVersMax),
		}
		p._Extensions = append(p._Extensions, &ks, &pskExchangeModes, &supportedVersionsExt)
	}
	r.rand.Shuffle(len(p._Extensions), func(i, j int) {
		p._Extensions[i], p._Extensions[j] = p._Extensions[j], p._Extensions[i]
	})

	return p, nil
}

func removeRandomCiphers(r *prng, s []uint16, maxRemovalProbability float64) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float64(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if r._FlipWeightedCoin(maxRemovalProbability * float64(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func shuffledCiphers(r *prng) ([]uint16, error) {
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm := r._Perm(len(cipherSuites))
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	return ciphers._GetCiphers(), nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) _GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

func removeRC4Ciphers(s []uint16) []uint16 {
	// removes elements in place
	sliceLen := len(s)
	for i := 0; i < sliceLen; i++ {
		cipher := s[i]
		if cipher == _TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ||
			cipher == _TLS_ECDHE_RSA_WITH_RC4_128_SHA ||
			cipher == _TLS_RSA_WITH_RC4_128_SHA {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}
