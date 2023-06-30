// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// _Fingerprinter is a struct largely for holding options for the FingerprintClientHello func
type _Fingerprinter struct {
	// _KeepPSK will ensure that the PreSharedKey extension is passed along into the resulting ClientHelloSpec as-is
	_KeepPSK bool
	// _AllowBluntMimicry will ensure that unknown extensions are
	// passed along into the resulting ClientHelloSpec as-is
	// It will not ensure that the PSK is passed along, if you require that, use KeepPSK
	// WARNING: there could be numerous subtle issues with ClientHelloSpecs
	// that are generated with this flag which could compromise security and/or mimicry
	_AllowBluntMimicry bool
	// _AlwaysAddPadding will always add a UtlsPaddingExtension with BoringPaddingStyle
	// at the end of the extensions list if it isn't found in the fingerprinted hello.
	// This could be useful in scenarios where the hello you are fingerprinting does not
	// have any padding, but you suspect that other changes you make to the final hello
	// (including things like different SNI lengths) would cause padding to be necessary
	_AlwaysAddPadding bool
}

// _FingerprintClientHello returns a ClientHelloSpec which is based on the
// ClientHello that is passed in as the data argument
//
// If the ClientHello passed in has extensions that are not recognized or cannot be handled
// it will return a non-nil error and a nil *ClientHelloSpec value
//
// The data should be the full tls record, including the record type/version/length header
// as well as the handshake type/length/version header
// https://tools.ietf.org/html/rfc5246#section-6.2
// https://tools.ietf.org/html/rfc5246#section-7.4
func (f *_Fingerprinter) _FingerprintClientHello(data []byte) (*_ClientHelloSpec, error) {
	clientHelloSpec := &_ClientHelloSpec{}
	s := cryptobyte.String(data)

	var contentType uint8
	var recordVersion uint16
	if !s.ReadUint8(&contentType) || // record type
		!s.ReadUint16(&recordVersion) || !s.Skip(2) { // record version and length
		return nil, errors.New("unable to read record type, version, and length")
	}

	if recordType(contentType) != recordTypeHandshake {
		return nil, errors.New("record is not a handshake")
	}

	var handshakeVersion uint16
	var handshakeType uint8

	if !s.ReadUint8(&handshakeType) || !s.Skip(3) || // message type and 3 byte length
		!s.ReadUint16(&handshakeVersion) || !s.Skip(32) { // 32 byte random
		return nil, errors.New("unable to read handshake message type, length, and random")
	}

	if handshakeType != typeClientHello {
		return nil, errors.New("handshake message is not a ClientHello")
	}

	clientHelloSpec._TLSVersMin = recordVersion
	clientHelloSpec._TLSVersMax = handshakeVersion

	var ignoredSessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredSessionID) {
		return nil, errors.New("unable to read session id")
	}

	var cipherSuitesBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesBytes) {
		return nil, errors.New("unable to read ciphersuites")
	}
	cipherSuites := []uint16{}
	for !cipherSuitesBytes.Empty() {
		var suite uint16
		if !cipherSuitesBytes.ReadUint16(&suite) {
			return nil, errors.New("unable to read ciphersuite")
		}
		cipherSuites = append(cipherSuites, unGREASEUint16(suite))
	}
	clientHelloSpec._CipherSuites = cipherSuites

	if !readUint8LengthPrefixed(&s, &clientHelloSpec._CompressionMethods) {
		return nil, errors.New("unable to read compression methods")
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return clientHelloSpec, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, errors.New("unable to read extensions data")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("unable to read extension data")
		}

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return nil, errors.New("unable to read server name extension data")
			}
			var serverName string
			for !nameList.Empty() {
				var nameType uint8
				var serverNameBytes cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverNameBytes) ||
					serverNameBytes.Empty() {
					return nil, errors.New("unable to read server name extension data")
				}
				if nameType != 0 {
					continue
				}
				if len(serverName) != 0 {
					return nil, errors.New("multiple names of the same name_type in server name extension are prohibited")
				}
				serverName = string(serverNameBytes)
				if strings.HasSuffix(serverName, ".") {
					return nil, errors.New("SNI value may not include a trailing dot")
				}

				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SNIExtension{})

			}
		case extensionNextProtoNeg:
			// draft-agl-tls-nextprotoneg-04
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_NPNExtension{})

		case extensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return nil, errors.New("unable to read status request extension data")
			}

			if statusType == statusTypeOCSP {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &StatusRequestExtension{})
			} else {
				return nil, errors.New("status request extension statusType is not statusTypeOCSP")
			}

		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curvesBytes cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curvesBytes) || curvesBytes.Empty() {
				return nil, errors.New("unable to read supported curves extension data")
			}
			curves := []_CurveID{}
			for !curvesBytes.Empty() {
				var curve uint16
				if !curvesBytes.ReadUint16(&curve) {
					return nil, errors.New("unable to read supported curves extension data")
				}
				curves = append(curves, _CurveID(unGREASEUint16(curve)))
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SupportedCurvesExtension{curves})

		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			supportedPoints := []uint8{}
			if !readUint8LengthPrefixed(&extData, &supportedPoints) ||
				len(supportedPoints) == 0 {
				return nil, errors.New("unable to read supported points extension data")
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SupportedPointsExtension{supportedPoints})

		case extensionSessionTicket:
			// RFC 5077, Section 3.2
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SessionTicketExtension{})

		case extensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return nil, errors.New("unable to read signature algorithms extension data")
			}
			supportedSignatureAlgorithms := []SignatureScheme{}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return nil, errors.New("unable to read signature algorithms extension data")
				}
				supportedSignatureAlgorithms = append(
					supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SignatureAlgorithmsExtension{supportedSignatureAlgorithms})

		case extensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			if f._AllowBluntMimicry {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})
			} else {
				return nil, errors.New("unsupported extension SignatureAlgorithmsCert")
			}

		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &RenegotiationInfoExtension{RenegotiateOnceAsClient})

		case extensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return nil, errors.New("unable to read ALPN extension data")
			}
			alpnProtocols := []string{}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return nil, errors.New("unable to read ALPN extension data")
				}
				alpnProtocols = append(alpnProtocols, string(proto))

			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_ALPNExtension{alpnProtocols})

		case extensionSCT:
			// RFC 6962, Section 3.3.1
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SCTExtension{})

		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return nil, errors.New("unable to read supported versions extension data")
			}
			supportedVersions := []uint16{}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return nil, errors.New("unable to read supported versions extension data")
				}
				supportedVersions = append(supportedVersions, unGREASEUint16(vers))
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &SupportedVersionsExtension{supportedVersions})
			// If SupportedVersionsExtension is present, use that instead of record+handshake versions
			clientHelloSpec._TLSVersMin = 0
			clientHelloSpec._TLSVersMax = 0

		case extensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return nil, errors.New("unable to read key share extension data")
			}
			keyShares := []_KeyShare{}
			for !clientShares.Empty() {
				var ks _KeyShare
				var group uint16
				if !clientShares.ReadUint16(&group) ||
					!readUint16LengthPrefixed(&clientShares, &ks._Data) ||
					len(ks._Data) == 0 {
					return nil, errors.New("unable to read key share extension data")
				}
				ks._Group = _CurveID(unGREASEUint16(group))
				// if not GREASE, key share data will be discarded as it should
				// be generated per connection
				if ks._Group != _GREASE_PLACEHOLDER {
					ks._Data = nil
				}
				keyShares = append(keyShares, ks)
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_KeyShareExtension{keyShares})

		case extensionPSKModes:
			// RFC 8446, Section 4.2.9
			// TODO: PSK Modes have their own form of GREASE-ing which is not currently implemented
			// the current functionality will NOT re-GREASE/re-randomize these values when using a fingerprinted spec
			// https://github.com/refraction-networking/utls/pull/58#discussion_r522354105
			// https://tools.ietf.org/html/draft-ietf-tls-grease-01#section-2
			pskModes := []uint8{}
			if !readUint8LengthPrefixed(&extData, &pskModes) {
				return nil, errors.New("unable to read PSK extension data")
			}
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_PSKKeyExchangeModesExtension{pskModes})

		case utlsExtensionExtendedMasterSecret:
			// https://tools.ietf.org/html/rfc7627
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &UtlsExtendedMasterSecretExtension{})

		case utlsExtensionPadding:
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle})

		case fakeExtensionChannelID, fakeCertCompressionAlgs, fakeRecordSizeLimit:
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})

		case extensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if f._KeepPSK {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})
			} else {
				return nil, errors.New("unsupported extension PreSharedKey")
			}

		case extensionCookie:
			// RFC 8446, Section 4.2.2
			if f._AllowBluntMimicry {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})
			} else {
				return nil, errors.New("unsupported extension Cookie")
			}

		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			if f._AllowBluntMimicry {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})
			} else {
				return nil, errors.New("unsupported extension EarlyData")
			}

		default:
			if isGREASEUint16(extension) {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &UtlsGREASEExtension{unGREASEUint16(extension), extData})
			} else if f._AllowBluntMimicry {
				clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &_GenericExtension{extension, extData})
			} else {
				return nil, fmt.Errorf("unsupported extension %#x", extension)
			}

			continue
		}
	}

	if f._AlwaysAddPadding {
		alreadyHasPadding := false
		for _, ext := range clientHelloSpec._Extensions {
			if _, ok := ext.(*UtlsPaddingExtension); ok {
				alreadyHasPadding = true
				break
			}
		}
		if !alreadyHasPadding {
			clientHelloSpec._Extensions = append(clientHelloSpec._Extensions, &UtlsPaddingExtension{_GetPaddingLen: _BoringPaddingStyle})
		}
	}

	return clientHelloSpec, nil
}
