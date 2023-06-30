// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls partially implements TLS 1.2, as specified in RFC 5246,
// and TLS 1.3, as specified in RFC 8446.
//
// TLS 1.3 is available on an opt-out basis in Go 1.13. To disable
// it, set the GODEBUG environment variable (comma-separated key=value
// options) such that it includes "tls13=0".
package tls

import (
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math/big"
	"strconv"
)

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

type alert uint8

const (
	// alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify            alert = 0
	alertUnexpectedMessage      alert = 10
	alertBadRecordMAC           alert = 20
	alertDecryptionFailed       alert = 21
	alertRecordOverflow         alert = 22
	alertDecompressionFailure   alert = 30
	alertHandshakeFailure       alert = 40
	alertBadCertificate         alert = 42
	alertUnsupportedCertificate alert = 43
	alertCertificateRevoked     alert = 44
	alertCertificateExpired     alert = 45
	alertCertificateUnknown     alert = 46
	alertIllegalParameter       alert = 47
	alertUnknownCA              alert = 48
	alertAccessDenied           alert = 49
	alertDecodeError            alert = 50
	alertDecryptError           alert = 51
	alertProtocolVersion        alert = 70
	alertInsufficientSecurity   alert = 71
	alertInternalError          alert = 80
	alertInappropriateFallback  alert = 86
	alertUserCanceled           alert = 90
	alertNoRenegotiation        alert = 100
	alertMissingExtension       alert = 109
	alertUnsupportedExtension   alert = 110
	alertNoApplicationProtocol  alert = 120
)

var alertText = map[alert]string{
	alertCloseNotify:            "close notify",
	alertUnexpectedMessage:      "unexpected message",
	alertBadRecordMAC:           "bad record MAC",
	alertDecryptionFailed:       "decryption failed",
	alertRecordOverflow:         "record overflow",
	alertDecompressionFailure:   "decompression failure",
	alertHandshakeFailure:       "handshake failure",
	alertBadCertificate:         "bad certificate",
	alertUnsupportedCertificate: "unsupported certificate",
	alertCertificateRevoked:     "revoked certificate",
	alertCertificateExpired:     "expired certificate",
	alertCertificateUnknown:     "unknown certificate",
	alertIllegalParameter:       "illegal parameter",
	alertUnknownCA:              "unknown certificate authority",
	alertAccessDenied:           "access denied",
	alertDecodeError:            "error decoding message",
	alertDecryptError:           "error decrypting message",
	alertProtocolVersion:        "protocol version not supported",
	alertInsufficientSecurity:   "insufficient security level",
	alertInternalError:          "internal error",
	alertInappropriateFallback:  "inappropriate fallback",
	alertUserCanceled:           "user canceled",
	alertNoRenegotiation:        "no renegotiation",
	alertMissingExtension:       "missing extension",
	alertUnsupportedExtension:   "unsupported extension",
	alertNoApplicationProtocol:  "no application protocol",
}

func (e alert) _String() string {
	s, ok := alertText[e]
	if ok {
		return "tls: " + s
	}
	return "tls: alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e._String()
}

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		h := c.hash.New()
		h.Write(context)
		return c.expandLabel(secret, "exporter", h.Sum(nil), length), nil
	}
}

// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	_CurveID() _CurveID
	_PublicKey() []byte
	_SharedKey(peerPublicKey []byte) []byte
}

func generateECDHEParameters(rand io.Reader, curveID _CurveID) (ecdheParameters, error) {
	if curveID == _X25519 {
		p := &x25519Parameters{}
		if _, err := io.ReadFull(rand, p.privateKey[:]); err != nil {
			return nil, err
		}
		curve25519.ScalarBaseMult(&p.publicKey, &p.privateKey)
		return p, nil
	}

	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	p := &nistParameters{curveID: curveID}
	var err error
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func curveForCurveID(id _CurveID) (elliptic.Curve, bool) {
	switch id {
	case _CurveP256:
		return elliptic.P256(), true
	case _CurveP384:
		return elliptic.P384(), true
	case _CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

type nistParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    _CurveID
}

func (p *nistParameters) _CurveID() _CurveID {
	return p.curveID
}

func (p *nistParameters) _PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

func (p *nistParameters) _SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)>>3)
	xBytes := xShared.Bytes()
	copy(sharedKey[len(sharedKey)-len(xBytes):], xBytes)

	return sharedKey
}

type x25519Parameters struct {
	privateKey [32]byte
	publicKey  [32]byte
}

func (p *x25519Parameters) _CurveID() _CurveID {
	return _X25519
}

func (p *x25519Parameters) _PublicKey() []byte {
	return p.publicKey[:]
}

func (p *x25519Parameters) _SharedKey(peerPublicKey []byte) []byte {
	if len(peerPublicKey) != 32 {
		return nil
	}
	var theirPublicKey, sharedKey [32]byte
	copy(theirPublicKey[:], peerPublicKey)
	curve25519.ScalarMult(&sharedKey, &p.privateKey, &theirPublicKey)
	return sharedKey[:]
}
