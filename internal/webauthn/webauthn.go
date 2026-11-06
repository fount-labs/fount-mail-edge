// Package webauthn verifies a single, deliberately narrow thing: a WebAuthn
// assertion (the result of a passkey get()) produced by a platform authenticator
// — Touch ID, Windows Hello, a security key — over a challenge the edge issued.
// It is the proof POST /recover (design §5) relies on: that the real owner's
// passkey, not the host, approved rotating a mailbox's keys.
//
// It supports exactly one algorithm, ES256 (ECDSA on P-256 with SHA-256, COSE
// alg -7), which is what platform passkeys overwhelmingly emit. Pinning one
// algorithm keeps this a fixed-shape parser — a known clientDataJSON (JSON we
// already parse) and a fixed authenticatorData layout — instead of a general
// COSE/CBOR decoder. That is the whole point: the fewer attacker-influenced
// shapes this touches, the smaller the trusted surface. An authenticator that
// can't do ES256 falls back to the recovery code (§5), not to more parser here.
//
// The verification follows the WebAuthn §7.2 assertion steps that matter under
// our threat model (the host is the adversary; the authenticator and the user
// are not): the authenticator signed authenticatorData || SHA-256(clientDataJSON),
// the clientDataJSON pins type and our challenge, and authenticatorData pins our
// RP id and that the user was present and verified.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// flagUserPresent and flagUserVerified are the authenticatorData flag bits we
// require. A platform passkey is always user-verifying, and recovery is a
// high-assurance action, so we demand both (WebAuthn §6.1).
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04

	authDataMinLen = 37 // 32-byte rpIdHash + 1 flags + 4 signCount
	p256PointLen   = 65 // SEC1 uncompressed: 0x04 || X(32) || Y(32)
)

// Assertion is a passkey get() result, as the native bridge forwards it. The
// signature is ASN.1 DER ECDSA (what WebAuthn carries for ES256).
type Assertion struct {
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// clientData is the subset of clientDataJSON we check. Unknown fields are
// ignored; we never re-serialize it, we verify the bytes as received.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"` // base64url, no padding (WebAuthn spec)
	Origin    string `json:"origin"`
}

var (
	ErrBadKey        = errors.New("webauthn: credential key is not a P-256 point")
	ErrBadAuthData   = errors.New("webauthn: authenticator data too short")
	ErrRPIDMismatch  = errors.New("webauthn: rp id hash does not match")
	ErrUserPresence  = errors.New("webauthn: user-present/verified flag not set")
	ErrBadClientData = errors.New("webauthn: client data does not parse")
	ErrWrongType     = errors.New("webauthn: client data type is not webauthn.get")
	ErrChallenge     = errors.New("webauthn: challenge does not match")
	ErrOrigin        = errors.New("webauthn: origin does not match")
	ErrSignature     = errors.New("webauthn: signature does not verify")
)

// Verify checks an ES256 assertion against the registered P-256 credential
// public key (65-byte SEC1 uncompressed). expectedChallenge is the raw challenge
// bytes the edge issued; rpID is the Relying Party id (the Fount domain serving
// the passkey's associated-domain file). expectedOrigin, when non-empty, must
// equal clientDataJSON.origin; an empty value skips the origin check (the
// rpIdHash binding below is the cryptographically load-bearing one).
func Verify(credPubSEC1 []byte, a Assertion, expectedChallenge []byte, rpID, expectedOrigin string) error {
	pub, err := parseP256(credPubSEC1)
	if err != nil {
		return err
	}
	if len(a.AuthenticatorData) < authDataMinLen {
		return ErrBadAuthData
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !constTimeEqual(a.AuthenticatorData[:32], rpHash[:]) {
		return ErrRPIDMismatch
	}
	flags := a.AuthenticatorData[32]
	if flags&flagUserPresent == 0 || flags&flagUserVerified == 0 {
		return ErrUserPresence
	}

	var cd clientData
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return ErrBadClientData
	}
	if cd.Type != "webauthn.get" {
		return ErrWrongType
	}
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(expectedChallenge) {
		return ErrChallenge
	}
	if expectedOrigin != "" && cd.Origin != expectedOrigin {
		return ErrOrigin
	}

	// The authenticator signed SHA-256(authenticatorData || SHA-256(clientDataJSON)).
	clientHash := sha256.Sum256(a.ClientDataJSON)
	signed := make([]byte, 0, len(a.AuthenticatorData)+len(clientHash))
	signed = append(signed, a.AuthenticatorData...)
	signed = append(signed, clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return ErrSignature
	}
	return nil
}

// parseP256 turns a 65-byte SEC1 uncompressed point into an ECDSA public key,
// validating that it is actually on the curve. ParseUncompressedPublicKey does
// both the length/format and the on-curve check and returns a key without the
// deprecated raw X/Y field construction.
func parseP256(sec1 []byte) (*ecdsa.PublicKey, error) {
	if len(sec1) != p256PointLen || sec1[0] != 0x04 {
		return nil, ErrBadKey
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), sec1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return pub, nil
}

// ValidCredentialKey reports whether b is a well-formed ES256 credential public
// key: a 65-byte SEC1 uncompressed point on P-256. The edge validates a newly
// registered passkey key with it so a malformed key can't be stored and then
// make a later recovery impossible.
func ValidCredentialKey(b []byte) bool {
	_, err := parseP256(b)
	return err == nil
}

func constTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
