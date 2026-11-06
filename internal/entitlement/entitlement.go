// Package entitlement is the edge's half of the proof-of-subscription that gates
// mailbox creation and handle checks (design §4 "short-lived signed entitlement,
// presented by the device", §8 the entitlement / new-keys signer classes).
//
// An entitlement is a short-lived token the Fount backend (api.fount.sh, as part
// of a license check) signs with its entitlement key; the edge verifies it with
// the public half, delivered by the keyserver as ENTITLEMENT_VERIFY_KEY. The
// token binds the device's request-signing public key, so a leaked entitlement
// can't be replayed with a different key: the edge checks both the token's
// signature and that the Device API request was signed by the key named inside
// it. It also carries the license's keyed hash, which the edge uses to enforce
// one mailbox per license (§4) without ever learning the license itself.
//
// # Wire format
//
// Compact, JWS-like: base64url(claims JSON) "." base64url(Ed25519 signature over
// the claims JSON bytes). Both ends are Fount, but pinning the shape keeps the
// backend and the edge from drifting. This is a contract defined by the edge
// (the broker/backend side does not exist yet); it is revisable.
package entitlement

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the only entitlement version M2 accepts.
const Version = 1

// Claims is the entitlement's payload.
type Claims struct {
	Version     int    `json:"v"`
	LicenseHash []byte `json:"lh"` // keyed hash of the license (one mailbox per license)
	DeviceKey   []byte `json:"dk"` // Ed25519 request-signing key this entitlement authorizes
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
}

var (
	ErrMalformed = errors.New("entitlement: malformed token")
	ErrSignature = errors.New("entitlement: signature does not verify")
	ErrExpired   = errors.New("entitlement: expired")
	ErrVersion   = errors.New("entitlement: unsupported version")
)

var b64 = base64.RawURLEncoding

// Verify decodes a token, checks its signature against verifyKey, and checks it
// is the supported version and not expired as of now (with a small skew for
// clock drift). It returns the claims only when all checks pass.
func Verify(token string, verifyKey ed25519.PublicKey, now time.Time, skew time.Duration) (*Claims, error) {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || payload == "" || sig == "" {
		return nil, ErrMalformed
	}
	jb, err := b64.DecodeString(payload)
	if err != nil {
		return nil, ErrMalformed
	}
	sigBytes, err := b64.DecodeString(sig)
	if err != nil {
		return nil, ErrMalformed
	}
	if len(verifyKey) != ed25519.PublicKeySize || !ed25519.Verify(verifyKey, jb, sigBytes) {
		return nil, ErrSignature
	}
	var c Claims
	if err := json.Unmarshal(jb, &c); err != nil {
		return nil, ErrMalformed
	}
	if c.Version != Version {
		return nil, ErrVersion
	}
	if len(c.DeviceKey) != ed25519.PublicKeySize || len(c.LicenseHash) == 0 {
		return nil, ErrMalformed
	}
	t := now.Unix()
	if t > c.ExpiresAt+int64(skew.Seconds()) {
		return nil, ErrExpired
	}
	return &c, nil
}

// Sign produces a token for the given claims. It is the reference the Fount
// backend's signing side must match; the edge never signs entitlements (it has
// only the public verify key), so this is used for tests and as the contract.
func Sign(c Claims, signKey ed25519.PrivateKey) (string, error) {
	if c.Version == 0 {
		c.Version = Version
	}
	jb, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("entitlement: marshal: %w", err)
	}
	sig := ed25519.Sign(signKey, jb)
	return b64.EncodeToString(jb) + "." + b64.EncodeToString(sig), nil
}
