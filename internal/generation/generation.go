// Package generation verifies coordinator generation certificates (fount
// launch-plan decision 18, "one coordinator at a time").
//
// The Cloud vault releases the coordinator's wrapping key with a generation
// number, and moves the number on with every restore and every coordinator
// upgrade. With it, the vault signs a certificate binding that generation to the
// coordinator's per-generation Ed25519 key. The edge holds the vault's public key
// (COORDINATOR_AUTHORITY_KEY) and accepts a mailbox's operations only from the
// newest generation it has seen, so a partitioned old coordinator can't fetch or
// send once its successor has spoken.
//
// The certificate is the compact shape internal/entitlement uses,
// b64url(json) "." b64url(sig), with the signature over a label and the JSON so it
// can't pass for any other token the authority signs.
package generation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// label separates a generation certificate's signature from anything else the
// authority key signs.
const label = "fount-coordinator-generation/v1\n"

// maxCertBytes bounds what Verify parses.
const maxCertBytes = 1024

// Cert binds a coordinator generation to that generation's request-signing key.
type Cert struct {
	Generation uint64 `json:"generation"`      // monotonic; 1 is the first
	Key        []byte `json:"coordinator_key"` // Ed25519 public key, 32 bytes
	IssuedAt   int64  `json:"issued_at"`       // unix seconds; informational
}

// Sign makes a certificate. The edge never signs one; this is the reference for
// the vault side and for tests.
func Sign(authority ed25519.PrivateKey, c Cert) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(authority, append([]byte(label), payload...))
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// Verify checks a certificate against the authority's public key and returns it.
func Verify(token string, authority ed25519.PublicKey) (Cert, error) {
	if len(authority) != ed25519.PublicKeySize {
		return Cert{}, errors.New("generation: no authority key")
	}
	if len(token) > maxCertBytes {
		return Cert{}, errors.New("generation: certificate too long")
	}
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return Cert{}, errors.New("generation: malformed certificate")
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(p)
	if err != nil {
		return Cert{}, fmt.Errorf("generation: payload: %w", err)
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return Cert{}, fmt.Errorf("generation: signature: %w", err)
	}
	if !ed25519.Verify(authority, append([]byte(label), payload...), sig) {
		return Cert{}, errors.New("generation: certificate signature does not verify")
	}
	var c Cert
	if err := json.Unmarshal(payload, &c); err != nil {
		return Cert{}, fmt.Errorf("generation: json: %w", err)
	}
	if err := c.check(); err != nil {
		return Cert{}, err
	}
	return c, nil
}

func (c Cert) check() error {
	if c.Generation == 0 {
		return errors.New("generation: generation must be at least 1")
	}
	if len(c.Key) != ed25519.PublicKeySize {
		return errors.New("generation: coordinator key must be a 32-byte Ed25519 public key")
	}
	return nil
}
