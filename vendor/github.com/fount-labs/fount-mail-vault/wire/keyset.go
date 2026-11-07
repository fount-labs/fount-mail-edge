// Package wire is what the vault and the edge must agree on: the keyset, its
// commitment, the sealed box that carries it, and the pull protocol. It uses only
// the standard library, so the edge can import it and stay dependency-free.
package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	keysetVersion    byte = 1
	commitmentDomain      = "fount-mail-keyset/v1"
	keySize               = 32
	maxACMEKeyBytes       = 1024
)

// Keyset is every key the vault generates. Mailbox IDs come from the MAC key, so
// a keyset is created once and never replaced.
type Keyset struct {
	AddressMACKey  [keySize]byte
	RoutingDataKey [keySize]byte
	ACMEAccountKey []byte // PKCS#8 DER, ECDSA P-256
}

// Generate makes a new keyset. Only a vault whose release has no commitment does this.
func Generate() (*Keyset, error) {
	k := &Keyset{}
	if _, err := rand.Read(k.AddressMACKey[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(k.RoutingDataKey[:]); err != nil {
		return nil, err
	}
	acme, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(acme)
	if err != nil {
		return nil, err
	}
	k.ACMEAccountKey = der
	return k, nil
}

// MarshalBinary is the fixed encoding the commitment covers: a version byte, both
// 32-byte keys, then the ACME key with a two-byte length.
func (k *Keyset) MarshalBinary() []byte {
	out := make([]byte, 0, 1+2*keySize+2+len(k.ACMEAccountKey))
	out = append(out, keysetVersion)
	out = append(out, k.AddressMACKey[:]...)
	out = append(out, k.RoutingDataKey[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.ACMEAccountKey)))
	return append(out, k.ACMEAccountKey...)
}

// ParseKeyset accepts only the exact encoding MarshalBinary makes, with a valid
// P-256 ACME key, so two encodings can never share a commitment.
func ParseKeyset(b []byte) (*Keyset, error) {
	if len(b) < 1+2*keySize+2 {
		return nil, errors.New("keyset is too short")
	}
	if b[0] != keysetVersion {
		return nil, fmt.Errorf("keyset version %d, want %d", b[0], keysetVersion)
	}
	k := &Keyset{}
	rest := b[1:]
	copy(k.AddressMACKey[:], rest[:keySize])
	copy(k.RoutingDataKey[:], rest[keySize:2*keySize])
	rest = rest[2*keySize:]
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if n > maxACMEKeyBytes || len(rest) != n {
		return nil, fmt.Errorf("keyset ACME key is %d bytes with %d declared", len(rest), n)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(rest)
	if err != nil {
		return nil, fmt.Errorf("keyset ACME key: %w", err)
	}
	if key, ok := parsed.(*ecdsa.PrivateKey); !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("keyset ACME key is %T, not ECDSA P-256", parsed)
	}
	k.ACMEAccountKey = append([]byte(nil), rest...)
	return k, nil
}

// Commitment is safe to publish, because every key in the set is random. A release
// with it in its config accepts this keyset and no other.
func (k *Keyset) Commitment() string {
	h := sha256.New()
	h.Write([]byte(commitmentDomain))
	h.Write(k.MarshalBinary())
	return hex.EncodeToString(h.Sum(nil))
}

// Matches compares in constant time, though the commitment is public anyway.
func (k *Keyset) Matches(commitment string) bool {
	return subtle.ConstantTimeCompare([]byte(k.Commitment()), []byte(commitment)) == 1
}

// ValidateCommitment rejects anything that isn't 64 lowercase hex characters, so
// a typo in config fails at boot rather than refusing every keyset.
func ValidateCommitment(c string) error {
	raw, err := hex.DecodeString(c)
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != c {
		return fmt.Errorf("commitment %q isn't 64 lowercase hex characters", c)
	}
	return nil
}

// ACMEAccountKeyPEM is the form the edge's ACME client reads.
func (k *Keyset) ACMEAccountKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k.ACMEAccountKey})
}
