package wire

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// TransferKeyPath is where Tinfoil writes the per-boot attested key both enclaves
// seal to. The config names it `transfer`.
const TransferKeyPath = "/run/tinfoil/keys/transfer/private_key.pem"

// LoadTransferKey reads Tinfoil's PKCS#8 PEM.
func LoadTransferKey(path string) (*ecdh.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%s is %T, not an X25519 key", path, parsed)
	}
	return key, nil
}

// ParseEndorsedKey reads the hex SPKI DER that an attestation endorses.
func ParseEndorsedKey(spkiHex string) (*ecdh.PublicKey, error) {
	der, err := hex.DecodeString(spkiHex)
	if err != nil {
		return nil, fmt.Errorf("decoding endorsed key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing endorsed key: %w", err)
	}
	key, ok := parsed.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("endorsed key is %T, not X25519", parsed)
	}
	return key, nil
}

// ParseRawKey reads a 32-byte X25519 public key, as sent on the wire.
func ParseRawKey(raw []byte) (*ecdh.PublicKey, error) {
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 key: %w", err)
	}
	return key, nil
}

// Fingerprint is short enough for logs and /status.
func Fingerprint(key *ecdh.PublicKey) string {
	sum := sha256.Sum256(key.Bytes())
	return hex.EncodeToString(sum[:8])
}

func RandomNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	_, err := rand.Read(n)
	return n, err
}

// DecodeNonce reads a hex nonce of exactly NonceSize bytes.
func DecodeNonce(encoded string) ([]byte, error) {
	n, err := hex.DecodeString(encoded)
	if err != nil || len(n) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d hex-encoded bytes", NonceSize)
	}
	return n, nil
}
