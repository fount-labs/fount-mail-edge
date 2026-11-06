// Package keys loads the per-boot attested keys the Tinfoil runtime generates
// inside the enclave and writes to the attested-key directory. Their public
// halves appear in the enclave's attestation, so a verifier (the broker) knows
// the exact keys this boot is using without the keyserver ever holding them.
//
//	mail-tls   ecdsa-p256  Terminates TLS. ACME issues a CA cert binding this
//	                       key (SMTP). The Device API serves a self-signed leaf
//	                       over the same key; the broker trusts it via attestation.
//	mail-sign  ed25519     Signs each stored message, so the device can prove
//	                       which boot's key encrypted it (design §9).
//
// No key here can decrypt stored mail (design §5): storage is encrypted to the
// address's public key with HPKE, which the edge never holds the private half of.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Keys struct {
	TLS        *ecdsa.PrivateKey
	Sign       ed25519.PrivateKey
	deviceCert tls.Certificate
}

// Load reads mail-tls and mail-sign from dir (e.g. /run/tinfoil/keys) and builds
// the Device API's self-signed certificate over the attested TLS key.
func Load(dir string) (*Keys, error) {
	tlsKey, err := loadECDSA(filepath.Join(dir, "mail-tls", "private_key.pem"))
	if err != nil {
		return nil, fmt.Errorf("attested TLS key: %w", err)
	}
	signKey, err := loadED25519(filepath.Join(dir, "mail-sign", "private_key.pem"))
	if err != nil {
		return nil, fmt.Errorf("attested signing key: %w", err)
	}
	cert, err := selfSigned(tlsKey)
	if err != nil {
		return nil, fmt.Errorf("device cert: %w", err)
	}
	return &Keys{TLS: tlsKey, Sign: signKey, deviceCert: cert}, nil
}

// DeviceAPITLSConfig serves the Device API with a self-signed leaf over the
// attested TLS key. Authenticity comes from attestation + per-request
// signatures, not from a CA. (mTLS on the tunnel is a separate M2 launch item.)
func (k *Keys) DeviceAPITLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{k.deviceCert},
		MinVersion:   tls.VersionTLS13,
	}
}

// TLSPublicSPKI is the SHA-256 of the attested TLS public key's SPKI, the value
// a verifier compares against the attestation and the issued certificate.
func (k *Keys) TLSPublicSPKI() string {
	der, _ := x509.MarshalPKIXPublicKey(&k.TLS.PublicKey)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// SignPublicB64 is the base64 ed25519 public key that signs stored messages.
func (k *Keys) SignPublicB64() string {
	return base64.StdEncoding.EncodeToString(k.Sign.Public().(ed25519.PublicKey))
}

func loadECDSA(path string) (*ecdsa.PrivateKey, error) {
	der, err := pemBlock(path)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse %s: not EC or PKCS8: %w", path, err)
	}
	k, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ECDSA key (%T)", path, anyKey)
	}
	return k, nil
}

func loadED25519(path string) (ed25519.PrivateKey, error) {
	der, err := pemBlock(path)
	if err != nil {
		return nil, err
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	k, ok := anyKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key (%T)", path, anyKey)
	}
	return k, nil
}

func pemBlock(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return block.Bytes, nil
}

func selfSigned(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fount-mail-edge device-api"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
