package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	sendKeysetVersion    byte = 1
	sendCommitmentDomain      = "fount-mail-send-keyset/v1"
	dkimRSABits               = 2048
	maxSendKeyBytes           = 2048
)

// SendKeyset is the edge's sending keys. Unlike the Keyset, none of them can read
// mail, and losing them costs a new DKIM selector and relay pin, not mailbox IDs,
// so they have no recovery shares. Each is PKCS#8 DER.
type SendKeyset struct {
	DKIMRSAKey     []byte // RSA-2048, selector f<N>._domainkey
	DKIMEd25519Key []byte // Ed25519, selector f<N>e._domainkey (RFC 8463)
	RelayClientKey []byte // Ed25519, the edge's client certificate key at the gateway relay
}

// GenerateSend makes a new send keyset. Only a vault whose release has a keyset
// commitment and no send commitment does this.
func GenerateSend() (*SendKeyset, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, dkimRSABits)
	if err != nil {
		return nil, err
	}
	_, dkimEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, relay, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k := &SendKeyset{}
	for _, f := range []struct {
		dst *[]byte
		key any
	}{{&k.DKIMRSAKey, rsaKey}, {&k.DKIMEd25519Key, dkimEd}, {&k.RelayClientKey, relay}} {
		der, err := x509.MarshalPKCS8PrivateKey(f.key)
		if err != nil {
			return nil, err
		}
		*f.dst = der
	}
	return k, nil
}

// MarshalBinary is the fixed encoding the send commitment covers: a version byte,
// then the RSA DKIM key, the Ed25519 DKIM key and the relay key, each with a
// two-byte big-endian length.
func (k *SendKeyset) MarshalBinary() []byte {
	out := make([]byte, 0, 1+6+len(k.DKIMRSAKey)+len(k.DKIMEd25519Key)+len(k.RelayClientKey))
	out = append(out, sendKeysetVersion)
	for _, der := range [][]byte{k.DKIMRSAKey, k.DKIMEd25519Key, k.RelayClientKey} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(der)))
		out = append(out, der...)
	}
	return out
}

// ParseSendKeyset accepts only the exact encoding MarshalBinary makes, with keys
// of the right types, so two encodings can never share a commitment.
func ParseSendKeyset(b []byte) (*SendKeyset, error) {
	if len(b) < 1 {
		return nil, errors.New("send keyset is empty")
	}
	if b[0] != sendKeysetVersion {
		return nil, fmt.Errorf("send keyset version %d, want %d", b[0], sendKeysetVersion)
	}
	rest := b[1:]
	var fields [3][]byte
	for i := range fields {
		if len(rest) < 2 {
			return nil, fmt.Errorf("send keyset is truncated at key %d", i)
		}
		n := int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
		if n > maxSendKeyBytes || len(rest) < n {
			return nil, fmt.Errorf("send keyset key %d declares %d bytes with %d left", i, n, len(rest))
		}
		fields[i] = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("send keyset has %d trailing bytes", len(rest))
	}
	k := &SendKeyset{DKIMRSAKey: fields[0], DKIMEd25519Key: fields[1], RelayClientKey: fields[2]}
	if _, err := k.DKIMRSA(); err != nil {
		return nil, err
	}
	dkimEd, err := k.DKIMEd25519()
	if err != nil {
		return nil, err
	}
	relay, err := k.RelayClient()
	if err != nil {
		return nil, err
	}
	if bytes.Equal(dkimEd.Seed(), relay.Seed()) {
		return nil, errors.New("send keyset uses one Ed25519 key for both DKIM and the relay")
	}
	return k, nil
}

// DKIMRSA is the rsa-sha256 DKIM signing key.
func (k *SendKeyset) DKIMRSA() (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(k.DKIMRSAKey)
	if err != nil {
		return nil, fmt.Errorf("send keyset RSA DKIM key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != dkimRSABits {
		return nil, fmt.Errorf("send keyset RSA DKIM key is %T, not RSA-%d", parsed, dkimRSABits)
	}
	return key, nil
}

// DKIMEd25519 is the ed25519-sha256 DKIM signing key.
func (k *SendKeyset) DKIMEd25519() (ed25519.PrivateKey, error) {
	return parseEd25519("Ed25519 DKIM", k.DKIMEd25519Key)
}

// RelayClient is the key the edge's client certificate at the relay is made from.
func (k *SendKeyset) RelayClient() (ed25519.PrivateKey, error) {
	return parseEd25519("relay client", k.RelayClientKey)
}

func parseEd25519(name string, der []byte) (ed25519.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("send keyset %s key: %w", name, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("send keyset %s key is %T, not Ed25519", name, parsed)
	}
	return key, nil
}

// Commitment is safe to publish, because every key in the set is random. A release
// with it as SEND_KEYSET_COMMITMENT accepts this send keyset and no other.
func (k *SendKeyset) Commitment() string {
	h := sha256.New()
	h.Write([]byte(sendCommitmentDomain))
	h.Write(k.MarshalBinary())
	return hex.EncodeToString(h.Sum(nil))
}

// Matches compares in constant time, though the commitment is public anyway.
func (k *SendKeyset) Matches(commitment string) bool {
	return subtle.ConstantTimeCompare([]byte(k.Commitment()), []byte(commitment)) == 1
}
