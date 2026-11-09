// Package dkim signs outbound mail for the edge's own domain (design §14 step 2).
//
// It implements the signing half of RFC 6376 with relaxed/relaxed
// canonicalization, for rsa-sha256 and ed25519-sha256 (RFC 8463). Sign with both:
// some receivers only check RSA. There is no verifier here; checking inbound mail
// is the broker's job, in its isolated verifier.
//
// Where the keys live is still open (docs/features/fount-fleet/fount-mail-send-keys.md
// in the Fount repo). This package takes any crypto.Signer of the right type, so
// the source can change without touching it.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/header"
)

// Signed are the fields covered when present (§11 lists what receivers should
// require be signed; the edge signs the same set it would demand of others).
var Signed = []string{
	"from", "to", "cc", "subject", "date", "message-id", "reply-to",
	"in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding",
}

// oversigned are listed one extra time, so a relay that adds a second copy breaks
// the signature instead of changing what the reader sees.
var oversigned = []string{"from", "to", "cc", "subject", "date", "reply-to"}

// Signer signs for one domain and selector.
type Signer struct {
	Domain   string        // d=, e.g. "fountbox.com"
	Selector string        // s=
	Key      crypto.Signer // *rsa.PrivateKey (2048 bits or more) or ed25519.PrivateKey
}

func (s *Signer) algorithm() (string, error) {
	switch k := s.Key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return "", errors.New("dkim: RSA key under 2048 bits")
		}
		return "rsa-sha256", nil
	case ed25519.PrivateKey:
		return "ed25519-sha256", nil
	}
	return "", fmt.Errorf("dkim: unsupported key type %T", s.Key)
}

// Sign returns a DKIM-Signature field, ending in CRLF, to put at the top of msg.
// msg must be a complete message that header.Split accepts.
func (s *Signer) Sign(msg []byte, now time.Time) ([]byte, error) {
	alg, err := s.algorithm()
	if err != nil {
		return nil, err
	}
	if s.Domain == "" || s.Selector == "" {
		return nil, errors.New("dkim: domain and selector are required")
	}
	fields, body, err := header.Split(msg)
	if err != nil {
		return nil, fmt.Errorf("dkim: %w", err)
	}
	if len(header.Get(fields, "from")) != 1 {
		return nil, errors.New("dkim: message needs exactly one From")
	}

	var names []string
	for _, n := range Signed {
		for range header.Get(fields, n) {
			names = append(names, n)
		}
	}
	names = append(names, oversigned...)

	bh := sha256.Sum256(RelaxedBody(body))
	tags := fmt.Sprintf("v=1; a=%s; c=relaxed/relaxed; d=%s; s=%s;\r\n t=%d; h=%s;\r\n bh=%s;\r\n b=",
		alg, s.Domain, s.Selector, now.Unix(), strings.Join(names, ":"),
		base64.StdEncoding.EncodeToString(bh[:]))
	unsigned := "DKIM-Signature: " + tags

	sig, err := s.sign(HeaderHash(fields, names, unsigned))
	if err != nil {
		return nil, err
	}
	return []byte(unsigned + base64.StdEncoding.EncodeToString(sig) + "\r\n"), nil
}

func (s *Signer) sign(digest []byte) ([]byte, error) {
	if k, ok := s.Key.(ed25519.PrivateKey); ok {
		// RFC 8463 §3: pure Ed25519 over the SHA-256 hash, not Ed25519ph.
		return ed25519.Sign(k, digest), nil
	}
	return s.Key.Sign(rand.Reader, digest, crypto.SHA256)
}

// HeaderHash is the SHA-256 of the canonical header the signature covers: each
// named field, picked bottom-up as RFC 6376 §5.4.2 says, then the DKIM-Signature
// field itself with an empty b= and no final CRLF. A name with no copy left adds
// nothing, which is what makes oversigning work.
func HeaderHash(fields []header.Field, names []string, dkimField string) []byte {
	h := sha256.New()
	used := map[string]int{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		copies := header.Get(fields, n)
		k := len(copies) - 1 - used[n]
		used[n]++
		if k < 0 {
			continue
		}
		h.Write(RelaxedHeader(copies[k].Raw))
		h.Write([]byte("\r\n"))
	}
	h.Write(RelaxedHeader([]byte(dkimField)))
	return h.Sum(nil)
}

// RelaxedHeader canonicalizes one field (RFC 6376 §3.4.2): lowercase name,
// unfolded, whitespace runs to one space, none around the colon or at the end.
func RelaxedHeader(raw []byte) []byte {
	i := bytes.IndexByte(raw, ':')
	if i < 0 {
		return nil
	}
	name := strings.ToLower(strings.TrimRight(string(raw[:i]), " \t"))
	value := bytes.ReplaceAll(raw[i+1:], []byte("\r\n"), nil)
	value = collapseWSP(value)
	value = bytes.Trim(value, " ")
	return append([]byte(name+":"), value...)
}

// RelaxedBody canonicalizes a body (RFC 6376 §3.4.4): whitespace runs to one
// space, none at line ends, no empty lines at the end, and a final CRLF unless
// the body is empty.
func RelaxedBody(body []byte) []byte {
	lines := bytes.Split(body, []byte("\r\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1] // the split after the final CRLF
	}
	var out bytes.Buffer
	pendingBlank := 0
	for _, l := range lines {
		l = bytes.TrimRight(collapseWSP(l), " ")
		if len(l) == 0 {
			pendingBlank++
			continue
		}
		for ; pendingBlank > 0; pendingBlank-- {
			out.WriteString("\r\n")
		}
		out.Write(l)
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

func collapseWSP(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inWSP := false
	for _, c := range b {
		if c == ' ' || c == '\t' {
			if !inWSP {
				out = append(out, ' ')
			}
			inWSP = true
			continue
		}
		inWSP = false
		out = append(out, c)
	}
	return out
}

// TXTRecord is the DNS TXT value that publishes key's public half.
func TXTRecord(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		pub := k.Public().(ed25519.PublicKey)
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub), nil
	case *rsa.PrivateKey:
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
	}
	return "", fmt.Errorf("dkim: unsupported key type %T", key)
}
