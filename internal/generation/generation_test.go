package generation

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	apub, apriv, _ := ed25519.GenerateKey(nil)
	cpub, _, _ := ed25519.GenerateKey(nil)
	tok, err := Sign(apriv, Cert{Generation: 7, Key: cpub, IssuedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(tok, apub)
	if err != nil || c.Generation != 7 || !cpub.Equal(ed25519.PublicKey(c.Key)) {
		t.Fatalf("%+v %v", c, err)
	}

	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(tok, other); err == nil {
		t.Fatal("verified under another authority")
	}
	if _, err := Verify(tok, nil); err == nil {
		t.Fatal("verified with no authority")
	}
	p, s, _ := strings.Cut(tok, ".")
	if _, err := Verify(p+"x."+s, apub); err == nil {
		t.Fatal("tampered payload verified")
	}
	if _, err := Verify(p, apub); err == nil {
		t.Fatal("unsigned verified")
	}
	if _, err := Verify(strings.Repeat("a", maxCertBytes+1), apub); err == nil {
		t.Fatal("overlong verified")
	}
}

// A signature over the bare JSON, as an entitlement-shaped token would carry,
// doesn't pass: the label is part of what's signed.
func TestLabelSeparates(t *testing.T) {
	apub, apriv, _ := ed25519.GenerateKey(nil)
	cpub, _, _ := ed25519.GenerateKey(nil)
	tok, _ := Sign(apriv, Cert{Generation: 1, Key: cpub})
	p, _, _ := strings.Cut(tok, ".")
	payload, _ := decode(p)
	forged := p + "." + encode(ed25519.Sign(apriv, payload))
	if _, err := Verify(forged, apub); err == nil {
		t.Fatal("unlabelled signature verified")
	}
}

func TestRefusesBadCerts(t *testing.T) {
	_, apriv, _ := ed25519.GenerateKey(nil)
	cpub, _, _ := ed25519.GenerateKey(nil)
	if _, err := Sign(apriv, Cert{Generation: 0, Key: cpub}); err == nil {
		t.Fatal("generation 0 signed")
	}
	if _, err := Sign(apriv, Cert{Generation: 1, Key: cpub[:31]}); err == nil {
		t.Fatal("short key signed")
	}
}

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
