package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/header"
)

// rfc8463Message is RFC 8463 Appendix A.3, with CRLF line ends. Its two
// signatures were made by other implementations, so checking them pins this
// package's canonicalization to an outside source.
var rfc8463Message = strings.ReplaceAll(`DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.
`, "\n", "\r\n")

const rfc8463Ed25519Seed = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="

const rfc8463RSA = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
-----END RSA PRIVATE KEY-----`

// verify is a test-only verifier for one DKIM-Signature field: it checks bh=
// and b= against pub. It reads only the tags this package writes.
func verify(t *testing.T, msg []byte, sigField header.Field, pub crypto.PublicKey) {
	t.Helper()
	fields, body, err := header.Split(msg)
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{}
	for _, part := range strings.Split(sigField.Value(), ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, v)
		tags[strings.TrimSpace(k)] = v
	}
	bh := sha256.Sum256(RelaxedBody(body))
	if got := base64.StdEncoding.EncodeToString(bh[:]); got != tags["bh"] {
		t.Fatalf("bh = %s, signature says %s", got, tags["bh"])
	}
	// b= is emptied in place, so the field's other bytes, folding included, stay.
	unsigned := regexp.MustCompile(`(;\s*b=)[^;]*`).ReplaceAllString(string(sigField.Raw), "$1")
	digest := HeaderHash(fields, strings.Split(tags["h"], ":"), unsigned)
	sig, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		t.Fatal(err)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, sig) {
			t.Fatal("ed25519 signature does not verify")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
			t.Fatalf("rsa signature does not verify: %v", err)
		}
	default:
		t.Fatalf("key type %T", pub)
	}
}

func rfcKeys(t *testing.T) (ed25519.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	seed, _ := base64.StdEncoding.DecodeString(rfc8463Ed25519Seed)
	block, _ := pem.Decode([]byte(rfc8463RSA))
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), rk
}

func TestRFC8463Vector(t *testing.T) {
	ek, rk := rfcKeys(t)
	// The published key record for the Ed25519 selector.
	if got := base64.StdEncoding.EncodeToString(ek.Public().(ed25519.PublicKey)); got != "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" {
		t.Fatalf("ed25519 public key = %s", got)
	}
	fields, _, err := header.Split([]byte(rfc8463Message))
	if err != nil {
		t.Fatal(err)
	}
	sigs := header.Get(fields, "dkim-signature")
	if len(sigs) != 2 {
		t.Fatalf("%d signatures", len(sigs))
	}
	verify(t, []byte(rfc8463Message), sigs[0], ek.Public())
	verify(t, []byte(rfc8463Message), sigs[1], &rk.PublicKey)
}

// Ed25519 is deterministic, so signing the vector's own unsigned field must give
// the vector's exact b= value.
func TestRFC8463Ed25519Exact(t *testing.T) {
	ek, _ := rfcKeys(t)
	fields, _, _ := header.Split([]byte(rfc8463Message))
	raw := string(header.Get(fields, "dkim-signature")[0].Raw)
	unsigned := raw[:strings.Index(raw, " b=")+3]
	names := strings.Split("from:to:subject:date:message-id:from:subject:date", ":")
	sig := ed25519.Sign(ek, HeaderHash(fields, names, unsigned))
	want := "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11BusFa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="
	if got := base64.StdEncoding.EncodeToString(sig); got != want {
		t.Fatalf("b = %s\nwant %s", got, want)
	}
}

const sample = "From: Accountant <ap.smithcpa@fountbox.com>\r\n" +
	"To: owner@example.com\r\n" +
	"Subject: Your result is ready\r\n" +
	"Date: Sun, 08 Nov 2026 12:00:00 +0000\r\n" +
	"Message-ID: <x1@fountbox.com>\r\n" +
	"\r\n" +
	"Open Fount.  \r\n\r\n\r\n"

func TestSignRoundTrip(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte(sample)
	for _, key := range []crypto.Signer{rk, ek} {
		s := &Signer{Domain: "fountbox.com", Selector: "f1", Key: key}
		field, err := s.Sign(msg, time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		signed := append(append([]byte(nil), field...), msg...)
		fields, _, err := header.Split(signed)
		if err != nil {
			t.Fatalf("signed message doesn't split: %v", err)
		}
		verify(t, signed, header.Get(fields, "dkim-signature")[0], key.Public())
	}
}

// A relay that adds a second From, or changes the body, must break the signature.
func TestSignatureBreaksOnTampering(t *testing.T) {
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	s := &Signer{Domain: "fountbox.com", Selector: "f1e", Key: ek}
	field, err := s.Sign([]byte(sample), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signed := string(field) + sample
	fields, _, _ := header.Split([]byte(signed))
	sigField := header.Get(fields, "dkim-signature")[0]
	for name, tampered := range map[string]string{
		"added From":    strings.Replace(signed, "To:", "From: evil@example.net\r\nTo:", 1),
		"added Subject": strings.Replace(signed, "To:", "Subject: Pay now\r\nTo:", 1),
		"changed body":  strings.Replace(signed, "Open Fount.", "Open evil.", 1),
	} {
		tf, body, err := header.Split([]byte(tampered))
		if err != nil {
			t.Fatal(err)
		}
		bh := sha256.Sum256(RelaxedBody(body))
		names := strings.Split(tagValue(sigField.Value(), "h"), ":")
		unsigned := regexp.MustCompile(`(;\s*b=)[^;]*`).ReplaceAllString(string(sigField.Raw), "$1")
		sig, _ := base64.StdEncoding.DecodeString(tagValue(sigField.Value(), "b"))
		bodyOK := base64.StdEncoding.EncodeToString(bh[:]) == tagValue(sigField.Value(), "bh")
		if bodyOK && ed25519.Verify(ek.Public().(ed25519.PublicKey), HeaderHash(tf, names, unsigned), sig) {
			t.Errorf("%s: still verifies", name)
		}
	}
}

func tagValue(v, tag string) string {
	for _, part := range strings.Split(v, ";") {
		k, val, _ := strings.Cut(part, "=")
		if strings.TrimSpace(k) == tag {
			return strings.Join(strings.Fields(val), "")
		}
	}
	return ""
}

func TestRelaxedBody(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"\r\n":               "",
		"a  b \t\r\n":        "a b\r\n",
		"a\r\n\r\nb\r\n\r\n": "a\r\n\r\nb\r\n",
		"no final newline":   "no final newline\r\n",
		" lead\r\n":          " lead\r\n",
	}
	for in, want := range cases {
		if got := string(RelaxedBody([]byte(in))); got != want {
			t.Errorf("RelaxedBody(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignRefuses(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := (&Signer{Domain: "d", Selector: "s", Key: small}).Sign([]byte(sample), time.Now()); err == nil {
		t.Error("signed with a 1024-bit key")
	}
	twoFrom := "From: a@fountbox.com\r\n" + sample
	if _, err := (&Signer{Domain: "d", Selector: "s", Key: ek}).Sign([]byte(twoFrom), time.Now()); err == nil {
		t.Error("signed a message with two From fields")
	}
	if _, err := (&Signer{Domain: "d", Selector: "s", Key: ek}).Sign([]byte("From: a\n\n"), time.Now()); err == nil {
		t.Error("signed a message with bare LF")
	}
}

func TestTXTRecord(t *testing.T) {
	ek, rk := rfcKeys(t)
	if got, _ := TXTRecord(ek); got != "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" {
		t.Errorf("ed25519 record %q", got)
	}
	got, _ := TXTRecord(rk)
	want := "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
	if got != want {
		t.Errorf("rsa record %q", got)
	}
}
