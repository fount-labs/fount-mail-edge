package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testAccountPEM(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key
}

func TestNewIssuerBuildsJWKAndThumbprint(t *testing.T) {
	pemBytes, _ := testAccountPEM(t)
	i, err := NewIssuer(pemBytes, "https://example/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	// P-256 x/y are 32 bytes -> 43 base64url chars (no padding).
	if len(i.jwk["x"]) != 43 || len(i.jwk["y"]) != 43 {
		t.Fatalf("jwk coords wrong length: x=%d y=%d", len(i.jwk["x"]), len(i.jwk["y"]))
	}
	if i.jwk["crv"] != "P-256" || i.jwk["kty"] != "EC" {
		t.Fatalf("unexpected jwk: %v", i.jwk)
	}
	if len(i.thumbprint) != 43 {
		t.Fatalf("thumbprint wrong length: %d", len(i.thumbprint))
	}
}

func TestNewIssuerRejectsNonECKey(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	if _, err := NewIssuer(bad, "https://example/dir", NewChallenges()); err == nil {
		t.Fatal("expected error for non-EC key")
	}
}

func TestSignProducesVerifiableRawES256(t *testing.T) {
	pemBytes, key := testAccountPEM(t)
	i, err := NewIssuer(pemBytes, "https://example/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := i.sign("protected.payload")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("ES256 signature must be 64 raw bytes, got %d", len(raw))
	}
	h := sha256.Sum256([]byte("protected.payload"))
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
		t.Fatal("signature did not verify as (r,s) halves")
	}
}

func TestChallengeResponder(t *testing.T) {
	ch := NewChallenges()
	ch.set("tok123", "tok123.thumb")

	// Serving a known token returns the key authorization.
	rec := httptest.NewRecorder()
	ch.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok123", nil))
	if rec.Body.String() != "tok123.thumb" {
		t.Fatalf("challenge body = %q", rec.Body.String())
	}

	// Reachable fired on the first hit.
	select {
	case <-ch.Reachable():
	default:
		t.Fatal("Reachable should have fired after a request")
	}

	// Unknown token -> 404.
	rec = httptest.NewRecorder()
	ch.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token code = %d", rec.Code)
	}
}

func TestBuildCertParsesChain(t *testing.T) {
	_, key := testAccountPEM(t)
	// Two dummy DER blobs; buildCert only needs CERTIFICATE PEM blocks.
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf-der")})
	inter := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("intermediate-der")})
	cert, err := buildCert(append(leaf, inter...), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("want 2 certs in chain, got %d", len(cert.Certificate))
	}
	if cert.PrivateKey == nil {
		t.Fatal("cert missing private key")
	}
}

func TestBuildCertEmptyChainErrors(t *testing.T) {
	_, key := testAccountPEM(t)
	if _, err := buildCert([]byte("no pem here"), key); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":                              0,
		"120":                           2 * time.Minute,
		"soon":                          0,
		"Sat, 07 Nov 2026 13:00:00 GMT": time.Hour,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestPostCarriesRetryAfter(t *testing.T) {
	pemBytes, _ := testAccountPEM(t)
	i, err := NewIssuer(pemBytes, "https://example/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	i.http = srv.Client()
	i.nonce = "n"
	_, _, err = i.post(context.Background(), srv.URL, map[string]any{})
	var asked interface{ RetryAfter() time.Duration }
	if !errors.As(fmt.Errorf("newOrder: %w", err), &asked) || asked.RetryAfter() != time.Hour {
		t.Fatalf("err = %v", err)
	}
}
