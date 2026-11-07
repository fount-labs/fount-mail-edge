package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// requireJWK fails a newAccount request not signed with the jwk, as a real CA does
// (RFC 8555 §6.2). r's body is left readable.
func requireJWK(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var jws struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		t.Error(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		t.Error(err)
	}
	var protected map[string]any
	if err := json.Unmarshal(raw, &protected); err != nil {
		t.Error(err)
	}
	_, hasKid := protected["kid"]
	_, hasJWK := protected["jwk"]
	if hasKid || !hasJWK {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed"}`))
		return false
	}
	return true
}

// A failed Issue leaves the account's kid behind. The retry must still sign
// newAccount with the jwk, or the edge can't get a certificate until it restarts.
func TestRetryAfterFailureSignsNewAccountWithJWK(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/neworder",
		})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
	})
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		if !requireJWK(t, w, r) {
			return
		}
		w.Header().Set("Location", base+"/acct/1")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /neworder", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	accountPEM, _ := testAccountPEM(t)
	issuer, err := NewIssuer(accountPEM, base+"/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for attempt := range 2 {
		_, err := issuer.Issue(context.Background(), []string{"mx1.fountbox.test"}, certKey)
		if err == nil || !strings.Contains(err.Error(), "newOrder") {
			t.Fatalf("attempt %d: err = %v, want a newOrder failure", attempt, err)
		}
	}
}

// A compact, compliant-enough ACME server to drive the client through a full
// order: directory -> nonce -> account -> order -> authz -> challenge ->
// finalize -> cert. It does not perform real HTTP-01 validation (the responder
// is unit-tested separately); it checks that the client walks the protocol.
func TestIssueEndToEndAgainstMockACME(t *testing.T) {
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// A cert the mock hands back after finalize.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail-edge.test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	var (
		mu         sync.Mutex
		nonceN     int
		authzState = "pending"
		ordered    int
		csrDER     []byte
	)
	// decodeJWS returns a JWS POST's decoded payload.
	decodeJWS := func(t *testing.T, r *http.Request) []byte {
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			t.Error(err)
		}
		b, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			t.Error(err)
		}
		return b
	}
	var base string
	mux := http.NewServeMux()
	nonce := func(w http.ResponseWriter) {
		mu.Lock()
		nonceN++
		mu.Unlock()
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceN))
	}
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/neworder",
		})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, _ *http.Request) { nonce(w); w.WriteHeader(200) })
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, r *http.Request) {
		nonce(w)
		if !requireJWK(t, w, r) {
			return
		}
		w.Header().Set("Location", base+"/acct/1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /neworder", func(w http.ResponseWriter, r *http.Request) {
		nonce(w)
		var order struct {
			Identifiers []map[string]string `json:"identifiers"`
		}
		if err := json.Unmarshal(decodeJWS(t, r), &order); err != nil {
			t.Error(err)
		}
		ordered = len(order.Identifiers)
		w.Header().Set("Location", base+"/order/1")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorizations": []string{base + "/authz/1"},
			"finalize":       base + "/finalize/1",
		})
	})
	mux.HandleFunc("POST /authz/1", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		mu.Lock()
		state := authzState
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": state,
			"challenges": []map[string]string{
				{"type": "http-01", "url": base + "/chall/1", "token": "tok-abc"},
			},
		})
	})
	mux.HandleFunc("POST /chall/1", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		mu.Lock()
		authzState = "valid"
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /finalize/1", func(w http.ResponseWriter, r *http.Request) {
		nonce(w)
		var final struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(decodeJWS(t, r), &final); err != nil {
			t.Error(err)
		}
		csrDER, _ = base64.RawURLEncoding.DecodeString(final.CSR)
		_, _ = w.Write([]byte(`{"status":"processing"}`))
	})
	mux.HandleFunc("POST /order/1", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": base + "/cert/1"})
	})
	mux.HandleFunc("POST /cert/1", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		_, _ = w.Write(certPEM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	accountPEM, _ := testAccountPEM(t)
	issuer, err := NewIssuer(accountPEM, base+"/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{"mx1.fountbox.test", "mx2.fountbox.test"}
	cert, err := issuer.Issue(context.Background(), hosts, certKey)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	// One order and one CSR must cover both MX names, or senders under strict
	// MTA-STS refuse whichever gateway the certificate doesn't name.
	if ordered != len(hosts) {
		t.Fatalf("order named %d identifiers, want %d", ordered, len(hosts))
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	if !slices.Equal(csr.DNSNames, hosts) {
		t.Fatalf("csr names %v, want %v", csr.DNSNames, hosts)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("want 1 cert in chain, got %d", len(cert.Certificate))
	}
	if cert.PrivateKey.(*ecdsa.PrivateKey) != certKey {
		t.Fatal("returned cert is not backed by the attested key")
	}
}
