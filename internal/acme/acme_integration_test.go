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
	if got := issuer.AccountURL(); got != base+"/acct/1" {
		t.Fatalf("AccountURL after Issue = %q, want %s/acct/1", got, base)
	}
}

// accountCA is a CA that only knows accounts: it hands each distinct jwk one URL,
// as Let's Encrypt does, and answers a known key with the same URL again.
func accountCA(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var (
		base  string
		mu    sync.Mutex
		calls int
		urls  = map[string]string{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct"})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Replay-Nonce", "n") })
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		if !requireJWK(t, w, r) {
			return
		}
		var jws struct{ Protected string }
		_ = json.NewDecoder(r.Body).Decode(&jws)
		raw, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
		var p struct{ JWK map[string]string }
		_ = json.Unmarshal(raw, &p)
		mu.Lock()
		defer mu.Unlock()
		calls++
		id := p.JWK["x"] + p.JWK["y"]
		u, ok := urls[id]
		if !ok {
			u = fmt.Sprintf("%s/acct/%d", base, len(urls)+1)
			urls[id] = u
		}
		w.Header().Set("Location", u)
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	return srv, &calls
}

// The URL CAA pins comes from newAccount alone, so a boot that reloads a cached
// certificate still publishes it; and the same account key, as the vault delivers
// every boot, gets the same URL, so the pin survives restarts.
func TestRegisterPublishesAStableAccountURL(t *testing.T) {
	srv, calls := accountCA(t)
	accountPEM, _ := testAccountPEM(t)

	first, err := NewIssuer(accountPEM, srv.URL+"/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	if got := first.AccountURL(); got != "" {
		t.Fatalf("AccountURL before registering = %q, want empty", got)
	}
	if err := first.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := srv.URL + "/acct/1"
	if got := first.AccountURL(); got != want {
		t.Fatalf("AccountURL = %q, want %q", got, want)
	}

	restarted, err := NewIssuer(accountPEM, srv.URL+"/dir", NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := restarted.AccountURL(); got != want {
		t.Fatalf("after a restart AccountURL = %q, want %q", got, want)
	}

	otherPEM, _ := testAccountPEM(t)
	other, _ := NewIssuer(otherPEM, srv.URL+"/dir", NewChallenges())
	if err := other.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if other.AccountURL() == want {
		t.Fatal("a different account key got the pinned URL")
	}
	if *calls != 3 {
		t.Fatalf("newAccount calls = %d, want 3", *calls)
	}
}

// A failed lookup leaves the URL empty rather than publishing something CAA
// can't use, and a CA that answers with no Location is an error.
func TestRegisterFailureLeavesAccountURLEmpty(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct"})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Replay-Nonce", "n") })
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(http.StatusOK) // no Location
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	accountPEM, _ := testAccountPEM(t)
	issuer, _ := NewIssuer(accountPEM, base+"/dir", NewChallenges())
	if err := issuer.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "Location") {
		t.Fatalf("err = %v, want a missing-Location error", err)
	}
	if got := issuer.AccountURL(); got != "" {
		t.Fatalf("AccountURL = %q, want empty", got)
	}
}
