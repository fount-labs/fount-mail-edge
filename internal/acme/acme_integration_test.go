package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

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
	)
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
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
		w.Header().Set("Location", base+"/acct/1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /neworder", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
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
	mux.HandleFunc("POST /finalize/1", func(w http.ResponseWriter, _ *http.Request) {
		nonce(w)
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

	cert, err := issuer.Issue(context.Background(), "mail-edge.test", certKey)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("want 1 cert in chain, got %d", len(cert.Certificate))
	}
	if cert.PrivateKey.(*ecdsa.PrivateKey) != certKey {
		t.Fatal("returned cert is not backed by the attested key")
	}
}
