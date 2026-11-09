package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
)

// The account lookup keeps trying until the CA answers, so a CA outage at boot
// only delays the URL /operator/status publishes.
func TestRegisterAccountRetriesUntilTheCAAnswers(t *testing.T) {
	var (
		base  string
		tries atomic.Int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct"})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Replay-Nonce", "n") })
	mux.HandleFunc("POST /acct", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		if tries.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Location", base+"/acct/7")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	issuer, err := acme.NewIssuer(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), base+"/dir", acme.NewChallenges())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		registerAccount(context.Background(), issuer, []time.Duration{time.Millisecond})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("registerAccount didn't finish")
	}
	if got := issuer.AccountURL(); got != base+"/acct/7" || tries.Load() != 3 {
		t.Fatalf("AccountURL = %q after %d tries", got, tries.Load())
	}
}
