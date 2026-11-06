package deviceapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type fakeResolver struct {
	pub   ed25519.PublicKey
	keyID string
}

func (f fakeResolver) Resolve(_ signer, keyID string) (ed25519.PublicKey, bool) {
	if keyID == f.keyID {
		return f.pub, true
	}
	return nil, false
}

func signedRequest(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string, body []byte, ts time.Time, nonce string) *http.Request {
	t.Helper()
	sum := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, hex.EncodeToString(sum[:]), ts.Unix(), nonce)
	sig := ed25519.Sign(priv, []byte(canonical))
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	req.Header.Set("Fount-Key-Id", keyID)
	req.Header.Set("Fount-Timestamp", strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set("Fount-Nonce", nonce)
	req.Header.Set("Fount-Signature", base64.StdEncoding.EncodeToString(sig))
	return req
}

func newTestAPI(t *testing.T) (*API, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "addr-1"
	return New(store.NewDiscard(), fakeResolver{pub: pub, keyID: keyID}), priv, keyID
}

func TestValidSignaturePassesToHandler(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), time.Now(), "n1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	// Signature is valid, so it reaches the stub handler (501), not the 401 guard.
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501 (reached handler), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestReplayedNonceRejected(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	ts := time.Now()
	for i, wantCode := range []int{http.StatusNotImplemented, http.StatusUnauthorized} {
		req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), ts, "same-nonce")
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != wantCode {
			t.Fatalf("attempt %d: want %d, got %d", i, wantCode, rec.Code)
		}
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), time.Now().Add(-30*time.Minute), "n-stale")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for stale timestamp, got %d", rec.Code)
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), time.Now(), "n-tamper")
	req.Body = http.NoBody
	req.Header.Set("Content-Length", "0")
	// body now differs from what was signed → hash mismatch → verify fails
	req2 := httptest.NewRequest("POST", "/entitlement", strings.NewReader(`{"tampered":true}`))
	for _, h := range []string{"Fount-Key-Id", "Fount-Timestamp", "Fount-Nonce", "Fount-Signature"} {
		req2.Header.Set(h, req.Header.Get(h))
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req2)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for tampered body, got %d", rec.Code)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	api, priv, _ := newTestAPI(t)
	req := signedRequest(t, priv, "wrong-key", "POST", "/entitlement", []byte(`{}`), time.Now(), "n-unknown")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for unknown key, got %d", rec.Code)
	}
}

func TestBootsNeedsNoSignature(t *testing.T) {
	api, _, _ := newTestAPI(t)
	req := httptest.NewRequest("GET", "/boots/abc", nil)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501 (open route reaches handler), got %d", rec.Code)
	}
}
