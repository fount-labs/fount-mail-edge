package deviceapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type fakeSender struct {
	err  error
	got  []byte
	from []byte
}

func (f *fakeSender) Send(_ context.Context, mailboxID, raw []byte) ([]send.Result, error) {
	f.from, f.got = mailboxID, raw
	if f.err != nil {
		return nil, f.err
	}
	return []send.Result{{Recipient: "pat@smithcpa.com", Status: send.Sent}}, nil
}

func sendAPI(t *testing.T, s Sender) (*API, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := hex.EncodeToString(make([]byte, 32))
	return New(Options{Store: store.NewDiscard(), Resolver: fakeResolver{pub: pub, keyID: keyID}, Sender: s}), priv, keyID
}

func TestSendRoute(t *testing.T) {
	s := &fakeSender{}
	api, priv, keyID := sendAPI(t, s)
	body := []byte(`{"message":"RnJvbTogYQ0KDQo="}`) // "From: a\r\n\r\n"
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/send", body, time.Now(), "s1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct{ Results []send.Result }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Results) != 1 || out.Results[0].Status != send.Sent {
		t.Fatalf("body %s", rec.Body)
	}
	if string(s.got) != "From: a\r\n\r\n" || hex.EncodeToString(s.from) != keyID {
		t.Fatalf("sender got %q from %x", s.got, s.from)
	}

	// Unsigned or signed by another key never reaches the sender.
	_, other, _ := ed25519.GenerateKey(nil)
	s.got = nil
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, other, keyID, "POST", "/send", body, time.Now(), "s2"))
	if rec.Code != http.StatusUnauthorized || s.got != nil {
		t.Fatalf("wrong key: %d", rec.Code)
	}
}

func TestSendRouteErrors(t *testing.T) {
	for err, code := range map[error]int{
		fmt.Errorf("%w: x", send.ErrBadMessage): http.StatusBadRequest,
		send.ErrNoMailbox:                       http.StatusNotFound,
		send.ErrNotOwner:                        http.StatusForbidden,
		send.ErrNotWorker:                       http.StatusForbidden,
		send.ErrNotProven:                       http.StatusForbidden,
		send.ErrLapsed:                          http.StatusForbidden,
		send.ErrPaused:                          http.StatusForbidden,
		send.ErrRateLimited:                     http.StatusTooManyRequests,
		fmt.Errorf("link: %w", send.ErrOff):     http.StatusNotImplemented,
		fmt.Errorf("relay down"):                http.StatusInternalServerError,
	} {
		api, priv, keyID := sendAPI(t, &fakeSender{err: err})
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/send", []byte(`{"message":"eA=="}`), time.Now(), "n"))
		if rec.Code != code {
			t.Errorf("%v: %d, want %d", err, rec.Code, code)
		}
	}
	api, priv, keyID := sendAPI(t, &fakeSender{})
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/send", []byte(`{}`), time.Now(), "e"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty message: %d", rec.Code)
	}
}

// With no Sender, which is the live release, POST /send stays a stub.
func TestSendRouteOffByDefault(t *testing.T) {
	api, priv, keyID := sendAPI(t, nil)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/send", []byte(`{"message":"eA=="}`), time.Now(), "o"))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status %d", rec.Code)
	}
}
