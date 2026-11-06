package deviceapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// fakeMail implements both store.Store and store.MailReader, scoped per mailbox
// id, so the real mail handlers are exercised end to end.
type fakeMail struct {
	objs map[string]map[string][]byte // hex(mailboxID) -> edgeID -> object
}

func newFakeMail() *fakeMail { return &fakeMail{objs: map[string]map[string][]byte{}} }

func (f *fakeMail) Put(context.Context, string, string, []byte) (string, error) {
	return "unused", nil
}

func (f *fakeMail) seed(mailboxID []byte, edgeID string, obj []byte) {
	k := hex.EncodeToString(mailboxID)
	if f.objs[k] == nil {
		f.objs[k] = map[string][]byte{}
	}
	f.objs[k][edgeID] = obj
}

func (f *fakeMail) List(_ context.Context, mailboxID []byte) ([]store.Stored, error) {
	var out []store.Stored
	for id, o := range f.objs[hex.EncodeToString(mailboxID)] {
		out = append(out, store.Stored{ID: id, Size: len(o)})
	}
	return out, nil
}

func (f *fakeMail) Get(_ context.Context, mailboxID []byte, edgeID string) ([]byte, error) {
	o, ok := f.objs[hex.EncodeToString(mailboxID)][edgeID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return o, nil
}

func (f *fakeMail) Delete(_ context.Context, mailboxID []byte, edgeID string) error {
	m := f.objs[hex.EncodeToString(mailboxID)]
	if _, ok := m[edgeID]; !ok {
		return store.ErrNotFound
	}
	delete(m, edgeID)
	return nil
}

func mailTestAPI(t *testing.T, mail store.Store) (*API, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	mailboxID := make([]byte, 32)
	for i := range mailboxID {
		mailboxID[i] = byte(i)
	}
	keyID := hex.EncodeToString(mailboxID)
	return New(Options{Store: mail, Resolver: fakeResolver{pub: pub, keyID: keyID}}), priv, keyID
}

func TestListMail(t *testing.T) {
	fm := newFakeMail()
	api, priv, keyID := mailTestAPI(t, fm)
	mailboxID, _ := hex.DecodeString(keyID)
	fm.seed(mailboxID, "aa", []byte("obj-a"))
	fm.seed(mailboxID, "bb", []byte("obj-bbbb"))

	req := signedRequest(t, priv, keyID, "GET", "/mail", nil, time.Now(), "list-1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Messages []store.Stored `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(got.Messages))
	}
}

func TestGetMail(t *testing.T) {
	fm := newFakeMail()
	api, priv, keyID := mailTestAPI(t, fm)
	mailboxID, _ := hex.DecodeString(keyID)
	fm.seed(mailboxID, "cc", []byte("the-signed-object"))

	req := signedRequest(t, priv, keyID, "GET", "/mail/cc", nil, time.Now(), "get-1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if rec.Body.String() != "the-signed-object" {
		t.Fatalf("body = %q", rec.Body.String())
	}

	// Unknown id -> 404.
	req = signedRequest(t, priv, keyID, "GET", "/mail/dd", nil, time.Now(), "get-2")
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestDeleteMail(t *testing.T) {
	fm := newFakeMail()
	api, priv, keyID := mailTestAPI(t, fm)
	mailboxID, _ := hex.DecodeString(keyID)
	fm.seed(mailboxID, "ee", []byte("x"))

	req := signedRequest(t, priv, keyID, "DELETE", "/mail/ee", nil, time.Now(), "del-1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	if _, ok := fm.objs[keyID]["ee"]; ok {
		t.Fatal("object not deleted")
	}

	// Deleting again -> 404.
	req = signedRequest(t, priv, keyID, "DELETE", "/mail/ee", nil, time.Now(), "del-2")
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 second delete, got %d", rec.Code)
	}
}

// An unsigned fetch is refused before reaching the handler.
func TestMailRequiresSignature(t *testing.T) {
	fm := newFakeMail()
	api, _, _ := mailTestAPI(t, fm)
	req := httptest.NewRequest("GET", "/mail", nil)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for unsigned, got %d", rec.Code)
	}
}

// A mailbox can't be addressed by a key id that isn't 32 bytes, even if the
// signature somehow verified (defense in depth behind guard).
func TestMailBadKeyIDShape(t *testing.T) {
	fm := newFakeMail()
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "not-hex-32"
	api := New(Options{Store: fm, Resolver: fakeResolver{pub: pub, keyID: keyID}})
	req := signedRequest(t, priv, keyID, "GET", "/mail", nil, time.Now(), "shape-1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad key id shape, got %d", rec.Code)
	}
}
