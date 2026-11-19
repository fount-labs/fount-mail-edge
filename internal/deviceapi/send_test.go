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
		send.ErrSendInProgress:                  http.StatusConflict,
		send.ErrMessageIDReused:                 http.StatusConflict,
		send.ErrSendInDoubt:                     http.StatusConflict,
		send.ErrRecordFailed:                    http.StatusServiceUnavailable,
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

// A send carries a whole message, so it may be larger than any other request,
// up to its own limit.
func TestSendRouteBodyLimit(t *testing.T) {
	s := &fakeSender{}
	api, priv, keyID := sendAPI(t, s)
	request := func(n int, nonce string) int {
		raw := make([]byte, n)
		for i := range raw {
			raw[i] = 'a'
		}
		body, _ := json.Marshal(sendRequest{Message: raw})
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/send", body, time.Now(), nonce))
		return rec.Code
	}
	if code := request(25<<20, "big"); code != http.StatusOK || len(s.got) != 25<<20 {
		t.Fatalf("a 25 MiB message: status %d, sender got %d bytes", code, len(s.got))
	}
	if code := request(maxSendBodyBytes, "too-big"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the send limit: status %d", code)
	}

	// Every other route keeps the control-message limit.
	big := []byte(fmt.Sprintf(`{"x":%q}`, make([]byte, maxBodyBytes)))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, priv, keyID, "PUT", "/routing", big, time.Now(), "routing"))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT /routing over 1 MiB: status %d", rec.Code)
	}
}

// lookupSender is a Sender that keeps send records.
type lookupSender struct {
	fakeSender
	asked [][]byte
	err   error
}

func (l *lookupSender) Lookup(_ context.Context, mailboxID []byte, id string) (send.SentStatus, error) {
	l.asked = append(l.asked, mailboxID)
	if l.err != nil {
		return send.SentStatus{}, l.err
	}
	if id == "<sent@fountbox.com>" {
		return send.SentStatus{MessageID: id, State: send.SentDone, Results: []send.Result{{Recipient: "pat@smithcpa.com", Status: send.Sent}}}, nil
	}
	return send.SentStatus{MessageID: id, State: send.SentNone}, nil
}

func TestSentQueryRoute(t *testing.T) {
	l := &lookupSender{}
	api, priv, keyID := sendAPI(t, l)
	query := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/sent/query", []byte(body), time.Now(), nextNonce()))
		return rec
	}
	rec := query(`{"message_ids":["<sent@fountbox.com>","<new@fountbox.com>"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct{ Records []send.SentStatus }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Records) != 2 ||
		out.Records[0].State != send.SentDone || out.Records[0].Results[0].Status != send.Sent || out.Records[1].State != send.SentNone {
		t.Fatalf("body %s", rec.Body)
	}
	if hex.EncodeToString(l.asked[0]) != keyID {
		t.Fatalf("asked for %x", l.asked[0])
	}

	many, _ := json.Marshal(sentQuery{MessageIDs: make([]string, maxSentQuery+1)})
	for _, bad := range []string{`{}`, `{"message_ids":[]}`, `{"message_ids":[""]}`, string(many)} {
		if rec := query(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%.40s: %d", bad, rec.Code)
		}
	}
	l.err = fmt.Errorf("s3 down")
	if rec := query(`{"message_ids":["<x@y>"]}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store down: %d", rec.Code)
	}

	// Another key can't ask about this worker's sends.
	_, other, _ := ed25519.GenerateKey(nil)
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, other, keyID, "POST", "/sent/query", []byte(`{"message_ids":["<x@y>"]}`), time.Now(), nextNonce()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", rec.Code)
	}

	// A Sender that keeps no records leaves the route a stub.
	api, priv, keyID = sendAPI(t, &fakeSender{})
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, priv, keyID, "POST", "/sent/query", []byte(`{"message_ids":["<x@y>"]}`), time.Now(), nextNonce()))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("no records: %d", rec.Code)
	}
}
