package deviceapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// pauseAPI serves GET /mail too, so a test can see the flag the broker reads.
func pauseAPI(t *testing.T, rt *routing.Store) *API {
	t.Helper()
	return New(Options{
		Store:          newFakeMail(),
		Resolver:       NewKeyResolver(rt),
		Mutator:        rt,
		MailDomain:     "@fountbox.com",
		RecoveryRPID:   recoverTestRPID,
		RecoveryOrigin: recoverTestOrigin,
	})
}

func pauseChallenge(t *testing.T, api *API, idHex, paused string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest("GET", "/pause/"+idHex+"?paused="+paused, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pause challenge: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Challenge string }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	tok, err := base64.RawURLEncoding.DecodeString(resp.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func pausePost(t *testing.T, api *API, idHex string, body pauseRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/pause", bytes.NewReader(raw))
	req.Header.Set("Fount-Key-Id", idHex)
	req.Header.Set("Fount-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("Fount-Nonce", "pause-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	return rec
}

func listPaused(t *testing.T, api *API, mb mbox) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, signedRequest(t, mb.sign, mb.idHex, "GET", "/mail", nil, time.Now(), "list-"+strconv.FormatInt(time.Now().UnixNano(), 10)))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /mail: %d %s", rec.Code, rec.Body.String())
	}
	var got struct{ Paused bool }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Paused
}

func ptr(b bool) *bool { return &b }

func TestPauseAndResume(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api := pauseAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	for _, want := range []bool{true, false} {
		state := strconv.FormatBool(want)
		ch := pauseChallenge(t, api, mb.idHex, state)
		rec := pausePost(t, api, mb.idHex, pauseRequest{
			Challenge: ch,
			Paused:    ptr(want),
			Assertion: passkeyAssertion(t, mb.passkeyPriv, ch, recoverTestRPID, recoverTestOrigin),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("paused=%v: %d %s", want, rec.Code, rec.Body.String())
		}
		if rt.Paused(mb.id) != want || listPaused(t, api, mb) != want {
			t.Fatalf("paused=%v not stored or not on GET /mail", want)
		}
	}
}

func TestPauseRefusals(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api := pauseAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")
	other := createMbox(t, rt, "other@fountbox.com", "lic-2")

	pauseCh := pauseChallenge(t, api, mb.idHex, "true")
	signed := passkeyAssertion(t, mb.passkeyPriv, pauseCh, recoverTestRPID, recoverTestOrigin)
	nk := freshKeys(t)
	recoveryCh := api.mintChallenge(mb.id, recoveryHash(nk.chain(), nk.mboxPub), time.Now().Add(challengeTTL).Unix())

	cases := []struct {
		name string
		id   string
		body pauseRequest
		want int
	}{
		{"no state", mb.idHex, pauseRequest{Challenge: pauseCh, Assertion: signed}, http.StatusBadRequest},
		{"pause approval used to resume", mb.idHex, pauseRequest{Challenge: pauseCh, Paused: ptr(false), Assertion: signed}, http.StatusUnauthorized},
		{"another worker's challenge", other.idHex, pauseRequest{Challenge: pauseCh, Paused: ptr(true), Assertion: signed}, http.StatusUnauthorized},
		{"wrong passkey", mb.idHex, pauseRequest{Challenge: pauseCh, Paused: ptr(true),
			Assertion: passkeyAssertion(t, other.passkeyPriv, pauseCh, recoverTestRPID, recoverTestOrigin)}, http.StatusUnauthorized},
		{"recovery challenge", mb.idHex, pauseRequest{Challenge: recoveryCh, Paused: ptr(true),
			Assertion: passkeyAssertion(t, mb.passkeyPriv, recoveryCh, recoverTestRPID, recoverTestOrigin)}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		if rec := pausePost(t, api, c.id, c.body); rec.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
	if rt.Paused(mb.id) || rt.Paused(other.id) {
		t.Fatal("a refused request paused a worker")
	}

	// A good request works once.
	good := pauseRequest{Challenge: pauseCh, Paused: ptr(true), Assertion: signed}
	if rec := pausePost(t, api, mb.idHex, good); rec.Code != http.StatusOK {
		t.Fatalf("good request: %d %s", rec.Code, rec.Body.String())
	}
	if rec := pausePost(t, api, mb.idHex, good); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed challenge: %d, want 401", rec.Code)
	}
}

func TestPauseStubWithoutRPID(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest("GET", "/pause/00?paused=true", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("pause without a Relying Party id: %d, want 501", rec.Code)
	}
}
