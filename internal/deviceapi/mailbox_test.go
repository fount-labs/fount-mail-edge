package deviceapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/entitlement"
	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// testCredential returns a P-256 passkey credential: the ECDSA private key and
// its 65-byte SEC1 uncompressed public key, the form the edge stores and
// internal/webauthn verifies assertions against.
func testCredential(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := append([]byte{0x04},
		append(priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32))...)...)
	return priv, pub
}

type fakeProv struct {
	available map[string]bool
	created   []routing.NewMailbox
	id        []byte
	createErr error
}

func (f *fakeProv) Available(_ context.Context, address string) (bool, error) {
	if v, ok := f.available[address]; ok {
		return v, nil
	}
	return true, nil
}

func (f *fakeProv) Create(_ context.Context, p routing.NewMailbox) ([]byte, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, p)
	if f.id != nil {
		return f.id, nil
	}
	return make([]byte, 32), nil
}

func (f *fakeProv) MailboxID(string) []byte {
	if f.id != nil {
		return f.id
	}
	return make([]byte, 32)
}

type deviceKeys struct {
	signPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey
	mboxPub  ed25519.PublicKey
	mboxPriv ed25519.PrivateKey
	ownerPub ed25519.PublicKey
	decPub   []byte
	passkey  []byte
}

func newDeviceKeys(t *testing.T) deviceKeys {
	t.Helper()
	sp, spriv, _ := ed25519.GenerateKey(rand.Reader)
	mp, mpriv, _ := ed25519.GenerateKey(rand.Reader)
	op, _, _ := ed25519.GenerateKey(rand.Reader)
	dec := make([]byte, 32)
	rand.Read(dec)
	_, pk := testCredential(t)
	return deviceKeys{sp, spriv, mp, mpriv, op, dec, pk}
}

func (d deviceKeys) request(t *testing.T) mailboxRequest {
	t.Helper()
	req := mailboxRequest{
		Handle:         "worker",
		DecryptionKey:  d.decPub,
		SigningKey:     d.signPub,
		MailboxKey:     d.mboxPub,
		OwnerChangeKey: d.ownerPub,
		PasskeyKey:     d.passkey,
	}
	req.KeyChainSig = ed25519.Sign(d.mboxPriv, keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey))
	return req
}

// entTestAPI builds an API with a working entitlement verify key and provisioner,
// and returns the backend signing key so tests can mint entitlements.
func entTestAPI(t *testing.T, prov Provisioner) (*API, ed25519.PrivateKey) {
	t.Helper()
	verifyPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	api := New(Options{
		Store:       store.NewDiscard(),
		Entitlement: verifyPub,
		Provisioner: prov,
		MailDomain:  "@fountbox.com",
	})
	return api, signPriv
}

func entToken(t *testing.T, backend ed25519.PrivateKey, deviceKey ed25519.PublicKey, exp time.Time) string {
	t.Helper()
	tok, err := entitlement.Sign(entitlement.Claims{
		LicenseHash: []byte("license-hash"),
		DeviceKey:   deviceKey,
		IssuedAt:    time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:   exp.Unix(),
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mailboxPost signs a POST /mailbox with the device signing key and attaches the
// entitlement token.
func mailboxPost(t *testing.T, signPriv ed25519.PrivateKey, token string, body mailboxRequest, nonce string) *http.Request {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := signedRequest(t, signPriv, "", "POST", "/mailbox", raw, time.Now(), nonce)
	req.Header.Set("Fount-Entitlement", token)
	return req
}

func TestCreateMailbox(t *testing.T) {
	prov := &fakeProv{id: make([]byte, 32)}
	api, backend := entTestAPI(t, prov)
	dk := newDeviceKeys(t)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, dk.request(t), "mk-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		MailboxID string `json:"mailbox_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.MailboxID) != 64 {
		t.Fatalf("mailbox_id = %q", resp.MailboxID)
	}
	if len(prov.created) != 1 {
		t.Fatalf("provisioner saw %d creates", len(prov.created))
	}
	got := prov.created[0]
	if got.Address != "worker@fountbox.com" {
		t.Fatalf("address = %q", got.Address)
	}
	if string(got.LicenseHash) != "license-hash" {
		t.Fatal("license hash not carried from entitlement")
	}
}

func TestCreateMailboxLogsInitialKey(t *testing.T) {
	ks := newRecoverStore() // implements store.KeyLog, so creation logs the key
	prov := &fakeProv{id: make([]byte, 32)}
	verifyPub, backend, _ := ed25519.GenerateKey(rand.Reader)
	api := New(Options{
		Store:       ks,
		Entitlement: verifyPub,
		Provisioner: prov,
		MailDomain:  "@fountbox.com",
	})
	dk := newDeviceKeys(t)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, dk.request(t), "mk-log"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	want := sha256.Sum256(dk.mboxPub)
	got := ks.appends[hex.EncodeToString(prov.id)]
	if len(got) != 1 || !bytes.Equal(got[0], want[:]) {
		t.Fatalf("creation did not log the initial mailbox key (entries=%d)", len(got))
	}
}

func TestCreateMailboxRequiresEntitlement(t *testing.T) {
	api, _ := entTestAPI(t, &fakeProv{})
	dk := newDeviceKeys(t)
	raw, _ := json.Marshal(dk.request(t))
	// Signed, but no Fount-Entitlement header.
	req := signedRequest(t, dk.signPriv, "", "POST", "/mailbox", raw, time.Now(), "mk-noent")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without entitlement, got %d", rec.Code)
	}
}

func TestCreateMailboxRejectsExpiredEntitlement(t *testing.T) {
	api, backend := entTestAPI(t, &fakeProv{})
	dk := newDeviceKeys(t)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(-time.Hour))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, dk.request(t), "mk-exp"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for expired entitlement, got %d", rec.Code)
	}
}

// The request must be signed by the exact device key the entitlement names.
func TestCreateMailboxRejectsWrongDeviceKey(t *testing.T) {
	api, backend := entTestAPI(t, &fakeProv{})
	dk := newDeviceKeys(t)
	// Entitlement names dk.signPub, but sign the request with a different key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, otherPriv, tok, dk.request(t), "mk-wrongdev"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when request not signed by entitled key, got %d", rec.Code)
	}
}

// A body whose signing key doesn't match the entitlement's device key is refused
// even though the request signature itself verifies.
func TestCreateMailboxBindsSigningKey(t *testing.T) {
	api, backend := entTestAPI(t, &fakeProv{})
	dk := newDeviceKeys(t)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))
	body := dk.request(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	body.SigningKey = other // mismatch; re-sign the chain so only the binding check fails
	body.KeyChainSig = ed25519.Sign(dk.mboxPriv, keyChain(body.DecryptionKey, body.SigningKey, body.OwnerChangeKey, body.PasskeyKey))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, body, "mk-bind"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for signing-key mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateMailboxRejectsBadKeyChain(t *testing.T) {
	api, backend := entTestAPI(t, &fakeProv{})
	dk := newDeviceKeys(t)
	tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))
	body := dk.request(t)
	body.KeyChainSig[0] ^= 0xff // corrupt the mailbox-key signature
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, body, "mk-chain"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad key chain, got %d", rec.Code)
	}
}

func TestCreateMailboxConflicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"handle", routing.ErrHandleTaken},
		{"license", routing.ErrLicenseTaken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, backend := entTestAPI(t, &fakeProv{createErr: tc.err})
			dk := newDeviceKeys(t)
			tok := entToken(t, backend, dk.signPub, time.Now().Add(time.Hour))
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, mailboxPost(t, dk.signPriv, tok, dk.request(t), "mk-"+tc.name))
			if rec.Code != http.StatusConflict {
				t.Fatalf("want 409, got %d", rec.Code)
			}
		})
	}
}

func TestCheckHandle(t *testing.T) {
	prov := &fakeProv{available: map[string]bool{"taken@fountbox.com": false}}
	api, backend := entTestAPI(t, prov)
	_, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub := devPriv.Public().(ed25519.PublicKey)
	tok := entToken(t, backend, devPub, time.Now().Add(time.Hour))

	check := func(name, nonce string) map[string]any {
		req := signedRequest(t, devPriv, "", "GET", "/handle/"+name, nil, time.Now(), nonce)
		req.Header.Set("Fount-Entitlement", tok)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("handle %q: want 200, got %d: %s", name, rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	if m := check("freeone", "h1"); m["available"] != true || m["valid"] != true {
		t.Fatalf("free handle = %v", m)
	}
	if m := check("taken", "h2"); m["available"] != false {
		t.Fatalf("taken handle = %v", m)
	}
	if m := check("admin", "h3"); m["valid"] != false {
		t.Fatalf("reserved handle should be invalid: %v", m)
	}
}

// GET /handle probes are throttled per entitlement license (§8): once a caller
// burns its burst, further checks get 429 rather than letting one subscription
// sweep the namespace.
func TestCheckHandleRateLimited(t *testing.T) {
	verifyPub, backend, _ := ed25519.GenerateKey(rand.Reader)
	api := New(Options{
		Store:         store.NewDiscard(),
		Entitlement:   verifyPub,
		Provisioner:   &fakeProv{},
		MailDomain:    "@fountbox.com",
		HandleLimiter: limit.New(0, 2), // 2 probes, no refill during the test
	})
	_, devPriv, _ := ed25519.GenerateKey(rand.Reader)
	devPub := devPriv.Public().(ed25519.PublicKey)
	tok := entToken(t, backend, devPub, time.Now().Add(time.Hour))

	code := func(nonce string) int {
		req := signedRequest(t, devPriv, "", "GET", "/handle/somename", nil, time.Now(), nonce)
		req.Header.Set("Fount-Entitlement", tok)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := code("rl1"); c != http.StatusOK {
		t.Fatalf("probe 1: want 200, got %d", c)
	}
	if c := code("rl2"); c != http.StatusOK {
		t.Fatalf("probe 2: want 200, got %d", c)
	}
	if c := code("rl3"); c != http.StatusTooManyRequests {
		t.Fatalf("probe 3: want 429 (burst exhausted), got %d", c)
	}
}

// With no entitlement verify key configured, the entitlement routes refuse
// rather than fall open.
func TestEntitlementRouteNotConfigured(t *testing.T) {
	api := New(Options{Store: store.NewDiscard(), Provisioner: &fakeProv{}, MailDomain: "@fountbox.com"})
	dk := newDeviceKeys(t)
	raw, _ := json.Marshal(dk.request(t))
	req := signedRequest(t, dk.signPriv, "", "POST", "/mailbox", raw, time.Now(), "mk-noconf")
	req.Header.Set("Fount-Entitlement", "whatever.sig")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when entitlement not configured, got %d", rec.Code)
	}
}
