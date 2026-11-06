package deviceapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type memBlobs struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemBlobs() *memBlobs { return &memBlobs{m: map[string][]byte{}} }

func (b *memBlobs) Put(_ context.Context, k string, d []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[k] = append([]byte(nil), d...)
	return nil
}

func (b *memBlobs) Get(_ context.Context, k string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (b *memBlobs) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (b *memBlobs) Delete(_ context.Context, k string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, k)
	return nil
}

func newRoutingStore(t *testing.T) (*routing.Store, *memBlobs) {
	t.Helper()
	blobs := newMemBlobs()
	rt, err := routing.New(context.Background(), blobs, []byte("test-routing-data-key"), []byte("test-mac-key"))
	if err != nil {
		t.Fatal(err)
	}
	return rt, blobs
}

// mutatorAPI builds an API with routing as the resolver and mutator, and a
// working entitlement verify key; it returns the backend signing key so renewal
// tests can mint entitlements.
func mutatorAPI(t *testing.T, rt *routing.Store) (*API, ed25519.PrivateKey) {
	t.Helper()
	verifyPub, verifyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api := New(Options{
		Store:       store.NewDiscard(),
		Resolver:    NewKeyResolver(rt),
		Mutator:     rt,
		Entitlement: verifyPub,
		MailDomain:  "@fountbox.com",
	})
	return api, verifyPriv
}

type mbox struct {
	id      []byte
	idHex   string
	sign    ed25519.PrivateKey
	mailbox ed25519.PrivateKey
	owner   ed25519.PrivateKey
}

func createMbox(t *testing.T, rt *routing.Store, address, license string) mbox {
	t.Helper()
	_, sp, _ := ed25519.GenerateKey(rand.Reader)
	_, mp, _ := ed25519.GenerateKey(rand.Reader)
	_, op, _ := ed25519.GenerateKey(rand.Reader)
	dec := make([]byte, 32)
	rand.Read(dec)
	pk := make([]byte, 32)
	rand.Read(pk)
	id, err := rt.Create(context.Background(), routing.NewMailbox{
		Address:        address,
		LicenseHash:    []byte(license),
		DecryptionKey:  dec,
		SigningKey:     sp.Public().(ed25519.PublicKey),
		MailboxKey:     mp.Public().(ed25519.PublicKey),
		OwnerChangeKey: op.Public().(ed25519.PublicKey),
		PasskeyKey:     pk,
		EntitlementExp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return mbox{id: id, idHex: hex.EncodeToString(id), sign: sp, mailbox: mp, owner: op}
}

// --- POST /address ---------------------------------------------------------

func childBody(t *testing.T, address string, parentMailboxKey ed25519.PrivateKey) addressRequest {
	t.Helper()
	_, cSign, _ := ed25519.GenerateKey(rand.Reader)
	_, cOwner, _ := ed25519.GenerateKey(rand.Reader)
	cDec := make([]byte, 32)
	rand.Read(cDec)
	cPass := make([]byte, 32)
	rand.Read(cPass)
	req := addressRequest{
		Address:        address,
		DecryptionKey:  cDec,
		SigningKey:     cSign.Public().(ed25519.PublicKey),
		OwnerChangeKey: cOwner.Public().(ed25519.PublicKey),
		PasskeyKey:     cPass,
	}
	req.KeyChainSig = ed25519.Sign(parentMailboxKey, keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey))
	return req
}

func TestPostAddress(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	parent := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	body := childBody(t, "sub.worker@fountbox.com", parent.mailbox)
	raw, _ := json.Marshal(body)
	// POST /address is signed by the mailbox key, Fount-Key-Id = parent mailbox id.
	req := signedRequest(t, parent.mailbox, parent.idHex, "POST", "/address", raw, time.Now(), "a1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if st, _ := rt.Status(context.Background(), "sub.worker@fountbox.com"); st != smtp.RecipientAccepting {
		t.Fatal("new address does not resolve after POST /address")
	}
}

func TestPostAddressBadKeyChain(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	parent := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	body := childBody(t, "sub.worker@fountbox.com", parent.mailbox)
	body.KeyChainSig[0] ^= 0xff
	raw, _ := json.Marshal(body)
	req := signedRequest(t, parent.mailbox, parent.idHex, "POST", "/address", raw, time.Now(), "a2")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad key chain, got %d", rec.Code)
	}
}

func TestPostAddressWrongDomain(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	parent := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	body := childBody(t, "sub.worker@elsewhere.com", parent.mailbox)
	raw, _ := json.Marshal(body)
	req := signedRequest(t, parent.mailbox, parent.idHex, "POST", "/address", raw, time.Now(), "a3")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for out-of-domain address, got %d", rec.Code)
	}
}

func TestPostAddressConflict(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	parent := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	post := func(nonce string) int {
		body := childBody(t, "sub.worker@fountbox.com", parent.mailbox)
		raw, _ := json.Marshal(body)
		req := signedRequest(t, parent.mailbox, parent.idHex, "POST", "/address", raw, time.Now(), nonce)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post("a4"); code != http.StatusCreated {
		t.Fatalf("first add: want 201, got %d", code)
	}
	if code := post("a5"); code != http.StatusConflict {
		t.Fatalf("second add: want 409, got %d", code)
	}
}

// --- PUT /routing ----------------------------------------------------------

func TestPutRouting(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	put := func(version uint64, owners []string, nonce string) int {
		raw, _ := json.Marshal(routingRequest{Version: version, Owners: owners})
		req := signedRequest(t, mb.owner, mb.idHex, "PUT", "/routing", raw, time.Now(), nonce)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := put(1, []string{"jane@smithcpa.com"}, "r1"); code != http.StatusOK {
		t.Fatalf("version 1: want 200, got %d", code)
	}
	if code := put(2, []string{"jane@smithcpa.com", "bob@smithcpa.com"}, "r2"); code != http.StatusOK {
		t.Fatalf("version 2: want 200, got %d", code)
	}
	if code := put(1, nil, "r3"); code != http.StatusConflict {
		t.Fatalf("stale version: want 409, got %d", code)
	}
	if snap, _ := rt.Snapshot(mb.id); snap.RoutingVersion != 2 || len(snap.OwnerHashes) != 2 {
		t.Fatalf("stored routing: %+v", snap)
	}
}

func TestPutRoutingVersionZero(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")
	raw, _ := json.Marshal(routingRequest{Version: 0, Owners: nil})
	req := signedRequest(t, mb.owner, mb.idHex, "PUT", "/routing", raw, time.Now(), "r0")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for version 0, got %d", rec.Code)
	}
}

// PUT /routing demands the owner-change key; a request signed by the (otherwise
// valid) request-signing key is refused at the guard.
func TestPutRoutingWrongKey(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")
	raw, _ := json.Marshal(routingRequest{Version: 1, Owners: nil})
	req := signedRequest(t, mb.sign, mb.idHex, "PUT", "/routing", raw, time.Now(), "rw")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when not signed by owner-change key, got %d", rec.Code)
	}
}

// --- POST /entitlement -----------------------------------------------------

func TestPostEntitlement(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, backend := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "license-hash")

	exp := time.Now().Add(2 * time.Hour)
	tok := entToken(t, backend, mb.sign.Public().(ed25519.PublicKey), exp)
	req := signedRequest(t, mb.sign, mb.idHex, "POST", "/entitlement", []byte("{}"), time.Now(), "e1")
	req.Header.Set("Fount-Entitlement", tok)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if snap, _ := rt.Snapshot(mb.id); snap.EntitlementExp != exp.Unix() {
		t.Fatalf("stored exp = %d, want %d", snap.EntitlementExp, exp.Unix())
	}
}

func TestPostEntitlementWrongLicense(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, backend := mutatorAPI(t, rt)
	// Mailbox bound to a different license than the entitlement carries.
	mb := createMbox(t, rt, "worker@fountbox.com", "other-license")
	tok := entToken(t, backend, mb.sign.Public().(ed25519.PublicKey), time.Now().Add(time.Hour))
	req := signedRequest(t, mb.sign, mb.idHex, "POST", "/entitlement", []byte("{}"), time.Now(), "e2")
	req.Header.Set("Fount-Entitlement", tok)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 for license mismatch, got %d", rec.Code)
	}
}

func TestPostEntitlementWrongDeviceKey(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, backend := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "license-hash")
	// Entitlement names a different device key than the mailbox's signing key.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok := entToken(t, backend, otherPub, time.Now().Add(time.Hour))
	req := signedRequest(t, mb.sign, mb.idHex, "POST", "/entitlement", []byte("{}"), time.Now(), "e3")
	req.Header.Set("Fount-Entitlement", tok)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for wrong device key, got %d", rec.Code)
	}
}

func TestPostEntitlementExpiredToken(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, backend := mutatorAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "license-hash")
	tok := entToken(t, backend, mb.sign.Public().(ed25519.PublicKey), time.Now().Add(-time.Hour))
	req := signedRequest(t, mb.sign, mb.idHex, "POST", "/entitlement", []byte("{}"), time.Now(), "e4")
	req.Header.Set("Fount-Entitlement", tok)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for expired entitlement, got %d", rec.Code)
	}
}

// --- GET /boots/:id --------------------------------------------------------

func TestGetBoot(t *testing.T) {
	rt, blobs := newRoutingStore(t)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	bootID := make([]byte, 16)
	rand.Read(bootID)
	st := store.New(rt, blobs, sign, bootID)
	bs, ok := st.(store.BootStore)
	if !ok {
		t.Fatal("real store should implement BootStore")
	}
	if err := bs.WriteBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	api := New(Options{Store: st, Resolver: NewKeyResolver(rt), Mutator: rt, MailDomain: "@fountbox.com"})

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest("GET", "/boots/"+hex.EncodeToString(bootID), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var b store.Boot
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.BootID != hex.EncodeToString(bootID) {
		t.Fatalf("boot id = %q", b.BootID)
	}
	if !bytes.Equal(b.SigningKey, sign.Public().(ed25519.PublicKey)) {
		t.Fatal("boot signing key mismatch")
	}

	// An unknown but well-formed boot id is 404; a malformed one is 404 too.
	for _, id := range []string{hex.EncodeToString(make([]byte, 16)), "not-hex"} {
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, httptest.NewRequest("GET", "/boots/"+id, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("boot %q: want 404, got %d", id, rec.Code)
		}
	}
}
