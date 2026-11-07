package deviceapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

const (
	recoverTestRPID   = "mail.fount.sh"
	recoverTestOrigin = "https://mail.fount.sh"
)

// recoverStore implements store.Store and store.KeyLog so New() turns recovery
// on and the test can see what was logged.
type recoverStore struct {
	mu      sync.Mutex
	appends map[string][][]byte
}

func newRecoverStore() *recoverStore { return &recoverStore{appends: map[string][][]byte{}} }

func (s *recoverStore) Put(context.Context, string, string, []byte) (string, error) {
	return "x", nil
}

func (s *recoverStore) AppendMailboxKeyHash(_ context.Context, midHex string, keyHash []byte, _ int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appends[midHex] = append(s.appends[midHex], append([]byte(nil), keyHash...))
	return nil
}

func recoverAPI(t *testing.T, rt *routing.Store) (*API, *recoverStore) {
	t.Helper()
	ks := newRecoverStore()
	api := New(Options{
		Store:          ks,
		Resolver:       NewKeyResolver(rt),
		Mutator:        rt,
		MailDomain:     "@fountbox.com",
		RecoveryRPID:   recoverTestRPID,
		RecoveryOrigin: recoverTestOrigin,
	})
	return api, ks
}

// newKeySet is a fresh device key set for a rotation: the four public keys, the
// mailbox private key (to sign the chain), and the new passkey public key.
type newKeySet struct {
	dec, signPub, mboxPub, ownerPub, passkey []byte
	mboxPriv                                 ed25519.PrivateKey
}

func freshKeys(t *testing.T) newKeySet {
	t.Helper()
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	mboxPub, mboxPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dec := make([]byte, 32)
	rand.Read(dec)
	_, passkey := testCredential(t)
	return newKeySet{dec: dec, signPub: signPub, mboxPub: mboxPub, ownerPub: ownerPub, passkey: passkey, mboxPriv: mboxPriv}
}

func (k newKeySet) chain() []byte { return keyChain(k.dec, k.signPub, k.ownerPub, k.passkey) }

// passkeyAssertion signs a WebAuthn assertion over challenge with priv, the way
// a platform authenticator would (user present + verified).
func passkeyAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, rpID, origin string) webauthn.Assertion {
	t.Helper()
	cdj := []byte(fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge), origin))
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(rpHash[:], 0x05, 0, 0, 0, 1)
	clientHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return webauthn.Assertion{AuthenticatorData: authData, ClientDataJSON: cdj, Signature: sig}
}

// getChallenge calls GET /recover/{id}?kc= and returns the decoded token bytes.
func getChallenge(t *testing.T, api *API, mbIDHex string, kc []byte) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	url := "/recover/" + mbIDHex + "?kc=" + hex.EncodeToString(kc)
	api.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	tok, err := base64.RawURLEncoding.DecodeString(resp.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func recoverPost(t *testing.T, api *API, mbIDHex string, body recoverRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/recover", bytes.NewReader(raw))
	req.Header.Set("Fount-Key-Id", mbIDHex)
	req.Header.Set("Fount-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("Fount-Nonce", "recover-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	return rec
}

func TestRecoverRotatesKeys(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, klog := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	nk := freshKeys(t)
	kc := recoveryHash(nk.chain(), nk.mboxPub)
	challenge := getChallenge(t, api, mb.idHex, kc)

	body := recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  nk.dec,
		SigningKey:     nk.signPub,
		MailboxKey:     nk.mboxPub,
		OwnerChangeKey: nk.ownerPub,
		PasskeyKey:     nk.passkey,
		KeyChainSig:    ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:      passkeyAssertion(t, mb.passkeyPriv, challenge, recoverTestRPID, recoverTestOrigin),
	}
	rec := recoverPost(t, api, mb.idHex, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if n := len(api.nonces.seen); n != 2 {
		t.Fatalf("%d entries spent by a verified recovery, want the nonce and the challenge", n)
	}

	// The record now holds the new keys.
	snap, ok := rt.Snapshot(mb.id)
	if !ok {
		t.Fatal("mailbox gone after recovery")
	}
	if !bytes.Equal(snap.MailboxKey, nk.mboxPub) || !bytes.Equal(snap.SigningKey, nk.signPub) ||
		!bytes.Equal(snap.PasskeyKey, nk.passkey) || !bytes.Equal(snap.DecryptionKey, nk.dec) {
		t.Fatal("keys did not rotate")
	}
	// The new mailbox key's hash was written to the write-once log, before the
	// rotation (fail-closed).
	want := sha256.Sum256(nk.mboxPub)
	got := klog.appends[mb.idHex]
	if len(got) != 1 || !bytes.Equal(got[0], want[:]) {
		t.Fatalf("key log has %d entries; want 1 matching the new mailbox key", len(got))
	}
}

func TestRecoverRejectsSwappedKeys(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, klog := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	// Challenge is issued for one key chain...
	approved := freshKeys(t)
	kc := recoveryHash(approved.chain(), approved.mboxPub)
	challenge := getChallenge(t, api, mb.idHex, kc)

	// ...but the POST submits a different key chain. The passkey approved the
	// first; the challenge MAC binds it, so the swap must be refused.
	swapped := freshKeys(t)
	body := recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  swapped.dec,
		SigningKey:     swapped.signPub,
		MailboxKey:     swapped.mboxPub,
		OwnerChangeKey: swapped.ownerPub,
		PasskeyKey:     swapped.passkey,
		KeyChainSig:    ed25519.Sign(swapped.mboxPriv, swapped.chain()),
		Assertion:      passkeyAssertion(t, mb.passkeyPriv, challenge, recoverTestRPID, recoverTestOrigin),
	}
	rec := recoverPost(t, api, mb.idHex, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for swapped keys, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(klog.appends[mb.idHex]) != 0 {
		t.Fatal("a refused recovery must not log a key")
	}
	if snap, _ := rt.Snapshot(mb.id); bytes.Equal(snap.MailboxKey, swapped.mboxPub) {
		t.Fatal("keys rotated despite a refused recovery")
	}
}

func TestRecoverRejectsWrongPasskey(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	nk := freshKeys(t)
	kc := recoveryHash(nk.chain(), nk.mboxPub)
	challenge := getChallenge(t, api, mb.idHex, kc)

	attacker, _ := testCredential(t) // not the registered passkey
	body := recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  nk.dec,
		SigningKey:     nk.signPub,
		MailboxKey:     nk.mboxPub,
		OwnerChangeKey: nk.ownerPub,
		PasskeyKey:     nk.passkey,
		KeyChainSig:    ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:      passkeyAssertion(t, attacker, challenge, recoverTestRPID, recoverTestOrigin),
	}
	rec := recoverPost(t, api, mb.idHex, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for wrong passkey, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRecoverRejectsExpiredChallenge(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	nk := freshKeys(t)
	kc := recoveryHash(nk.chain(), nk.mboxPub)
	// Mint a challenge that already expired (internal path, so we control exp).
	challenge := api.mintChallenge(mb.id, kc, time.Now().Add(-time.Minute).Unix())

	body := recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  nk.dec,
		SigningKey:     nk.signPub,
		MailboxKey:     nk.mboxPub,
		OwnerChangeKey: nk.ownerPub,
		PasskeyKey:     nk.passkey,
		KeyChainSig:    ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:      passkeyAssertion(t, mb.passkeyPriv, challenge, recoverTestRPID, recoverTestOrigin),
	}
	rec := recoverPost(t, api, mb.idHex, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for expired challenge, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRecoverUnknownMailbox(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := recoverAPI(t, rt)

	unknown := make([]byte, 32)
	rand.Read(unknown)
	unknownHex := hex.EncodeToString(unknown)

	nk := freshKeys(t)
	kc := recoveryHash(nk.chain(), nk.mboxPub)
	challenge := getChallenge(t, api, unknownHex, kc)

	priv, _ := testCredential(t)
	body := recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  nk.dec,
		SigningKey:     nk.signPub,
		MailboxKey:     nk.mboxPub,
		OwnerChangeKey: nk.ownerPub,
		PasskeyKey:     nk.passkey,
		KeyChainSig:    ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:      passkeyAssertion(t, priv, challenge, recoverTestRPID, recoverTestOrigin),
	}
	rec := recoverPost(t, api, unknownHex, body)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown mailbox, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRecoverStubWhenNotConfigured(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := mutatorAPI(t, rt) // no RecoveryRPID, no KeyLog store -> recovery not live
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	rec := recoverPost(t, api, mb.idHex, recoverRequest{})
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501 when recovery not configured, got %d", rec.Code)
	}
}

// POST /recover has no signature, so anyone can send one. Only a verified passkey
// may spend a nonce.
func TestRecoverNonceSpentOnlyAfterAssertion(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	if rec := recoverPost(t, api, mb.idHex, recoverRequest{}); rec.Code == http.StatusOK {
		t.Fatal("an empty recovery must not pass")
	}
	if n := len(api.nonces.seen); n != 0 {
		t.Fatalf("%d nonces cached before any assertion", n)
	}
}

func TestRecoverMissingNonce(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, _ := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	raw, _ := json.Marshal(recoverRequest{})
	req := httptest.NewRequest("POST", "/recover", bytes.NewReader(raw))
	req.Header.Set("Fount-Key-Id", mb.idHex)
	req.Header.Set("Fount-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	// no Fount-Nonce
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without a nonce, got %d", rec.Code)
	}
}

func recoveryBody(t *testing.T, mb mbox, api *API, nk newKeySet) recoverRequest {
	t.Helper()
	challenge := getChallenge(t, api, mb.idHex, recoveryHash(nk.chain(), nk.mboxPub))
	return recoverRequest{
		Challenge:      challenge,
		DecryptionKey:  nk.dec,
		SigningKey:     nk.signPub,
		MailboxKey:     nk.mboxPub,
		OwnerChangeKey: nk.ownerPub,
		PasskeyKey:     nk.passkey,
		KeyChainSig:    ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:      passkeyAssertion(t, mb.passkeyPriv, challenge, recoverTestRPID, recoverTestOrigin),
	}
}

// The mailbox key signs the chain instead of sitting in it, so an approved request
// could carry a different mailbox key that signs the same chain.
func TestRecoverChallengeCoversTheMailboxKey(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, klog := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	nk := freshKeys(t)
	body := recoveryBody(t, mb, api, nk)
	swap := freshKeys(t)
	body.MailboxKey = swap.mboxPub
	body.KeyChainSig = ed25519.Sign(swap.mboxPriv, nk.chain())

	rec := recoverPost(t, api, mb.idHex, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for a swapped mailbox key, got %d: %s", rec.Code, rec.Body.String())
	}
	if snap, _ := rt.Snapshot(mb.id); bytes.Equal(snap.MailboxKey, swap.mboxPub) {
		t.Fatal("the swapped mailbox key went live")
	}
	if len(klog.appends) != 0 {
		t.Fatal("a refused recovery logged a key")
	}
}

// recoverPost uses a fresh nonce each time, so only the challenge can stop this.
func TestRecoverChallengeWorksOnce(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, klog := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	body := recoveryBody(t, mb, api, freshKeys(t))
	if rec := recoverPost(t, api, mb.idHex, body); rec.Code != http.StatusOK {
		t.Fatalf("first use: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// Put the original passkey back, so its assertion still verifies and only the
	// spent challenge can refuse the resend.
	nk := freshKeys(t)
	if _, err := rt.RotateKeys(context.Background(), mb.id, routing.RotatedKeys{
		DecryptionKey: nk.dec, SigningKey: nk.signPub, MailboxKey: nk.mboxPub, OwnerChangeKey: nk.ownerPub,
		PasskeyKey: mustPublic(mb),
	}); err != nil {
		t.Fatal(err)
	}
	if rec := recoverPost(t, api, mb.idHex, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("resend: want 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := len(klog.appends[mb.idHex]); n != 1 {
		t.Fatalf("%d log entries, want 1", n)
	}
}

func mustPublic(mb mbox) []byte {
	k := mb.passkeyPriv
	return append([]byte{0x04}, append(k.X.FillBytes(make([]byte, 32)), k.Y.FillBytes(make([]byte, 32))...)...)
}

// One mailbox key covers the handle and its workers, so a lost device's key must
// stop working everywhere, and each address needs its own log entry.
func TestRecoverRotatesTheMailboxKeyOnEveryAddress(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, klog := recoverAPI(t, rt)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")

	raw, _ := json.Marshal(childBody(t, "sub.worker@fountbox.com", mb.mailbox))
	add := httptest.NewRecorder()
	api.ServeHTTP(add, signedRequest(t, mb.mailbox, mb.idHex, "POST", "/address", raw, time.Now(), "add-1"))
	if add.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", add.Code, add.Body.String())
	}
	var created struct {
		MailboxID string `json:"mailbox_id"`
	}
	if err := json.Unmarshal(add.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	childID, _ := hex.DecodeString(created.MailboxID)
	before, _ := rt.Snapshot(childID)

	nk := freshKeys(t)
	if rec := recoverPost(t, api, mb.idHex, recoveryBody(t, mb, api, nk)); rec.Code != http.StatusOK {
		t.Fatalf("recover: %d %s", rec.Code, rec.Body.String())
	}

	after, _ := rt.Snapshot(childID)
	if !bytes.Equal(after.MailboxKey, nk.mboxPub) {
		t.Fatal("the worker kept the old mailbox key")
	}
	if !bytes.Equal(after.SigningKey, before.SigningKey) || !bytes.Equal(after.DecryptionKey, before.DecryptionKey) {
		t.Fatal("recovery replaced a sibling's own keys")
	}
	want := sha256.Sum256(nk.mboxPub)
	for _, id := range []string{mb.idHex, created.MailboxID} {
		entries := klog.appends[id]
		if len(entries) == 0 || !bytes.Equal(entries[len(entries)-1], want[:]) {
			t.Fatalf("no log entry for the new key on %s", id)
		}
	}
	raw, _ = json.Marshal(childBody(t, "other.worker@fountbox.com", mb.mailbox))
	old := httptest.NewRecorder()
	api.ServeHTTP(old, signedRequest(t, mb.mailbox, created.MailboxID, "POST", "/address", raw, time.Now(), "add-2"))
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("old key through the worker's id: want 401, got %d: %s", old.Code, old.Body.String())
	}
}
