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
	kc := sha256.Sum256(nk.chain())
	challenge := getChallenge(t, api, mb.idHex, kc[:])

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
	kc := sha256.Sum256(approved.chain())
	challenge := getChallenge(t, api, mb.idHex, kc[:])

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
	kc := sha256.Sum256(nk.chain())
	challenge := getChallenge(t, api, mb.idHex, kc[:])

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
	kc := sha256.Sum256(nk.chain())
	// Mint a challenge that already expired (internal path, so we control exp).
	challenge := api.mintChallenge(mb.id, kc[:], time.Now().Add(-time.Minute).Unix())

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
	kc := sha256.Sum256(nk.chain())
	challenge := getChallenge(t, api, unknownHex, kc[:])

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
