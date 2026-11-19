package deviceapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// Security review 2026-11-19, H1: on an enrolled mailbox the creator's passkey,
// owner-change key and mailbox key are no authority. The coordinator is the
// only key holder.

func custodyFixture(t *testing.T) (*coordFixture, mbox, coordinatorKey) {
	t.Helper()
	f := newCoordFixture(t)
	f.opts.RecoveryRPID, f.opts.RecoveryOrigin = recoverTestRPID, recoverTestOrigin
	f.opts.Store = newRecoverStore()
	f.api = New(f.opts)
	mb := createMbox(t, f.rt, "worker@fountbox.com", "lic-1")
	c1 := f.coordinator(1)
	wantCode(t, f.claim(c1), http.StatusOK, "")
	return f, mb, c1
}

// legacyEnrolled is routing data where some mailboxes count as enrolled but
// still hold their device keys, as an edge from before enrollment dropped them
// left them. It tests the refusals themselves, apart from the dropped keys.
type legacyEnrolled struct {
	*routing.Store
	ids map[string]bool
}

func (l legacyEnrolled) Coordinated(mid []byte) bool {
	return l.ids[hex.EncodeToString(mid)] || l.Store.Coordinated(mid)
}

// recoverWith posts a full recovery of mb by its registered passkey.
func recoverWith(t *testing.T, api *API, mb mbox) (*httptest.ResponseRecorder, newKeySet) {
	t.Helper()
	nk := freshKeys(t)
	ch := getChallenge(t, api, mb.idHex, recoveryHash(nk.chain(), nk.mboxPub))
	rec := recoverPost(t, api, mb.idHex, recoverRequest{
		Challenge: ch, DecryptionKey: nk.dec, SigningKey: nk.signPub, MailboxKey: nk.mboxPub,
		OwnerChangeKey: nk.ownerPub, PasskeyKey: nk.passkey,
		KeyChainSig: ed25519.Sign(nk.mboxPriv, nk.chain()),
		Assertion:   passkeyAssertion(t, mb.passkeyPriv, ch, recoverTestRPID, recoverTestOrigin),
	})
	return rec, nk
}

// The review's probe: recovery by the creator's passkey on an enrolled mailbox
// replaced every key and locked the coordinator out.
func TestCoordinatedMailboxRefusesPasskeyRecovery(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	rec, nk := recoverWith(t, f.api, mb)
	if rec.Code == http.StatusOK {
		t.Fatalf("recovered a coordinated mailbox: %s", rec.Body)
	}
	snap, _ := f.rt.Snapshot(mb.id)
	if bytes.Equal(snap.SigningKey, nk.signPub) || bytes.Equal(snap.DecryptionKey, nk.dec) {
		t.Fatal("recovery replaced the coordinated mailbox's keys")
	}
	if !bytes.Equal(snap.SigningKey, mb.sign.Public().(ed25519.PublicKey)) {
		t.Fatal("the coordinator's address key was replaced")
	}

	// Where the passkey is still registered, the route itself refuses.
	f.opts.Mutator = legacyEnrolled{f.rt, map[string]bool{mb.idHex: true}}
	f.api = New(f.opts)
	mb2 := createMbox(t, f.rt, "w2@fountbox.com", "lic-3")
	f.opts.Mutator.(legacyEnrolled).ids[mb2.idHex] = true
	rec, _ = recoverWith(t, f.api, mb2)
	wantCode(t, rec, http.StatusConflict, codeCoordinatorOnly)
}

// And the store refuses it whatever the handler does.
func TestRotateKeysRefusesCoordinatedMailbox(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	nk := freshKeys(t)
	_, err := f.rt.RotateKeys(t.Context(), mb.id, routing.RotatedKeys{DecryptionKey: nk.dec, SigningKey: nk.signPub, MailboxKey: nk.mboxPub, OwnerChangeKey: nk.ownerPub, PasskeyKey: nk.passkey})
	if !errors.Is(err, routing.ErrCoordinated) {
		t.Fatalf("RotateKeys on a coordinated mailbox: %v", err)
	}
}

func TestCoordinatedMailboxRefusesPasskeyPause(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	pause := func(mb mbox) *httptest.ResponseRecorder {
		ch := pauseChallenge(t, f.api, mb.idHex, "true")
		return pausePost(t, f.api, mb.idHex, pauseRequest{Paused: ptr(true), Challenge: ch, Assertion: passkeyAssertion(t, mb.passkeyPriv, ch, recoverTestRPID, recoverTestOrigin)})
	}
	if rec := pause(mb); rec.Code == http.StatusOK {
		t.Fatalf("the creator's passkey paused a coordinated mailbox: %s", rec.Body)
	}
	if f.rt.Paused(mb.id) {
		t.Fatal("paused")
	}

	mb2 := createMbox(t, f.rt, "w2@fountbox.com", "lic-3")
	f.opts.Mutator = legacyEnrolled{f.rt, map[string]bool{mb2.idHex: true}}
	f.api = New(f.opts)
	wantCode(t, pause(mb2), http.StatusConflict, codeCoordinatorOnly)
	if f.rt.Paused(mb2.id) {
		t.Fatal("paused")
	}
}

func TestCoordinatedMailboxRefusesOwnerChangeAndMailboxKeys(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	routingBody, _ := json.Marshal(map[string]any{"version": 9, "owners": []string{"attacker@evil.example"}})
	connect, _ := json.Marshal(map[string]string{"address": "worker@fountbox.com", "owner": "attacker@evil.example"})
	address, _ := json.Marshal(childBody(t, "w3.worker@fountbox.com", mb.mailbox))
	try := func(mb mbox, status int, code string) {
		t.Helper()
		wantCode(t, f.serve(genRequest(t, mb.owner, mb.idHex, "PUT", "/routing", routingBody, "1")), status, code)
		wantCode(t, f.serve(genRequest(t, mb.owner, mb.idHex, "POST", "/connect", connect, "1")), status, code)
		wantCode(t, f.serve(genRequest(t, mb.mailbox, mb.idHex, "POST", "/address", address, "1")), http.StatusConflict, codeCoordinatorOnly)
		if snap, _ := f.rt.Snapshot(mb.id); snap.RoutingVersion == 9 {
			t.Fatal("the owner-change key re-owned a coordinated mailbox")
		}
	}
	// Enrolling dropped the owner-change key, so it doesn't even verify.
	try(mb, http.StatusUnauthorized, "")

	mb2 := createMbox(t, f.rt, "worker2@fountbox.com", "lic-3")
	f.opts.Mutator = legacyEnrolled{f.rt, map[string]bool{mb2.idHex: true}}
	f.opts.Resolver = NewKeyResolver(f.rt)
	f.api = New(f.opts)
	try(mb2, http.StatusConflict, codeCoordinatorOnly)
}

func TestEnrollDropsOwnerChangeKeyAndPasskey(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	snap, _ := f.rt.Snapshot(mb.id)
	if len(snap.OwnerChangeKey) != 0 || len(snap.PasskeyKey) != 0 {
		t.Fatal("enrollment kept a device's owner-change key or passkey")
	}
}

// Security review 2026-11-19, M1: the coordinator rotates the decryption key.
func TestCoordinatorRotatesDecryptionKey(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	newKey := make([]byte, 32)
	_, _ = rand.Read(newKey)
	body := func(idHex string, key []byte) []byte {
		b, _ := json.Marshal(decryptionKeyRequest{MailboxID: idHex, DecryptionKey: base64.StdEncoding.EncodeToString(key)})
		return b
	}
	rotate := func(priv ed25519.PrivateKey, id string, b []byte) int {
		return f.serve(genRequest(t, priv, id, "POST", "/coordinator/decryption-key", b, strconv.FormatUint(c1.gen, 10))).Code
	}
	// Not with the address key.
	if code := rotate(mb.sign, mb.idHex, body(mb.idHex, newKey)); code != http.StatusUnauthorized {
		t.Fatalf("address key rotated it: %d", code)
	}
	rec := f.serve(genRequest(t, c1.priv, c1.id, "POST", "/coordinator/decryption-key", body(mb.idHex, newKey), "1"))
	wantCode(t, rec, http.StatusOK, "")
	sum := sha256.Sum256(newKey)
	if !bytes.Contains(rec.Body.Bytes(), []byte(hex.EncodeToString(sum[:]))) {
		t.Fatalf("body %s", rec.Body)
	}
	snap, _ := f.rt.Snapshot(mb.id)
	if !bytes.Equal(snap.DecryptionKey, newKey) {
		t.Fatal("the decryption key didn't change")
	}
	if code := rotate(c1.priv, c1.id, body(mb.idHex, newKey)); code != http.StatusConflict {
		t.Fatalf("the same key again: %d", code)
	}
	wantCode(t, f.serve(genRequest(t, c1.priv, c1.id, "POST", "/coordinator/decryption-key", body(other.idHex, newKey), "1")), http.StatusConflict, codeNotCoordinated)
}

func TestCoordinatorWritesRoutingAndPause(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	routing, _ := json.Marshal(map[string]any{"mailbox_id": mb.idHex, "version": 3, "owners": []string{"pat@smithcpa.com"}})
	wantCode(t, f.serve(genRequest(t, c1.priv, c1.id, "POST", "/coordinator/routing", routing, "1")), http.StatusOK, "")
	if snap, _ := f.rt.Snapshot(mb.id); snap.RoutingVersion != 3 || len(snap.OwnerHashes) != 1 {
		t.Fatalf("routing not written: version %d, %d owners", snap.RoutingVersion, len(snap.OwnerHashes))
	}
	older, _ := json.Marshal(map[string]any{"mailbox_id": mb.idHex, "version": 2, "owners": []string{}})
	wantCode(t, f.serve(genRequest(t, c1.priv, c1.id, "POST", "/coordinator/routing", older, "1")), http.StatusConflict, "")

	pause, _ := json.Marshal(map[string]any{"mailbox_id": mb.idHex, "paused": true})
	wantCode(t, f.serve(genRequest(t, c1.priv, c1.id, "POST", "/coordinator/pause", pause, "1")), http.StatusOK, "")
	if !f.rt.Paused(mb.id) {
		t.Fatal("not paused")
	}
	wantCode(t, f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/coordinator/pause", pause, "1")), http.StatusUnauthorized, "")
}
