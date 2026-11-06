package routing_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// The routing store is the one implementation behind all three seams.
var (
	_ store.Directory       = (*routing.Store)(nil)
	_ smtp.RecipientChecker = (*routing.Store)(nil)
	_ deviceapi.KeyProvider = (*routing.Store)(nil)
	_ deviceapi.KeyResolver = deviceapi.NewKeyResolver((*routing.Store)(nil))
)

type memBlobs struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newMemBlobs() *memBlobs { return &memBlobs{objs: map[string][]byte{}} }

func (b *memBlobs) Put(_ context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs[key] = append([]byte(nil), data...)
	return nil
}

func (b *memBlobs) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.objs[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (b *memBlobs) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (b *memBlobs) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objs, key)
	return nil
}

type keyset struct {
	dec         *ecdh.PrivateKey
	sign        ed25519.PrivateKey
	mailbox     ed25519.PrivateKey
	ownerChange ed25519.PrivateKey
	passkey     ed25519.PrivateKey
}

func newKeyset(t *testing.T) keyset {
	t.Helper()
	dec, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyset{dec: dec, sign: edKey(t), mailbox: edKey(t), ownerChange: edKey(t), passkey: edKey(t)}
}

func edKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func (k keyset) record(mailboxID []byte) *routing.Mailbox {
	return &routing.Mailbox{
		MailboxID:      mailboxID,
		DecryptionKey:  k.dec.PublicKey().Bytes(),
		SigningKey:     k.sign.Public().(ed25519.PublicKey),
		MailboxKey:     k.mailbox.Public().(ed25519.PublicKey),
		OwnerChangeKey: k.ownerChange.Public().(ed25519.PublicKey),
		PasskeyKey:     k.passkey.Public().(ed25519.PublicKey),
		LicenseHash:    []byte("lic-hash"),
	}
}

func keys(t *testing.T) (routingKey, macKey []byte) {
	t.Helper()
	routingKey = make([]byte, 40) // deliberately not 32, to prove HKDF handles any length
	macKey = make([]byte, 32)
	rand.Read(routingKey)
	rand.Read(macKey)
	return
}

func newStore(t *testing.T, blobs store.Blobs, routingKey, macKey []byte) *routing.Store {
	t.Helper()
	s, err := routing.New(context.Background(), blobs, routingKey, macKey)
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	return s
}

func TestResolveAndStatus(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()

	const addr = "Worker@FountBox.com" // mixed case; resolution is case-folded
	ks := newKeyset(t)
	id := s.MailboxID(addr)
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	got, err := s.Resolve(ctx, "worker@fountbox.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got.MailboxID, id) {
		t.Fatal("resolved mailbox id mismatch")
	}
	if !bytes.Equal(got.PublicKey, ks.dec.PublicKey().Bytes()) {
		t.Fatal("resolved decryption key mismatch")
	}

	st, _ := s.Status(ctx, addr)
	if st != smtp.RecipientAccepting {
		t.Fatalf("Status for a registered address = %v, want Accepting", st)
	}

	if _, err := s.Resolve(ctx, "nobody@fountbox.com"); !errors.Is(err, store.ErrNoRecipient) {
		t.Fatalf("unknown Resolve err = %v, want ErrNoRecipient", err)
	}
	if st, _ := s.Status(ctx, "nobody@fountbox.com"); st != smtp.RecipientUnknown {
		t.Fatalf("Status for an unregistered address = %v, want Unknown", st)
	}
}

func TestStatusEntitlementExpiry(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()

	// A record with no recorded entitlement (exp 0) accepts: dev/smoke and
	// pre-enforcement records must not bounce.
	noExp := s.MailboxID("none@fountbox.com")
	if err := s.Upsert(ctx, newKeyset(t).record(noExp)); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx, "none@fountbox.com"); st != smtp.RecipientAccepting {
		t.Fatalf("zero EntitlementExp Status = %v, want Accepting", st)
	}

	// A current entitlement accepts.
	live := newKeyset(t).record(s.MailboxID("live@fountbox.com"))
	live.EntitlementExp = time.Now().Add(time.Hour).Unix()
	if err := s.Upsert(ctx, live); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx, "live@fountbox.com"); st != smtp.RecipientAccepting {
		t.Fatalf("future EntitlementExp Status = %v, want Accepting", st)
	}

	// A lapsed entitlement bounces (550): grace is over.
	dead := newKeyset(t).record(s.MailboxID("dead@fountbox.com"))
	dead.EntitlementExp = time.Now().Add(-time.Hour).Unix()
	if err := s.Upsert(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx, "dead@fountbox.com"); st != smtp.RecipientExpired {
		t.Fatalf("past EntitlementExp Status = %v, want Expired", st)
	}
}

func TestNextSequencePersists(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	for want := uint64(1); want <= 3; want++ {
		got, err := s.NextSequence(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("sequence = %d, want %d", got, want)
		}
	}

	// A fresh store over the same blobs resumes from the persisted counter.
	s2 := newStore(t, blobs, routingKey, macKey)
	got, err := s2.NextSequence(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got != 4 {
		t.Fatalf("after reload, sequence = %d, want 4", got)
	}

	if _, err := s.NextSequence(ctx, make([]byte, 32)); err == nil {
		t.Fatal("NextSequence for an unknown mailbox must error")
	}
}

func TestKeyProvider(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}
	keyID := hex.EncodeToString(id)

	cases := []struct {
		name string
		get  func(string) (ed25519.PublicKey, bool)
		want ed25519.PublicKey
	}{
		{"address", s.AddressKey, ks.sign.Public().(ed25519.PublicKey)},
		{"mailbox", s.MailboxKey, ks.mailbox.Public().(ed25519.PublicKey)},
		{"owner-change", s.OwnerChangeKey, ks.ownerChange.Public().(ed25519.PublicKey)},
		{"passkey", s.PasskeyKey, ks.passkey.Public().(ed25519.PublicKey)},
	}
	for _, c := range cases {
		pub, ok := c.get(keyID)
		if !ok {
			t.Fatalf("%s: not found", c.name)
		}
		if !bytes.Equal(pub, c.want) {
			t.Fatalf("%s: key mismatch", c.name)
		}
		if _, ok := c.get("deadbeef"); ok {
			t.Fatalf("%s: unknown key id must not resolve", c.name)
		}
	}
}

// A record missing a key (e.g. no passkey registered yet) resolves false for
// that class rather than returning a short slice as a public key.
func TestKeyProviderRejectsShortKey(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	rec := ks.record(id)
	rec.PasskeyKey = nil
	if err := s.Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.PasskeyKey(hex.EncodeToString(id)); ok {
		t.Fatal("a nil passkey must not resolve")
	}
	// The other keys still resolve.
	if _, ok := s.AddressKey(hex.EncodeToString(id)); !ok {
		t.Fatal("address key should still resolve")
	}
}

// At rest the object is magic-framed ciphertext; the keys and the recipient's
// keyed hash must not be recoverable without ROUTING_DATA_KEY.
func TestObjectEncryptedAtRest(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	raw, err := blobs.Get(ctx, "edge/routing/current")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("FMR1")) {
		t.Fatal("object is not magic-framed")
	}
	if bytes.Contains(raw, ks.dec.PublicKey().Bytes()) {
		t.Fatal("decryption key appears in the at-rest object")
	}
	if bytes.Contains(raw, id) {
		t.Fatal("mailbox id appears in the at-rest object")
	}

	// A store built with the wrong key cannot read it.
	wrong := make([]byte, 40)
	rand.Read(wrong)
	if _, err := routing.New(ctx, blobs, wrong, macKey); err == nil {
		t.Fatal("wrong ROUTING_DATA_KEY must fail to decrypt")
	}
}

func TestCreateEnforcesUniqueness(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)

	mk := func(addr, lic string) routing.NewMailbox {
		return routing.NewMailbox{
			Address:        addr,
			LicenseHash:    []byte(lic),
			DecryptionKey:  ks.dec.PublicKey().Bytes(),
			SigningKey:     ks.sign.Public().(ed25519.PublicKey),
			MailboxKey:     ks.mailbox.Public().(ed25519.PublicKey),
			OwnerChangeKey: ks.ownerChange.Public().(ed25519.PublicKey),
			PasskeyKey:     ks.passkey.Public().(ed25519.PublicKey),
			EntitlementExp: 123,
		}
	}

	if avail, _ := s.Available(ctx, "a@fountbox.com"); !avail {
		t.Fatal("handle should start available")
	}
	id, err := s.Create(ctx, mk("a@fountbox.com", "lic-1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !bytes.Equal(id, s.MailboxID("a@fountbox.com")) {
		t.Fatal("Create returned the wrong mailbox id")
	}
	if avail, _ := s.Available(ctx, "a@fountbox.com"); avail {
		t.Fatal("handle should be taken after Create")
	}

	// Same handle again -> ErrHandleTaken.
	if _, err := s.Create(ctx, mk("a@fountbox.com", "lic-2")); !errors.Is(err, routing.ErrHandleTaken) {
		t.Fatalf("err = %v, want ErrHandleTaken", err)
	}
	// Different handle, same license -> ErrLicenseTaken.
	if _, err := s.Create(ctx, mk("b@fountbox.com", "lic-1")); !errors.Is(err, routing.ErrLicenseTaken) {
		t.Fatalf("err = %v, want ErrLicenseTaken", err)
	}
	// Different handle and license -> ok, and it resolves + its sequence starts at 1.
	if _, err := s.Create(ctx, mk("b@fountbox.com", "lic-2")); err != nil {
		t.Fatalf("second mailbox: %v", err)
	}
	if _, err := s.Resolve(ctx, "b@fountbox.com"); err != nil {
		t.Fatalf("Resolve new mailbox: %v", err)
	}
	seq, err := s.NextSequence(ctx, s.MailboxID("b@fountbox.com"))
	if err != nil || seq != 1 {
		t.Fatalf("first sequence = %d, %v, want 1", seq, err)
	}
}

func TestAddAddressInheritsLicenseAndMailboxKey(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	parent := newKeyset(t)

	parentID, err := s.Create(ctx, routing.NewMailbox{
		Address:        "worker@fountbox.com",
		LicenseHash:    []byte("lic-1"),
		DecryptionKey:  parent.dec.PublicKey().Bytes(),
		SigningKey:     parent.sign.Public().(ed25519.PublicKey),
		MailboxKey:     parent.mailbox.Public().(ed25519.PublicKey),
		OwnerChangeKey: parent.ownerChange.Public().(ed25519.PublicKey),
		PasskeyKey:     parent.passkey.Public().(ed25519.PublicKey),
		EntitlementExp: 999,
	})
	if err != nil {
		t.Fatal(err)
	}

	child := newKeyset(t)
	const childAddr = "sub.worker@fountbox.com"
	childID, err := s.AddAddress(ctx, routing.NewAddress{
		ParentMailboxID: parentID,
		Address:         childAddr,
		DecryptionKey:   child.dec.PublicKey().Bytes(),
		SigningKey:      child.sign.Public().(ed25519.PublicKey),
		OwnerChangeKey:  child.ownerChange.Public().(ed25519.PublicKey),
		PasskeyKey:      child.passkey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("AddAddress: %v", err)
	}
	if !bytes.Equal(childID, s.MailboxID(childAddr)) {
		t.Fatal("AddAddress returned the wrong id")
	}

	// The child resolves and signs with its own keys...
	if pub, ok := s.AddressKey(hex.EncodeToString(childID)); !ok || !bytes.Equal(pub, child.sign.Public().(ed25519.PublicKey)) {
		t.Fatal("child address key not its own")
	}
	// ...but shares the parent's mailbox key, license, and entitlement (§5).
	if pub, ok := s.MailboxKey(hex.EncodeToString(childID)); !ok || !bytes.Equal(pub, parent.mailbox.Public().(ed25519.PublicKey)) {
		t.Fatal("child must share the parent mailbox key")
	}
	snap, ok := s.Snapshot(childID)
	if !ok || string(snap.LicenseHash) != "lic-1" || snap.EntitlementExp != 999 {
		t.Fatalf("child did not inherit license/entitlement: %+v", snap)
	}

	// A second address, same handle -> taken; under an unknown parent -> no mailbox.
	if _, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: parentID, Address: childAddr, DecryptionKey: child.dec.PublicKey().Bytes(), SigningKey: child.sign.Public().(ed25519.PublicKey), OwnerChangeKey: child.ownerChange.Public().(ed25519.PublicKey), PasskeyKey: child.passkey.Public().(ed25519.PublicKey)}); !errors.Is(err, routing.ErrHandleTaken) {
		t.Fatalf("err = %v, want ErrHandleTaken", err)
	}
	if _, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: make([]byte, 32), Address: "x.worker@fountbox.com"}); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("err = %v, want ErrNoMailbox", err)
	}
}

func TestSetOwnersMonotonicVersion(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	if err := s.SetOwners(ctx, id, 1, []string{"jane@smithcpa.com", "bob@smithcpa.com"}); err != nil {
		t.Fatalf("version 1: %v", err)
	}
	snap, _ := s.Snapshot(id)
	if snap.RoutingVersion != 1 || len(snap.OwnerHashes) != 2 {
		t.Fatalf("after version 1: %+v", snap)
	}
	// Owners are stored only as keyed hashes, never the plaintext address.
	if bytes.Contains(bytes.Join(snap.OwnerHashes, nil), []byte("jane@smithcpa.com")) {
		t.Fatal("owner plaintext stored")
	}

	// Re-asserting the same version is accepted (corrects a rollback).
	if err := s.SetOwners(ctx, id, 1, []string{"jane@smithcpa.com"}); err != nil {
		t.Fatalf("re-assert version 1: %v", err)
	}
	// Advancing is accepted.
	if err := s.SetOwners(ctx, id, 2, []string{"jane@smithcpa.com"}); err != nil {
		t.Fatalf("version 2: %v", err)
	}
	// Going backwards is refused.
	if err := s.SetOwners(ctx, id, 1, nil); !errors.Is(err, routing.ErrStaleVersion) {
		t.Fatalf("stale err = %v, want ErrStaleVersion", err)
	}
	if err := s.SetOwners(ctx, make([]byte, 32), 1, nil); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("unknown mailbox err = %v, want ErrNoMailbox", err)
	}
}

func TestRenewEntitlement(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	rec := ks.record(id)
	rec.LicenseHash = []byte("lic-1")
	rec.EntitlementExp = 100
	if err := s.Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}

	if err := s.RenewEntitlement(ctx, id, []byte("lic-1"), 500); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if snap, _ := s.Snapshot(id); snap.EntitlementExp != 500 {
		t.Fatalf("exp = %d, want 500", snap.EntitlementExp)
	}
	// A renewal for a different license can't move the mailbox.
	if err := s.RenewEntitlement(ctx, id, []byte("lic-2"), 900); !errors.Is(err, routing.ErrLicenseMismatch) {
		t.Fatalf("err = %v, want ErrLicenseMismatch", err)
	}
	if snap, _ := s.Snapshot(id); snap.EntitlementExp != 500 {
		t.Fatal("expiry changed on a mismatched renewal")
	}
	if err := s.RenewEntitlement(ctx, make([]byte, 32), []byte("lic-1"), 900); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("err = %v, want ErrNoMailbox", err)
	}
}

// A store survives a reload over the same blobs with its records intact.
func TestReloadRoundTrip(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	s2 := newStore(t, blobs, routingKey, macKey)
	got, err := s2.Resolve(ctx, "a@fountbox.com")
	if err != nil {
		t.Fatalf("Resolve after reload: %v", err)
	}
	if !bytes.Equal(got.PublicKey, ks.dec.PublicKey().Bytes()) {
		t.Fatal("decryption key lost across reload")
	}
	if pub, ok := s2.AddressKey(hex.EncodeToString(id)); !ok || !bytes.Equal(pub, ks.sign.Public().(ed25519.PublicKey)) {
		t.Fatal("signing key lost across reload")
	}
}
