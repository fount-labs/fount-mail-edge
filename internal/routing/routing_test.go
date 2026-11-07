package routing_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

func (b *memBlobs) List(_ context.Context, prefix string) ([]store.Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []store.Object
	for k, v := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, store.Object{Key: k, Size: int64(len(v))})
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

func (b *memBlobs) GetVersioned(ctx context.Context, k string) ([]byte, string, error) {
	v, err := b.Get(ctx, k)
	if err != nil {
		return nil, "", err
	}
	return v, etagOf(v), nil
}

func (b *memBlobs) PutIfMatch(ctx context.Context, k string, d []byte, etag string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.objs[k]
	if ok && etag != etagOf(cur) || !ok && etag != "" {
		return "", store.ErrConflict
	}
	b.objs[k] = append([]byte(nil), d...)
	return etagOf(d), nil
}

func etagOf(d []byte) string {
	h := sha256.Sum256(d)
	return hex.EncodeToString(h[:])
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

func newStore(t *testing.T, blobs routing.Blobs, routingKey, macKey []byte) *routing.Store {
	t.Helper()
	initialize(t, blobs, routingKey)
	s, err := routing.New(context.Background(), blobs, routingKey, macKey)
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	return s
}

// initialize creates the routing object unless the test already has one.
func initialize(t *testing.T, blobs routing.Blobs, routingKey []byte) {
	t.Helper()
	if err := routing.Initialize(context.Background(), blobs, routingKey); err != nil && !errors.Is(err, routing.ErrObjectExists) {
		t.Fatalf("routing.Initialize: %v", err)
	}
}

// A lost object must stop the boot. Booting it as empty would answer 550 for every
// address and let the first write replace it.
func TestMissingObjectRefusesToBoot(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	if _, err := routing.New(context.Background(), blobs, routingKey, macKey); !errors.Is(err, routing.ErrNoObject) {
		t.Fatalf("err = %v, want ErrNoObject", err)
	}
	if objs, _ := blobs.List(context.Background(), ""); len(objs) != 0 {
		t.Fatalf("a refused boot wrote %d objects", len(objs))
	}
}

func TestInitializeCreatesAnObjectTheEdgeCanOpen(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	if err := routing.Initialize(context.Background(), blobs, routingKey); err != nil {
		t.Fatal(err)
	}
	if _, err := routing.New(context.Background(), blobs, routingKey, macKey); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeNeverReplacesAnObject(t *testing.T) {
	routingKey, _ := keys(t)
	blobs := newMemBlobs()
	if err := routing.Initialize(context.Background(), blobs, routingKey); err != nil {
		t.Fatal(err)
	}
	before, _ := blobs.Get(context.Background(), "edge/routing/current")
	if err := routing.Initialize(context.Background(), blobs, routingKey); !errors.Is(err, routing.ErrObjectExists) {
		t.Fatalf("err = %v, want ErrObjectExists", err)
	}
	after, _ := blobs.Get(context.Background(), "edge/routing/current")
	if !bytes.Equal(before, after) {
		t.Fatal("Initialize replaced an existing object")
	}
}

// failingGet stands in for an S3 permission error, where the object may well exist.
type failingGet struct{ routing.Blobs }

func (failingGet) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("s3: 403 Forbidden")
}

func TestInitializeStopsOnAReadError(t *testing.T) {
	routingKey, _ := keys(t)
	blobs := newMemBlobs()
	err := routing.Initialize(context.Background(), failingGet{blobs}, routingKey)
	if err == nil || errors.Is(err, routing.ErrObjectExists) {
		t.Fatalf("err = %v", err)
	}
	if objs, _ := blobs.List(context.Background(), ""); len(objs) != 0 {
		t.Fatalf("wrote %d objects after a read error", len(objs))
	}
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

// A record missing a key for a class resolves false for that class rather than
// returning a short slice as a public key.
func TestKeyProviderRejectsShortKey(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()

	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	rec := ks.record(id)
	rec.OwnerChangeKey = nil
	if err := s.Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.OwnerChangeKey(hex.EncodeToString(id)); ok {
		t.Fatal("a nil owner-change key must not resolve")
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
		Handle:          "worker@fountbox.com",
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
	if _, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: parentID, Handle: "worker@fountbox.com", Address: childAddr, DecryptionKey: child.dec.PublicKey().Bytes(), SigningKey: child.sign.Public().(ed25519.PublicKey), OwnerChangeKey: child.ownerChange.Public().(ed25519.PublicKey), PasskeyKey: child.passkey.Public().(ed25519.PublicKey)}); !errors.Is(err, routing.ErrHandleTaken) {
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

	// Resending the same version and list changes nothing.
	if err := s.SetOwners(ctx, id, 1, []string{"jane@smithcpa.com", "bob@smithcpa.com"}); err != nil {
		t.Fatalf("resend version 1: %v", err)
	}
	// Only a greater version can change the list.
	if err := s.SetOwners(ctx, id, 1, []string{"jane@smithcpa.com"}); !errors.Is(err, routing.ErrStaleVersion) {
		t.Fatalf("new list at version 1: err = %v, want ErrStaleVersion", err)
	}
	if snap, _ := s.Snapshot(id); len(snap.OwnerHashes) != 2 {
		t.Fatalf("list changed without a new version: %+v", snap)
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

func TestRotateKeys(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	rec := ks.record(id)
	rec.LicenseHash = []byte("lic-1")
	rec.EntitlementExp = 500
	if err := s.Upsert(ctx, rec); err != nil {
		t.Fatal(err)
	}

	nk := newKeyset(t)
	newMailbox := nk.mailbox.Public().(ed25519.PublicKey)
	hash, err := s.RotateKeys(ctx, id, routing.RotatedKeys{
		DecryptionKey:  nk.dec.PublicKey().Bytes(),
		SigningKey:     nk.sign.Public().(ed25519.PublicKey),
		MailboxKey:     newMailbox,
		OwnerChangeKey: nk.ownerChange.Public().(ed25519.PublicKey),
		PasskeyKey:     nk.passkey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	want := sha256.Sum256(newMailbox)
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("returned hash is not sha256 of the new mailbox key")
	}
	snap, _ := s.Snapshot(id)
	if !bytes.Equal(snap.MailboxKey, newMailbox) || !bytes.Equal(snap.SigningKey, nk.sign.Public().(ed25519.PublicKey)) {
		t.Fatal("keys did not rotate")
	}
	// License, entitlement, and id are untouched by a rotation.
	if !bytes.Equal(snap.LicenseHash, []byte("lic-1")) || snap.EntitlementExp != 500 || !bytes.Equal(snap.MailboxID, id) {
		t.Fatal("rotation disturbed license/entitlement/id")
	}
	if _, err := s.RotateKeys(ctx, make([]byte, 32), routing.RotatedKeys{}); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("err = %v, want ErrNoMailbox", err)
	}
}

// family is a handle with two workers.
func family(t *testing.T, s *routing.Store) (root, one, two []byte) {
	t.Helper()
	ctx := context.Background()
	root, err := s.Create(ctx, routing.NewMailbox{
		Address: "worker@fountbox.com", LicenseHash: []byte("lic-1"), EntitlementExp: 100,
		MailboxKey: newKeyset(t).mailbox.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	add := func(parent []byte, addr string) []byte {
		id, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: parent, Handle: "worker@fountbox.com", Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	one = add(root, "one.worker@fountbox.com")
	return root, one, add(one, "two.worker@fountbox.com") // a worker can add a sibling
}

func TestRenewingAnyAddressRenewsThemAll(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	root, one, two := family(t, s)
	if _, err := s.Create(context.Background(), routing.NewMailbox{Address: "other@fountbox.com", LicenseHash: []byte("lic-2"), EntitlementExp: 100}); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewEntitlement(context.Background(), two, []byte("lic-1"), 500); err != nil {
		t.Fatal(err)
	}
	s = reload(t, blobs, routingKey, macKey)
	for _, id := range [][]byte{root, one, two} {
		if snap, _ := s.Snapshot(id); snap.EntitlementExp != 500 {
			t.Fatalf("expiry = %d, want 500", snap.EntitlementExp)
		}
	}
	if snap, _ := s.Snapshot(s.MailboxID("other@fountbox.com")); snap.EntitlementExp != 100 {
		t.Fatal("renewal reached another mailbox")
	}
}

func reload(t *testing.T, blobs routing.Blobs, routingKey, macKey []byte) *routing.Store {
	t.Helper()
	s, err := routing.New(context.Background(), blobs, routingKey, macKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type refusingPut struct {
	routing.Blobs
	refuse *bool
}

func (b refusingPut) PutIfMatch(ctx context.Context, k string, d []byte, etag string) (string, error) {
	if *b.refuse {
		return "", errors.New("s3 down")
	}
	return b.Blobs.PutIfMatch(ctx, k, d, etag)
}

func TestFailedWriteLeavesEveryAddressUnchanged(t *testing.T) {
	routingKey, macKey := keys(t)
	refuse := false
	s := newStore(t, refusingPut{newMemBlobs(), &refuse}, routingKey, macKey)
	root, one, two := family(t, s)
	want, _ := s.Snapshot(root)

	refuse = true
	if err := s.RenewEntitlement(context.Background(), one, []byte("lic-1"), 500); err == nil {
		t.Fatal("renew survived a failed write")
	}
	if _, err := s.RotateKeys(context.Background(), one, routing.RotatedKeys{MailboxKey: []byte("new")}); err == nil {
		t.Fatal("rotate survived a failed write")
	}
	for _, id := range [][]byte{root, one, two} {
		snap, _ := s.Snapshot(id)
		if snap.EntitlementExp != 100 || !bytes.Equal(snap.MailboxKey, want.MailboxKey) {
			t.Fatalf("a failed write changed memory: %+v", snap)
		}
	}
}

func TestAKeyLogFailureStopsTheWrite(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	root, one, _ := family(t, s)
	want, _ := s.Snapshot(one)
	refuse := func(context.Context, []byte, []byte) error { return errors.New("log down") }

	if _, err := s.RotateKeys(ctx, root, routing.RotatedKeys{MailboxKey: []byte("new"), Log: refuse}); !errors.Is(err, routing.ErrKeyNotLogged) {
		t.Fatalf("rotate err = %v", err)
	}
	if snap, _ := s.Snapshot(one); !bytes.Equal(snap.MailboxKey, want.MailboxKey) {
		t.Fatal("a key went live without a log entry")
	}
	_, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: root, Handle: "worker@fountbox.com", Address: "three.worker@fountbox.com", Log: refuse})
	if !errors.Is(err, routing.ErrKeyNotLogged) {
		t.Fatalf("add err = %v", err)
	}
	if ok, _ := s.Available(ctx, "three.worker@fountbox.com"); !ok {
		t.Fatal("an address went live without a log entry")
	}
	_, err = s.Create(ctx, routing.NewMailbox{Address: "new@fountbox.com", Log: refuse})
	if !errors.Is(err, routing.ErrKeyNotLogged) {
		t.Fatalf("create err = %v", err)
	}
	if ok, _ := s.Available(ctx, "new@fountbox.com"); !ok {
		t.Fatal("a mailbox went live without a log entry")
	}
}

func TestAddAddressChecksTheHandleBeforeTheName(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	root, _, _ := family(t, s)
	other, err := s.Create(ctx, routing.NewMailbox{Address: "other@fountbox.com", LicenseHash: []byte("lic-2")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: other, Handle: "worker@fountbox.com", Address: "one.worker@fountbox.com"})
	if !errors.Is(err, routing.ErrNotHandle) {
		t.Fatalf("err = %v, want ErrNotHandle", err)
	}
	if _, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: root, Handle: "other@fountbox.com", Address: "x.other@fountbox.com"}); !errors.Is(err, routing.ErrNotHandle) {
		t.Fatalf("err = %v, want ErrNotHandle", err)
	}
}

func TestWorkerLimit(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	root, err := s.Create(ctx, routing.NewMailbox{Address: "worker@fountbox.com"})
	if err != nil {
		t.Fatal(err)
	}
	add := func(i int) error {
		_, err := s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: root, Handle: "worker@fountbox.com", Address: fmt.Sprintf("w%d.worker@fountbox.com", i)})
		return err
	}
	for i := range routing.MaxWorkers {
		if err := add(i); err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	if err := add(routing.MaxWorkers); !errors.Is(err, routing.ErrWorkerLimit) {
		t.Fatalf("err = %v, want ErrWorkerLimit", err)
	}
}

// Readers must not see a record while a rotation replaces it. Run under -race.
func TestReadersDontRaceWrites(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			if _, err := s.RotateKeys(ctx, id, routing.RotatedKeys{
				DecryptionKey: ks.dec.PublicKey().Bytes(),
				SigningKey:    ks.sign.Public().(ed25519.PublicKey),
			}); err != nil {
				t.Error(err)
			}
			s.RenewEntitlement(ctx, id, []byte("lic-hash"), 0)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			s.AddressKey(hex.EncodeToString(id))
			s.Resolve(ctx, "a@fountbox.com")
			s.Status(ctx, "a@fountbox.com")
		}
	}
}

// During a deploy two edges run at once. Neither may lose the other's change.
func TestTwoEdgesCantOverwriteEachOther(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	ctx := context.Background()
	oldEdge := newStore(t, blobs, routingKey, macKey)
	newEdge := reload(t, blobs, routingKey, macKey)

	if _, err := oldEdge.Create(ctx, routing.NewMailbox{Address: "a@fountbox.com", LicenseHash: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	b := routing.NewMailbox{Address: "b@fountbox.com", LicenseHash: []byte("b")}
	if _, err := newEdge.Create(ctx, b); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second writer: err = %v, want ErrConflict", err)
	}
	if ok, _ := newEdge.Available(ctx, "b@fountbox.com"); !ok {
		t.Fatal("a refused write stayed in memory")
	}
	if _, err := newEdge.Create(ctx, b); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := reload(t, blobs, routingKey, macKey)
	for _, addr := range []string{"a@fountbox.com", "b@fountbox.com"} {
		if ok, _ := final.Available(ctx, addr); ok {
			t.Fatalf("%s was lost", addr)
		}
	}
}

func TestEdgesNeverIssueTheSameSequence(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	ctx := context.Background()
	a := newStore(t, blobs, routingKey, macKey)
	id := a.MailboxID("a@fountbox.com")
	if err := a.Upsert(ctx, newKeyset(t).record(id)); err != nil {
		t.Fatal(err)
	}
	b := reload(t, blobs, routingKey, macKey)
	seen := map[uint64]bool{}
	for i := range 40 {
		s := a
		if i%3 != 0 {
			s = b
		}
		n, err := s.NextSequence(ctx, id)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("sequence %d issued twice", n)
		}
		seen[n] = true
	}
	if len(seen) < 10 {
		t.Fatalf("only %d issued, so this proved little", len(seen))
	}
}

// lostAnswer stores the object and then reports a failure, like a timeout after S3
// took the write.
type lostAnswer struct {
	routing.Blobs
	lose *bool
}

func (b lostAnswer) PutIfMatch(ctx context.Context, k string, d []byte, etag string) (string, error) {
	next, err := b.Blobs.PutIfMatch(ctx, k, d, etag)
	if *b.lose {
		return "", errors.New("timed out")
	}
	return next, err
}

func TestAWriteThatLandedWithoutAnAnswerDoesntReuseASequence(t *testing.T) {
	routingKey, macKey := keys(t)
	lose := false
	s := newStore(t, lostAnswer{newMemBlobs(), &lose}, routingKey, macKey)
	ctx := context.Background()
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, newKeyset(t).record(id)); err != nil {
		t.Fatal(err)
	}
	lose = true
	if _, err := s.NextSequence(ctx, id); err == nil {
		t.Fatal("want a failure")
	}
	lose = false
	if _, err := s.NextSequence(ctx, id); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	n, err := s.NextSequence(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("sequence = %d, want 2", n)
	}
}

// A running edge must not adopt an older object. It would reuse sequences and revive
// old keys. A restore stops the edges first.
func TestRunningEdgeRefusesAnOlderObject(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	ctx := context.Background()
	s := newStore(t, blobs, routingKey, macKey)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, newKeyset(t).record(id)); err != nil {
		t.Fatal(err)
	}
	old, err := blobs.Get(ctx, routing.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Put(ctx, routing.ObjectKey, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextSequence(ctx, id); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("first write: %v", err)
	}
	for range 2 {
		if _, err := s.NextSequence(ctx, id); !errors.Is(err, routing.ErrRolledBack) {
			t.Fatalf("err = %v, want ErrRolledBack", err)
		}
	}
	if err := s.Upsert(ctx, newKeyset(t).record(id)); !errors.Is(err, routing.ErrRolledBack) {
		t.Fatalf("Upsert err = %v", err)
	}
	// Restarting is the deliberate step.
	if _, err := reload(t, blobs, routingKey, macKey).NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
}

// countingGets reports reads, and can miss an object once, like a second operator
// racing Initialize.
type countingGets struct {
	routing.Blobs
	gets atomic.Int32
	miss atomic.Bool
}

func (b *countingGets) Get(ctx context.Context, k string) ([]byte, error) {
	if b.miss.Swap(false) {
		return nil, store.ErrNotFound
	}
	return b.Blobs.Get(ctx, k)
}

func (b *countingGets) GetVersioned(ctx context.Context, k string) ([]byte, string, error) {
	b.gets.Add(1)
	return b.Blobs.GetVersioned(ctx, k)
}

func TestInitializeCantReplaceAnObjectThatAppeared(t *testing.T) {
	routingKey, _ := keys(t)
	b := &countingGets{Blobs: newMemBlobs()}
	if err := routing.Initialize(context.Background(), b, routingKey); err != nil {
		t.Fatal(err)
	}
	b.miss.Store(true)
	if err := routing.Initialize(context.Background(), b, routingKey); !errors.Is(err, routing.ErrObjectExists) {
		t.Fatalf("err = %v, want ErrObjectExists", err)
	}
}

// One reload per lost race, so a store that has caught up stops paying for it.
func TestReloadsOnlyAfterALostRace(t *testing.T) {
	routingKey, macKey := keys(t)
	ctx := context.Background()
	b := &countingGets{Blobs: newMemBlobs()}
	s := newStore(t, b, routingKey, macKey)
	id := s.MailboxID("a@fountbox.com")
	if err := s.Upsert(ctx, newKeyset(t).record(id)); err != nil {
		t.Fatal(err)
	}
	other := reload(t, b, routingKey, macKey)
	if _, err := other.NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextSequence(ctx, id); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	before := b.gets.Load()
	for range 3 {
		if _, err := s.NextSequence(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if n := b.gets.Load() - before; n != 1 {
		t.Fatalf("%d reloads, want 1", n)
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
