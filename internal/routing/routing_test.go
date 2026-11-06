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

func TestResolveAndKnown(t *testing.T) {
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

	known, _ := s.Known(ctx, addr)
	if !known {
		t.Fatal("Known should be true for a registered address")
	}

	if _, err := s.Resolve(ctx, "nobody@fountbox.com"); !errors.Is(err, store.ErrNoRecipient) {
		t.Fatalf("unknown Resolve err = %v, want ErrNoRecipient", err)
	}
	if known, _ := s.Known(ctx, "nobody@fountbox.com"); known {
		t.Fatal("Known should be false for an unregistered address")
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
