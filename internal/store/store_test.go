package store

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/hpke"
)

// memDir is an in-memory Directory: one recipient -> one X25519 keypair, with a
// keyed-MAC mailbox id and a per-mailbox sequence counter.
type memDir struct {
	macKey []byte
	mu     sync.Mutex
	addrs  map[string]*ecdh.PrivateKey // lowercased recipient -> decryption key
	seq    map[string]uint64           // hex mailbox id -> last sequence
}

func newMemDir(macKey []byte) *memDir {
	return &memDir{macKey: macKey, addrs: map[string]*ecdh.PrivateKey{}, seq: map[string]uint64{}}
}

func (d *memDir) add(t *testing.T, recipient string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d.addrs[strings.ToLower(recipient)] = k
	return k
}

func (d *memDir) mailboxID(recipient string) []byte {
	m := hmac.New(sha256.New, d.macKey)
	m.Write([]byte(strings.ToLower(recipient)))
	return m.Sum(nil)
}

func (d *memDir) Resolve(_ context.Context, recipient string) (Address, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k, ok := d.addrs[strings.ToLower(recipient)]
	if !ok {
		return Address{}, ErrNoRecipient
	}
	return Address{MailboxID: d.mailboxID(recipient), PublicKey: k.PublicKey().Bytes()}, nil
}

func (d *memDir) NextSequence(_ context.Context, mailboxID []byte) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := string(mailboxID)
	d.seq[key]++
	return d.seq[key], nil
}

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
		return nil, ErrNotFound
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

func newSignKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestPutRoundTrip(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	recipientKey := dir.add(t, "worker@fountbox.com")
	blobs := newMemBlobs()
	sign, signPub := newSignKey(t)
	bootID := make([]byte, lenBootID)
	rand.Read(bootID)

	s := New(dir, blobs, sign, bootID)
	raw := []byte("From: owner@example.com\r\nSubject: hi\r\n\r\nrun the thing\r\n")
	id, err := s.Put(context.Background(), "worker@fountbox.com", "owner@example.com", raw)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// One object, keyed by mailbox id + edge id.
	wantKey := "edge/mail/" + hexStr(dir.mailboxID("worker@fountbox.com")) + "/" + id
	obj, ok := blobs.objs[wantKey]
	if !ok {
		t.Fatalf("no object at %s; have %v", wantKey, keysOf(blobs.objs))
	}

	// Signature verifies against the mail-sign public key.
	p, err := Parse(obj, signPub)
	if err != nil {
		t.Fatalf("Parse/verify: %v", err)
	}
	if p.Sequence != 1 {
		t.Fatalf("sequence = %d, want 1", p.Sequence)
	}
	if !bytes.Equal(p.BootID, bootID) {
		t.Fatal("boot id mismatch")
	}
	if !bytes.Equal(p.MailboxID, dir.mailboxID("worker@fountbox.com")) {
		t.Fatal("mailbox id mismatch")
	}
	if !bytes.Equal(p.PubKeyHash, pubKeyHash(recipientKey.PublicKey().Bytes())) {
		t.Fatal("pubkey hash mismatch")
	}

	// The ciphertext opens with the recipient key, bound to its own header.
	plain, err := hpke.Open(recipientKey.Bytes(), p.Enc, []byte(hpkeInfo), p.header(), p.Ct)
	if err != nil {
		t.Fatalf("hpke.Open: %v", err)
	}
	sender, recipient, body := unframe(t, plain)
	if sender != "owner@example.com" || recipient != "worker@fountbox.com" {
		t.Fatalf("envelope = %q/%q", sender, recipient)
	}
	if !bytes.Equal(body, raw) {
		t.Fatalf("raw mismatch:\n got %q\nwant %q", body, raw)
	}
}

// A tampered header must break the signature.
func TestParseRejectsTamper(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	sign, signPub := newSignKey(t)
	s := New(dir, blobs, sign, make([]byte, lenBootID))
	if _, err := s.Put(context.Background(), "a@fountbox.com", "x@y.com", []byte("body")); err != nil {
		t.Fatal(err)
	}
	var obj []byte
	for _, v := range blobs.objs {
		obj = v
	}
	obj[headerLen-1] ^= 0xff // flip a bit in the boot id
	if _, err := Parse(obj, signPub); err == nil {
		t.Fatal("tampered object must fail to verify")
	}
}

// Opening with the header AAD altered must fail, proving the ciphertext is
// bound to its header (Fount can't swap S3 objects, §9).
func TestCiphertextBoundToHeader(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	k := dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	sign, signPub := newSignKey(t)
	s := New(dir, blobs, sign, make([]byte, lenBootID))
	if _, err := s.Put(context.Background(), "a@fountbox.com", "x@y.com", []byte("body")); err != nil {
		t.Fatal(err)
	}
	var obj []byte
	for _, v := range blobs.objs {
		obj = v
	}
	p, err := Parse(obj, signPub)
	if err != nil {
		t.Fatal(err)
	}
	badHeader := append([]byte(nil), p.header()...)
	badHeader[len(badHeader)-1] ^= 0x01
	if _, err := hpke.Open(k.Bytes(), p.Enc, []byte(hpkeInfo), badHeader, p.Ct); err == nil {
		t.Fatal("open with altered header AAD must fail")
	}
}

func TestPutUnknownRecipient(t *testing.T) {
	dir := newMemDir(make([]byte, 32))
	s := New(dir, newMemBlobs(), mustSign(t), make([]byte, lenBootID))
	_, err := s.Put(context.Background(), "nobody@fountbox.com", "x@y.com", []byte("body"))
	if !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("err = %v, want ErrNoRecipient", err)
	}
}

func TestMailReaderRoundTrip(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	s := New(dir, blobs, mustSign(t), make([]byte, lenBootID))
	mr, ok := s.(MailReader)
	if !ok {
		t.Fatal("realStore must implement MailReader")
	}
	mbox := dir.mailboxID("a@fountbox.com")
	ctx := context.Background()

	id1, err := s.Put(ctx, "a@fountbox.com", "x@y.com", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.Put(ctx, "a@fountbox.com", "x@y.com", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	list, err := mr.List(ctx, mbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %d, want 2", len(list))
	}
	got := map[string]bool{list[0].ID: true, list[1].ID: true}
	if !got[id1] || !got[id2] {
		t.Fatalf("list ids %v missing %s/%s", got, id1, id2)
	}

	obj, err := mr.Get(ctx, mbox, id1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(obj) == 0 {
		t.Fatal("empty object")
	}

	// Another mailbox can't reach these objects.
	other := dir.mailboxID("b@fountbox.com")
	if _, err := mr.Get(ctx, other, id1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-mailbox Get err = %v, want ErrNotFound", err)
	}

	if err := mr.Delete(ctx, mbox, id1); err != nil {
		t.Fatal(err)
	}
	list, _ = mr.List(ctx, mbox)
	if len(list) != 1 || list[0].ID != id2 {
		t.Fatalf("after delete, list = %v, want [%s]", list, id2)
	}

	// A malformed id can't escape the prefix.
	if _, err := mr.Get(ctx, mbox, "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("traversal Get err = %v, want ErrNotFound", err)
	}
}

func mustSign(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func unframe(t *testing.T, p []byte) (sender, recipient string, raw []byte) {
	t.Helper()
	sl := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	sender = string(p[:sl])
	p = p[sl:]
	rl := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	recipient = string(p[:rl])
	return sender, recipient, p[rl:]
}

func hexStr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
