package store

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/hpke"
	"github.com/fount-labs/fount-mail-edge/internal/sendercheck"
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
	mod  map[string]time.Time // per-key last-modified, set by the sweep tests
}

func newMemBlobs() *memBlobs {
	return &memBlobs{objs: map[string][]byte{}, mod: map[string]time.Time{}}
}

func (b *memBlobs) Put(_ context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs[key] = append([]byte(nil), data...)
	return nil
}

// setMod stamps a stored object's modified time so a sweep test can age it.
func (b *memBlobs) setMod(key string, t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mod[key] = t
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

func (b *memBlobs) List(_ context.Context, prefix string) ([]Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Object
	for k, v := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, Object{Key: k, Size: int64(len(v)), Modified: b.mod[k]})
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

	var checked struct {
		raw        []byte
		recipient  string
		receivedAt time.Time
	}
	s := New(dir, blobs, sign, bootID, WithSenderCheck(func(_ context.Context, raw []byte, recipient string, at time.Time) []byte {
		checked.raw, checked.recipient, checked.receivedAt = raw, recipient, at
		return []byte(`{"v":1,"checked_by":"edge"}`)
	}))
	raw := []byte("From: owner@example.com\r\nSubject: hi\r\n\r\nrun the thing\r\n")
	in := Envelope{
		Sender: "owner@example.com", Recipient: "worker@fountbox.com",
		ClientIP: "2001:db8::25", ClientIPFrom: ClientIPProxy, HELO: "mail.example.com",
	}
	id, err := s.Put(context.Background(), in, raw)
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
	if p.Version != formatVersion {
		t.Fatalf("version = %d, want %d", p.Version, formatVersion)
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
	env, check, body, err := unframe(p.Version, plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(check) != `{"v":1,"checked_by":"edge"}` {
		t.Fatalf("check = %q", check)
	}
	if !bytes.Equal(checked.raw, raw) || checked.recipient != in.Recipient || !checked.receivedAt.Equal(p.ReceivedAt) {
		t.Fatalf("the checker got %q %q %v; object received_at %v", checked.raw, checked.recipient, checked.receivedAt, p.ReceivedAt)
	}
	if env != in {
		t.Fatalf("envelope = %+v, want %+v", env, in)
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
	if _, err := s.Put(context.Background(), Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body")); err != nil {
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
	if _, err := s.Put(context.Background(), Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body")); err != nil {
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
	_, err := s.Put(context.Background(), Envelope{Recipient: "nobody@fountbox.com", Sender: "x@y.com"}, []byte("body"))
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

	id1, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("two"))
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

// storedSize must equal what MarshalSigned actually produces, or the quota
// would be checked against a wrong figure. This pins the closed form against a
// real sealed object so an HPKE suite change (different enc/tag length) breaks
// the build instead of silently skewing accounting.
func TestStoredSizeMatchesMarshal(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	k := dir.add(t, "a@fountbox.com")
	for _, raw := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("m"), 5000)} {
		env := Envelope{Sender: "owner@example.com", Recipient: "a@fountbox.com", ClientIP: "192.0.2.1", ClientIPFrom: ClientIPProxy, HELO: "mx.example.com"}
		recipient := env.Recipient
		msg := &Message{
			EdgeID: make([]byte, lenEdgeID), MailboxID: dir.mailboxID(recipient),
			PubKeyHash: pubKeyHash(k.PublicKey().Bytes()), Sequence: 7, BootID: make([]byte, lenBootID),
		}
		check := []byte(`{"v":1,"checked_by":"edge","error":"x"}`)
		if err := msg.seal(k.PublicKey().Bytes(), env, check, raw); err != nil {
			t.Fatal(err)
		}
		got := int64(len(msg.MarshalSigned(mustSign(t))))
		if want := storedSize(env, len(check), len(raw)); got != want {
			t.Fatalf("raw=%d: storedSize=%d, MarshalSigned=%d", len(raw), want, got)
		}
	}
}

// Put refuses a message that would push a mailbox over its cap (§6), and does so
// without consuming a sequence number — a rejected message must leave no gap in
// the per-mailbox counter (§8). Room freed by a delete lets the next message in.
func TestPutEnforcesMailboxQuota(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	ctx := context.Background()

	// Cap at exactly two messages of this shape; the third must be refused.
	body := []byte("a short message body\r\n")
	one := storedSize(Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, len(noChecker), len(body))
	s := New(dir, blobs, mustSign(t), make([]byte, lenBootID), WithMaxMailboxBytes(2*one))
	mr := s.(MailReader)
	mbox := dir.mailboxID("a@fountbox.com")

	id1, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, body)
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if _, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, body); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	// Third exceeds the cap.
	if _, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, body); !errors.Is(err, ErrMailboxFull) {
		t.Fatalf("third Put err = %v, want ErrMailboxFull", err)
	}
	// The rejected Put consumed no sequence number: the next accepted message is
	// sequence 3, not 4.
	if err := mr.Delete(ctx, mbox, id1); err != nil {
		t.Fatal(err)
	}
	id, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, body)
	if err != nil {
		t.Fatalf("Put after freeing room: %v", err)
	}
	obj, _ := mr.Get(ctx, mbox, id)
	p, err := Parse(obj, s.(*realStore).sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if p.Sequence != 3 {
		t.Fatalf("sequence = %d, want 3 (a rejected Put must not burn a number)", p.Sequence)
	}
}

// List reports each object's stored size, so GET /mail can show it and the
// quota can sum it.
func TestListReportsSizes(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	s := New(dir, newMemBlobs(), mustSign(t), make([]byte, lenBootID))
	ctx := context.Background()
	body := []byte("hello world body\r\n")
	if _, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, body); err != nil {
		t.Fatal(err)
	}
	list, err := s.(MailReader).List(ctx, dir.mailboxID("a@fountbox.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list = %d, want 1", len(list))
	}
	if want := int(storedSize(Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, len(noChecker), len(body))); list[0].Size != want {
		t.Fatalf("Size = %d, want %d", list[0].Size, want)
	}
}

// The sweep expires mail past the retention window: too-old messages are
// deleted, each leaves a signed expiry record naming its sequence number (so the
// gap reads as an expiry, not withheld mail, §6/§8), and in-window mail is kept.
func TestRetentionSweep(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	sign, signPub := newSignKey(t)
	bootID := make([]byte, lenBootID)
	rand.Read(bootID)
	s := New(dir, blobs, sign, bootID, WithRetention(30*24*time.Hour))
	sw := s.(Sweeper)
	ctx := context.Background()
	mbox := dir.mailboxID("a@fountbox.com")
	mboxHex := hexStr(mbox)
	now := time.Now()

	// Three messages (sequences 1,2,3). Age the first two past the window.
	ids := make([]string, 3)
	for i := range ids {
		id, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		ids[i] = id
	}
	blobs.setMod("edge/mail/"+mboxHex+"/"+ids[0], now.Add(-40*24*time.Hour))
	blobs.setMod("edge/mail/"+mboxHex+"/"+ids[1], now.Add(-31*24*time.Hour))
	blobs.setMod("edge/mail/"+mboxHex+"/"+ids[2], now.Add(-1*24*time.Hour)) // fresh

	res, err := sw.Sweep(ctx, now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Expired != 2 {
		t.Fatalf("swept %d, want 2", res.Expired)
	}

	// The two old messages are gone, the fresh one remains.
	if _, ok := blobs.objs["edge/mail/"+mboxHex+"/"+ids[0]]; ok {
		t.Fatal("expired message 0 still present")
	}
	if _, ok := blobs.objs["edge/mail/"+mboxHex+"/"+ids[2]]; !ok {
		t.Fatal("in-window message 2 was deleted")
	}

	// A verifiable expiry record exists for each expired sequence (1 and 2).
	for seq := uint64(1); seq <= 2; seq++ {
		body, ok := blobs.objs[expiryKey(mboxHex, seq)]
		if !ok {
			t.Fatalf("no expiry record for sequence %d", seq)
		}
		rec, err := ParseExpiryRecord(body, signPub)
		if err != nil {
			t.Fatalf("expiry record %d: %v", seq, err)
		}
		if rec.Sequence != seq || rec.MailboxID != mboxHex || rec.BootID != hexStr(bootID) {
			t.Fatalf("expiry record = %+v", rec)
		}
		if rec.ExpiredAt != now.UTC().Unix() {
			t.Fatalf("expiry record %d expired_at = %d, want %d", seq, rec.ExpiredAt, now.UTC().Unix())
		}
	}
	// No expiry record for the message that wasn't expired.
	if _, ok := blobs.objs[expiryKey(mboxHex, 3)]; ok {
		t.Fatal("wrote an expiry record for an in-window message")
	}

	// A tampered expiry record must fail to verify.
	body := blobs.objs[expiryKey(mboxHex, 1)]
	body[0] ^= 0xff
	if _, err := ParseExpiryRecord(body, signPub); err == nil {
		t.Fatal("tampered expiry record verified")
	}
}

// Sweep never deletes a message it can't date, and a zero/negative retention
// disables it entirely.
func TestSweepSkipsUndatableAndDisabled(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	ctx := context.Background()
	now := time.Now()

	// Undatable: object stored but no modified time -> never swept.
	blobs := newMemBlobs()
	s := New(dir, blobs, mustSign(t), make([]byte, lenBootID), WithRetention(time.Hour))
	if _, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if res, err := s.(Sweeper).Sweep(ctx, now); err != nil || res.Expired != 0 {
		t.Fatalf("sweep of undatable objects: n=%d err=%v, want 0/nil", res.Expired, err)
	}

	// Disabled: even a provably-old object is left alone.
	blobs2 := newMemBlobs()
	s2 := New(dir, blobs2, mustSign(t), make([]byte, lenBootID), WithRetention(0))
	id, err := s2.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	blobs2.setMod("edge/mail/"+hexStr(dir.mailboxID("a@fountbox.com"))+"/"+id, now.Add(-365*24*time.Hour))
	if res, err := s2.(Sweeper).Sweep(ctx, now); err != nil || res.Expired != 0 {
		t.Fatalf("disabled sweep: n=%d err=%v, want 0/nil", res.Expired, err)
	}
	if len(blobs2.objs) != 1 {
		t.Fatalf("disabled sweep deleted objects: %d remain, want 1", len(blobs2.objs))
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

// The boot and key logs go to their own bucket, under the keys §4 lays out. GET
// /boots still reads the mail bucket, because the edge can't read the log.
func TestLogsUseTheirOwnBucket(t *testing.T) {
	macKey := []byte("mac")
	dir := newMemDir(macKey)
	blobs, logs := newMemBlobs(), newMemBlobs()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootID := bytes.Repeat([]byte{9}, 16)
	st := New(dir, blobs, priv, bootID, WithLogBlobs(logs))
	ctx := context.Background()

	if err := st.(BootStore).WriteBoot(ctx); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(bootID)
	if logs.objs["boots/"+id] == nil {
		t.Fatal("boot not in the log bucket")
	}
	if blobs.objs["edge/boots/"+id] == nil {
		t.Fatal("boot not in the mail bucket")
	}
	if _, err := st.(BootStore).ReadBoot(ctx, id); err != nil {
		t.Fatalf("ReadBoot: %v", err)
	}

	mid, hash := "ab", bytes.Repeat([]byte{1}, 32)
	if err := st.(KeyLog).AppendMailboxKeyHash(ctx, mid, hash, 42); err != nil {
		t.Fatal(err)
	}
	raw := logs.objs["mailboxes/"+mid+"/"+hex.EncodeToString(hash)]
	var entry struct {
		KeyHash string `json:"key_hash"`
		At      int64  `json:"at"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("key log entry: %v", err)
	}
	if entry.KeyHash != hex.EncodeToString(hash) || entry.At != 42 {
		t.Fatalf("entry = %+v", entry)
	}
	for k := range blobs.objs {
		if strings.HasPrefix(k, "mailboxes/") {
			t.Fatalf("key log leaked into the mail bucket: %s", k)
		}
	}
}

// A failed log write is returned, so a creation or recovery that must log first
// fails closed, and the boot record is still tried in both places.
func TestLogFailuresAreReported(t *testing.T) {
	blobs := newMemBlobs()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	bootID := make([]byte, 16)
	st := New(newMemDir([]byte("mac")), blobs, priv, bootID, WithLogBlobs(failingLog{newMemBlobs()}))
	ctx := context.Background()
	if err := st.(KeyLog).AppendMailboxKeyHash(ctx, "ab", []byte{1}, 1); err == nil {
		t.Fatal("key log failure swallowed")
	}
	if err := st.(BootStore).WriteBoot(ctx); err == nil {
		t.Fatal("boot log failure swallowed")
	}
	if blobs.objs["edge/boots/"+hex.EncodeToString(bootID)] == nil {
		t.Fatal("mail-bucket copy skipped after a log failure")
	}
}

type failingLog struct{ *memBlobs }

func (failingLog) Put(context.Context, string, []byte) error { return errors.New("log down") }

// sweepBox is a store with one address, plus what a test needs to age its mail.
func sweepBox(t *testing.T, blobs Blobs) (Store, *memDir) {
	t.Helper()
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	bootID := make([]byte, lenBootID)
	rand.Read(bootID)
	return New(dir, blobs, mustSign(t), bootID, WithRetention(time.Hour)), dir
}

// Mail outlives the boot that stored it, so a sweep has to recognise earlier boots.
func TestSweepExpiresMailFromAnEarlierBoot(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	earlier, dir := sweepBox(t, blobs)
	if err := earlier.(BootStore).WriteBoot(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := earlier.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	mbox := hexStr(dir.mailboxID("a@fountbox.com"))
	key := "edge/mail/" + mbox + "/" + id
	now := time.Now()
	blobs.setMod(key, now.Add(-2*time.Hour))
	parsed, err := Parse(blobs.objs[key], earlier.(*realStore).sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	current := New(dir, blobs, mustSign(t), bytes.Repeat([]byte{7}, lenBootID), WithRetention(time.Hour))
	res, err := current.(Sweeper).Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if res != (SweepResult{Expired: 1}) {
		t.Fatalf("result = %+v", res)
	}
	if _, ok := blobs.objs[key]; ok {
		t.Fatal("old mail is still stored, and still counts against the quota")
	}
	rec, err := ParseExpiryRecord(blobs.objs[expiryKey(mbox, parsed.Sequence)], current.(*realStore).sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if rec.MessageBoot != hexStr(parsed.BootID) || rec.BootID == rec.MessageBoot || rec.Reason != ReasonExpired {
		t.Fatalf("record = %+v", rec)
	}
}

func TestSweepSkipsWhatItCantVerify(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	blobs := newMemBlobs()
	earlier, dir := sweepBox(t, blobs)
	mbox := hexStr(dir.mailboxID("a@fountbox.com"))
	put := func() string {
		t.Helper()
		id, err := earlier.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
		if err != nil {
			t.Fatal(err)
		}
		return "edge/mail/" + mbox + "/" + id
	}
	noRecord := put() // earlier never wrote its boot record
	if err := blobs.Put(ctx, "edge/mail/"+mbox+"/junk", []byte("not a message")); err != nil {
		t.Fatal(err)
	}
	blobs.setMod(noRecord, now.Add(-2*time.Hour))
	blobs.setMod("edge/mail/"+mbox+"/junk", now.Add(-2*time.Hour))

	current := New(dir, blobs, mustSign(t), bytes.Repeat([]byte{7}, lenBootID), WithRetention(time.Hour))
	res, err := current.(Sweeper).Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if res != (SweepResult{Skipped: 2}) {
		t.Fatalf("result = %+v", res)
	}
	if _, ok := blobs.objs[noRecord]; !ok {
		t.Fatal("deleted a message it couldn't verify")
	}

	// A record that names the wrong key verifies nothing either.
	raw, _ := json.Marshal(Boot{SigningKey: mustSign(t).Public().(ed25519.PublicKey)})
	bootID, _ := bootIDOf(blobs.objs[noRecord])
	if err := blobs.Put(ctx, bootObjectKey(hexStr(bootID)), raw); err != nil {
		t.Fatal(err)
	}
	if res, err := current.(Sweeper).Sweep(ctx, now); err != nil || res != (SweepResult{Skipped: 2}) {
		t.Fatalf("result = %+v, %v", res, err)
	}

	// S3 holds the record, so a short key can't be allowed to crash the sweep.
	raw, _ = json.Marshal(Boot{SigningKey: []byte{1, 2, 3}})
	if err := blobs.Put(ctx, bootObjectKey(hexStr(bootID)), raw); err != nil {
		t.Fatal(err)
	}
	if res, err := current.(Sweeper).Sweep(ctx, now); err != nil || res != (SweepResult{Skipped: 2}) {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

// A real message filed under another mailbox must not write that mailbox's record.
func TestSweepSkipsAMessageInTheWrongPlace(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	blobs := newMemBlobs()
	s, dir := sweepBox(t, blobs)
	id, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	mbox := hexStr(dir.mailboxID("a@fountbox.com"))
	moved := "edge/mail/" + strings.Repeat("ab", 32) + "/" + id
	blobs.objs[moved] = blobs.objs["edge/mail/"+mbox+"/"+id]
	delete(blobs.objs, "edge/mail/"+mbox+"/"+id)
	blobs.setMod(moved, now.Add(-2*time.Hour))
	if res, err := s.(Sweeper).Sweep(ctx, now); err != nil || res != (SweepResult{Skipped: 1}) {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if _, ok := blobs.objs[expiryKey(mbox, 1)]; ok {
		t.Fatal("wrote an expiry record for a moved message")
	}
}

type mailDown struct {
	*memBlobs
	logDown bool
}

func (b mailDown) Put(ctx context.Context, k string, d []byte) error {
	if strings.HasPrefix(k, "edge/mail/") || b.logDown {
		return errors.New("s3 down")
	}
	return b.memBlobs.Put(ctx, k, d)
}

func TestFailedWriteVoidsItsSequence(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	s, dir := sweepBox(t, mailDown{memBlobs: blobs})
	if _, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body")); err == nil {
		t.Fatal("Put hid a failed write")
	}
	mbox := hexStr(dir.mailboxID("a@fountbox.com"))
	rec, err := ParseExpiryRecord(blobs.objs[expiryKey(mbox, 1)], s.(*realStore).sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("no void record: %v", err)
	}
	if rec.Reason != ReasonVoid || rec.Sequence != 1 || rec.MailboxID != mbox {
		t.Fatalf("record = %+v", rec)
	}
}

func TestFailedVoidIsReportedWithTheCause(t *testing.T) {
	blobs := mailDown{memBlobs: newMemBlobs(), logDown: true}
	s, _ := sweepBox(t, blobs)
	if _, err := s.Put(context.Background(), Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body")); err == nil || strings.Count(err.Error(), "s3 down") != 2 {
		t.Fatalf("err = %v", err)
	}
}

type ctxCheckingBlobs struct{ *memBlobs }

func (b ctxCheckingBlobs) Put(ctx context.Context, k string, d []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.memBlobs.Put(ctx, k, d)
}

type cancelOnSequence struct {
	Directory
	cancel context.CancelFunc
	seen   error
}

func (d *cancelOnSequence) NextSequence(ctx context.Context, id []byte) (uint64, error) {
	d.cancel()
	d.seen = ctx.Err()
	return d.Directory.NextSequence(ctx, id)
}

// Shutdown cancels the session, and a sequence that's been spent has to reach S3.
func TestSessionEndingDoesntStopTheWrite(t *testing.T) {
	macKey := make([]byte, 32)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &cancelOnSequence{Directory: dir, cancel: cancel}
	blobs := ctxCheckingBlobs{newMemBlobs()}
	s := New(d, blobs, mustSign(t), make([]byte, lenBootID))
	id, err := s.Put(ctx, Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("body"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := blobs.objs["edge/mail/"+hexStr(dir.mailboxID("a@fountbox.com"))+"/"+id]; !ok {
		t.Fatal("message not stored")
	}
	if d.seen != nil {
		t.Fatalf("the sequence write inherited the session's end: %v", d.seen)
	}
}

func TestGaps(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	s, dir := sweepBox(t, blobs)
	mailbox := dir.mailboxID("a@fountbox.com")
	mbox := hexStr(mailbox)
	for seq := uint64(1); seq <= MaxGaps+5; seq++ {
		if err := blobs.Put(ctx, expiryKey(mbox, seq), []byte(strconv.FormatUint(seq, 10))); err != nil {
			t.Fatal(err)
		}
	}
	if err := blobs.Put(ctx, expiryPrefix(mbox)+"not-a-number", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Put(ctx, expiryKey(strings.Repeat("ab", 32), 1), []byte("other mailbox")); err != nil {
		t.Fatal(err)
	}
	g := s.(GapReader)
	first, err := g.Gaps(ctx, mailbox, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != MaxGaps || string(first[0]) != "1" || string(first[9]) != "10" {
		t.Fatalf("got %d, first %q, tenth %q", len(first), first[0], first[9])
	}
	rest, err := g.Gaps(ctx, mailbox, MaxGaps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 5 || string(rest[0]) != strconv.Itoa(MaxGaps+1) {
		t.Fatalf("rest = %d", len(rest))
	}
}

// An id comes from the request path, so it can't be allowed to leave its prefix.
func TestCraftedIDsStayInTheirPrefix(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	s, dir := sweepBox(t, blobs)
	mailbox := dir.mailboxID("a@fountbox.com")
	const crafted = "../../routing/current"
	mailKey := mailObjectKey(mailbox, crafted)
	bootKey := bootObjectKey(crafted)
	blobs.objs[mailKey] = []byte("secret")
	blobs.objs[bootKey] = []byte(`{"boot_id":"x"}`)

	r := s.(MailReader)
	if _, err := r.Get(ctx, mailbox, crafted); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get err = %v", err)
	}
	if err := r.Delete(ctx, mailbox, crafted); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete err = %v", err)
	}
	if _, ok := blobs.objs[mailKey]; !ok {
		t.Fatal("Delete reached outside the mailbox")
	}
	if _, err := s.(BootStore).ReadBoot(ctx, crafted); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadBoot err = %v", err)
	}
}

// noChecker is what a store with no checker seals.
var noChecker = sendercheck.Failed("the edge has no sender checker")

// The version 3 framing, byte for byte. The broker decodes this layout by hand, so
// a change here must be a new version.
func TestPlaintextV3Layout(t *testing.T) {
	got, err := messagePlaintext(Envelope{
		Sender: "a@b.c", Recipient: "w@f.co",
		ClientIP: "192.0.2.1", ClientIPFrom: ClientIPProxy, HELO: "mx.b.c",
	}, []byte("CHK"), []byte("RAW"))
	if err != nil {
		t.Fatal(err)
	}
	want := "\x00\x05a@b.c" + "\x00\x06w@f.co" + "\x01" + "\x09192.0.2.1" + "\x06mx.b.c" + "\x00\x00\x00\x03CHK" + "RAW"
	if string(got) != want {
		t.Fatalf("framing = %q\n    want %q", got, want)
	}
	none, err := messagePlaintext(Envelope{Sender: "", Recipient: "w@f.co"}, []byte("C"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "\x00\x00" + "\x00\x06w@f.co" + "\x00" + "\x00" + "\x00" + "\x00\x00\x00\x01C"; string(none) != want {
		t.Fatalf("empty framing = %q, want %q", none, want)
	}
	for _, c := range [][]byte{nil, {}, make([]byte, maxCheckBytes+1)} {
		if _, err := messagePlaintext(Envelope{Recipient: "w@f.co"}, c, nil); !errors.Is(err, errCheck) {
			t.Errorf("check of %d bytes: %v", len(c), err)
		}
	}
}

// The store seals a check even when there's no checker, or the checker returns
// nothing usable: never an empty one.
func TestPutAlwaysSealsACheck(t *testing.T) {
	for name, c := range map[string]SenderCheck{
		"none":  nil,
		"empty": func(context.Context, []byte, string, time.Time) []byte { return nil },
		"huge":  func(context.Context, []byte, string, time.Time) []byte { return make([]byte, maxCheckBytes+1) },
	} {
		macKey := make([]byte, 32)
		rand.Read(macKey)
		dir := newMemDir(macKey)
		k := dir.add(t, "a@fountbox.com")
		blobs := newMemBlobs()
		sign, signPub := newSignKey(t)
		var opts []Option
		if c != nil {
			opts = append(opts, WithSenderCheck(c))
		}
		s := New(dir, blobs, sign, make([]byte, lenBootID), opts...)
		if _, err := s.Put(context.Background(), Envelope{Recipient: "a@fountbox.com", Sender: "x@y.com"}, []byte("b")); err != nil {
			t.Fatal(err)
		}
		for _, obj := range blobs.objs {
			p, err := Parse(obj, signPub)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := hpke.Open(k.Bytes(), p.Enc, []byte(hpkeInfo), p.header(), p.Ct)
			if err != nil {
				t.Fatal(err)
			}
			_, check, _, err := unframe(p.Version, plain)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(check, &m); err != nil || m["v"] != float64(1) || m["checked_by"] != "edge" || m["error"] == "" || len(m) != 3 {
				t.Errorf("%s: check %s", name, check)
			}
		}
	}
}

// Mail stored as version 2, before the sender check, still reads, with no check.
func TestVersion2ObjectStillReads(t *testing.T) {
	plain := "\x00\x05a@b.c" + "\x00\x06w@f.co" + "\x01" + "\x09192.0.2.1" + "\x06mx.b.c" + "RAW"
	env, check, raw, err := unframe(formatV2, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if check != nil || string(raw) != "RAW" || env.HELO != "mx.b.c" || env.ClientIP != "192.0.2.1" {
		t.Fatalf("%+v %q %q", env, check, raw)
	}
	sign, signPub := newSignKey(t)
	msg := &Message{Version: formatV2, EdgeID: make([]byte, lenEdgeID), MailboxID: make([]byte, lenMailboxID),
		PubKeyHash: make([]byte, lenPubKeyHash), BootID: make([]byte, lenBootID), Enc: make([]byte, 32)}
	if _, err := Parse(msg.MarshalSigned(sign), signPub); err != nil {
		t.Fatalf("Parse refused version 2: %v", err)
	}
	if err := msg.seal(make([]byte, 32), Envelope{}, []byte("c"), nil); err == nil {
		t.Fatal("sealed a version 2 object")
	}
}

// Mail stored before version 2 still verifies and opens, with no client IP.
func TestVersion1ObjectStillReads(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	k := dir.add(t, "a@fountbox.com")
	sign, signPub := newSignKey(t)
	msg := &Message{
		Version: formatV1,
		EdgeID:  make([]byte, lenEdgeID), MailboxID: dir.mailboxID("a@fountbox.com"),
		PubKeyHash: pubKeyHash(k.PublicKey().Bytes()), Sequence: 3, BootID: make([]byte, lenBootID),
		ReceivedAt: time.UnixMilli(1_700_000_000_000),
	}
	v1 := "\x00\x07x@y.com" + "\x00\x0ea@fountbox.com" + "body"
	enc, ct, err := hpke.Seal(k.PublicKey().Bytes(), []byte(hpkeInfo), msg.header(), []byte(v1))
	if err != nil {
		t.Fatal(err)
	}
	msg.Enc, msg.Ct = enc, ct
	obj := msg.MarshalSigned(sign)
	if obj[lenMagic] != formatV1 {
		t.Fatalf("version byte = %d", obj[lenMagic])
	}

	p, err := Parse(obj, signPub)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plain, err := hpke.Open(k.Bytes(), p.Enc, []byte(hpkeInfo), p.header(), p.Ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	env, check, raw, err := unframe(p.Version, plain)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Envelope{Sender: "x@y.com", Recipient: "a@fountbox.com"}); env != want || string(raw) != "body" || check != nil {
		t.Fatalf("v1 = %+v %q", env, raw)
	}
}

func TestParseRejectsUnknownVersion(t *testing.T) {
	sign, signPub := newSignKey(t)
	msg := &Message{Version: 4, EdgeID: make([]byte, lenEdgeID), MailboxID: make([]byte, lenMailboxID),
		PubKeyHash: make([]byte, lenPubKeyHash), BootID: make([]byte, lenBootID), Enc: make([]byte, 32)}
	if _, err := Parse(msg.MarshalSigned(sign), signPub); err == nil {
		t.Fatal("Parse accepted version 4")
	}
}

// Put stores nothing, and spends no sequence number, for an envelope it can't frame.
func TestPutRefusesUnframeableEnvelope(t *testing.T) {
	macKey := make([]byte, 32)
	rand.Read(macKey)
	dir := newMemDir(macKey)
	dir.add(t, "a@fountbox.com")
	blobs := newMemBlobs()
	sign, _ := newSignKey(t)
	s := New(dir, blobs, sign, make([]byte, lenBootID))
	for name, env := range map[string]Envelope{
		"long helo":    {Recipient: "a@fountbox.com", HELO: strings.Repeat("h", maxHELOBytes+1)},
		"long ip":      {Recipient: "a@fountbox.com", ClientIP: strings.Repeat("1", maxClientIPBytes+1), ClientIPFrom: ClientIPProxy},
		"ip no source": {Recipient: "a@fountbox.com", ClientIP: "192.0.2.1"},
		"source no ip": {Recipient: "a@fountbox.com", ClientIPFrom: ClientIPProxy},
	} {
		if _, err := s.Put(context.Background(), env, []byte("body")); err == nil {
			t.Errorf("%s: Put accepted it", name)
		}
	}
	if len(blobs.objs) != 0 {
		t.Fatalf("stored %d objects", len(blobs.objs))
	}
}

// unframe must reject truncations rather than panic or invent fields.
func TestUnframeRejectsTruncation(t *testing.T) {
	full, err := messagePlaintext(Envelope{Sender: "a@b.c", Recipient: "w@f.co", ClientIP: "192.0.2.1", ClientIPFrom: ClientIPProxy, HELO: "mx.b.c"}, []byte(`{"v":1}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(full); n++ {
		if _, _, _, err := unframe(formatVersion, full[:n]); err == nil {
			t.Fatalf("accepted %d of %d bytes", n, len(full))
		}
	}
	if _, _, _, err := unframe(formatVersion, full); err != nil {
		t.Fatal(err)
	}
}
