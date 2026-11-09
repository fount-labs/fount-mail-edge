package routing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type ownerFixture struct {
	s      *routing.Store
	blobs  *memBlobs
	rk, mk []byte
	clk    *clock
	id     []byte
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	t.Helper()
	f := &ownerFixture{blobs: newMemBlobs(), clk: &clock{time.Unix(1_800_000_000, 0)}}
	f.rk, f.mk = keys(t)
	f.s = f.reload(t)
	f.id = f.s.MailboxID("smith@fountbox.com")
	if err := f.s.Upsert(context.Background(), newKeyset(t).record(f.id)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *ownerFixture) reload(t *testing.T) *routing.Store {
	t.Helper()
	return newStore(t, f.blobs, f.rk, f.mk, routing.WithClock(f.clk.now))
}

func (f *ownerFixture) set(t *testing.T, id []byte, version uint64, owners ...string) {
	t.Helper()
	if err := f.s.SetOwners(context.Background(), id, version, owners); err != nil {
		t.Fatalf("SetOwners v%d %v: %v", version, owners, err)
	}
}

func pending(t *testing.T, s *routing.Store) []routing.PendingNotice {
	t.Helper()
	n, err := s.PendingNotices("@fountbox.com")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func find(ns []routing.PendingNotice, kind routing.NoticeKind, to string) (routing.PendingNotice, bool) {
	for _, n := range ns {
		if n.Kind == kind && n.To == to {
			return n, true
		}
	}
	return routing.PendingNotice{}, false
}

// prove replies to the owner's proof mail through SMTP's store, the way intake does.
func (f *ownerFixture) prove(t *testing.T, owner string) {
	t.Helper()
	n, ok := find(pending(t, f.s), routing.NoticeOwnerProof, owner)
	if !ok {
		t.Fatalf("no proof mail queued for %s", owner)
	}
	if st, _ := f.s.Status(context.Background(), n.ReplyTo); st != smtp.RecipientAccepting {
		t.Fatalf("RCPT %s: %v, want accepting", n.ReplyTo, st)
	}
	next := &countingStorer{}
	id, err := f.s.ProofIntake(next).Put(context.Background(), store.Envelope{Recipient: n.ReplyTo}, []byte("yes"))
	if err != nil || id != "owner-proof" {
		t.Fatalf("proof reply: %q %v", id, err)
	}
	if next.n != 0 {
		t.Fatal("a proof reply was stored as mail")
	}
}

type countingStorer struct{ n int }

func (c *countingStorer) Put(context.Context, store.Envelope, []byte) (string, error) {
	c.n++
	return "stored", nil
}

func (f *ownerFixture) hash(addr string) []byte { return f.s.MailboxID(addr) }

func TestFirstOwnerProvesWithoutWaiting(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "Jane@Example.com")

	ns := pending(t, f.s)
	if len(ns) != 1 || ns[0].Kind != routing.NoticeOwnerProof || ns[0].To != "jane@example.com" {
		t.Fatalf("queued %+v, want one proof mail to jane", ns)
	}
	if !strings.HasPrefix(ns[0].ReplyTo, "fount+") || !strings.HasSuffix(ns[0].ReplyTo, "@fountbox.com") {
		t.Fatalf("reply address %q", ns[0].ReplyTo)
	}
	if f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("proven before the reply")
	}

	f.prove(t, "jane@example.com")
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("the first owner waits, but nobody could be told about them")
	}
	if ns := pending(t, f.s); len(ns) != 0 {
		t.Fatalf("a proved owner's proof mail is still queued: %+v", ns)
	}
	// It lasts across a reload, and a second reply doesn't bounce.
	f.s = f.reload(t)
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("proof lost on reload")
	}
}

func TestProofAddressRefusesAWrongToken(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	for _, rcpt := range []string{
		"fount+" + strings.Repeat("a", 26) + "@fountbox.com",
		"fount+short@fountbox.com",
		"fount@fountbox.com",
	} {
		if st, _ := f.s.Status(context.Background(), rcpt); st != smtp.RecipientUnknown {
			t.Errorf("RCPT %s: %v, want unknown", rcpt, st)
		}
		if _, err := f.s.ProofIntake(&countingStorer{}).Put(context.Background(), store.Envelope{Recipient: rcpt}, nil); strings.HasPrefix(rcpt, "fount+") && !errors.Is(err, store.ErrNoRecipient) {
			t.Errorf("Put %s: %v, want ErrNoRecipient", rcpt, err)
		}
	}
	if f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("a wrong token proved an owner")
	}
}

func TestNewOwnerWaitsAndIsAnnounced(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	f.prove(t, "jane@example.com")

	f.set(t, f.id, 2, "jane@example.com", "bob@example.com")
	ns := pending(t, f.s)
	n, ok := find(ns, routing.NoticeNewOwner, "jane@example.com")
	if !ok || n.About != "bob@example.com" || !bytes.Equal(n.Worker, f.id) {
		t.Fatalf("jane wasn't told about bob: %+v", ns)
	}
	f.prove(t, "bob@example.com")
	if f.s.OwnerProven(f.id, f.hash("bob@example.com")) {
		t.Fatal("a new owner was mailable before the wait ended")
	}
	f.clk.t = f.clk.t.Add(routing.OwnerWait)
	if !f.s.OwnerProven(f.id, f.hash("bob@example.com")) {
		t.Fatal("still waiting after OwnerWait")
	}
}

func TestRemovedOwnerIsTold(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	f.prove(t, "jane@example.com")

	// Removing every owner and then adding one: jane hears about both, and the
	// newcomer isn't a first owner.
	f.set(t, f.id, 2)
	f.set(t, f.id, 3, "mallory@example.com")
	ns := pending(t, f.s)
	if _, ok := find(ns, routing.NoticeOwnerRemoved, "jane@example.com"); !ok {
		t.Fatalf("jane wasn't told she was removed: %+v", ns)
	}
	f.prove(t, "mallory@example.com")
	if f.s.OwnerProven(f.id, f.hash("mallory@example.com")) {
		t.Fatal("an owner added after emptying the list skipped the wait")
	}
	if f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("a removed owner is still proven")
	}
}

func TestNewOwnerDailyCap(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	owners := []string{"jane@example.com"}
	for i := range routing.DefaultNewOwnersPerDay {
		owners = append(owners, fmt.Sprintf("o%d@example.com", i))
		f.set(t, f.id, uint64(i+2), owners...)
	}
	over := append(owners, "one-too-many@example.com")
	if err := f.s.SetOwners(context.Background(), f.id, 99, over); !errors.Is(err, routing.ErrOwnerLimit) {
		t.Fatalf("over the cap: %v, want ErrOwnerLimit", err)
	}
	// Removing an owner doesn't free a slot, and re-adding one is new again.
	if err := f.s.SetOwners(context.Background(), f.id, 99, owners[:1]); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetOwners(context.Background(), f.id, 100, owners[:2]); !errors.Is(err, routing.ErrOwnerLimit) {
		t.Fatalf("cap reset by removing an owner: %v", err)
	}
	f.clk.t = f.clk.t.Add(24 * time.Hour)
	if err := f.s.SetOwners(context.Background(), f.id, 100, owners[:2]); err != nil {
		t.Fatalf("a day later: %v", err)
	}
}

func TestWorkerCopiesOwnersWithoutANewOwner(t *testing.T) {
	f := newOwnerFixture(t)
	ctx := context.Background()
	f.set(t, f.id, 1, "jane@example.com")
	f.prove(t, "jane@example.com")
	child := newKeyset(t)
	wid, err := f.s.AddAddress(ctx, routing.NewAddress{
		ParentMailboxID: f.id, Handle: "smith@fountbox.com", Address: "ap.smith@fountbox.com",
		DecryptionKey: child.dec.PublicKey().Bytes(), SigningKey: child.sign.Public().(ed25519.PublicKey),
		OwnerChangeKey: child.ownerChange.Public().(ed25519.PublicKey), PasskeyKey: child.passkey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.s.OwnerProven(wid, f.hash("jane@example.com")) {
		t.Fatal("jane is proven for a worker she doesn't own yet")
	}
	f.set(t, wid, 1, "jane@example.com")
	if !f.s.OwnerProven(wid, f.hash("jane@example.com")) {
		t.Fatal("copying a proved owner to a new worker made them new again")
	}
	if ns := pending(t, f.s); len(ns) != 0 {
		t.Fatalf("copying an owner queued %+v", ns)
	}
	// Taking jane off the handle keeps her as the worker's owner.
	f.set(t, f.id, 2)
	if !f.s.OwnerProven(wid, f.hash("jane@example.com")) {
		t.Fatal("jane lost her proof while still owning a worker")
	}
}

func TestPreM3OwnersAreRecordedOnResend(t *testing.T) {
	f := newOwnerFixture(t)
	ctx := context.Background()
	m, _ := f.s.Snapshot(f.id)
	m.OwnerHashes, m.RoutingVersion = [][]byte{f.hash("jane@example.com")}, 4
	if err := f.s.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}
	f.set(t, f.id, 4, "jane@example.com")
	if _, ok := find(pending(t, f.s), routing.NoticeOwnerProof, "jane@example.com"); !ok {
		t.Fatal("a resend didn't record a pre-M3 owner")
	}
	f.prove(t, "jane@example.com")
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("a pre-M3 owner counts as a first owner")
	}
	// After that a resend is a no-op again.
	before := f.blobs.objs[routing.ObjectKey]
	f.set(t, f.id, 4, "jane@example.com")
	if !bytes.Equal(before, f.blobs.objs[routing.ObjectKey]) {
		t.Fatal("a plain resend rewrote routing data")
	}
}

func TestOwnerAddressesAreSealed(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	m, _ := f.s.Snapshot(f.id)
	if len(m.OwnerState) != 1 || bytes.Contains(m.OwnerState[0].Sealed, []byte("jane")) {
		t.Fatalf("owner state %+v", m.OwnerState)
	}
	// A sealed copy moved to another license won't open.
	other := f.s.MailboxID("other@fountbox.com")
	r := newKeyset(t).record(other)
	r.OwnerState = m.OwnerState
	r.OwnersSeen = true
	r.Notices = m.Notices
	if err := f.s.Upsert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PendingNotices("@fountbox.com"); err == nil {
		t.Fatal("a sealed owner address opened under another license")
	}
}

type fakeMailer struct {
	sent []routing.PendingNotice
	fail bool
}

func (m *fakeMailer) SendNotice(_ context.Context, n routing.PendingNotice) error {
	if m.fail {
		return errors.New("relay down")
	}
	m.sent = append(m.sent, n)
	return nil
}

func TestDrainNotices(t *testing.T) {
	f := newOwnerFixture(t)
	ctx := context.Background()
	f.set(t, f.id, 1, "jane@example.com", "bob@example.com")

	if n, err := f.s.DrainNotices(ctx, &fakeMailer{fail: true}, "@fountbox.com"); n != 0 || err == nil {
		t.Fatalf("failed send: %d %v", n, err)
	}
	f.s = f.reload(t)
	if len(pending(t, f.s)) != 2 {
		t.Fatal("notices didn't survive a failed send and a reboot")
	}
	m := &fakeMailer{}
	if n, err := f.s.DrainNotices(ctx, m, "@fountbox.com"); n != 2 || err != nil {
		t.Fatalf("drain: %d %v", n, err)
	}
	if len(m.sent) != 2 || m.sent[0].ReplyTo == "" {
		t.Fatalf("sent %+v", m.sent)
	}
	f.s = f.reload(t)
	if ns := pending(t, f.s); len(ns) != 0 {
		t.Fatalf("sent notices still queued: %+v", ns)
	}
	// A sent proof mail still proves when answered.
	if st, _ := f.s.Status(ctx, m.sent[0].ReplyTo); st != smtp.RecipientAccepting {
		t.Fatal("the reply address stopped working once its mail was sent")
	}
}

func TestPause(t *testing.T) {
	f := newOwnerFixture(t)
	ctx := context.Background()
	if f.s.Paused(f.id) {
		t.Fatal("paused at creation")
	}
	if err := f.s.SetPaused(ctx, f.id, true); err != nil {
		t.Fatal(err)
	}
	f.s = f.reload(t)
	if !f.s.Paused(f.id) {
		t.Fatal("pause lost on reload")
	}
	// A paused worker still receives mail.
	if st, _ := f.s.Status(ctx, "smith@fountbox.com"); st != smtp.RecipientAccepting {
		t.Fatalf("paused worker RCPT: %v", st)
	}
	if err := f.s.SetPaused(ctx, f.id, false); err != nil || f.s.Paused(f.id) {
		t.Fatalf("resume: %v", err)
	}
	if err := f.s.SetPaused(ctx, make([]byte, 32), true); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("unknown worker: %v", err)
	}
}
