package routing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const backedUpAddr = "a@fountbox.com"

// backedUp is a Store with one mailbox and a backup target.
type backedUp struct {
	*routing.Store
	primary, backups *memBlobs
	pub              ed25519.PublicKey
	routingKey       []byte
	macKey           []byte
}

func newBackedUp(t *testing.T) backedUp {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	routingKey, macKey := keys(t)
	b := backedUp{primary: newMemBlobs(), backups: newMemBlobs(), pub: pub, routingKey: routingKey, macKey: macKey}
	initialize(t, b.primary, routingKey)
	b.Store, err = routing.New(context.Background(), b.primary, routingKey, macKey,
		routing.WithBackup(b.backups, priv, bytes.Repeat([]byte{7}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Upsert(context.Background(), newKeyset(t).record(b.MailboxID(backedUpAddr))); err != nil {
		t.Fatal(err)
	}
	return b
}

// A backup restores to exactly the object the primary holds, and a Store built on
// the restored bytes reads the same mailboxes.
func TestBackupRestores(t *testing.T) {
	b := newBackedUp(t)

	framed := b.backups.objs["routing/current"]
	if framed == nil {
		t.Fatal("no backup written")
	}
	id, err := routing.BackupBootID(framed)
	if err != nil || !bytes.Equal(id, bytes.Repeat([]byte{7}, 16)) {
		t.Fatalf("boot id %x err %v", id, err)
	}
	object, err := routing.OpenBackup(framed, b.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(object, b.primary.objs["edge/routing/current"]) {
		t.Fatal("backup differs from the primary object")
	}

	restored := newMemBlobs()
	restored.objs["edge/routing/current"] = object
	r, err := routing.New(context.Background(), restored, b.routingKey, b.macKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), backedUpAddr); err != nil {
		t.Fatalf("restored store lost the mailbox: %v", err)
	}
}

// Each change is copied, so sequence advances are never missing from a restore.
func TestEveryChangeIsBackedUp(t *testing.T) {
	b := newBackedUp(t)
	first := bytes.Clone(b.backups.objs["routing/current"])
	addr, err := b.Resolve(context.Background(), backedUpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.NextSequence(context.Background(), addr.MailboxID); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, b.backups.objs["routing/current"]) {
		t.Fatal("sequence advance wasn't backed up")
	}
}

func TestBackupRejectsTampering(t *testing.T) {
	b := newBackedUp(t)
	framed := b.backups.objs["routing/current"]

	for name, tampered := range map[string][]byte{
		"object":  flip(framed, len(framed)-1),
		"boot id": flip(framed, 5),
		"sig":     flip(framed, 30),
		"magic":   flip(framed, 0),
	} {
		if _, err := routing.OpenBackup(tampered, b.pub); err == nil {
			t.Fatalf("tampered %s accepted", name)
		}
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := routing.OpenBackup(framed, otherPub); err == nil {
		t.Fatal("another boot's key accepted")
	}
	if _, err := routing.OpenBackup(framed[:20], b.pub); err == nil {
		t.Fatal("truncated backup accepted")
	}
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

// A failed backup never fails the change: the primary already holds it.
func TestBackupFailureDoesNotFailTheChange(t *testing.T) {
	routingKey, macKey := keys(t)
	primary := newMemBlobs()
	initialize(t, primary, routingKey)
	s, err := routing.New(context.Background(), primary, routingKey, macKey,
		routing.WithBackup(failingBlobs{primary}, edKey(t), make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(context.Background(), newKeyset(t).record(s.MailboxID(backedUpAddr))); err != nil {
		t.Fatalf("Upsert failed over a backup problem: %v", err)
	}
	if primary.objs["edge/routing/current"] == nil {
		t.Fatal("primary not written")
	}
}

type failingBlobs struct{ *memBlobs }

func (failingBlobs) Put(context.Context, string, []byte) error { return errors.New("backup down") }

func TestRestoreReplacesARolledForwardObject(t *testing.T) {
	ctx := context.Background()
	b := newBackedUp(t)
	id := b.MailboxID(backedUpAddr)
	if _, err := b.NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
	snapshot := append([]byte(nil), b.backups.objs["routing/current"]...)
	if _, err := b.NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.NextSequence(ctx, id); err != nil {
		t.Fatal(err)
	}
	object, err := routing.OpenBackup(snapshot, b.pub)
	if err != nil {
		t.Fatal(err)
	}
	r := routing.Restore{Object: object, RoutingDataKey: b.routingKey, SkipSequences: 1000}

	sum, err := r.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if sum.Mailboxes != 1 || sum.Sequences != 1 {
		t.Fatalf("inspect = %+v", sum)
	}
	if _, err := r.Apply(ctx, b.primary); !errors.Is(err, routing.ErrObjectExists) {
		t.Fatalf("err = %v, want ErrObjectExists", err)
	}
	r.Replace = true
	if sum, err = r.Apply(ctx, b.primary); err != nil {
		t.Fatal(err)
	}
	if sum.Sequences != 1001 {
		t.Fatalf("applied = %+v", sum)
	}

	// The edge left running refuses what it finds, and a fresh one continues past
	// every number the old counter issued.
	if _, err := b.NextSequence(ctx, id); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	if _, err := b.NextSequence(ctx, id); !errors.Is(err, routing.ErrRolledBack) {
		t.Fatalf("err = %v, want ErrRolledBack", err)
	}
	n, err := reload(t, b.primary, b.routingKey, b.macKey).NextSequence(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1002 {
		t.Fatalf("sequence = %d, want 1002", n)
	}
}

func TestRestoreIntoAnEmptyBucket(t *testing.T) {
	ctx := context.Background()
	b := newBackedUp(t)
	object, err := routing.OpenBackup(b.backups.objs["routing/current"], b.pub)
	if err != nil {
		t.Fatal(err)
	}
	empty := newMemBlobs()
	if _, err := (routing.Restore{Object: object, RoutingDataKey: b.routingKey}).Apply(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reload(t, empty, b.routingKey, b.macKey).Available(ctx, backedUpAddr); ok {
		t.Fatal("the mailbox wasn't restored")
	}
}

func TestRestoreRefusesTheWrongKey(t *testing.T) {
	b := newBackedUp(t)
	object, err := routing.OpenBackup(b.backups.objs["routing/current"], b.pub)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := keys(t)
	if _, err := (routing.Restore{Object: object, RoutingDataKey: wrong}).Inspect(); err == nil {
		t.Fatal("restored with the wrong key")
	}
	empty := newMemBlobs()
	if _, err := (routing.Restore{Object: object, RoutingDataKey: wrong}).Apply(context.Background(), empty); err == nil {
		t.Fatal("restored with the wrong key")
	}
	if len(empty.objs) != 0 {
		t.Fatal("a refused restore wrote something")
	}
}
