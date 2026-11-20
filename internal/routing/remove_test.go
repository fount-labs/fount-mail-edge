package routing_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
)

func TestRemoveAddressFreesItAndKeepsATombstone(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, blobs, routingKey, macKey, routing.WithClock(clk.now))
	ctx := context.Background()
	root, one, two := family(t, s)
	for range 3 {
		if _, err := s.NextSequence(ctx, one); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.RemoveAddress(ctx, root, one); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Snapshot(one); ok {
		t.Fatal("removed address is still live")
	}
	if st, _ := s.Status(ctx, "one.worker@fountbox.com"); st != smtp.RecipientUnknown {
		t.Fatalf("RCPT for a removed address: %v", st)
	}
	if _, ok := s.AddressKey(hexID(one)); ok {
		t.Fatal("a removed address's signing key still resolves")
	}
	if free, _ := s.Available(ctx, "one.worker@fountbox.com"); free {
		t.Fatal("a removed address shows as available")
	}
	tomb, ok := s.RemovedOf(one)
	if !ok || tomb.Sequence != 3 || tomb.RemovedAt != clk.t.Unix() {
		t.Fatalf("tombstone %+v %v", tomb, ok)
	}

	// Retried, under the removed address's own id too: nil.
	if err := s.RemoveAddress(ctx, one, one); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := s.RemoveAddress(ctx, two, one); err != nil {
		t.Fatalf("retry from a sibling: %v", err)
	}
	if _, ok := s.MailboxKey(hexID(one)); !ok {
		t.Fatal("a tombstone doesn't resolve its handle's mailbox key")
	}

	// It survives a reboot.
	s2 := newStore(t, blobs, routingKey, macKey, routing.WithClock(clk.now))
	if _, ok := s2.RemovedOf(one); !ok {
		t.Fatal("tombstone lost on reload")
	}
}

func TestRemoveAddressRefusals(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	root, one, _ := family(t, s)
	other, err := s.Create(ctx, routing.NewMailbox{Address: "other@fountbox.com", LicenseHash: []byte("lic-2")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAddress(ctx, other, one); !errors.Is(err, routing.ErrNotHandle) {
		t.Fatalf("another handle removed it: %v", err)
	}
	if err := s.RemoveAddress(ctx, one, root); !errors.Is(err, routing.ErrIsHandle) {
		t.Fatalf("removed the handle: %v", err)
	}
	if err := s.RemoveAddress(ctx, root, s.MailboxID("nobody.worker@fountbox.com")); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.RemoveAddress(ctx, root, one); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAddress(ctx, other, one); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("another handle saw the tombstone: %v", err)
	}
	if err := s.RemoveCoordinated(ctx, s.MailboxID("two.worker@fountbox.com")); !errors.Is(err, routing.ErrNotCoordinated) {
		t.Fatalf("coordinator removed a device worker: %v", err)
	}
}

func TestRemovedAddressQuarantine(t *testing.T) {
	routingKey, macKey := keys(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, newMemBlobs(), routingKey, macKey, routing.WithClock(clk.now))
	ctx := context.Background()
	root, one, _ := family(t, s)
	if _, err := s.NextSequence(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAddress(ctx, root, one); err != nil {
		t.Fatal(err)
	}
	add := func() ([]byte, error) {
		return s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: root, Handle: "worker@fountbox.com", Address: "one.worker@fountbox.com"})
	}
	if _, err := add(); !errors.Is(err, routing.ErrRecentlyRemoved) {
		t.Fatalf("re-added inside the quarantine: %v", err)
	}
	clk.t = clk.t.Add(routing.RemovedQuarantine)
	id, err := add()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.RemovedOf(id); ok {
		t.Fatal("tombstone kept after reuse")
	}
	if seq, _ := s.NextSequence(ctx, id); seq != 2 {
		t.Fatalf("sequence restarted: %d", seq)
	}
}

func TestRemovingAWorkerFreesItsSlot(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	root, err := s.Create(ctx, routing.NewMailbox{Address: "cap@fountbox.com", LicenseHash: []byte("lic"), MailboxKey: newKeyset(t).mailbox.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	var last []byte
	for i := range routing.MaxWorkers {
		if last, err = s.AddAddress(ctx, routing.NewAddress{ParentMailboxID: root, Handle: "cap@fountbox.com", Address: workerName(i) + ".cap@fountbox.com"}); err != nil {
			t.Fatal(i, err)
		}
	}
	extra := routing.NewAddress{ParentMailboxID: root, Handle: "cap@fountbox.com", Address: "extra.cap@fountbox.com"}
	if _, err := s.AddAddress(ctx, extra); !errors.Is(err, routing.ErrWorkerLimit) {
		t.Fatalf("over the cap: %v", err)
	}
	if err := s.RemoveAddress(ctx, root, last); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAddress(ctx, extra); err != nil {
		t.Fatalf("a removed worker didn't free its slot: %v", err)
	}
}

func workerName(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	return "w" + string(letters[i%26]) + string(letters[(i/26)%26])
}

func hexID(id []byte) string { return hex.EncodeToString(id) }
