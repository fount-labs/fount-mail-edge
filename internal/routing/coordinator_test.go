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

// A worker paused for lapse holds mail past its entitlement's expiry, for the
// hold, and only then bounces. Without the pause an expired one bounces at once.
// The pause survives a reboot, and setting it again doesn't stretch the hold.
func TestLapseHoldsMailThenBounces(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	exp := time.Unix(1_800_000_000, 0)
	clk := &clock{t: exp.Add(-time.Hour)}
	s := newStore(t, blobs, routingKey, macKey, routing.WithClock(clk.now))
	ctx := context.Background()

	held := newKeyset(t).record(s.MailboxID("held@fountbox.com"))
	held.EntitlementExp = exp.Unix()
	other := newKeyset(t).record(s.MailboxID("other@fountbox.com"))
	other.EntitlementExp = exp.Unix()
	for _, m := range []*routing.Mailbox{held, other} {
		if err := s.Upsert(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	status := func(s *routing.Store, addr string) smtp.RecipientStatus {
		t.Helper()
		st, err := s.Status(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	if err := s.SetLapsed(ctx, held.MailboxID, true); err != nil {
		t.Fatal(err)
	}
	if lapsed, until := s.Lapse(held.MailboxID); !lapsed || until != exp.Add(routing.DefaultLapseHold).Unix() {
		t.Fatalf("lapse %v until %d", lapsed, until)
	}
	if l, _ := s.Lapse(other.MailboxID); l {
		t.Fatal("other worker lapsed")
	}

	clk.t = exp.Add(time.Hour)
	if got := status(s, "held@fountbox.com"); got != smtp.RecipientAccepting {
		t.Fatalf("lapsed, inside the hold: %v", got)
	}
	if got := status(s, "held+t0k3n@fountbox.com"); got != smtp.RecipientAccepting {
		t.Fatalf("tagged, inside the hold: %v", got)
	}
	if got := status(s, "other@fountbox.com"); got != smtp.RecipientExpired {
		t.Fatalf("not lapsed, expired: %v", got)
	}

	// A reboot keeps the pause.
	s2, err := routing.New(ctx, blobs, routingKey, macKey, routing.WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	if got := status(s2, "held@fountbox.com"); got != smtp.RecipientAccepting {
		t.Fatalf("after reboot: %v", got)
	}

	// Setting it again later doesn't move the end of the hold.
	clk.t = exp.Add(routing.DefaultLapseHold - time.Minute)
	if err := s2.SetLapsed(ctx, held.MailboxID, false); err != nil {
		t.Fatal(err)
	}
	if err := s2.SetLapsed(ctx, held.MailboxID, true); err != nil {
		t.Fatal(err)
	}
	clk.t = exp.Add(routing.DefaultLapseHold)
	if got := status(s2, "held@fountbox.com"); got != smtp.RecipientExpired {
		t.Fatalf("past the hold: %v", got)
	}

	if err := s2.SetLapsed(ctx, make([]byte, 32), true); !errors.Is(err, routing.ErrNoMailbox) {
		t.Fatalf("unknown mailbox: %v", err)
	}
}

func TestLapseHoldOption(t *testing.T) {
	routingKey, macKey := keys(t)
	exp := time.Unix(1_800_000_000, 0)
	clk := &clock{t: exp.Add(2 * time.Hour)}
	s := newStore(t, newMemBlobs(), routingKey, macKey, routing.WithClock(clk.now), routing.WithLapseHold(time.Hour))
	ctx := context.Background()
	m := newKeyset(t).record(s.MailboxID("held@fountbox.com"))
	m.EntitlementExp = exp.Unix()
	m.Lapsed = true
	if err := s.Upsert(ctx, m); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx, "held@fountbox.com"); st != smtp.RecipientExpired {
		t.Fatalf("past a one-hour hold: %v", st)
	}
}

// The generation only moves forward, one key per generation, and survives a
// reboot.
func TestCoordinatorGeneration(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	b1 := []byte(edKey(t).Public().(ed25519.PublicKey))
	b2 := []byte(edKey(t).Public().(ed25519.PublicKey))

	if _, _, ok := s.CurrentCoordinator(); ok {
		t.Fatal("coordinator before any")
	}
	m := newKeyset(t).record(s.MailboxID("w@fountbox.com"))
	if err := s.Upsert(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := s.EnrollCoordinator(ctx, m.MailboxID, 1, b1); err != nil {
		t.Fatal(err)
	}
	if !s.Coordinated(m.MailboxID) {
		t.Fatal("not enrolled")
	}
	if err := s.AdvanceCoordinator(ctx, 1, b2); !errors.Is(err, routing.ErrGenerationConflict) {
		t.Fatalf("same generation, other key: %v", err)
	}
	if err := s.AdvanceCoordinator(ctx, 2, b2); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceCoordinator(ctx, 1, b1); !errors.Is(err, routing.ErrStaleGeneration) {
		t.Fatalf("older: %v", err)
	}
	if err := s.EnrollCoordinator(ctx, m.MailboxID, 1, b1); !errors.Is(err, routing.ErrStaleGeneration) {
		t.Fatalf("enroll older: %v", err)
	}
	s2, err := routing.New(ctx, blobs, routingKey, macKey)
	if err != nil {
		t.Fatal(err)
	}
	if gen, k, ok := s2.CurrentCoordinator(); !ok || gen != 2 || string(k) != string(b2) || !s2.Coordinated(m.MailboxID) {
		t.Fatalf("after reboot: %d %x %v", gen, k, ok)
	}
	if err := s2.AdvanceCoordinator(ctx, 1, b1); !errors.Is(err, routing.ErrStaleGeneration) {
		t.Fatalf("older after reboot: %v", err)
	}
}

func TestRotateSigningKey(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	ks := newKeyset(t)
	m := ks.record(s.MailboxID("w@fountbox.com"))
	if err := s.Upsert(ctx, m); err != nil {
		t.Fatal(err)
	}
	k := edKey(t).Public().(ed25519.PublicKey)
	if err := s.RotateSigningKey(ctx, m.MailboxID, k); !errors.Is(err, routing.ErrNotCoordinated) {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := s.EnrollCoordinator(ctx, m.MailboxID, 1, edKey(t).Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateSigningKey(ctx, m.MailboxID, m.SigningKey); !errors.Is(err, routing.ErrSameSigningKey) {
		t.Fatalf("same: %v", err)
	}
	if err := s.RotateSigningKey(ctx, m.MailboxID, k); err != nil {
		t.Fatal(err)
	}
	s2, err := routing.New(ctx, blobs, routingKey, macKey)
	if err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(m.MailboxID)
	got, ok := s2.AddressKey(id)
	if !ok || !got.Equal(k) {
		t.Fatal("rotation lost in reboot")
	}
	if mk, _ := s2.MailboxKey(id); !mk.Equal(ks.mailbox.Public()) {
		t.Fatal("mailbox key changed")
	}
}
