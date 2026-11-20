package routing_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

func TestChangesFeed(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	s := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	coord := []byte(edKey(t).Public().(ed25519.PublicKey))

	var ids [][]byte
	for _, a := range []string{"a@fountbox.com", "b@fountbox.com", "c@fountbox.com", "loose@fountbox.com"} {
		m := newKeyset(t).record(s.MailboxID(a))
		if err := s.Upsert(ctx, m); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.MailboxID)
	}
	for _, id := range ids[:3] {
		if err := s.EnrollCoordinator(ctx, id, 1, coord); err != nil {
			t.Fatal(err)
		}
	}
	page := func(s *routing.Store, cursor string, limit int) routing.ChangesPage {
		t.Helper()
		p, err := s.Changes(cursor, limit)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// From the start: every coordinated mailbox, a page at a time; never the
	// one that isn't enrolled.
	p := page(s, "", 2)
	if !p.Reset || !p.More || len(p.Changes) != 2 {
		t.Fatalf("first page %+v", p)
	}
	p2 := page(s, p.Cursor, 2)
	if p2.Reset || p2.More || len(p2.Changes) != 1 {
		t.Fatalf("second page %+v", p2)
	}
	seen := map[string]bool{}
	for _, c := range append(p.Changes, p2.Changes...) {
		seen[string(c.MailboxID)] = true
	}
	if len(seen) != 3 || seen[string(ids[3])] {
		t.Fatalf("seen %d", len(seen))
	}
	if p3 := page(s, p2.Cursor, 2); len(p3.Changes) != 0 || p3.More || p3.Cursor != p2.Cursor {
		t.Fatalf("caught up %+v", p3)
	}

	// New mail, a lapse, an unenrolled mailbox's mail.
	cur := p2.Cursor
	if _, err := s.NextSequence(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextSequence(ctx, ids[3]); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLapsed(ctx, ids[2], true); err != nil {
		t.Fatal(err)
	}
	p = page(s, cur, 10)
	if len(p.Changes) != 2 || string(p.Changes[0].MailboxID) != string(ids[1]) || p.Changes[0].Sequence != 1 ||
		string(p.Changes[1].MailboxID) != string(ids[2]) || !p.Changes[1].Lapsed {
		t.Fatalf("changes %+v", p)
	}

	// The cursor survives a reboot.
	s2, err := routing.New(ctx, blobs, routingKey, macKey)
	if err != nil {
		t.Fatal(err)
	}
	if p2 := page(s2, cur, 10); p2.Reset || len(p2.Changes) != 2 {
		t.Fatalf("after reboot %+v", p2)
	}
	if p2 := page(s2, p.Cursor, 10); len(p2.Changes) != 0 {
		t.Fatalf("after reboot, caught up %+v", p2)
	}

	// A cursor from ahead of the object (a restore went back) starts over.
	if p := page(s2, p.Cursor[:len(p.Cursor)-1]+"9999", 10); !p.Reset || len(p.Changes) != 3 {
		t.Fatalf("ahead %+v", p)
	}
	for _, bad := range []string{"x", "zz.1", "00.x"} {
		if _, err := s2.Changes(bad, 10); !errors.Is(err, routing.ErrBadCursor) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}
