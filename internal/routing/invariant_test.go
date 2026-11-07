package routing_test

// Tier-2 verification (design §8a/§21): property/invariant tests for the routing
// store's state machine. Tier-1 fuzzes the parsers a live sender reaches; these
// drive the typed API through randomized *valid* operation sequences and assert a
// security-relevant invariant holds after every step — the class of silent logic
// failure a no-panic fuzz target cannot see. Each property loops over many seeds
// and reports the seed + step on failure so a counterexample is reproducible.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// flakyBlobs wraps the in-memory blob store with an on-demand write failure, so a
// test can make persist() fail exactly where it wants and observe the rollback.
type flakyBlobs struct {
	*memBlobs
	fail atomic.Bool
}

func newFlakyBlobs() *flakyBlobs { return &flakyBlobs{memBlobs: newMemBlobs()} }

func (f *flakyBlobs) PutIfMatch(ctx context.Context, key string, data []byte, etag string) (string, error) {
	if f.fail.Load() {
		return "", errors.New("injected put failure")
	}
	return f.memBlobs.PutIfMatch(ctx, key, data, etag)
}

// Property: a per-mailbox sequence number is never handed out twice — not across a
// storage-write failure (which must roll back and consume nothing) and not across
// a crash + reload (which must resume at exactly the last persisted number + 1).
// A reused sequence is the §9 integrity hole the broker's gap check exists to
// catch; the edge must never create one on its own.
func TestSequenceNeverReusedProperty(t *testing.T) {
	ctx := context.Background()
	for seed := uint64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0x5EEDF00D))
		routingKey, macKey := keys(t)
		blobs := newFlakyBlobs()
		s := newStore(t, blobs, routingKey, macKey)
		ks := newKeyset(t)
		id := s.MailboxID("worker@fountbox.com")
		if err := s.Upsert(ctx, ks.record(id)); err != nil {
			t.Fatal(err)
		}

		var model uint64 // highest successfully issued number (== what is persisted)
		issued := map[uint64]bool{}
		record := func(step int, got uint64, err error) {
			if err != nil {
				t.Fatalf("seed %d step %d: NextSequence: %v", seed, step, err)
			}
			if issued[got] {
				t.Fatalf("seed %d step %d: sequence %d handed out twice", seed, step, got)
			}
			if got != model+1 {
				t.Fatalf("seed %d step %d: sequence = %d, want %d", seed, step, got, model+1)
			}
			issued[got] = true
			model = got
		}

		for step := 0; step < 300; step++ {
			switch rng.IntN(3) {
			case 0: // ordinary advance
				got, err := s.NextSequence(ctx, id)
				record(step, got, err)
			case 1: // storage write fails: the attempt must consume no number
				blobs.fail.Store(true)
				if _, err := s.NextSequence(ctx, id); err == nil {
					t.Fatalf("seed %d step %d: NextSequence succeeded despite a failed persist", seed, step)
				}
				blobs.fail.Store(false)
				// In-memory rollback: the next success resumes at model+1, not model+2.
				got, err := s.NextSequence(ctx, id)
				record(step, got, err)
			case 2: // crash + reload over the same blobs: resume at the persisted number + 1
				s = newStore(t, blobs, routingKey, macKey)
				got, err := s.NextSequence(ctx, id)
				record(step, got, err)
			}
		}
	}
}

// Property: the routing (owner-list) version never goes backwards. SetOwners
// accepts a greater version, or the stored version with the stored list (a resend).
// A lower version, or the stored version with a new list, is ErrStaleVersion, and
// the stored version equals the running maximum — including across a reload. This is the §4 rollback defense: a
// stale owner set can never be replayed over a newer one.
func TestRoutingVersionMonotonicProperty(t *testing.T) {
	ctx := context.Background()
	for seed := uint64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0xA11CE))
		routingKey, macKey := keys(t)
		blobs := newMemBlobs()
		s := newStore(t, blobs, routingKey, macKey)
		id := s.MailboxID("worker@fountbox.com")
		if err := s.Upsert(ctx, newKeyset(t).record(id)); err != nil {
			t.Fatal(err)
		}

		var cur uint64 // highest accepted (and therefore stored) version
		var list []string
		for step := 0; step < 200; step++ {
			v := uint64(rng.IntN(12)) // spans below, at, and above cur
			owners := make([]string, rng.IntN(4))
			for i := range owners {
				owners[i] = fmt.Sprintf("owner%d@smithcpa.com", rng.IntN(100))
			}

			err := s.SetOwners(ctx, id, v, owners)
			switch {
			case v > cur || v == cur && slices.Equal(owners, list):
				if err != nil {
					t.Fatalf("seed %d step %d: version %d, stored %d, rejected: %v", seed, step, v, cur, err)
				}
				cur, list = v, owners
			default:
				if !errors.Is(err, routing.ErrStaleVersion) {
					t.Fatalf("seed %d step %d: stale version %d (stored %d) err = %v, want ErrStaleVersion", seed, step, v, cur, err)
				}
			}

			snap, ok := s.Snapshot(id)
			if !ok || snap.RoutingVersion != cur {
				t.Fatalf("seed %d step %d: stored version = %d, want %d", seed, step, snap.RoutingVersion, cur)
			}

			if rng.IntN(6) == 0 { // the version must survive a crash + reload
				s = newStore(t, blobs, routingKey, macKey)
				if snap, _ := s.Snapshot(id); snap.RoutingVersion != cur {
					t.Fatalf("seed %d step %d: version regressed across reload: %d, want %d", seed, step, snap.RoutingVersion, cur)
				}
			}
		}
	}
}

// Property: a license authorizes exactly one mailbox, and only its own. Over a
// full matrix of mailboxes and licenses, a renewal succeeds iff the entitlement's
// license hash matches the one bound at creation; every cross-license renewal is
// ErrLicenseMismatch and leaves the target's expiry untouched. This is the §4
// "one mailbox per license" / "a renewal can't move a mailbox between licenses"
// invariant — the routing-layer enforcement behind the Device API binding.
func TestLicenseIsolationProperty(t *testing.T) {
	ctx := context.Background()
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)

	const n = 8
	ids := make([][]byte, n)
	lics := make([][]byte, n)
	exps := make([]int64, n)
	for i := range ids {
		ks := newKeyset(t)
		lic := []byte(fmt.Sprintf("license-%d", i))
		id, err := s.Create(ctx, routing.NewMailbox{
			Address:        fmt.Sprintf("worker%d@fountbox.com", i),
			LicenseHash:    lic,
			DecryptionKey:  ks.dec.PublicKey().Bytes(),
			SigningKey:     ks.sign.Public().(ed25519.PublicKey),
			MailboxKey:     ks.mailbox.Public().(ed25519.PublicKey),
			OwnerChangeKey: ks.ownerChange.Public().(ed25519.PublicKey),
			PasskeyKey:     ks.passkey.Public().(ed25519.PublicKey),
			EntitlementExp: 1000,
		})
		if err != nil {
			t.Fatalf("create mailbox %d: %v", i, err)
		}
		ids[i], lics[i], exps[i] = id, lic, 1000
	}

	// One mailbox per license: a second mailbox on an already-bound license is refused.
	for i := range ids {
		ks := newKeyset(t)
		if _, err := s.Create(ctx, routing.NewMailbox{
			Address:        fmt.Sprintf("dup%d@fountbox.com", i),
			LicenseHash:    lics[i],
			DecryptionKey:  ks.dec.PublicKey().Bytes(),
			SigningKey:     ks.sign.Public().(ed25519.PublicKey),
			MailboxKey:     ks.mailbox.Public().(ed25519.PublicKey),
			OwnerChangeKey: ks.ownerChange.Public().(ed25519.PublicKey),
			PasskeyKey:     ks.passkey.Public().(ed25519.PublicKey),
			EntitlementExp: 1000,
		}); !errors.Is(err, routing.ErrLicenseTaken) {
			t.Fatalf("second mailbox on license %d: err = %v, want ErrLicenseTaken", i, err)
		}
	}

	// Renewal matrix: only the mailbox's own license may extend it.
	for i := range ids {
		for j := range lics {
			newExp := exps[i] + int64(100+j)
			err := s.RenewEntitlement(ctx, ids[i], lics[j], newExp)
			snap, _ := s.Snapshot(ids[i])
			if i == j {
				if err != nil {
					t.Fatalf("mailbox %d renewal with its own license failed: %v", i, err)
				}
				if snap.EntitlementExp != newExp {
					t.Fatalf("mailbox %d expiry = %d, want %d", i, snap.EntitlementExp, newExp)
				}
				exps[i] = newExp
			} else {
				if !errors.Is(err, routing.ErrLicenseMismatch) {
					t.Fatalf("mailbox %d (license %d) accepted license %d: err = %v, want ErrLicenseMismatch", i, i, j, err)
				}
				if snap.EntitlementExp != exps[i] {
					t.Fatalf("mailbox %d expiry changed on a cross-license renewal: %d, want %d", i, snap.EntitlementExp, exps[i])
				}
			}
		}
	}
}
