package routing_test

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

func (f *ownerFixture) proof(owner string, issued time.Time) routing.ConnectProof {
	return f.proofFor(f.id, owner, owner, issued)
}

// proofFor is a proof minted for macOwner on mailboxID, presented for owner.
func (f *ownerFixture) proofFor(mailboxID []byte, owner, macOwner string, issued time.Time) routing.ConnectProof {
	return routing.ConnectProof{Owner: owner, IssuedAt: issued.Unix(), MAC: f.s.ConnectMAC(mailboxID, macOwner, issued.Unix())}
}

func (f *ownerFixture) state(t *testing.T, owner string) routing.Owner {
	t.Helper()
	m, _ := f.s.Snapshot(f.id)
	for _, o := range m.OwnerState {
		if hmac.Equal(o.Hash, f.hash(owner)) {
			return o
		}
	}
	t.Fatalf("%s isn't an owner", owner)
	return routing.Owner{}
}

// The MAC is the contract's, byte for byte: HMAC-SHA256 under HKDF(ADDRESS_MAC_KEY,
// "fount-mail-edge/v1/owner-connect") of mailbox id, owner hash and issuedAt.
func TestConnectMACIsTheContracts(t *testing.T) {
	f := newOwnerFixture(t)
	prk, _ := hkdf.Extract(sha256.New, f.mk, nil)
	key, _ := hkdf.Expand(sha256.New, prk, "fount-mail-edge/v1/owner-connect", 32)
	mac := hmac.New(sha256.New, key)
	mac.Write(f.id)
	mac.Write(f.hash("jane@example.com"))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], 1_800_000_000)
	mac.Write(ts[:])
	want := mac.Sum(nil)[:16]
	if got := f.s.ConnectMAC(f.id, " Jane@Example.com", 1_800_000_000); !hmac.Equal(got, want) {
		t.Fatalf("mac %x, want %x", got, want)
	}

	id := routing.ConnectID(1_800_000_000, want, "@fountbox.com")
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(want))
	if id != "<c.1800000000."+enc+"@fountbox.com>" {
		t.Fatalf("Message-ID %s", id)
	}
}

func TestParseConnectID(t *testing.T) {
	mac := make([]byte, 16)
	mac[3] = 7
	id := routing.ConnectID(1_800_000_000, mac, "fountbox.com")
	for _, in := range []string{id, strings.Trim(id, "<>"), " " + id + " ", strings.Replace(id, "fountbox.com", "FountBox.com", 1)} {
		ts, got, ok := routing.ParseConnectID(in, "@fountbox.com")
		if !ok || ts != 1_800_000_000 || !hmac.Equal(got, mac) {
			t.Errorf("%q: %d %x %v", in, ts, got, ok)
		}
	}
	enc := strings.TrimSuffix(strings.TrimPrefix(id, "<c.1800000000."), "@fountbox.com>")
	for _, in := range []string{
		"",
		"<" + strings.Trim(id, "<>"), // unbalanced
		strings.Trim(id, "<>") + ">", // unbalanced
		strings.Replace(id, "fountbox.com", "x.com", 1), // another domain
		"<d.1800000000." + enc + "@fountbox.com>",       // another prefix
		"<c.01800000000." + enc + "@fountbox.com>",      // leading zero
		"<c.-5." + enc + "@fountbox.com>",
		"<c.+5." + enc + "@fountbox.com>",
		"<c.." + enc + "@fountbox.com>",
		"<c.1800000000." + strings.ToUpper(enc) + "@fountbox.com>",
		"<c.1800000000." + enc + "a@fountbox.com>", // 17 bytes' worth
		"<c.1800000000." + enc[:len(enc)-1] + "@fountbox.com>",
		"<c.99999999999999999999." + enc + "@fountbox.com>", // overflows int64
		"<c.1800000000." + enc + "@fountbox.com@fountbox.com>",
	} {
		if _, _, ok := routing.ParseConnectID(in, "@fountbox.com"); ok {
			t.Errorf("parsed %q", in)
		}
	}
}

func TestConnectProofProvesFirstOwner(t *testing.T) {
	f := newOwnerFixture(t)
	if err := f.s.SetOwners(context.Background(), f.id, 1, []string{"Jane@Example.com"}, f.proof("jane@example.com", f.clk.t)); err != nil {
		t.Fatal(err)
	}
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("a connected first owner isn't proven")
	}
	if o := f.state(t, "jane@example.com"); o.ProvedAt != f.clk.t.Unix() {
		t.Fatalf("ProvedAt %d", o.ProvedAt)
	}
	if ns := pending(t, f.s); len(ns) != 0 {
		t.Fatalf("a connected owner was queued mail: %+v", ns)
	}
	f.s = f.reload(t)
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("proof lost on reload")
	}
}

// A connected owner who isn't the license's first still waits, is announced to
// the proved owners, and counts toward the daily new-owner cap.
func TestConnectProofKeepsTheOtherOwnerRules(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	f.prove(t, "jane@example.com")

	issued := f.clk.t.Add(-time.Hour)
	if err := f.s.SetOwners(context.Background(), f.id, 2, []string{"jane@example.com", "bob@example.com"}, f.proof("bob@example.com", issued)); err != nil {
		t.Fatal(err)
	}
	ns := pending(t, f.s)
	if _, ok := find(ns, routing.NoticeOwnerProof, "bob@example.com"); ok {
		t.Fatal("a connected owner was sent a proof mail")
	}
	if n, ok := find(ns, routing.NoticeNewOwner, "jane@example.com"); !ok || n.About != "bob@example.com" {
		t.Fatalf("jane wasn't told about bob: %+v", ns)
	}
	if o := f.state(t, "bob@example.com"); o.ProvedAt != f.clk.t.Unix() || o.ActiveAt != f.clk.t.Add(routing.OwnerWait).Unix() {
		t.Fatalf("bob: %+v", o)
	}
	if f.s.OwnerProven(f.id, f.hash("bob@example.com")) {
		t.Fatal("a connected new owner skipped the wait")
	}
	f.clk.t = f.clk.t.Add(routing.OwnerWait)
	if !f.s.OwnerProven(f.id, f.hash("bob@example.com")) {
		t.Fatal("still waiting after OwnerWait")
	}
	m, _ := f.s.Snapshot(f.id)
	if len(m.OwnerAdds) != 1 {
		t.Fatalf("owner adds %v, want bob counted", m.OwnerAdds)
	}
}

func TestConnectProofCountsTowardTheDailyCap(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	owners := []string{"jane@example.com"}
	var proofs []routing.ConnectProof
	for i := range routing.DefaultNewOwnersPerDay + 1 {
		o := "o" + strconv.Itoa(i) + "@example.com"
		owners = append(owners, o)
		proofs = append(proofs, f.proof(o, f.clk.t))
	}
	if err := f.s.SetOwners(context.Background(), f.id, 2, owners, proofs...); !errors.Is(err, routing.ErrOwnerLimit) {
		t.Fatalf("over the cap with proofs: %v", err)
	}
}

// An owner already listed but not yet proved is proved by a connect reply, even on
// a resend of the same version, and their queued proof mail goes.
func TestConnectProofProvesAListedOwner(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	if _, ok := find(pending(t, f.s), routing.NoticeOwnerProof, "jane@example.com"); !ok {
		t.Fatal("no proof mail queued")
	}
	f.clk.t = f.clk.t.Add(time.Minute)
	if err := f.s.SetOwners(context.Background(), f.id, 1, []string{"jane@example.com"}, f.proof("jane@example.com", f.clk.t)); err != nil {
		t.Fatal(err)
	}
	if o := f.state(t, "jane@example.com"); o.ProvedAt != f.clk.t.Unix() {
		t.Fatalf("ProvedAt %d", o.ProvedAt)
	}
	m, _ := f.s.Snapshot(f.id)
	if len(m.Notices) != 0 {
		t.Fatalf("the proof mail is still queued: %+v", m.Notices)
	}
	// Proving again changes nothing.
	f.clk.t = f.clk.t.Add(time.Minute)
	if err := f.s.SetOwners(context.Background(), f.id, 1, []string{"jane@example.com"}, f.proof("jane@example.com", f.clk.t)); err != nil {
		t.Fatal(err)
	}
	if o := f.state(t, "jane@example.com"); o.ProvedAt != f.clk.t.Add(-time.Minute).Unix() {
		t.Fatalf("ProvedAt moved to %d", o.ProvedAt)
	}
}

func TestConnectProofBoundaries(t *testing.T) {
	f := newOwnerFixture(t)
	if err := f.s.SetOwners(context.Background(), f.id, 1, []string{"jane@example.com"}, f.proof("jane@example.com", f.clk.t.Add(-routing.ConnectLifetime))); err != nil {
		t.Fatalf("a proof at exactly its lifetime: %v", err)
	}
	if err := f.s.SetOwners(context.Background(), f.id, 2, []string{"jane@example.com", "bob@example.com"}, f.proof("bob@example.com", f.clk.t.Add(time.Minute))); err != nil {
		t.Fatalf("a proof a minute ahead: %v", err)
	}
}

func TestBadConnectProofChangesNothing(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	other := f.s.MailboxID("other@fountbox.com")
	now := f.clk.t
	tampered := f.proof("bob@example.com", now)
	tampered.MAC[0] ^= 1
	shifted := f.proof("bob@example.com", now)
	shifted.IssuedAt++
	for name, p := range map[string]routing.ConnectProof{
		"expired":          f.proof("bob@example.com", now.Add(-routing.ConnectLifetime-time.Second)),
		"from the future":  f.proof("bob@example.com", now.Add(10*time.Minute)),
		"another mailbox":  f.proofFor(other, "bob@example.com", "bob@example.com", now),
		"another owner":    f.proofFor(f.id, "bob@example.com", "mallory@example.com", now),
		"tampered mac":     tampered,
		"another time":     shifted,
		"owner not listed": f.proof("carol@example.com", now),
		"no mac":           {Owner: "bob@example.com", IssuedAt: now.Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			before, _ := f.s.Snapshot(f.id)
			ok := f.proof("bob@example.com", now)
			err := f.s.SetOwners(context.Background(), f.id, 2, []string{"jane@example.com", "bob@example.com"}, ok, p)
			if !errors.Is(err, routing.ErrConnectProof) {
				t.Fatalf("got %v, want ErrConnectProof", err)
			}
			after, _ := f.s.Snapshot(f.id)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("a refused write changed the record")
			}
			f.s = f.reload(t)
			if reloaded, _ := f.s.Snapshot(f.id); !reflect.DeepEqual(before, reloaded) {
				t.Fatal("a refused write reached storage")
			}
		})
	}
}

// Without proofs, a write is what it always was: a new owner gets a proof mail.
func TestNoConnectProofIsUnchanged(t *testing.T) {
	f := newOwnerFixture(t)
	if err := f.s.SetOwners(context.Background(), f.id, 1, []string{"jane@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := find(pending(t, f.s), routing.NoticeOwnerProof, "jane@example.com"); !ok {
		t.Fatal("no proof mail without a connect proof")
	}
	if f.state(t, "jane@example.com").ProvedAt != 0 || f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("proved without a reply")
	}
}
