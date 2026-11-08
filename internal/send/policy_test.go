package send

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

type fakeDir struct{ boxes map[string]routing.Mailbox }

func mac(addr string) []byte {
	m := hmac.New(sha256.New, []byte("test mac key"))
	m.Write([]byte(strings.ToLower(strings.TrimSpace(addr))))
	return m.Sum(nil)
}

func (d fakeDir) MailboxID(a string) []byte { return mac(a) }
func (d fakeDir) Snapshot(id []byte) (routing.Mailbox, bool) {
	m, ok := d.boxes[hex.EncodeToString(id)]
	return m, ok
}

func newDir(owners ...string) (fakeDir, []byte) {
	id := mac(worker)
	var hashes [][]byte
	for _, o := range owners {
		hashes = append(hashes, mac(o))
	}
	return fakeDir{boxes: map[string]routing.Mailbox{
		hex.EncodeToString(id): {MailboxID: id, OwnerHashes: hashes, LicenseHash: []byte("lic")},
	}}, id
}

func parsed(t *testing.T, raw []byte) *Message {
	t.Helper()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPolicy(t *testing.T) {
	dir, id := newDir("pat@smithcpa.com", "jo@smithcpa.com")
	p := NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com"})
	if err := p.Check(id, parsed(t, good("Cc: jo@smithcpa.com"))); err != nil {
		t.Fatalf("owners: %v", err)
	}

	cases := map[string]struct {
		id  []byte
		raw []byte
		err error
	}{
		"stranger in Cc":    {id, good("Cc: stranger@example.net"), ErrNotOwner},
		"another worker":    {mac("close.smithcpa@fountbox.com"), good(), ErrNoMailbox},
		"From not caller":   {id, []byte(strings.Replace(string(good()), worker, "close.smithcpa@fountbox.com", 1)), ErrNotWorker},
		"From other domain": {id, []byte(strings.Replace(string(good()), "fountbox.com>", "fountbox.co>", 1)), ErrNotWorker},
		"worker recipient":  {id, good("Cc: close.smithcpa@fountbox.com"), ErrNotOwner},
	}
	for name, c := range cases {
		if err := p.Check(c.id, parsed(t, c.raw)); !errors.Is(err, c.err) {
			t.Errorf("%s: %v, want %v", name, err, c.err)
		}
	}
}

func TestPolicyLapsedAndProof(t *testing.T) {
	dir, id := newDir("pat@smithcpa.com")
	m := dir.boxes[hex.EncodeToString(id)]
	m.EntitlementExp = time.Now().Add(-time.Hour).Unix()
	dir.boxes[hex.EncodeToString(id)] = m
	p := NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com"})
	if err := p.Check(id, parsed(t, good())); !errors.Is(err, ErrLapsed) {
		t.Fatalf("lapsed: %v", err)
	}

	dir, id = newDir("pat@smithcpa.com")
	p = NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com",
		Proven: func(_, _ []byte) bool { return false }})
	if err := p.Check(id, parsed(t, good())); !errors.Is(err, ErrNotProven) {
		t.Fatalf("unproven: %v", err)
	}
}

func TestPolicyLimits(t *testing.T) {
	dir, id := newDir("pat@smithcpa.com")
	p := NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com", PerWorker: 3, PerLicense: 100})
	m := parsed(t, good())
	for i := 0; i < 3; i++ {
		if err := p.Check(id, m); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := p.Check(id, m); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th send: %v", err)
	}
	// A refused message costs nothing.
	p = NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com", PerWorker: 1})
	bad := parsed(t, good("Cc: stranger@example.net"))
	for i := 0; i < 5; i++ {
		_ = p.Check(id, bad)
	}
	if err := p.Check(id, m); err != nil {
		t.Fatalf("budget spent by refused messages: %v", err)
	}

	// The license budget is shared by every worker on it.
	p = NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com", PerWorker: 10, PerLicense: 2})
	_ = p.Check(id, m)
	_ = p.Check(id, m)
	if err := p.Check(id, m); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("license cap: %v", err)
	}
}
