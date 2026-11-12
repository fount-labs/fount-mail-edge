package notice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/header"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

type delivery struct {
	from  string
	rcpts []string
	data  []byte
}

// fakeDeliverer stands in for send.Deliverer: it records each message and answers
// with status for every recipient.
type fakeDeliverer struct {
	mu     sync.Mutex
	got    []delivery
	status send.Status
}

func (d *fakeDeliverer) Deliver(_ context.Context, from string, rcpts []string, data []byte) []send.Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, delivery{from, rcpts, data})
	st := d.status
	if st == "" {
		st = send.Sent
	}
	out := make([]send.Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = send.Result{Recipient: r, Status: st, Detail: "test"}
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newMailer(t *testing.T, d *fakeDeliverer, clk *clock, perLicense int) *Mailer {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m, err := New(Options{
		MailDomain: "@fountbox.com",
		Signers:    []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: key}},
		Deliverer:  d,
		License:    func(w []byte) ([]byte, bool) { return append([]byte("lic-"), w...), true },
		PerLicense: perLicense,
		Now:        clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func proof(id, to string) routing.PendingNotice {
	return routing.PendingNotice{ID: id, Kind: routing.NoticeOwnerProof, To: to,
		ReplyTo: "fount+abc234@fountbox.com", Worker: []byte("w1")}
}

func fields(t *testing.T, raw []byte) ([]header.Field, []byte) {
	t.Helper()
	f, body, err := header.Split(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f, body
}

func value(t *testing.T, f []header.Field, name string) string {
	t.Helper()
	v := header.Get(f, name)
	if len(v) != 1 {
		t.Fatalf("%d %s fields", len(v), name)
	}
	return strings.TrimSpace(v[0].Value())
}

func TestProofMailShape(t *testing.T) {
	d := &fakeDeliverer{}
	m := newMailer(t, d, &clock{time.Unix(1_800_000_000, 0)}, 0)
	if err := m.SendNotice(context.Background(), proof("n1", "jane@example.com")); err != nil {
		t.Fatal(err)
	}
	if len(d.got) != 1 {
		t.Fatalf("%d deliveries", len(d.got))
	}
	g := d.got[0]
	if g.from != "fount@fountbox.com" || len(g.rcpts) != 1 || g.rcpts[0] != "jane@example.com" {
		t.Fatalf("envelope %q %v", g.from, g.rcpts)
	}
	f, body := fields(t, g.data)
	if f[0].Name != "DKIM-Signature" || !strings.Contains(f[0].Value(), "d=fountbox.com") {
		t.Fatalf("not DKIM signed first: %q", f[0].Name)
	}
	for name, want := range map[string]string{
		"from":           "Fount Mail <fount@fountbox.com>",
		"to":             "<jane@example.com>",
		"reply-to":       "<fount+abc234@fountbox.com>",
		"subject":        "Reply to turn on email updates",
		"auto-submitted": "auto-generated",
	} {
		if got := value(t, f, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !bytes.Contains(body, []byte("reply to this email")) || bytes.Contains(body, []byte("\n\n")) {
		t.Fatalf("body isn't the fixed CRLF text: %q", body)
	}
}

func TestOtherNotices(t *testing.T) {
	d := &fakeDeliverer{}
	m := newMailer(t, d, &clock{time.Unix(1_800_000_000, 0)}, 0)
	ctx := context.Background()
	if err := m.SendNotice(ctx, routing.PendingNotice{ID: "a", Kind: routing.NoticeNewOwner,
		To: "jane@example.com", About: "bob@example.org", Worker: []byte("w")}); err != nil {
		t.Fatal(err)
	}
	if err := m.SendNotice(ctx, routing.PendingNotice{ID: "b", Kind: routing.NoticeOwnerRemoved,
		To: "jane@example.com", Worker: []byte("w")}); err != nil {
		t.Fatal(err)
	}
	f, body := fields(t, d.got[0].data)
	if !bytes.Contains(body, []byte("bob@example.org was added")) || len(header.Get(f, "reply-to")) != 0 {
		t.Fatalf("new-owner notice: %q", body)
	}
	f, _ = fields(t, d.got[1].data)
	if !strings.Contains(value(t, f, "subject"), "removed") {
		t.Fatal("owner-removed notice subject")
	}
}

func TestPermanentFailureIsUndeliverable(t *testing.T) {
	d := &fakeDeliverer{status: send.Permanent}
	m := newMailer(t, d, &clock{time.Unix(1_800_000_000, 0)}, 0)
	err := m.SendNotice(context.Background(), proof("n1", "jane@example.com"))
	if !errors.Is(err, routing.ErrNoticeUndeliverable) {
		t.Fatalf("permanent: %v", err)
	}
}

func TestTemporaryFailureBacksOffThenGivesUp(t *testing.T) {
	d := &fakeDeliverer{status: send.Temporary}
	clk := &clock{time.Unix(1_800_000_000, 0)}
	m := newMailer(t, d, clk, 10_000)
	ctx := context.Background()
	n := proof("n1", "jane@example.com")

	err := m.SendNotice(ctx, n)
	if err == nil || errors.Is(err, routing.ErrNoticeUndeliverable) {
		t.Fatalf("first temporary failure: %v", err)
	}
	if err := m.SendNotice(ctx, n); !errors.Is(err, ErrNotDue) || len(d.got) != 1 {
		t.Fatalf("retried during backoff: %v, %d deliveries", err, len(d.got))
	}
	// Another notice isn't held up by this one's backoff.
	if err := m.SendNotice(ctx, proof("n2", "bob@example.com")); errors.Is(err, ErrNotDue) {
		t.Fatal("one notice's backoff held up another")
	}
	clk.t = clk.t.Add(FirstRetry)
	if err := m.SendNotice(ctx, n); errors.Is(err, ErrNotDue) || len(d.got) != 3 {
		t.Fatalf("not retried after %s: %v", FirstRetry, err)
	}
	clk.t = clk.t.Add(FirstRetry) // the second wait is twice the first
	if err := m.SendNotice(ctx, n); !errors.Is(err, ErrNotDue) {
		t.Fatalf("backoff didn't grow: %v", err)
	}
	for clk.t.Sub(time.Unix(1_800_000_000, 0)) < GiveUp {
		clk.t = clk.t.Add(MaxRetry)
		err = m.SendNotice(ctx, n)
		if errors.Is(err, routing.ErrNoticeUndeliverable) {
			break
		}
	}
	if !errors.Is(err, routing.ErrNoticeUndeliverable) {
		t.Fatalf("never gave up: %v", err)
	}
	// Once sent, a recovered domain clears the state.
	d.status = send.Sent
	if err := m.SendNotice(ctx, n); err != nil {
		t.Fatalf("after giving up, a fresh offer: %v", err)
	}
}

func TestLicenseNoticeCapWaits(t *testing.T) {
	d := &fakeDeliverer{}
	m := newMailer(t, d, &clock{time.Unix(1_800_000_000, 0)}, 2)
	ctx := context.Background()
	for i, id := range []string{"a", "b"} {
		if err := m.SendNotice(ctx, proof(id, "jane@example.com")); err != nil {
			t.Fatalf("notice %d: %v", i, err)
		}
	}
	err := m.SendNotice(ctx, proof("c", "jane@example.com"))
	if !errors.Is(err, ErrLimited) || errors.Is(err, routing.ErrNoticeUndeliverable) || len(d.got) != 2 {
		t.Fatalf("over the cap: %v, %d deliveries", err, len(d.got))
	}
	other := proof("d", "jane@example.com")
	other.Worker = []byte("w2")
	if err := m.SendNotice(ctx, other); err != nil {
		t.Fatalf("another license was capped: %v", err)
	}
}

func TestUnsafeAddressesNeverReachAHeader(t *testing.T) {
	d := &fakeDeliverer{}
	m := newMailer(t, d, &clock{time.Unix(1_800_000_000, 0)}, 0)
	for _, to := range []string{
		"jane@example.com\r\nBcc: x@evil.example",
		"Jane <jane@example.com>",
		"jane@example.com, bob@example.com",
		"jane",
		"jané@example.com",
	} {
		err := m.SendNotice(context.Background(), proof("n", to))
		if !errors.Is(err, routing.ErrNoticeUndeliverable) {
			t.Errorf("%q: %v", to, err)
		}
	}
	bad := proof("n", "jane@example.com")
	bad.ReplyTo = "someone-else@fountbox.com"
	if err := m.SendNotice(context.Background(), bad); !errors.Is(err, routing.ErrNoticeUndeliverable) {
		t.Errorf("a Reply-To that isn't fount+…: %v", err)
	}
	if len(d.got) != 0 {
		t.Fatalf("%d unsafe notices delivered", len(d.got))
	}
}

func TestNewNeedsTheSendPath(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signers := []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: key}}
	lic := func([]byte) ([]byte, bool) { return nil, false }
	for name, o := range map[string]Options{
		"no signers":   {MailDomain: "@fountbox.com", Deliverer: &fakeDeliverer{}, License: lic},
		"no deliverer": {MailDomain: "@fountbox.com", Signers: signers, License: lic},
		"no domain":    {Signers: signers, Deliverer: &fakeDeliverer{}, License: lic},
		"no license":   {MailDomain: "@fountbox.com", Signers: signers, Deliverer: &fakeDeliverer{}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: built a mailer", name)
		}
	}
}

type fakeQueue struct {
	mu     sync.Mutex
	passes int
}

func (q *fakeQueue) DrainNotices(context.Context, routing.NoticeMailer, string) (routing.DrainResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.passes++
	return routing.DrainResult{}, nil
}

func TestRunDrainsAtOnceAndStops(t *testing.T) {
	q := &fakeQueue{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, q, nil, "@fountbox.com", time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		q.mu.Lock()
		p := q.passes
		q.mu.Unlock()
		if p > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no pass at start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

type offTransmitter struct{ calls int }

func (o *offTransmitter) Transmit(context.Context, string, []string, []byte) ([]send.Result, error) {
	o.calls++
	return nil, send.ErrOff
}

// When the signer is off or out of reach (mail-send in a split edge), nothing was
// sent, so the notice stays queued and the wait doesn't count toward GiveUp.
func TestNoticeWaitsOutASignerThatIsOff(t *testing.T) {
	clk := &clock{time.Unix(1_800_000_000, 0)}
	out := &offTransmitter{}
	m, err := New(Options{MailDomain: "@fountbox.com", Out: out, Now: clk.now,
		License: func(w []byte) ([]byte, bool) { return w, true }})
	if err != nil {
		t.Fatal(err)
	}
	n := proof("n1", "jane@example.com")
	for range 2 {
		err := m.SendNotice(context.Background(), n)
		if !errors.Is(err, send.ErrOff) || errors.Is(err, routing.ErrNoticeUndeliverable) {
			t.Fatalf("err = %v", err)
		}
		clk.t = clk.t.Add(GiveUp)
	}
	if out.calls != 2 {
		t.Fatalf("%d tries, want each pass to try again", out.calls)
	}
}
