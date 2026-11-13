package send

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOut is a Transmitter that answers each recipient from status (Sent when
// unset) and can hold a delivery open until release is closed.
type fakeOut struct {
	mu      sync.Mutex
	calls   [][]string
	status  map[string]Status
	err     error
	entered chan struct{} // gets a value as each Transmit starts, if set
	release chan struct{} // Transmit waits for it, if set
	ctxErr  error         // ctx.Err() as the last Transmit returned
}

func (f *fakeOut) Transmit(ctx context.Context, from string, rcpts []string, raw []byte) ([]Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, slices.Clone(rcpts))
	entered, release, err := f.entered, f.release, f.err
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if release != nil {
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ctxErr = ctx.Err()
	if err != nil {
		return nil, err
	}
	var out []Result
	// Reversed, as Deliver groups by domain and needn't keep the order.
	for i := len(rcpts) - 1; i >= 0; i-- {
		s := f.status[rcpts[i]]
		if s == "" {
			s = Sent
		}
		out = append(out, Result{Recipient: rcpts[i], Status: s, Detail: "d " + string(s)})
	}
	return out, nil
}

func (f *fakeOut) set(rcpt string, s Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status == nil {
		f.status = map[string]Status{}
	}
	f.status[rcpt] = s
}

func (f *fakeOut) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func dedupeRig(t *testing.T, perWorker int, owners ...string) (*Service, *fakeOut, *testClock, []byte) {
	t.Helper()
	if len(owners) == 0 {
		owners = []string{"pat@smithcpa.com"}
	}
	dir, id := newDir(owners...)
	clk := &testClock{t: time.Unix(1_800_000_000, 0)}
	out := &fakeOut{}
	return &Service{
		Policy: NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com", PerWorker: perWorker, PerLicense: 1000}),
		Out:    out,
		Dedupe: NewDedupe(DedupeOptions{Now: clk.now}),
	}, out, clk, id
}

func withID(raw []byte, id string) []byte {
	return []byte(strings.Replace(string(raw), "Message-ID: <1@fountbox.com>", "Message-ID: <"+id+">", 1))
}

func mustSend(t *testing.T, svc *Service, id, raw []byte) []Result {
	t.Helper()
	res, err := svc.Send(context.Background(), id, raw)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return res
}

// A repeat answers from the record: no second delivery, no second token.
func TestDedupeRepeatReturnsFirstResults(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 2)
	out.set("pat@smithcpa.com", Sent)
	first := mustSend(t, svc, id, good())
	for i := 0; i < 5; i++ {
		again := mustSend(t, svc, id, good())
		if !slices.Equal(first, again) {
			t.Fatalf("repeat %d: %+v, first %+v", i, again, first)
		}
	}
	if out.n() != 1 {
		t.Fatalf("%d transmits, want 1", out.n())
	}
	// The worker's budget is 2: the repeats spent none of it.
	mustSend(t, svc, id, withID(good(), "2@fountbox.com"))
	if _, err := svc.Send(context.Background(), id, withID(good(), "3@fountbox.com")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third distinct message: %v, want rate limited", err)
	}
}

func TestDedupeDifferentMessageIDSends(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 10)
	mustSend(t, svc, id, good())
	mustSend(t, svc, id, withID(good(), "2@fountbox.com"))
	mustSend(t, svc, id, withID(good(), "3@fountbox.com"))
	if out.n() != 3 {
		t.Fatalf("%d transmits, want 3", out.n())
	}
}

// The same Message-ID with other bytes is refused, not answered from the record.
func TestDedupeMessageIDReused(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 10)
	mustSend(t, svc, id, good())
	other := []byte(strings.Replace(string(good()), "Your result is ready.", "Something else.", 1))
	if _, err := svc.Send(context.Background(), id, other); !errors.Is(err, ErrMessageIDReused) {
		t.Fatalf("reused id: %v", err)
	}
	if out.n() != 1 {
		t.Fatalf("%d transmits, want 1", out.n())
	}
}

func TestDedupeTTLExpiry(t *testing.T) {
	svc, out, clk, id := dedupeRig(t, 2)
	mustSend(t, svc, id, good())
	clk.add(DefaultDedupeTTL - time.Second)
	mustSend(t, svc, id, good())
	if out.n() != 1 {
		t.Fatalf("repeat inside the TTL transmitted: %d", out.n())
	}
	clk.add(2 * time.Second)
	mustSend(t, svc, id, good())
	if out.n() != 2 {
		t.Fatalf("repeat past the TTL: %d transmits, want 2", out.n())
	}
	if svc.Dedupe.Len() != 1 {
		t.Fatalf("%d records, want 1", svc.Dedupe.Len())
	}
}

// A repeat during the first send waits for it, and gets its results; the first
// keeps delivering when its own caller hangs up.
func TestDedupeInFlightRepeatWaits(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 10)
	out.entered, out.release = make(chan struct{}, 4), make(chan struct{})

	firstCtx, hangUp := context.WithCancel(context.Background())
	type answer struct {
		res []Result
		err error
	}
	first, second := make(chan answer, 1), make(chan answer, 1)
	go func() {
		r, err := svc.Send(firstCtx, id, good())
		first <- answer{r, err}
	}()
	<-out.entered
	hangUp()
	go func() {
		r, err := svc.Send(context.Background(), id, good())
		second <- answer{r, err}
	}()
	select {
	case a := <-second:
		t.Fatalf("repeat answered while the first was in flight: %+v", a)
	case <-time.After(50 * time.Millisecond):
	}
	close(out.release)
	a, b := <-first, <-second
	if a.err != nil || b.err != nil || !slices.Equal(a.res, b.res) || a.res[0].Status != Sent {
		t.Fatalf("first %+v, repeat %+v", a, b)
	}
	if out.n() != 1 {
		t.Fatalf("%d transmits, want 1", out.n())
	}
	if out.ctxErr != nil {
		t.Fatalf("the first send's delivery was cancelled with its caller: %v", out.ctxErr)
	}
}

// A repeat whose caller gives up while the first is in flight hears so.
func TestDedupeInFlightRepeatGivesUp(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 10)
	out.entered, out.release = make(chan struct{}, 4), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := svc.Send(context.Background(), id, good())
		done <- err
	}()
	<-out.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := svc.Send(ctx, id, good()); !errors.Is(err, ErrSendInProgress) {
		t.Fatalf("repeat: %v, want in progress", err)
	}
	close(out.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if out.n() != 1 {
		t.Fatalf("%d transmits, want 1", out.n())
	}
}

// A repeat re-attempts the recipients that ended Temporary, and only those;
// that re-attempt is a delivery, so it spends a token.
func TestDedupeRetriesOnlyTemporary(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 3, "pat@smithcpa.com", "jo@smithcpa.com", "al@smithcpa.com")
	raw := good("Cc: jo@smithcpa.com, al@smithcpa.com")
	out.set("jo@smithcpa.com", Temporary)
	out.set("al@smithcpa.com", Permanent)
	res := mustSend(t, svc, id, raw)
	want := []Status{Sent, Temporary, Permanent}
	for i, r := range res {
		if r.Recipient != []string{"pat@smithcpa.com", "jo@smithcpa.com", "al@smithcpa.com"}[i] || r.Status != want[i] {
			t.Fatalf("first: %+v", res)
		}
	}

	// Still failing: jo alone is tried again.
	res = mustSend(t, svc, id, raw)
	if out.n() != 2 || !slices.Equal(out.calls[1], []string{"jo@smithcpa.com"}) {
		t.Fatalf("calls %v", out.calls)
	}
	if res[1].Status != Temporary || res[0].Status != Sent || res[2].Status != Permanent {
		t.Fatalf("second: %+v", res)
	}

	// Now it goes through, and the record is settled.
	out.set("jo@smithcpa.com", Sent)
	res = mustSend(t, svc, id, raw)
	if !slices.Equal(out.calls[2], []string{"jo@smithcpa.com"}) || res[1].Status != Sent || res[1].Detail != "d sent" {
		t.Fatalf("third: %+v, calls %v", res, out.calls)
	}
	mustSend(t, svc, id, raw)
	if out.n() != 3 {
		t.Fatalf("a settled repeat transmitted: %v", out.calls)
	}
	// The first send and two re-attempts spent the worker's 3 tokens.
	if _, err := svc.Send(context.Background(), id, withID(raw, "2@fountbox.com")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("budget after re-attempts: %v", err)
	}
}

// A re-attempt passes Policy again: a paused worker retries nothing, and the
// record stays for after the pause.
func TestDedupeReattemptChecksPolicy(t *testing.T) {
	dir, id := newDir("pat@smithcpa.com", "jo@smithcpa.com")
	out := &fakeOut{}
	svc := &Service{Policy: NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com"}), Out: out}
	raw := good("Cc: jo@smithcpa.com")
	out.set("jo@smithcpa.com", Temporary)
	mustSend(t, svc, id, raw)

	key := fmt.Sprintf("%x", id)
	mb := dir.boxes[key]
	mb.Paused = true
	dir.boxes[key] = mb
	if _, err := svc.Send(context.Background(), id, raw); !errors.Is(err, ErrPaused) {
		t.Fatalf("paused re-attempt: %v", err)
	}
	mb.Paused = false
	dir.boxes[key] = mb
	out.set("jo@smithcpa.com", Sent)
	res := mustSend(t, svc, id, raw)
	if out.n() != 2 || !slices.Equal(out.calls[1], []string{"jo@smithcpa.com"}) || res[0].Status != Sent || res[1].Status != Sent {
		t.Fatalf("after resume: %+v, calls %v", res, out.calls)
	}
}

// A send that sent nothing leaves no record, so its retry is a fresh send.
func TestDedupeFailedSendLeavesNoRecord(t *testing.T) {
	svc, out, _, id := dedupeRig(t, 10)
	out.err = fmt.Errorf("link: %w", ErrOff)
	if _, err := svc.Send(context.Background(), id, good()); !errors.Is(err, ErrOff) {
		t.Fatalf("off: %v", err)
	}
	if _, err := svc.Send(context.Background(), id, good("Cc: stranger@example.net")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("stranger: %v", err)
	}
	if svc.Dedupe.Len() != 0 {
		t.Fatalf("%d records after failed sends", svc.Dedupe.Len())
	}
	out.err = nil
	mustSend(t, svc, id, good())
	if out.n() != 2 {
		t.Fatalf("%d transmits, want 2", out.n())
	}
}

func TestDedupeKeyedPerMailbox(t *testing.T) {
	d := NewDedupe(DedupeOptions{})
	m := parsed(t, good())
	calls := 0
	attempt := func(context.Context, *Message) ([]Result, error) {
		calls++
		return []Result{{Recipient: "pat@smithcpa.com", Status: Sent}}, nil
	}
	for _, mb := range [][]byte{[]byte("a"), []byte("b"), []byte("a")} {
		if _, err := d.Do(context.Background(), mb, m, attempt); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("%d attempts, want one per mailbox", calls)
	}
}

func TestDedupeBounded(t *testing.T) {
	d := NewDedupe(DedupeOptions{Max: 2})
	calls := 0
	attempt := func(context.Context, *Message) ([]Result, error) {
		calls++
		return []Result{{Recipient: "pat@smithcpa.com", Status: Sent}}, nil
	}
	for _, mid := range []string{"1@fountbox.com", "2@fountbox.com", "3@fountbox.com"} {
		if _, err := d.Do(context.Background(), []byte("a"), parsed(t, withID(good(), mid)), attempt); err != nil {
			t.Fatal(err)
		}
	}
	if d.Len() != 2 {
		t.Fatalf("%d records, want 2", d.Len())
	}
	// The oldest went first; the newest is still answered from the record.
	_, _ = d.Do(context.Background(), []byte("a"), parsed(t, withID(good(), "3@fountbox.com")), attempt)
	if calls != 3 {
		t.Fatalf("newest repeat attempted: %d", calls)
	}
	_, _ = d.Do(context.Background(), []byte("a"), parsed(t, withID(good(), "1@fountbox.com")), attempt)
	if calls != 4 {
		t.Fatalf("evicted repeat not attempted: %d", calls)
	}
}
