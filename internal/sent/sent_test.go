package sent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// memBlobs is S3 for the tests: it survives a "reboot" (a new Store and a new
// Dedupe over it), dates each write, and can be told to fail writes.
type memBlobs struct {
	mu       sync.Mutex
	m        map[string][]byte
	modified map[string]time.Time
	now      time.Time
	failPuts int // fail the next n Puts
	puts     int
}

func newMemBlobs() *memBlobs {
	return &memBlobs{m: map[string][]byte{}, modified: map[string]time.Time{}, now: time.Unix(1_800_000_000, 0)}
}

func (b *memBlobs) Put(_ context.Context, k string, d []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.puts++
	if b.failPuts > 0 {
		b.failPuts--
		return errors.New("s3 down")
	}
	b.m[k] = bytes.Clone(d)
	b.modified[k] = b.now
	return nil
}

func (b *memBlobs) Get(_ context.Context, k string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(v), nil
}

func (b *memBlobs) List(_ context.Context, prefix string) ([]store.Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []store.Object
	for k, v := range b.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, store.Object{Key: k, Size: int64(len(v)), Modified: b.modified[k]})
		}
	}
	return out, nil
}

func (b *memBlobs) Delete(_ context.Context, k string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, k)
	return nil
}

func (b *memBlobs) failNext(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failPuts = n
}

var secret = []byte("test-routing-data-key")

const worker = "ap.smithcpa@fountbox.com"

func message(id string, cc ...string) []byte {
	h := []string{
		"From: Accounts payable <" + worker + ">",
		"To: Pat Smith <pat@smithcpa.com>",
		"Subject: Your result is ready",
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + id + ">",
	}
	if len(cc) > 0 {
		h = append(h, "Cc: "+strings.Join(cc, ", "))
	}
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\nYour result is ready.\r\n")
}

// edge is one boot: a fresh Dedupe (new boot key, empty memory) over S3.
type edge struct {
	d     *send.Dedupe
	store *Store
}

func boot(t *testing.T, blobs *memBlobs) edge {
	t.Helper()
	st, err := New(blobs, secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	return edge{d: send.NewDedupe(send.DedupeOptions{Records: st}), store: st}
}

// transmit is an attempt that delivers by status, counting deliveries.
type transmit struct {
	mu     sync.Mutex
	status map[string]send.Status
	calls  [][]string
	err    error
}

func (x *transmit) attempt(_ context.Context, sub *send.Message, commit func() error) ([]send.Result, error) {
	if err := commit(); err != nil {
		return nil, err
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.err != nil {
		return nil, x.err
	}
	x.calls = append(x.calls, sub.Recipients)
	var out []send.Result
	for _, r := range sub.Recipients {
		s := x.status[r]
		if s == "" {
			s = send.Sent
		}
		out = append(out, send.Result{Recipient: r, Status: s})
	}
	return out, nil
}

func parse(t *testing.T, raw []byte) *send.Message {
	t.Helper()
	m, err := send.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var mailbox = bytes.Repeat([]byte{7}, 32)

// A message sent before a reboot is answered from the durable record after it:
// no second delivery, and "was it sent?" says done.
func TestSentSurvivesReboot(t *testing.T) {
	blobs := newMemBlobs()
	x := &transmit{}
	raw := message("draft-1.r2@fountbox.com")
	ctx := context.Background()

	e1 := boot(t, blobs)
	if _, err := e1.d.Do(ctx, mailbox, parse(t, raw), x.attempt); err != nil {
		t.Fatal(err)
	}

	e2 := boot(t, blobs)
	res, err := e2.d.Do(ctx, mailbox, parse(t, raw), x.attempt)
	if err != nil || len(res) != 1 || res[0].Status != send.Sent || res[0].Recipient != "pat@smithcpa.com" {
		t.Fatalf("after reboot: %+v %v", res, err)
	}
	if len(x.calls) != 1 {
		t.Fatalf("%d deliveries, want 1", len(x.calls))
	}

	e3 := boot(t, blobs)
	st, err := e3.d.Lookup(ctx, mailbox, "draft-1.r2@fountbox.com") // without brackets
	sum := sha256.Sum256(raw)
	if err != nil || st.State != send.SentDone || st.SHA256 != hex.EncodeToString(sum[:]) || len(st.Results) != 1 || st.Results[0].Recipient != "pat@smithcpa.com" {
		t.Fatalf("lookup: %+v %v", st, err)
	}
	if st, _ := e3.d.Lookup(ctx, mailbox, "<other@fountbox.com>"); st.State != send.SentNone {
		t.Fatalf("unsent: %+v", st)
	}
	// Another worker's record is its own.
	if st, _ := e3.d.Lookup(ctx, bytes.Repeat([]byte{8}, 32), "<draft-1.r2@fountbox.com>"); st.State != send.SentNone {
		t.Fatalf("other worker: %+v", st)
	}

	// Other bytes under the same Message-ID are refused after a reboot too.
	if _, err := e3.d.Do(ctx, mailbox, parse(t, message("draft-1.r2@fountbox.com", "jo@smithcpa.com")), x.attempt); !errors.Is(err, send.ErrMessageIDReused) {
		t.Fatalf("reused: %v", err)
	}
}

// A reboot between starting delivery and recording its outcome leaves the send
// in doubt: the edge won't deliver it again.
func TestSentInDoubtAfterACrashMidSend(t *testing.T) {
	blobs := newMemBlobs()
	x := &transmit{}
	raw := message("draft-2.r1@fountbox.com")
	ctx := context.Background()

	e1 := boot(t, blobs)
	// The first write (Unknown, before delivery) lands; the second (the outcome)
	// doesn't, as if the edge had stopped.
	failSecond := &secondPutFails{memBlobs: blobs}
	e1.store.blobs = failSecond
	if _, err := e1.d.Do(ctx, mailbox, parse(t, raw), x.attempt); err != nil {
		t.Fatal(err)
	}

	e2 := boot(t, blobs)
	if st, err := e2.d.Lookup(ctx, mailbox, "<draft-2.r1@fountbox.com>"); err != nil || st.State != send.SentInDoubt || st.Results[0].Status != send.Unknown {
		t.Fatalf("lookup: %+v %v", st, err)
	}
	if _, err := e2.d.Do(ctx, mailbox, parse(t, raw), x.attempt); !errors.Is(err, send.ErrSendInDoubt) {
		t.Fatalf("resend: %v", err)
	}
	if len(x.calls) != 1 {
		t.Fatalf("%d deliveries, want 1", len(x.calls))
	}
}

type secondPutFails struct {
	*memBlobs
	n int
}

func (b *secondPutFails) Put(ctx context.Context, k string, d []byte) error {
	b.n++
	if b.n == 2 {
		return errors.New("edge stopped")
	}
	return b.memBlobs.Put(ctx, k, d)
}

// After a reboot, a retry re-attempts exactly the recipients that ended
// Temporary.
func TestSentRetriesTemporaryAcrossReboot(t *testing.T) {
	blobs := newMemBlobs()
	x := &transmit{status: map[string]send.Status{"jo@smithcpa.com": send.Temporary}}
	raw := message("draft-3.r1@fountbox.com", "jo@smithcpa.com")
	ctx := context.Background()

	if _, err := boot(t, blobs).d.Do(ctx, mailbox, parse(t, raw), x.attempt); err != nil {
		t.Fatal(err)
	}
	e2 := boot(t, blobs)
	if st, _ := e2.d.Lookup(ctx, mailbox, "<draft-3.r1@fountbox.com>"); st.State != send.SentRetryable {
		t.Fatalf("lookup: %+v", st)
	}
	x.status = nil
	res, err := e2.d.Do(ctx, mailbox, parse(t, raw), x.attempt)
	if err != nil || len(x.calls) != 2 || strings.Join(x.calls[1], ",") != "jo@smithcpa.com" || res[0].Status != send.Sent || res[1].Status != send.Sent {
		t.Fatalf("retry: %+v %v %v", res, err, x.calls)
	}
	if st, _ := boot(t, blobs).d.Lookup(ctx, mailbox, "<draft-3.r1@fountbox.com>"); st.State != send.SentDone {
		t.Fatalf("after retry: %+v", st)
	}
}

// If the record can't be written before delivery, nothing is sent.
func TestSentRecordFailureSendsNothing(t *testing.T) {
	blobs := newMemBlobs()
	x := &transmit{}
	e := boot(t, blobs)
	blobs.failNext(1)
	if _, err := e.d.Do(context.Background(), mailbox, parse(t, message("draft-4.r1@fountbox.com")), x.attempt); !errors.Is(err, send.ErrRecordFailed) {
		t.Fatalf("err %v", err)
	}
	if len(x.calls) != 0 {
		t.Fatal("delivered without a record")
	}
	if _, err := e.d.Do(context.Background(), mailbox, parse(t, message("draft-4.r1@fountbox.com")), x.attempt); err != nil || len(x.calls) != 1 {
		t.Fatalf("retry: %v %d", err, len(x.calls))
	}
}

// A send that sent nothing leaves no durable record behind.
func TestSentFailedSendLeavesNoRecord(t *testing.T) {
	blobs := newMemBlobs()
	x := &transmit{err: send.ErrOff}
	if _, err := boot(t, blobs).d.Do(context.Background(), mailbox, parse(t, message("draft-5.r1@fountbox.com")), x.attempt); !errors.Is(err, send.ErrOff) {
		t.Fatalf("err %v", err)
	}
	if objs, _ := blobs.List(context.Background(), Prefix); len(objs) != 0 {
		t.Fatalf("%d records after a send that sent nothing", len(objs))
	}
}

// S3 sees neither the Message-ID nor the recipients, and a record moved to
// another name doesn't open.
func TestSentRecordsAreSealed(t *testing.T) {
	blobs := newMemBlobs()
	e := boot(t, blobs)
	x := &transmit{}
	ctx := context.Background()
	for _, id := range []string{"a@fountbox.com", "b@fountbox.com"} {
		if _, err := e.d.Do(ctx, mailbox, parse(t, message(id)), x.attempt); err != nil {
			t.Fatal(err)
		}
	}
	keyA, keyB := e.store.objectKey(mailbox, "a@fountbox.com"), e.store.objectKey(mailbox, "<b@fountbox.com>")
	for k, v := range blobs.m {
		for _, leak := range []string{"a@fountbox.com", "smithcpa", "pat@"} {
			if strings.Contains(k, leak) || bytes.Contains(v, []byte(leak)) {
				t.Fatalf("%q visible in S3", leak)
			}
		}
	}
	blobs.m[keyA] = blobs.m[keyB]
	if _, err := e.store.Load(ctx, mailbox, "a@fountbox.com"); err == nil {
		t.Fatal("a swapped record opened")
	}
	other, _ := New(blobs, []byte("another key"), 0)
	if r, _ := other.Load(ctx, mailbox, "b@fountbox.com"); r != nil {
		t.Fatal("opened under another key")
	}
}

func TestSentSweep(t *testing.T) {
	blobs := newMemBlobs()
	st, _ := New(blobs, secret, 10*24*time.Hour)
	ctx := context.Background()
	rec := func(id string) *send.SentRecord {
		return &send.SentRecord{MessageID: "<" + id + ">", Recipients: []string{"pat@smithcpa.com"}, Outcomes: []send.Result{{Status: send.Sent}}}
	}
	if err := st.Save(ctx, mailbox, rec("old@x")); err != nil {
		t.Fatal(err)
	}
	blobs.now = blobs.now.Add(5 * 24 * time.Hour)
	_ = st.Save(ctx, mailbox, rec("new@x"))
	n, err := st.Sweep(ctx, blobs.now.Add(6*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("swept %d %v", n, err)
	}
	if r, _ := st.Load(ctx, mailbox, "old@x"); r != nil {
		t.Fatal("old record kept")
	}
	if r, _ := st.Load(ctx, mailbox, "new@x"); r == nil {
		t.Fatal("record inside the retention swept")
	}
	if st.Retention() != 10*24*time.Hour {
		t.Fatal(st.Retention())
	}
	if d, _ := New(blobs, secret, 0); d.Retention() != DefaultRetention {
		t.Fatal("default")
	}
}
