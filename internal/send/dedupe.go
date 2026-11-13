package send

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Dedupe defaults. Per-worker sends are capped at DefaultPerWorkerPerDay, so an
// entry per send for a day is small; the cap only stops a flood of workers
// growing memory without bound.
const (
	DefaultDedupeTTL = 24 * time.Hour
	DefaultDedupeMax = 20000
)

// transmitBudget bounds one delivery once it has left the caller's hands: the
// Outbox's own sendBudget, plus the link to mail-send in a split edge. It stays
// inside the Device API's 2-minute write timeout.
const transmitBudget = sendBudget + 15*time.Second

var (
	// ErrSendInProgress means a send of this Message-ID from this worker is
	// still being delivered, and the caller stopped waiting for it.
	ErrSendInProgress = errors.New("a send of this Message-ID is in progress")
	// ErrMessageIDReused means this worker already sent a different message
	// under this Message-ID. A retry resends the same bytes.
	ErrMessageIDReused = errors.New("this Message-ID was already sent with different content")
)

// Dedupe makes POST /send safe to retry. It records, per worker and Message-ID,
// what the first send did to each recipient, so a device retrying after a
// timeout or a failed DATA can't deliver twice or spend a second token from
// Policy's limits.
//
//   - A repeat of a message whose recipients all ended Sent or Permanent returns
//     those results and sends nothing.
//   - A repeat while the first is still being delivered waits for it and returns
//     its results. The first runs detached from its request, so a device that
//     hung up still gets the outcome on its retry instead of a torn session.
//   - A repeat re-attempts exactly the recipients whose latest result is
//     Temporary, and none other. Temporary means "the device may retry"
//     (deliver.go): the edge keeps no queue, so the device's retry is the only
//     way such a recipient is ever reached, and answering it from the record
//     would turn a passing failure into a lost message for a day. A re-attempt
//     is a new delivery, so it passes Policy again and spends a token, as any
//     send does; the limits stay the one bound on what a worker sends.
//   - The same Message-ID with other bytes is ErrMessageIDReused, not a repeat:
//     answering it from the record would silently drop a different message.
//
// The record is keyed by HMAC(mailbox ID, Message-ID) under a key drawn at boot,
// and holds a keyed digest of the message and each recipient's status and
// detail by position. It stores no address of its own, though a detail may quote
// one from an MX's reply, and never logs. It lives in memory only and
// resets on a reboot, like Policy's limits: a retry across a reboot is a fresh
// send. Entries expire DefaultDedupeTTL after the first send; past the size cap
// the oldest settled entry goes first.
type Dedupe struct {
	key []byte
	ttl time.Duration
	max int
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*sendRecord
	order   *list.List // keys, oldest first send at the front
}

type sendRecord struct {
	digest   []byte
	expires  time.Time
	busy     chan struct{} // non-nil while a delivery runs; closed when it ends
	outcomes []Result      // by position in the message's Recipients; Recipient unset
	elem     *list.Element
}

type DedupeOptions struct {
	TTL time.Duration    // 0 is DefaultDedupeTTL
	Max int              // 0 is DefaultDedupeMax
	Now func() time.Time // nil is time.Now
}

func NewDedupe(o DedupeOptions) *Dedupe {
	d := &Dedupe{
		key:     make([]byte, 32),
		ttl:     o.TTL,
		max:     o.Max,
		now:     o.Now,
		entries: map[string]*sendRecord{},
		order:   list.New(),
	}
	if d.ttl <= 0 {
		d.ttl = DefaultDedupeTTL
	}
	if d.max <= 0 {
		d.max = DefaultDedupeMax
	}
	if d.now == nil {
		d.now = time.Now
	}
	if _, err := rand.Read(d.key); err != nil {
		panic("send: cannot read random for the dedupe key: " + err.Error())
	}
	return d
}

// attemptFunc checks and delivers sub, a copy of the message with only the
// recipients to try now.
type attemptFunc func(ctx context.Context, sub *Message) ([]Result, error)

// Do runs attempt for m from mailboxID unless the record already answers it.
// Its error is attempt's, ErrSendInProgress, or ErrMessageIDReused.
func (d *Dedupe) Do(ctx context.Context, mailboxID []byte, m *Message, attempt attemptFunc) ([]Result, error) {
	k := d.recordKey(mailboxID, m.MessageID)
	digest := d.mac('r', m.Raw)
	for {
		d.mu.Lock()
		now := d.now()
		d.expire(now)
		rec := d.entries[k]
		if rec != nil && rec.busy == nil && !now.Before(rec.expires) {
			d.remove(k, rec)
			rec = nil
		}
		if rec == nil {
			rec = d.add(k, digest, now)
			d.mu.Unlock()
			return d.run(ctx, k, rec, m, allPositions(len(m.Recipients)), attempt)
		}
		if !hmac.Equal(rec.digest, digest) {
			d.mu.Unlock()
			return nil, ErrMessageIDReused
		}
		if ch := rec.busy; ch != nil {
			d.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ErrSendInProgress
			}
		}
		var retry []int
		for i, o := range rec.outcomes {
			if o.Status == Temporary {
				retry = append(retry, i)
			}
		}
		if len(retry) == 0 {
			out := rec.results(m)
			d.mu.Unlock()
			return out, nil
		}
		rec.busy = make(chan struct{})
		d.mu.Unlock()
		return d.run(ctx, k, rec, m, retry, attempt)
	}
}

// run delivers to the recipients at positions, detached from ctx so a caller
// that hangs up doesn't tear the SMTP session, and records what happened.
func (d *Dedupe) run(ctx context.Context, k string, rec *sendRecord, m *Message, positions []int, attempt attemptFunc) ([]Result, error) {
	sub := *m
	sub.Recipients = make([]string, len(positions))
	for i, p := range positions {
		sub.Recipients[i] = m.Recipients[p]
	}
	tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), transmitBudget)
	res, err := attempt(tctx, &sub)
	cancel()

	d.mu.Lock()
	defer d.mu.Unlock()
	close(rec.busy)
	rec.busy = nil
	if err != nil {
		// Nothing was sent. A first send leaves no record, so a retry is a fresh
		// send; a re-attempt leaves the earlier outcomes as they were.
		if rec.outcomes == nil {
			d.remove(k, rec)
		}
		return nil, err
	}
	if rec.outcomes == nil {
		rec.outcomes = make([]Result, len(m.Recipients))
	}
	for _, p := range positions {
		rec.outcomes[p] = Result{Status: Temporary, Detail: "no result for this recipient"}
		for _, r := range res {
			if r.Recipient == m.Recipients[p] {
				rec.outcomes[p] = Result{Status: r.Status, Detail: r.Detail}
				break
			}
		}
	}
	return rec.results(m), nil
}

// results names each recorded outcome's recipient from m, whose bytes match the
// recorded digest, so its Recipients are the recorded ones in the same order.
func (r *sendRecord) results(m *Message) []Result {
	out := make([]Result, len(r.outcomes))
	for i, o := range r.outcomes {
		out[i] = Result{Recipient: m.Recipients[i], Status: o.Status, Detail: o.Detail}
	}
	return out
}

func (d *Dedupe) add(k string, digest []byte, now time.Time) *sendRecord {
	// Settled entries go oldest first. One being delivered stays, so the cap can
	// be passed by at most the sends in flight.
	for e := d.order.Front(); e != nil && len(d.entries) >= d.max; {
		next := e.Next()
		key := e.Value.(string)
		if old := d.entries[key]; old.busy == nil {
			d.remove(key, old)
		}
		e = next
	}
	rec := &sendRecord{digest: digest, expires: now.Add(d.ttl), busy: make(chan struct{})}
	rec.elem = d.order.PushBack(k)
	d.entries[k] = rec
	return rec
}

func (d *Dedupe) remove(k string, rec *sendRecord) {
	if d.entries[k] == rec {
		delete(d.entries, k)
		d.order.Remove(rec.elem)
	}
}

// expire drops entries past their TTL. Every entry has the same TTL from its
// first send, and order is by first send, so the expired ones are at the front.
func (d *Dedupe) expire(now time.Time) {
	for e := d.order.Front(); e != nil; e = d.order.Front() {
		key := e.Value.(string)
		rec := d.entries[key]
		if rec.busy != nil || now.Before(rec.expires) {
			return
		}
		d.remove(key, rec)
	}
}

func (d *Dedupe) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

func (d *Dedupe) recordKey(mailboxID []byte, messageID string) string {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(mailboxID)))
	b = append(b, mailboxID...)
	return string(d.mac('k', append(b, messageID...)))
}

// mac separates the record key from the content digest by a leading label.
func (d *Dedupe) mac(label byte, b []byte) []byte {
	h := hmac.New(sha256.New, d.key)
	h.Write([]byte{label})
	h.Write(b)
	return h.Sum(nil)
}

func allPositions(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}
