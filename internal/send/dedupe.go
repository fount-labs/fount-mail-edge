package send

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
)

// Dedupe defaults. Per-worker sends are capped at DefaultPerWorkerPerDay, so an
// entry per send for a day is small; the cap only stops a flood of workers
// growing memory without bound. Past them, the durable record answers.
const (
	DefaultDedupeTTL = 24 * time.Hour
	DefaultDedupeMax = 20000
)

// transmitBudget bounds one delivery once it has left the caller's hands: the
// Outbox's own sendBudget, plus the link to mail-send in a split edge. It stays
// inside the Device API's 2-minute write timeout.
const transmitBudget = sendBudget + 15*time.Second

// recordBudget bounds one write of a durable send record.
const recordBudget = 7 * time.Second

// Unknown is a recipient whose delivery began and whose outcome was never
// recorded: the edge stopped mid-send. Only a durable record carries it.
const Unknown Status = "unknown"

var (
	// ErrSendInProgress means a send of this Message-ID from this worker is
	// still being delivered, and the caller stopped waiting for it.
	ErrSendInProgress = errors.New("a send of this Message-ID is in progress")
	// ErrMessageIDReused means this worker already sent a different message
	// under this Message-ID. A retry resends the same bytes.
	ErrMessageIDReused = errors.New("this Message-ID was already sent with different content")
	// ErrSendInDoubt means an earlier send of this Message-ID began and the edge
	// stopped before recording how it ended, so it may have been delivered. The
	// edge won't send it again; a new Message-ID is a new message.
	ErrSendInDoubt = errors.New("an earlier send of this Message-ID may have been delivered, and its outcome is unknown")
	// ErrRecordFailed means the send record couldn't be read or written, so
	// nothing was sent.
	ErrRecordFailed = errors.New("could not record the send")
)

// SentRecord is the durable record of one Message-ID's sends from one worker,
// what SentRecords keeps. Outcomes are by position in Recipients.
type SentRecord struct {
	MessageID  string   `json:"message_id"`
	SHA256     []byte   `json:"sha256"` // of the message as posted to /send
	FirstAt    int64    `json:"first_at"`
	UpdatedAt  int64    `json:"updated_at"`
	Recipients []string `json:"recipients"`
	Outcomes   []Result `json:"outcomes"` // Recipient unset
	// Kind is KindInvite for a team invite (POST /coordinator/invite), else
	// empty. It's set on the first send and kept.
	Kind string `json:"kind,omitempty"`
}

// SentRecords keeps send records across reboots (package sent, over S3). Load
// returns nil and no error for a Message-ID never sent.
type SentRecords interface {
	Load(ctx context.Context, mailboxID []byte, messageID string) (*SentRecord, error)
	Save(ctx context.Context, mailboxID []byte, r *SentRecord) error
	Delete(ctx context.Context, mailboxID []byte, messageID string) error
}

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
//   - A recipient whose outcome is Unknown (the edge stopped mid-send) is never
//     re-attempted: the message is ErrSendInDoubt.
//
// The in-memory record is keyed by HMAC(mailbox ID, Message-ID) under a key
// drawn at boot, holds the message's SHA-256 and each recipient's status and
// detail by position, and never logs. Entries expire DefaultDedupeTTL after the
// first send; past the size cap the oldest settled entry goes first.
//
// With Records set, every send is also recorded durably (fount launch-plan
// decision 14), so a retry across a reboot is answered as one within it: before
// delivery starts the record marks the recipients being tried Unknown, and once
// they're done it holds their outcomes. If the edge stops in between, they stay
// Unknown. That record is also what GET-style lookups (Lookup) answer from.
type Dedupe struct {
	key     []byte
	ttl     time.Duration
	max     int
	now     func() time.Time
	records SentRecords

	mu      sync.Mutex
	entries map[string]*sendRecord
	order   *list.List // keys, oldest first send at the front
}

type sendRecord struct {
	digest   []byte // SHA-256 of the message
	expires  time.Time
	firstAt  int64
	busy     chan struct{} // non-nil while a delivery or a durable read runs; closed when it ends
	outcomes []Result      // by position in the message's Recipients; Recipient unset
	rcpts    []string      // the message's Recipients, for Lookup
	kind     string        // the first send's Message.Kind
	elem     *list.Element
}

type DedupeOptions struct {
	TTL     time.Duration    // 0 is DefaultDedupeTTL
	Max     int              // 0 is DefaultDedupeMax
	Now     func() time.Time // nil is time.Now
	Records SentRecords      // nil keeps records in memory only
}

func NewDedupe(o DedupeOptions) *Dedupe {
	d := &Dedupe{
		key:     make([]byte, 32),
		ttl:     o.TTL,
		max:     o.Max,
		now:     o.Now,
		records: o.Records,
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

// NormalizeMessageID is the form a Message-ID keys records under: trimmed, in
// angle brackets.
func NormalizeMessageID(id string) string {
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, "<") {
		id = "<" + id + ">"
	}
	return id
}

// attemptFunc checks sub, a copy of the message with only the recipients to try
// now, calls commit once it has decided to deliver, and delivers. It returns
// commit's error, if any, without delivering.
type attemptFunc func(ctx context.Context, sub *Message, commit func() error) ([]Result, error)

// Do runs attempt for m from mailboxID unless the record already answers it.
// Its error is attempt's, ErrSendInProgress, ErrMessageIDReused, ErrSendInDoubt
// or ErrRecordFailed.
func (d *Dedupe) Do(ctx context.Context, mailboxID []byte, m *Message, attempt attemptFunc) ([]Result, error) {
	k := d.recordKey(mailboxID, m.MessageID)
	sum := sha256.Sum256(m.Raw)
	digest := sum[:]
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
			rec.rcpts = slices.Clone(m.Recipients)
			rec.kind = m.Kind
			d.mu.Unlock()
			return d.first(ctx, k, rec, mailboxID, m, attempt)
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
		rec.busy = make(chan struct{})
		d.mu.Unlock()
		return d.resume(ctx, k, rec, mailboxID, m, attempt)
	}
}

// first handles a Message-ID this boot has no record of. With durable records it
// may still have been sent before a reboot, so their record decides.
func (d *Dedupe) first(ctx context.Context, k string, rec *sendRecord, mailboxID []byte, m *Message, attempt attemptFunc) ([]Result, error) {
	if d.records == nil {
		return d.run(ctx, k, rec, mailboxID, m, allPositions(len(m.Recipients)), attempt)
	}
	lctx, cancel := context.WithTimeout(ctx, recordBudget)
	prev, err := d.records.Load(lctx, mailboxID, m.MessageID)
	cancel()
	switch {
	case err != nil:
		d.finish(k, rec, true)
		return nil, fmt.Errorf("%w: %v", ErrRecordFailed, err)
	case prev == nil:
		return d.run(ctx, k, rec, mailboxID, m, allPositions(len(m.Recipients)), attempt)
	case !hmac.Equal(prev.SHA256, rec.digest):
		d.finish(k, rec, true)
		return nil, ErrMessageIDReused
	}
	d.mu.Lock()
	rec.firstAt, rec.kind = prev.FirstAt, prev.Kind
	rec.outcomes = make([]Result, len(m.Recipients))
	for i := range rec.outcomes {
		rec.outcomes[i] = Result{Status: Unknown}
		if i < len(prev.Outcomes) {
			rec.outcomes[i] = Result{Status: prev.Outcomes[i].Status, Detail: prev.Outcomes[i].Detail}
		}
	}
	d.mu.Unlock()
	return d.resume(ctx, k, rec, mailboxID, m, attempt)
}

// resume decides a repeat, holding rec.busy: answer from the record, refuse an
// in-doubt send, or re-attempt the Temporary recipients.
func (d *Dedupe) resume(ctx context.Context, k string, rec *sendRecord, mailboxID []byte, m *Message, attempt attemptFunc) ([]Result, error) {
	d.mu.Lock()
	var retry []int
	doubt := false
	for i, o := range rec.outcomes {
		switch o.Status {
		case Temporary:
			retry = append(retry, i)
		case Unknown:
			doubt = true
		}
	}
	out := rec.results(m)
	d.mu.Unlock()
	switch {
	case doubt:
		d.finish(k, rec, false)
		return nil, ErrSendInDoubt
	case len(retry) == 0:
		d.finish(k, rec, false)
		return out, nil
	}
	return d.run(ctx, k, rec, mailboxID, m, retry, attempt)
}

// run delivers to the recipients at positions, detached from ctx so a caller
// that hangs up doesn't tear the SMTP session, and records what happened. It
// holds rec.busy until the durable record is written, so the next attempt can't
// overtake it.
func (d *Dedupe) run(ctx context.Context, k string, rec *sendRecord, mailboxID []byte, m *Message, positions []int, attempt attemptFunc) ([]Result, error) {
	sub := *m
	sub.Recipients = make([]string, len(positions))
	for i, p := range positions {
		sub.Recipients[i] = m.Recipients[p]
	}
	dctx := context.WithoutCancel(ctx)
	firstSend := rec.outcomes == nil
	committed := false
	commit := func() error {
		if d.records == nil {
			committed = true
			return nil
		}
		d.mu.Lock()
		pre := d.durable(rec, m, positions)
		d.mu.Unlock()
		if err := d.save(dctx, mailboxID, pre); err != nil {
			return fmt.Errorf("%w: %v", ErrRecordFailed, err)
		}
		committed = true
		return nil
	}
	tctx, cancel := context.WithTimeout(dctx, transmitBudget)
	res, err := attempt(tctx, &sub, commit)
	cancel()

	if err != nil {
		// Nothing was sent. A first send leaves no record, so a retry is a fresh
		// send; a re-attempt leaves the earlier outcomes as they were.
		if committed && d.records != nil {
			d.undo(dctx, rec, mailboxID, m, firstSend)
		}
		d.finish(k, rec, firstSend)
		return nil, err
	}
	d.mu.Lock()
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
	out := rec.results(m)
	post := d.durable(rec, m, nil)
	d.mu.Unlock()
	if d.records != nil {
		if err := d.save(dctx, mailboxID, post); err != nil {
			// The record says Unknown for these recipients, so after a reboot this
			// send is in doubt rather than repeated. Counts only in the log.
			log.Printf("send: recording a send's outcome failed; it stays in doubt after a reboot: %v", err)
		}
	}
	d.finish(k, rec, false)
	return out, nil
}

// undo puts the durable record back after an attempt that sent nothing.
func (d *Dedupe) undo(ctx context.Context, rec *sendRecord, mailboxID []byte, m *Message, firstSend bool) {
	var err error
	if firstSend {
		dctx, cancel := context.WithTimeout(ctx, recordBudget)
		err = d.records.Delete(dctx, mailboxID, m.MessageID)
		cancel()
	} else {
		d.mu.Lock()
		prev := d.durable(rec, m, nil)
		d.mu.Unlock()
		err = d.save(ctx, mailboxID, prev)
	}
	if err != nil {
		log.Printf("send: restoring a send record after a send that sent nothing failed; it reads in doubt: %v", err)
	}
}

func (d *Dedupe) save(ctx context.Context, mailboxID []byte, r *SentRecord) error {
	sctx, cancel := context.WithTimeout(ctx, recordBudget)
	defer cancel()
	return d.records.Save(sctx, mailboxID, r)
}

// durable is rec as a SentRecord, with the recipients at pending marked
// Unknown. Caller holds d.mu.
func (d *Dedupe) durable(rec *sendRecord, m *Message, pending []int) *SentRecord {
	out := &SentRecord{
		MessageID:  m.MessageID,
		SHA256:     bytes.Clone(rec.digest),
		FirstAt:    rec.firstAt,
		UpdatedAt:  d.now().Unix(),
		Recipients: slices.Clone(m.Recipients),
		Outcomes:   make([]Result, len(m.Recipients)),
		Kind:       rec.kind,
	}
	for i := range out.Outcomes {
		out.Outcomes[i] = Result{Status: Unknown}
		if i < len(rec.outcomes) {
			out.Outcomes[i] = rec.outcomes[i]
		}
	}
	for _, p := range pending {
		out.Outcomes[p] = Result{Status: Unknown}
	}
	return out
}

// finish releases rec.busy, and drops rec when nothing was recorded.
func (d *Dedupe) finish(k string, rec *sendRecord, drop bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	close(rec.busy)
	rec.busy = nil
	if drop {
		d.remove(k, rec)
	}
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
	rec := &sendRecord{digest: digest, expires: now.Add(d.ttl), firstAt: now.Unix(), busy: make(chan struct{})}
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
	return string(d.mac('k', append(b, NormalizeMessageID(messageID)...)))
}

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

// SentState sums up what the edge knows of one Message-ID from one worker.
type SentState string

const (
	SentNone       SentState = "none"        // no record: never sent, or past retention
	SentInProgress SentState = "in_progress" // being delivered now
	SentInDoubt    SentState = "in_doubt"    // a send began and its outcome was never recorded
	SentRetryable  SentState = "retryable"   // some recipient ended Temporary; POST /send again re-attempts them
	SentDone       SentState = "done"        // every recipient ended Sent or Permanent
)

// SentStatus answers "was this Message-ID sent?".
type SentStatus struct {
	MessageID string    `json:"message_id"`
	State     SentState `json:"state"`
	SHA256    string    `json:"sha256,omitempty"` // hex, of the message as posted
	FirstAt   int64     `json:"first_at,omitempty"`
	UpdatedAt int64     `json:"updated_at,omitempty"`
	Results   []Result  `json:"results,omitempty"` // by recipient, in the message's order
	Kind      string    `json:"kind,omitempty"`    // KindInvite for a team invite
}

// Lookup reports what the edge knows of messageID from mailboxID: this boot's
// record if it has one, otherwise the durable one.
func (d *Dedupe) Lookup(ctx context.Context, mailboxID []byte, messageID string) (SentStatus, error) {
	st := SentStatus{MessageID: messageID, State: SentNone}
	d.mu.Lock()
	rec := d.entries[d.recordKey(mailboxID, messageID)]
	if rec != nil && (rec.busy != nil || d.now().Before(rec.expires)) && (rec.busy != nil || rec.outcomes != nil) {
		st.SHA256, st.FirstAt, st.Kind = hex.EncodeToString(rec.digest), rec.firstAt, rec.kind
		st.Results = make([]Result, len(rec.outcomes))
		for i, o := range rec.outcomes {
			st.Results[i] = Result{Recipient: rec.rcpts[i], Status: o.Status, Detail: o.Detail}
		}
		st.State = stateOf(st.Results)
		if rec.busy != nil {
			st.State = SentInProgress
		}
		d.mu.Unlock()
		return st, nil
	}
	d.mu.Unlock()
	if d.records == nil {
		return st, nil
	}
	prev, err := d.records.Load(ctx, mailboxID, messageID)
	if err != nil || prev == nil {
		return st, err
	}
	st.SHA256, st.FirstAt, st.UpdatedAt, st.Kind = hex.EncodeToString(prev.SHA256), prev.FirstAt, prev.UpdatedAt, prev.Kind
	st.Results = make([]Result, len(prev.Outcomes))
	for i, o := range prev.Outcomes {
		st.Results[i] = Result{Status: o.Status, Detail: o.Detail}
		if i < len(prev.Recipients) {
			st.Results[i].Recipient = prev.Recipients[i]
		}
	}
	st.State = stateOf(st.Results)
	return st, nil
}

func stateOf(outcomes []Result) SentState {
	st := SentDone
	for _, o := range outcomes {
		switch o.Status {
		case Unknown:
			return SentInDoubt
		case Temporary:
			st = SentRetryable
		}
	}
	return st
}
