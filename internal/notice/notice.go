// Package notice sends the edge's owner notices (design §10, §14): the "Reply to
// turn on email updates" proof mail, and the new-owner and owner-removed notices.
// They queue in routing data (routing.Notice); Mailer is routing.NoticeMailer on
// top of the send path, so a notice gets the same DKIM keys, the same validated
// TLS and the same locked relay as POST /send.
//
// The connect mail (connect.go) goes the same way, sent at once for POST /connect.
//
// cmd/edge runs it only when sending is on. With sending off nothing drains the
// queue, so notices wait in routing data rather than being dropped.
//
// Decisions (2026-11-11, **proposed**, like every other limit here):
//
//   - From is fount@<domain>, the reserved name the proof reply address already
//     uses (routing.ProofLocalPart). It isn't a mailbox, so a reply to anything
//     but a proof mail is refused at RCPT. It is the envelope sender too, so the
//     DKIM d= and the From domain align (DMARC).
//   - Notices don't spend, and aren't blocked by, a worker's or a license's
//     POST /send caps. Security notices go out in every mode and through a pause
//     (§8, §14), and a device that spent its send budget mustn't be able to add
//     an owner unseen. Their volume is bounded where they're made (5 new owners a
//     license a day, MaxNotices queued), and they have their own per-license
//     cap, PerLicensePerDay, past which they wait rather than drop.
//   - A temporary failure waits and retries with backoff, from FirstRetry
//     doubling to MaxRetry, for GiveUp from the first try. The retry state is in
//     memory, like every limit: a reboot retries at once and restarts GiveUp, and
//     the notice itself is never lost to one.
//   - A permanent failure (a 5xx, no MX, a null MX, an address the edge can't
//     write in a header), or GiveUp passing, removes the notice: it can never
//     be sent, and keeping it would fill the queue that refuses owner changes.
//     Only the count is logged; no address reaches a log (gap 3.2).
package notice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

const (
	PerLicensePerDay = 50
	FirstRetry       = time.Minute
	MaxRetry         = time.Hour
	GiveUp           = 5 * 24 * time.Hour // RFC 5321 §4.5.4.1 suggests 4–5 days
	DrainEvery       = time.Minute

	// sendBudget matches POST /send's: one notice's MX lookup, MTA-STS and session.
	sendBudget = 90 * time.Second
)

var (
	// ErrNotDue means the notice is waiting out its backoff.
	ErrNotDue = errors.New("notice: waiting to retry")
	// ErrLimited means the license's notice cap is spent for now.
	ErrLimited = errors.New("notice: license notice limit reached")
)

// Deliverer is send.Deliverer: delivery straight to the recipient's MX through
// the relay, with validated TLS.
type Deliverer interface {
	Deliver(ctx context.Context, from string, recipients []string, data []byte) []send.Result
}

// Options is everything a Mailer needs. cmd/edge passes the Transmitter its
// send.Service uses, so there's no second way out: the edge's own Outbox in one
// container, mail-send over the link in a split edge. Without Out, a Mailer
// builds an Outbox from Signers and Deliverer.
type Options struct {
	MailDomain string // "@fountbox.com"
	Out        send.Transmitter
	Signers    []*dkim.Signer
	Deliverer  Deliverer
	License    func(worker []byte) ([]byte, bool) // routing.Store.LicenseOf
	PerLicense int                                // notices per license per day; 0 is PerLicensePerDay
	Now        func() time.Time
}

// Mailer is routing.NoticeMailer.
type Mailer struct {
	domain  string // "fountbox.com"
	from    string
	out     send.Transmitter
	license func([]byte) ([]byte, bool)
	limit   *limit.Limiter
	now     func() time.Time

	mu    sync.Mutex
	tries map[string]*tries
}

type tries struct {
	first, next time.Time
	n           int
}

var _ routing.NoticeMailer = (*Mailer)(nil)

func New(o Options) (*Mailer, error) {
	domain := strings.TrimPrefix(strings.ToLower(o.MailDomain), "@")
	switch {
	case domain == "":
		return nil, errors.New("notice: no mail domain")
	case o.Out == nil && len(o.Signers) == 0:
		return nil, errors.New("notice: no DKIM key")
	case o.Out == nil && o.Deliverer == nil:
		return nil, errors.New("notice: no send path")
	case o.License == nil:
		return nil, errors.New("notice: no license lookup")
	}
	per := o.PerLicense
	if per <= 0 {
		per = PerLicensePerDay
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	out := o.Out
	if out == nil {
		out = &send.Outbox{MailDomain: "@" + domain, Signers: o.Signers, Deliverer: o.Deliverer, Now: now}
	}
	return &Mailer{
		domain:  domain,
		from:    routing.ProofLocalPart + "@" + domain,
		out:     out,
		license: o.License,
		limit:   limit.PerWindow(float64(per), 24*time.Hour),
		now:     now,
		tries:   map[string]*tries{},
	}, nil
}

// SendNotice sends one notice. nil means sent; an error wrapping
// routing.ErrNoticeUndeliverable means drop it; any other error means try again
// on a later pass.
func (m *Mailer) SendNotice(ctx context.Context, n routing.PendingNotice) error {
	now := m.now()
	m.mu.Lock()
	m.prune(now)
	t := m.tries[n.ID]
	m.mu.Unlock()
	if t != nil && now.Before(t.next) {
		return ErrNotDue
	}

	raw, err := m.message(n, now)
	if err != nil {
		m.forget(n.ID)
		return fmt.Errorf("%w: %v", routing.ErrNoticeUndeliverable, err)
	}
	key := "worker:" + hex.EncodeToString(n.Worker)
	if lic, ok := m.license(n.Worker); ok && len(lic) > 0 {
		key = string(lic)
	}
	if !m.limit.Allow(key) {
		return ErrLimited
	}
	ctx, cancel := context.WithTimeout(ctx, sendBudget)
	defer cancel()
	res, err := m.out.Transmit(ctx, m.from, []string{n.To}, raw)
	if err != nil {
		// Nothing was sent: a key problem, or mail-send off or out of reach. None
		// is the notice's fault, so keep it, and don't count it toward GiveUp.
		return err
	}
	if len(res) != 1 {
		return m.retry(n.ID, now, "no delivery result")
	}
	switch res[0].Status {
	case send.Sent:
		m.forget(n.ID)
		return nil
	case send.Permanent:
		m.forget(n.ID)
		return fmt.Errorf("%w: %s", routing.ErrNoticeUndeliverable, res[0].Detail)
	default:
		return m.retry(n.ID, now, res[0].Detail)
	}
}

// retry records a temporary failure and sets the next try, or gives up.
func (m *Mailer) retry(id string, now time.Time, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tries[id]
	if t == nil {
		t = &tries{first: now}
		m.tries[id] = t
	}
	if now.Sub(t.first) >= GiveUp {
		delete(m.tries, id)
		return fmt.Errorf("%w: still failing after %s: %s", routing.ErrNoticeUndeliverable, GiveUp, detail)
	}
	wait := FirstRetry << min(t.n, 10)
	if wait > MaxRetry {
		wait = MaxRetry
	}
	t.n++
	t.next = now.Add(wait)
	return fmt.Errorf("notice: temporary failure, retrying in %s: %s", wait, detail)
}

func (m *Mailer) forget(id string) {
	m.mu.Lock()
	delete(m.tries, id)
	m.mu.Unlock()
}

// prune drops retry state for notices the queue no longer offers, such as a proof
// mail made moot by a reply. Caller holds m.mu.
func (m *Mailer) prune(now time.Time) {
	for id, t := range m.tries {
		if now.Sub(t.first) > 2*GiveUp {
			delete(m.tries, id)
		}
	}
}

// Run drains q through m at once and then every interval, until ctx ends. Only
// counts reach the log.
func Run(ctx context.Context, q Queue, m routing.NoticeMailer, domain string, every time.Duration) {
	pass := func() {
		r, err := q.DrainNotices(ctx, m, domain)
		if err != nil && ctx.Err() == nil {
			log.Printf("notice: drain failed: %v", err)
		}
		if r.Sent > 0 || r.Dropped > 0 {
			log.Printf("notice: %d sent, %d undeliverable and dropped, %d waiting", r.Sent, r.Dropped, r.Waiting)
		}
	}
	pass()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}

// Queue is the notice queue in routing data. routing.Store implements it.
type Queue interface {
	DrainNotices(ctx context.Context, m routing.NoticeMailer, domain string) (routing.DrainResult, error)
}

var _ Queue = (*routing.Store)(nil)

// message builds the fixed notice. It carries no user content beyond the owner
// addresses: the edge doesn't know a worker's address, only its hash.
func (m *Mailer) message(n routing.PendingNotice, now time.Time) ([]byte, error) {
	to, err := plainAddress(n.To)
	if err != nil {
		return nil, err
	}
	var subject, body, replyTo string
	switch n.Kind {
	case routing.NoticeOwnerProof:
		if replyTo, err = plainAddress(n.ReplyTo); err != nil {
			return nil, fmt.Errorf("reply address: %w", err)
		}
		subject = "Reply to turn on email updates"
		body = proofBody
	case routing.NoticeNewOwner:
		about, err := plainAddress(n.About)
		if err != nil {
			return nil, fmt.Errorf("new owner: %w", err)
		}
		subject = "A new owner was added to your Fount workers"
		body = fmt.Sprintf(newOwnerBody, about, int(routing.OwnerWait.Hours()))
	case routing.NoticeOwnerRemoved:
		subject = "You were removed as an owner of Fount workers"
		body = removedBody
	default:
		return nil, fmt.Errorf("unknown notice kind %q", n.Kind)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	var b strings.Builder
	field := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	field("From", "Fount Mail <"+m.from+">")
	field("To", "<"+to+">")
	if replyTo != "" {
		field("Reply-To", "<"+replyTo+">")
	}
	field("Subject", subject)
	field("Date", now.UTC().Format(time.RFC1123Z))
	field("Message-ID", "<"+hex.EncodeToString(id)+"@"+m.domain+">")
	field("Auto-Submitted", "auto-generated") // RFC 3834: no autoresponder answers it, so none proves an owner
	field("MIME-Version", "1.0")
	field("Content-Type", "text/plain; charset=us-ascii")
	field("Content-Transfer-Encoding", "7bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	raw := []byte(b.String())

	// The same shape check POST /send makes, so a notice is never a message the
	// edge would refuse from a device: one From, a Reply-To that is From's own
	// address, and exactly this one recipient.
	msg, err := send.Parse(raw)
	if err != nil {
		return nil, err
	}
	if msg.From != m.from || len(msg.Recipients) != 1 || msg.Recipients[0] != to {
		return nil, errors.New("notice addresses didn't survive parsing")
	}
	return raw, nil
}

// plainAddress accepts only an address that is safe to write in a header as is:
// 7-bit, no display name, no comment, nothing to quote.
func plainAddress(a string) (string, error) {
	for _, c := range []byte(a) {
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`<>()[],;:\"`, c) >= 0 {
			return "", errors.New("address isn't plain 7-bit")
		}
	}
	p, err := mail.ParseAddress(a)
	if err != nil || p.Name != "" || p.Address != a || strings.Count(a, "@") != 1 {
		return "", errors.New("address doesn't parse")
	}
	return strings.ToLower(a), nil
}

const proofBody = `Someone using Fount listed this address as an owner of their Fount
workers.

To turn on email updates from those workers, reply to this email. The
reply doesn't need any text.

If you don't know why you got this, ignore it. Fount Mail sends this
address nothing else unless you reply.
`

const newOwnerBody = `%s was added as an owner of the Fount workers you own.

After a %d-hour wait, and once they reply to their own confirmation
email, they will get email from those workers.

If you didn't expect this, check the workers' owners in the Fount app,
or ask whoever runs them.
`

const removedBody = `This address is no longer an owner of a set of Fount workers, so it
won't get email from them.

If you didn't expect this, check the workers' owners in the Fount app,
or ask whoever runs them.
`
