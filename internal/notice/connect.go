package notice

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// The connect mail (POST /connect, routing/connect.go): one message from the
// worker's own address to someone the device wants as an owner. Their reply goes
// to the worker, the device matches it to this mail's Message-ID, and hands that
// back on PUT /routing as proof. Like a notice it skips send.Policy, because the
// recipient isn't an owner yet, and goes out through the same Transmitter.
//
// Decisions (2026-11-12, **proposed**):
//
//   - It's sent at once or not at all: the device is waiting, and it can ask
//     again. Nothing queues in routing data.
//   - Its caps are its own and in memory, like every limit: ConnectPerOwnerPerHour
//     per worker and owner, ConnectPerLicensePerDay per license. A connect isn't a
//     new owner, so PUT /routing's daily new-owner cap still applies afterwards.

const (
	ConnectPerOwnerPerHour  = 3
	ConnectPerLicensePerDay = 20

	connectSubject = "Reply to connect your email to %s"
	connectBody    = `Reply to this email to let %s take work from you. You don't need to write anything.

If you didn't ask for this, ignore it and nothing changes.
`
)

var (
	// ErrConnectNotWorker means the address isn't the calling worker's (404).
	ErrConnectNotWorker = errors.New("the address is not this worker's")
	// ErrConnectBadOwner means the owner isn't one plain address outside the
	// mail domain (400).
	ErrConnectBadOwner = errors.New("the owner must be one plain address outside the mail domain")
	// ErrConnectLimited is wrapped by a *ConnectLimitError (429).
	ErrConnectLimited = errors.New("connect limit reached")
	// ErrConnectUndelivered means the owner's server didn't take the mail.
	ErrConnectUndelivered = errors.New("the connect mail wasn't delivered")
)

// ConnectLimitError is a spent connect cap, and roughly when it has room again.
type ConnectLimitError struct{ Wait time.Duration }

func (e *ConnectLimitError) Error() string        { return ErrConnectLimited.Error() }
func (e *ConnectLimitError) Is(target error) bool { return target == ErrConnectLimited }

// ConnectRouting is what a Connector reads. routing.Store implements it.
type ConnectRouting interface {
	MailboxID(address string) []byte
	LicenseOf(mailboxID []byte) ([]byte, bool)
	Snapshot(mailboxID []byte) (routing.Mailbox, bool)
	ConnectMAC(mailboxID []byte, owner string, issuedAt int64) []byte
}

var _ ConnectRouting = (*routing.Store)(nil)

// ConnectOptions is everything a Connector needs.
type ConnectOptions struct {
	MailDomain string // "@fountbox.com"
	Out        send.Transmitter
	Routing    ConnectRouting
	// On reports whether sending is on now; nil is always. A split edge's
	// mail-core follows mail-send's state with it, as POST /send does.
	On  func() bool
	Now func() time.Time
}

// Connector sends connect mail. It's deviceapi.Connector.
type Connector struct {
	domain string // "@fountbox.com"
	out    send.Transmitter
	rt     ConnectRouting
	on     func() bool
	now    func() time.Time
	pair   *limit.Limiter
	lic    *limit.Limiter
}

func NewConnector(o ConnectOptions) (*Connector, error) {
	domain := strings.ToLower(o.MailDomain)
	switch {
	case !strings.HasPrefix(domain, "@") || len(domain) < 2:
		return nil, errors.New("notice: connect needs a mail domain")
	case o.Out == nil:
		return nil, errors.New("notice: connect needs a send path")
	case o.Routing == nil:
		return nil, errors.New("notice: connect needs routing")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Connector{
		domain: domain,
		out:    o.Out,
		rt:     o.Routing,
		on:     o.On,
		now:    now,
		pair:   limit.PerWindow(ConnectPerOwnerPerHour, time.Hour),
		lic:    limit.PerWindow(ConnectPerLicensePerDay, 24*time.Hour),
	}, nil
}

// Connect mails owner from address, which must be mailboxID's own, and returns
// when its proof expires. send.ErrOff means sending is off; nothing was sent.
func (c *Connector) Connect(ctx context.Context, mailboxID []byte, address, owner string) (time.Time, error) {
	worker, err := plainAddress(strings.TrimSpace(address))
	if err != nil || !strings.HasSuffix(worker, c.domain) || len(mailboxID) == 0 || !hmac.Equal(c.rt.MailboxID(worker), mailboxID) {
		return time.Time{}, ErrConnectNotWorker
	}
	// A paused or lapsed worker sends nothing, connect mail included, as POST /send refuses.
	if mb, ok := c.rt.Snapshot(mailboxID); ok && mb.Paused {
		return time.Time{}, send.ErrPaused
	} else if ok && mb.EntitlementExp != 0 && c.now().Unix() >= mb.EntitlementExp {
		return time.Time{}, send.ErrLapsed
	}
	to, err := plainAddress(strings.TrimSpace(owner))
	if err != nil || strings.HasSuffix(to, c.domain) {
		return time.Time{}, ErrConnectBadOwner
	}
	if c.on != nil && !c.on() {
		return time.Time{}, send.ErrOff
	}
	if !c.pair.Allow(hex.EncodeToString(mailboxID) + ":" + hex.EncodeToString(c.rt.MailboxID(to))) {
		return time.Time{}, &ConnectLimitError{Wait: time.Hour / ConnectPerOwnerPerHour}
	}
	lic := "worker:" + hex.EncodeToString(mailboxID)
	if l, ok := c.rt.LicenseOf(mailboxID); ok && len(l) > 0 {
		lic = hex.EncodeToString(l)
	}
	if !c.lic.Allow(lic) {
		return time.Time{}, &ConnectLimitError{Wait: 24 * time.Hour / ConnectPerLicensePerDay}
	}

	now := c.now()
	issued := now.Unix()
	raw := connectMessage(worker, to, routing.ConnectID(issued, c.rt.ConnectMAC(mailboxID, to, issued), c.domain), now)
	ctx, cancel := context.WithTimeout(ctx, sendBudget)
	defer cancel()
	res, err := c.out.Transmit(ctx, worker, []string{to}, raw)
	if err != nil {
		return time.Time{}, err
	}
	if len(res) != 1 {
		return time.Time{}, fmt.Errorf("%w: no delivery result", ErrConnectUndelivered)
	}
	if res[0].Status != send.Sent {
		return time.Time{}, fmt.Errorf("%w: %s", ErrConnectUndelivered, res[0].Detail)
	}
	return time.Unix(issued, 0).Add(routing.ConnectLifetime), nil
}

// connectMessage is the fixed connect mail. Both addresses passed plainAddress,
// so they're safe in a header as is, and the body is 7-bit.
func connectMessage(worker, owner, messageID string, now time.Time) []byte {
	var b strings.Builder
	field := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	field("From", "<"+worker+">")
	field("To", "<"+owner+">")
	field("Subject", fmt.Sprintf(connectSubject, worker))
	field("Date", now.UTC().Format(time.RFC1123Z))
	field("Message-ID", messageID)
	field("Auto-Submitted", "auto-generated") // RFC 3834: most out-of-office replies skip it
	field("MIME-Version", "1.0")
	field("Content-Type", "text/plain; charset=utf-8")
	field("Content-Transfer-Encoding", "7bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(fmt.Sprintf(connectBody, worker), "\n", "\r\n"))
	return []byte(b.String())
}
