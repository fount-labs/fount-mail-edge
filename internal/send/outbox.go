package send

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

// ErrOff means sending is off where the message would be signed: in a split edge,
// mail-send has no send keyset or a gate is shut. Nothing was sent.
var ErrOff = errors.New("sending is off")

// Transmitter signs and delivers a message whose sender and recipients its
// caller has already decided on. Outbox is the one that holds the DKIM and relay
// keys; in a split edge (docs/CONTAINER-SPLIT.md) mail-core reaches mail-send's
// Outbox over the link.
type Transmitter interface {
	Transmit(ctx context.Context, from string, recipients []string, raw []byte) ([]Result, error)
}

// Outbox signs with the send keyset and delivers through the relay. It doesn't
// read routing data, so it can't tell an owner from a stranger: Policy does that,
// before the message reaches it. What it checks is what it can see in the message
// itself (CheckHandoff).
type Outbox struct {
	MailDomain string         // "@fountbox.com"
	Signers    []*dkim.Signer // RSA first, then Ed25519 (RFC 8463 §4)
	Deliverer  deliverer
	Now        func() time.Time
	// DNS is the outbox's DoH resolver. The inbound sender check borrows it for
	// DKIM key records (TXT), the one way out mail-core has to DNS.
	DNS Resolver
}

// TXT looks up a TXT record through the outbox's resolver. ErrNoRecord means
// there is none.
func (o *Outbox) TXT(ctx context.Context, name string) ([]string, error) {
	if o.DNS == nil {
		return nil, errors.New("send: no resolver")
	}
	return o.DNS.TXT(ctx, name)
}

var _ Transmitter = (*Outbox)(nil)

// Transmit checks the handoff, signs raw and delivers it. A non-nil error means
// nothing was sent; otherwise each recipient has its own result.
func (o *Outbox) Transmit(ctx context.Context, from string, recipients []string, raw []byte) ([]Result, error) {
	if err := CheckHandoff(o.MailDomain, from, recipients, raw); err != nil {
		return nil, err
	}
	if len(o.Signers) == 0 {
		return nil, errors.New("no DKIM key")
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	var signed []byte
	for _, signer := range o.Signers {
		field, err := signer.Sign(raw, now())
		if err != nil {
			return nil, err
		}
		signed = append(signed, field...)
	}
	signed = append(signed, raw...)
	ctx, cancel := context.WithTimeout(ctx, sendBudget)
	defer cancel()
	res := o.Deliverer.Deliver(ctx, from, recipients, signed)
	sent := 0
	for _, r := range res {
		if r.Status == Sent {
			sent++
		}
	}
	// Counts only: an address or a reply text never reaches the log (gap 3.2).
	log.Printf("send: %d of %d recipients sent", sent, len(res))
	return res, nil
}

// CheckHandoff is what the signer checks again, whoever decided to send: raw has
// the shape Parse accepts, its one From is from and in domain, and recipients
// are some of its To and Cc, none in domain, at most MaxRecipients, no repeats.
// It doesn't replace Policy, which alone knows who owns a worker.
func CheckHandoff(domain, from string, recipients []string, raw []byte) error {
	m, err := Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	domain = strings.ToLower(domain)
	if domain == "" || from != m.From || !strings.HasSuffix(from, domain) {
		return fmt.Errorf("%w: the sender isn't the message's From in %s", ErrBadMessage, domain)
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return fmt.Errorf("%w: %d recipients", ErrBadMessage, len(recipients))
	}
	for i, r := range recipients {
		if !slices.Contains(m.Recipients, r) || slices.Contains(recipients[:i], r) {
			return fmt.Errorf("%w: a recipient isn't one of the message's own, once", ErrBadMessage)
		}
		if strings.HasSuffix(r, domain) {
			return ErrNotOwner
		}
	}
	return nil
}
