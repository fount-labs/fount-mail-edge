// Package send is the edge's outbound path (design §14): POST /send from the
// device, the checks the edge makes itself, DKIM signing, and delivery with
// validated TLS through the gateway's relay.
//
// It launches dark. cmd/edge builds a Service only when the release sets
// SEND_KEYSET_COMMITMENT, SEND_ENABLED, the relay and a DKIM selector, and a vault
// hands over the committed send keyset (fount-mail-vault docs/SEND-KEYS.md). The
// live release sets none of them, and the shim doesn't forward /send.
package send

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// sendBudget keeps a send inside the Device API's 2-minute write timeout, so the
// device always hears how it went.
const sendBudget = 90 * time.Second

// ErrBadMessage wraps every reason Parse refuses a message.
var ErrBadMessage = errors.New("bad message")

type deliverer interface {
	Deliver(ctx context.Context, from string, recipients []string, data []byte) []Result
}

// Service runs one send: check, then hand to the Transmitter. Every POST /send
// passes through it, in the one-container edge and in a split edge's mail-core,
// so its Dedupe sees every send a device makes.
type Service struct {
	Policy *Policy
	Out    Transmitter // an *Outbox in one container; mail-send over the link in a split edge
	Dedupe *Dedupe     // nil is a NewDedupe with the defaults and Records, made on first use
	// Records keeps send records across reboots for the Dedupe made on first use.
	// nil keeps them in memory only.
	Records SentRecords

	once sync.Once
}

// Send delivers raw from the worker mailboxID. A non-nil error means nothing was
// sent this time; otherwise each recipient has its own result. A repeat of a
// Message-ID returns the first send's results, re-attempting only recipients
// that ended Temporary (see Dedupe).
func (s *Service) Send(ctx context.Context, mailboxID, raw []byte) ([]Result, error) {
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	return s.dedupe().Do(ctx, mailboxID, m, func(ctx context.Context, sub *Message, commit func() error) ([]Result, error) {
		if err := s.Policy.Check(mailboxID, sub); err != nil {
			return nil, err
		}
		if err := commit(); err != nil {
			return nil, err
		}
		return s.Out.Transmit(ctx, sub.From, sub.Recipients, sub.Raw)
	})
}

// SendInvite delivers raw from the worker mailboxID as a team invite: the same
// send records and retry rules as Send, but Policy.CheckInvite instead of the
// owner check, and the record marked KindInvite. Its caller has checked the
// coordinator's signature (POST /coordinator/invite).
func (s *Service) SendInvite(ctx context.Context, mailboxID, raw []byte) ([]Result, error) {
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	m.Kind = KindInvite
	return s.dedupe().Do(ctx, mailboxID, m, func(ctx context.Context, sub *Message, commit func() error) ([]Result, error) {
		if err := s.Policy.CheckInvite(mailboxID, sub); err != nil {
			return nil, err
		}
		if err := commit(); err != nil {
			return nil, err
		}
		// Counts only, as Outbox logs: never the address.
		log.Printf("send: a team invite, %d recipient", len(sub.Recipients))
		return s.Out.Transmit(ctx, sub.From, sub.Recipients, sub.Raw)
	})
}

// Lookup answers "was this Message-ID sent?" for the worker mailboxID, from this
// boot's record or the durable one (Dedupe.Lookup).
func (s *Service) Lookup(ctx context.Context, mailboxID []byte, messageID string) (SentStatus, error) {
	return s.dedupe().Lookup(ctx, mailboxID, messageID)
}

func (s *Service) dedupe() *Dedupe {
	s.once.Do(func() {
		if s.Dedupe == nil {
			s.Dedupe = NewDedupe(DedupeOptions{Records: s.Records})
		}
	})
	return s.Dedupe
}
