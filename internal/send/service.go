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

// Service runs one send: check, then hand to the Transmitter.
type Service struct {
	Policy *Policy
	Out    Transmitter // an *Outbox in one container; mail-send over the link in a split edge
}

// Send delivers raw from the worker mailboxID. A non-nil error means nothing was
// sent; otherwise each recipient has its own result.
func (s *Service) Send(ctx context.Context, mailboxID, raw []byte) ([]Result, error) {
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	if err := s.Policy.Check(mailboxID, m); err != nil {
		return nil, err
	}
	return s.Out.Transmit(ctx, m.From, m.Recipients, m.Raw)
}
