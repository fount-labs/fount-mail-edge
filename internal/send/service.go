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
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

// sendBudget keeps a send inside the Device API's 2-minute write timeout, so the
// device always hears how it went.
const sendBudget = 90 * time.Second

// ErrBadMessage wraps every reason Parse refuses a message.
var ErrBadMessage = errors.New("bad message")

type deliverer interface {
	Deliver(ctx context.Context, from string, recipients []string, data []byte) []Result
}

// Service runs one send: check, sign, deliver.
type Service struct {
	Policy    *Policy
	Signers   []*dkim.Signer // RSA first, then Ed25519 (RFC 8463 §4)
	Deliverer deliverer
	Now       func() time.Time
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
	if len(s.Signers) == 0 {
		return nil, errors.New("no DKIM key")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	var signed []byte
	for _, signer := range s.Signers {
		field, err := signer.Sign(m.Raw, now())
		if err != nil {
			return nil, err
		}
		signed = append(signed, field...)
	}
	signed = append(signed, m.Raw...)
	ctx, cancel := context.WithTimeout(ctx, sendBudget)
	defer cancel()
	res := s.Deliverer.Deliver(ctx, m.From, m.Recipients, signed)
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
