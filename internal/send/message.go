package send

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fount-labs/fount-mail-edge/internal/header"
)

// MaxRecipients caps the owners one message can go to.
const MaxRecipients = 10

// forbidden are fields the device may not write. The edge adds DKIM itself, and
// the rest either name a party the edge doesn't check (Bcc, Sender) or claim a
// route the message didn't take.
var forbidden = []string{
	"bcc", "sender", "return-path", "received", "dkim-signature",
	"arc-seal", "arc-message-signature", "arc-authentication-results",
	"authentication-results", "resent-from", "resent-sender", "resent-to",
	"resent-cc", "resent-bcc", "resent-date", "resent-message-id",
}

// singletons may appear at most once. Two copies would let the signer and a
// reader each pick a different one.
var singletons = []string{
	"from", "to", "cc", "subject", "date", "message-id", "reply-to",
	"in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding",
}

var required = []string{"from", "to", "subject", "date", "message-id"}

// Message is a checked outbound message.
type Message struct {
	Raw        []byte   // exactly what the device sent; the edge only prepends DKIM
	From       string   // the worker's address, lowercased
	Recipients []string // To and Cc, lowercased, without repeats
}

// Parse checks the message shape the edge will sign and send. It doesn't decide
// who may receive it; Policy does that.
func Parse(raw []byte) (*Message, error) {
	fields, body, err := header.Split(raw)
	if err != nil {
		return nil, err
	}
	for _, c := range body {
		if c >= 0x80 {
			return nil, errors.New("8-bit body: encode it as quoted-printable or base64")
		}
	}
	for _, f := range fields {
		name := strings.ToLower(f.Name)
		if strings.HasPrefix(name, "resent-") || slices.Contains(forbidden, name) {
			return nil, fmt.Errorf("the device may not set %s", f.Name)
		}
	}
	for _, n := range singletons {
		if len(header.Get(fields, n)) > 1 {
			return nil, fmt.Errorf("more than one %s", n)
		}
	}
	for _, n := range required {
		if len(header.Get(fields, n)) == 0 {
			return nil, fmt.Errorf("no %s", n)
		}
	}

	from, err := parseMailboxList(header.Get(fields, "from")[0].Value())
	if err != nil || len(from) != 1 {
		return nil, errors.New("From must hold exactly one plain address")
	}
	m := &Message{Raw: raw, From: from[0]}

	if rt := header.Get(fields, "reply-to"); len(rt) == 1 {
		addrs, err := parseMailboxList(rt[0].Value())
		if err != nil || len(addrs) != 1 || withoutTag(addrs[0]) != m.From {
			return nil, errors.New("Reply-To must be the worker's own address")
		}
	}

	seen := map[string]bool{}
	for _, n := range []string{"to", "cc"} {
		for _, f := range header.Get(fields, n) {
			addrs, err := parseMailboxList(f.Value())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			for _, a := range addrs {
				if !seen[a] {
					seen[a] = true
					m.Recipients = append(m.Recipients, a)
				}
			}
		}
	}
	if len(m.Recipients) == 0 {
		return nil, errors.New("no recipients")
	}
	if len(m.Recipients) > MaxRecipients {
		return nil, fmt.Errorf("more than %d recipients", MaxRecipients)
	}
	return m, nil
}
