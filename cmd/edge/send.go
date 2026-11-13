package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/sendercheck"
)

// sendState is what /operator/status reports about sending. Tinfoil keeps no
// container logs, so this is how the owner sees why it's off.
type sendState struct {
	State      string // "on", or "off: <why>"
	Commitment string // the held send keyset's commitment, "" if none
}

// sendRouting is what sending reads from routing.Store: the owner lists, and the
// edge's own proof that each owner reads the address.
type sendRouting interface {
	send.Directory
	OwnerProven(mailboxID, ownerHash []byte) bool
}

var _ sendRouting = (*routing.Store)(nil)

// sendGate names the first send gate that is shut, or returns "" when the
// release has turned sending on and holds the committed send keyset. The order
// is the order the owner turns them on. The one-container edge and mail-send
// both pass through it.
func sendGate(cfg *config.Config) string {
	switch {
	case cfg.SendKeysetCommitment == "":
		return "SEND_KEYSET_COMMITMENT unset"
	case cfg.Secrets.Send == nil:
		return "no vault had the send keyset at boot"
	case !cfg.SendEnabled:
		return "SEND_ENABLED unset"
	}
	return ""
}

func heldCommitment(cfg *config.Config) string {
	if cfg.Secrets.Send != nil {
		return cfg.Secrets.Send.Commitment
	}
	return ""
}

// newSender builds POST /send's Sender for the one-container edge from the
// pulled send keyset. Each gate that isn't met leaves it nil, so the route stays
// 501, and names itself in the state.
func newSender(cfg *config.Config, rt sendRouting) (deviceapi.Sender, sendState) {
	st := sendState{Commitment: heldCommitment(cfg)}
	off := func(why string) (deviceapi.Sender, sendState) {
		st.State = "off: " + why
		return nil, st
	}
	if why := sendGate(cfg); why != "" {
		return off(why)
	}
	if rt == nil {
		return off("no routing")
	}
	o, err := sendOptions(cfg)
	if err != nil {
		return off(err.Error())
	}
	o.Directory, o.Proven = rt, rt.OwnerProven
	svc, err := send.New(o)
	if err != nil {
		return off(err.Error())
	}
	st.State = "on"
	return svc, st
}

// newOutbox is mail-send's half of newSender: the same gates, and signing and
// delivery with no routing data. mail-core makes the checks that need it.
func newOutbox(cfg *config.Config) (*send.Outbox, sendState) {
	st := sendState{Commitment: heldCommitment(cfg)}
	if why := sendGate(cfg); why != "" {
		st.State = "off: " + why
		return nil, st
	}
	o, err := sendOptions(cfg)
	if err == nil {
		var out *send.Outbox
		if out, err = send.NewOutbox(o); err == nil {
			st.State = "on"
			return out, st
		}
	}
	st.State = "off: " + err.Error()
	return nil, st
}

func sendOptions(cfg *config.Config) (send.Options, error) {
	keys := cfg.Secrets.Send
	clientCert, err := send.RelayClientCert(keys.RelayClient)
	if err != nil {
		return send.Options{}, fmt.Errorf("relay client certificate: %w", err)
	}
	domain := strings.TrimPrefix(cfg.MailDomain, "@")
	return send.Options{
		MailDomain: cfg.MailDomain,
		Hostname:   ehloName(cfg),
		Relay:      &send.Relay{Addr: cfg.SendRelayAddr, ClientCert: clientCert, Pins: cfg.SendRelayPins},
		Signers:    dkimSigners(domain, cfg.DKIMSelector, keys),
	}, nil
}

func ehloName(cfg *config.Config) string {
	if cfg.SendEHLOName != "" {
		return cfg.SendEHLOName
	}
	return cfg.MailHostnames[0]
}

// dkimSigners signs with RSA first, then Ed25519 (RFC 8463 §4), under the
// selectors the vault's send_public TXT values are published at.
func dkimSigners(domain, selector string, keys *config.SendKeys) []*dkim.Signer {
	return []*dkim.Signer{
		{Domain: domain, Selector: selector, Key: keys.DKIMRSA},
		{Domain: domain, Selector: selector + "e", Key: keys.DKIMEd25519},
	}
}

// outboxDNS is the one-container edge's DNS for the sender check: the outbox's
// own resolver, with its "no record" turned into the check's.
type outboxDNS struct{ out *send.Outbox }

func (o outboxDNS) TXT(ctx context.Context, name string) ([]string, error) {
	txt, err := o.out.TXT(ctx, name)
	if errors.Is(err, send.ErrNoRecord) {
		return nil, sendercheck.ErrNoRecord
	}
	return txt, err
}
