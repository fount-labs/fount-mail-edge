package main

import (
	"fmt"
	"strings"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
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

// newSender builds POST /send's Sender from the pulled send keyset. Each gate
// that isn't met leaves it nil, so the route stays 501, and names itself in the
// state. The order is the order the owner turns them on.
func newSender(cfg *config.Config, rt sendRouting) (deviceapi.Sender, sendState) {
	var st sendState
	keys := cfg.Secrets.Send
	if keys != nil {
		st.Commitment = keys.Commitment
	}
	off := func(why string) (deviceapi.Sender, sendState) {
		st.State = "off: " + why
		return nil, st
	}
	switch {
	case cfg.SendKeysetCommitment == "":
		return off("SEND_KEYSET_COMMITMENT unset")
	case keys == nil:
		return off("no vault had the send keyset at boot")
	case !cfg.SendEnabled:
		return off("SEND_ENABLED unset")
	case rt == nil:
		return off("no routing")
	}
	svc, err := buildSender(cfg, keys, rt)
	if err != nil {
		return off(err.Error())
	}
	st.State = "on"
	return svc, st
}

func buildSender(cfg *config.Config, keys *config.SendKeys, rt sendRouting) (*send.Service, error) {
	clientCert, err := send.RelayClientCert(keys.RelayClient)
	if err != nil {
		return nil, fmt.Errorf("relay client certificate: %w", err)
	}
	domain := strings.TrimPrefix(cfg.MailDomain, "@")
	return send.New(send.Options{
		Directory:  rt,
		MailDomain: cfg.MailDomain,
		Hostname:   cfg.MailHostnames[0],
		Relay:      &send.Relay{Addr: cfg.SendRelayAddr, ClientCert: clientCert, Pins: cfg.SendRelayPins},
		Signers:    dkimSigners(domain, cfg.DKIMSelector, keys),
		Proven:     rt.OwnerProven,
	})
}

// dkimSigners signs with RSA first, then Ed25519 (RFC 8463 §4), under the
// selectors the vault's send_public TXT values are published at.
func dkimSigners(domain, selector string, keys *config.SendKeys) []*dkim.Signer {
	return []*dkim.Signer{
		{Domain: domain, Selector: selector, Key: keys.DKIMRSA},
		{Domain: domain, Selector: selector + "e", Key: keys.DKIMEd25519},
	}
}
