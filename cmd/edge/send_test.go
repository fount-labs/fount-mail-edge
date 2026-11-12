package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-vault/wire"
)

type fakeRouting struct{}

func (fakeRouting) MailboxID(string) []byte                      { return nil }
func (fakeRouting) Snapshot([]byte) (routing.Mailbox, bool)      { return routing.Mailbox{}, false }
func (fakeRouting) OwnerProven(mailboxID, ownerHash []byte) bool { return false }

// sendConfig is a release config with every send setting, holding the send
// keyset a vault handed over.
func sendConfig(t *testing.T) (*config.Config, *wire.SendKeyset) {
	t.Helper()
	keyset, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		MailHostnames:        []string{"mx1.fountbox.com"},
		MailDomain:           "@fountbox.com",
		SendKeysetCommitment: sk.Commitment(),
		SendEnabled:          true,
		SendRelayAddr:        "relay.example:8443",
		SendRelayPins:        []gatewaytls.Pin{{1}},
		DKIMSelector:         "f1",
	}
	err = cfg.InstallVaultKeys(&wire.PullResult{Keyset: keyset, SendKeyset: sk,
		S3: &wire.S3Credentials{AccessKeyID: "A", SecretAccessKey: "B"}})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, sk
}

// Each gate keeps POST /send a 501 and says which one is shut.
func TestSenderStaysOffUntilEveryGateOpens(t *testing.T) {
	cases := map[string]struct {
		edit func(*config.Config)
		rt   sendRouting
		want string
	}{
		"no commitment":    {func(c *config.Config) { c.SendKeysetCommitment = ""; c.Secrets.Send = nil }, fakeRouting{}, "off: SEND_KEYSET_COMMITMENT unset"},
		"no vault had it":  {func(c *config.Config) { c.Secrets.Send = nil }, fakeRouting{}, "off: no vault had the send keyset"},
		"not enabled":      {func(c *config.Config) { c.SendEnabled = false }, fakeRouting{}, "off: SEND_ENABLED unset"},
		"no routing (dev)": {func(*config.Config) {}, nil, "off: no routing"},
		"no relay pins":    {func(c *config.Config) { c.SendRelayPins = nil }, fakeRouting{}, "off: send: the relay needs"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, _ := sendConfig(t)
			c.edit(cfg)
			sender, st := newSender(cfg, c.rt)
			if sender != nil || !strings.HasPrefix(st.State, c.want) {
				t.Fatalf("sender=%v state=%q, want off %q", sender != nil, st.State, c.want)
			}
		})
	}
}

func TestSenderUsesThePulledSendKeyset(t *testing.T) {
	cfg, sk := sendConfig(t)
	sender, st := newSender(cfg, fakeRouting{})
	if sender == nil || st.State != "on" || st.Commitment != sk.Commitment() {
		t.Fatalf("sender=%v state=%+v", sender != nil, st)
	}
	svc := sender.(*send.Service).Out.(*send.Outbox)
	rsaKey, _ := sk.DKIMRSA()
	edKey, _ := sk.DKIMEd25519()
	if len(svc.Signers) != 2 {
		t.Fatalf("%d signers", len(svc.Signers))
	}
	// RSA first, then Ed25519 (RFC 8463 §4), at the selectors send_public's TXT values go under.
	for i, want := range []struct {
		selector string
		key      any
	}{{"f1", rsaKey}, {"f1e", edKey}} {
		s := svc.Signers[i]
		if s.Domain != "fountbox.com" || s.Selector != want.selector {
			t.Errorf("signer %d: d=%s s=%s", i, s.Domain, s.Selector)
		}
		type equaler interface{ Equal(crypto.PrivateKey) bool }
		if !s.Key.(equaler).Equal(want.key) {
			t.Errorf("signer %d signs with the wrong key", i)
		}
	}

	// The relay client certificate carries the send keyset's relay key, which is
	// what the gateway pins (send_public relay_client_pin).
	relayKey, _ := sk.RelayClient()
	cert, err := send.RelayClientCert(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(ed25519.PublicKey).Equal(cfg.Secrets.Send.RelayClient.Public()) {
		t.Fatal("relay client key isn't the send keyset's")
	}
}

func TestEHLONameDefaultsToTheFirstMailHostname(t *testing.T) {
	cfg := &config.Config{MailHostnames: []string{"mx1.fountbox.com", "mx2.fountbox.com"}}
	if got := ehloName(cfg); got != "mx1.fountbox.com" {
		t.Errorf("default = %q", got)
	}
	cfg.SendEHLOName = "out.fountbox.com"
	if got := ehloName(cfg); got != "out.fountbox.com" {
		t.Errorf("set = %q", got)
	}
}
