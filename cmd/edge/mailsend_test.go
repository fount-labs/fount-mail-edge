package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// mail-send keeps every gate the one-container edge has, except routing, which
// it doesn't hold.
func TestOutboxStaysOffUntilEveryGateOpens(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(*config.Config)
		want string
	}{
		"no commitment":   {func(c *config.Config) { c.SendKeysetCommitment = ""; c.Secrets.Send = nil }, "off: SEND_KEYSET_COMMITMENT unset"},
		"no vault had it": {func(c *config.Config) { c.Secrets.Send = nil }, "off: no vault had the send keyset"},
		"not enabled":     {func(c *config.Config) { c.SendEnabled = false }, "off: SEND_ENABLED unset"},
		"no relay pins":   {func(c *config.Config) { c.SendRelayPins = nil }, "off: send: the relay needs"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := sendConfig(t)
			c.edit(cfg)
			out, st := newOutbox(cfg)
			if out != nil || !strings.HasPrefix(st.State, c.want) {
				t.Fatalf("outbox=%v state=%q, want %q", out != nil, st.State, c.want)
			}
		})
	}
	cfg, sk := sendConfig(t)
	out, st := newOutbox(cfg)
	if out == nil || st.State != "on" || st.Commitment != sk.Commitment() || len(out.Signers) != 2 {
		t.Fatalf("outbox=%v state=%+v", out != nil, st)
	}
}

func TestSendPullRound(t *testing.T) {
	sk, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"vault-a", "vault-b"}
	for name, c := range map[string]struct {
		answers map[string]*wire.SendKeyset
		fail    map[string]bool
		install error
		want    bool
		asked   int
	}{
		"first has it":       {map[string]*wire.SendKeyset{"vault-a": sk}, nil, nil, true, 1},
		"first has none":     {map[string]*wire.SendKeyset{"vault-b": sk}, nil, nil, true, 2},
		"first is down":      {map[string]*wire.SendKeyset{"vault-b": sk}, map[string]bool{"vault-a": true}, nil, true, 2},
		"none has it":        {nil, nil, nil, false, 2},
		"install refuses it": {map[string]*wire.SendKeyset{"vault-a": sk, "vault-b": sk}, nil, errors.New("no"), false, 2},
	} {
		t.Run(name, func(t *testing.T) {
			asked := 0
			pull := func(_ context.Context, host string) (*wire.SendKeyset, error) {
				asked++
				if c.fail[host] {
					return nil, errors.New("down")
				}
				return c.answers[host], nil
			}
			install := func(*wire.SendKeyset) error { return c.install }
			if got := sendPullRound(context.Background(), hosts, pull, install); got != c.want || asked != c.asked {
				t.Fatalf("installed=%t asked=%d, want %t %d", got, asked, c.want, c.asked)
			}
		})
	}
}

// ownerRouting has one worker with one proven owner.
type ownerRouting struct{ worker, owner string }

func hashAddr(a string) []byte { s := sha256.Sum256([]byte(a)); return s[:] }

func (o ownerRouting) MailboxID(a string) []byte { return hashAddr(a) }
func (o ownerRouting) Snapshot(id []byte) (routing.Mailbox, bool) {
	if string(id) != string(hashAddr(o.worker)) {
		return routing.Mailbox{}, false
	}
	return routing.Mailbox{MailboxID: id, OwnerHashes: [][]byte{hashAddr(o.owner)}, LicenseHash: []byte("lic")}, true
}
func (o ownerRouting) OwnerProven(_, _ []byte) bool { return true }

type recordingDeliverer struct {
	mu   sync.Mutex
	got  [][]byte
	from []string
}

func (d *recordingDeliverer) Deliver(_ context.Context, from string, rcpts []string, data []byte) []send.Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, data)
	d.from = append(d.from, from)
	out := make([]send.Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = send.Result{Recipient: r, Status: send.Sent}
	}
	return out
}

func outboundMessage(extra ...string) []byte {
	h := append([]string{
		"From: <ap@fountbox.com>",
		"To: <pat@smithcpa.com>",
		"Subject: s",
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <1@fountbox.com>",
	}, extra...)
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\nbody\r\n")
}

// POST /send in a split edge: core checks owners and spends limits, mail-send
// signs and delivers, and nothing goes out while mail-send says sending is off.
func TestCoreSendsThroughMailSend(t *testing.T) {
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	d := &recordingDeliverer{}
	ls := link.NewSendServer(1 << 20)
	ts := httptest.NewServer(ls)
	defer ts.Close()
	client := &link.SendClient{Base: ts.URL, HTTP: ts.Client()}

	cfg := &config.Config{MailDomain: "@fountbox.com", SendLink: "mail-send:7026"}
	var state atomic.Pointer[sendState]
	rt := ownerRouting{worker: "ap@fountbox.com", owner: "pat@smithcpa.com"}
	sender, why := newCoreSender(cfg, rt, client, &state)
	if sender == nil {
		t.Fatal(why)
	}
	worker := hashAddr("ap@fountbox.com")
	ctx := context.Background()

	// Off before mail-send has answered, and off while it reports off.
	if _, err := sender.Send(ctx, worker, outboundMessage()); !errors.Is(err, send.ErrOff) {
		t.Fatalf("err = %v", err)
	}
	sendWatchEvery = time.Millisecond
	t.Cleanup(func() { sendWatchEvery = 15 * time.Second })
	wctx, stop := context.WithCancel(ctx)
	defer stop()
	ons := make(chan struct{}, 4)
	go watchSend(wctx, client, &state, func() { ons <- struct{}{} })
	waitState(t, &state, "off: mail-send: starting")
	if _, err := sender.Send(ctx, worker, outboundMessage()); !errors.Is(err, send.ErrOff) {
		t.Fatalf("err = %v", err)
	}

	out := &send.Outbox{MailDomain: "@fountbox.com", Signers: []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: ek}}, Deliverer: d}
	ls.Set(out, link.SendStatus{State: "on", Commitment: "c0"})
	waitState(t, &state, "on")
	<-ons
	if s := state.Load(); s.Commitment != "c0" {
		t.Fatalf("commitment %q", s.Commitment)
	}

	res, err := sender.Send(ctx, worker, outboundMessage())
	if err != nil || len(res) != 1 || res[0].Status != send.Sent {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.HasPrefix(string(d.got[0]), "DKIM-Signature: v=1; a=ed25519-sha256;") {
		t.Fatalf("delivered %q", d.got[0])
	}
	// Core keeps the send record: a device's retry of the same message gets the
	// same results and never reaches mail-send.
	again, err := sender.Send(ctx, worker, outboundMessage())
	if err != nil || len(again) != 1 || again[0] != res[0] || len(d.got) != 1 {
		t.Fatalf("retry: %+v %v, %d deliveries", again, err, len(d.got))
	}
	// Core's own checks still run: a stranger never reaches mail-send.
	stranger := strings.Replace(string(outboundMessage("Cc: stranger@example.net")), "<1@", "<2@", 1)
	if _, err := sender.Send(ctx, worker, []byte(stranger)); !errors.Is(err, send.ErrNotOwner) {
		t.Fatalf("stranger: %v", err)
	}
	if len(d.got) != 1 {
		t.Fatal("a refused message reached the deliverer")
	}

	// mail-send going off (a restart) turns core off again; on fires only once.
	ls.Set(nil, link.SendStatus{State: "off: waiting for a vault's send keyset"})
	waitState(t, &state, "off: mail-send: waiting for a vault's send keyset")
	ls.Set(out, link.SendStatus{State: "on"})
	waitState(t, &state, "on")
	time.Sleep(10 * time.Millisecond)
	if len(ons) != 0 {
		t.Fatal("on fired twice")
	}
}

func TestCoreSenderNeedsMailSendAndRouting(t *testing.T) {
	var state atomic.Pointer[sendState]
	if s, why := newCoreSender(&config.Config{}, fakeRouting{}, &link.SendClient{}, &state); s != nil || !strings.Contains(why, "SEND_LINK") {
		t.Fatalf("no link: %v %q", s != nil, why)
	}
	if s, why := newCoreSender(&config.Config{SendLink: "mail-send:7026"}, nil, &link.SendClient{}, &state); s != nil || why != "off: no routing" {
		t.Fatalf("no routing: %v %q", s != nil, why)
	}
}

func TestWatchSendReportsAnUnreachableMailSend(t *testing.T) {
	sendWatchEvery = time.Millisecond
	t.Cleanup(func() { sendWatchEvery = 15 * time.Second })
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var state atomic.Pointer[sendState]
	client := &link.SendClient{Base: "http://127.0.0.1:1"}
	go watchSend(ctx, client, &state, func() { t.Error("on with mail-send unreachable") })
	waitState(t, &state, "off: mail-send unreachable")
}

func waitState(t *testing.T, state *atomic.Pointer[sendState], want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if s := state.Load(); s != nil && s.State == want {
			return
		}
		if time.Now().After(deadline) {
			s := state.Load()
			t.Fatalf("state %+v, want %q", s, want)
		}
		time.Sleep(time.Millisecond)
	}
}
