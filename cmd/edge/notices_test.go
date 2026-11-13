package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
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
)

type countingQueue struct {
	mu     sync.Mutex
	passes int
}

func (q *countingQueue) DrainNotices(context.Context, routing.NoticeMailer, string) (routing.DrainResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.passes++
	return routing.DrainResult{}, nil
}

func (q *countingQueue) LicenseOf([]byte) ([]byte, bool) { return nil, false }

func (q *countingQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.passes
}

// With any send gate shut there's no sender, and nothing ever drains the queue,
// so notices stay in routing data instead of being sent or dropped.
func TestNoticesStayQueuedWithSendingOff(t *testing.T) {
	for name, edit := range map[string]func(*config.Config){
		"release (no commitment)": func(c *config.Config) { c.SendKeysetCommitment = ""; c.Secrets.Send = nil },
		"not enabled":             func(c *config.Config) { c.SendEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := sendConfig(t)
			edit(cfg)
			sender, _ := newSender(cfg, fakeRouting{})
			q := &countingQueue{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if startNotices(ctx, cfg, transmitterOf(sender), q) {
				t.Fatal("owner notices started with sending off")
			}
			time.Sleep(20 * time.Millisecond)
			if q.count() != 0 {
				t.Fatal("the notice queue was drained with sending off")
			}
		})
	}
}

func TestNoticesDrainWhenSendingIsOn(t *testing.T) {
	cfg, _ := sendConfig(t)
	sender, st := newSender(cfg, fakeRouting{})
	if st.State != "on" {
		t.Fatalf("sending %q", st.State)
	}
	q := &countingQueue{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !startNotices(ctx, cfg, transmitterOf(sender), q) {
		t.Fatal("owner notices didn't start with sending on")
	}
	deadline := time.Now().Add(5 * time.Second)
	for q.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no drain pass")
		}
		time.Sleep(time.Millisecond)
	}
}

type connectRouting struct{ ownerRouting }

func (connectRouting) LicenseOf([]byte) ([]byte, bool) { return []byte("lic"), true }
func (connectRouting) ConnectMAC(id []byte, owner string, issued int64) []byte {
	return hashAddr(fmt.Sprint(id, owner, issued))[:16]
}

// In a split edge the connect mail goes to mail-send over the link, like a
// notice, and only while mail-send says sending is on.
func TestConnectReachesMailSend(t *testing.T) {
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	d := &recordingDeliverer{}
	ls := link.NewSendServer(1 << 20)
	ts := httptest.NewServer(ls)
	defer ts.Close()
	client := &link.SendClient{Base: ts.URL, HTTP: ts.Client()}
	ls.Set(&send.Outbox{MailDomain: "@fountbox.com", Signers: []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: ek}}, Deliverer: d},
		link.SendStatus{State: "on"})

	var state atomic.Pointer[sendState]
	cfg := &config.Config{MailDomain: "@fountbox.com"}
	c := newConnector(cfg, client, connectRouting{}, sendingOn(&state))
	if c == nil {
		t.Fatal("no connector")
	}
	worker := hashAddr("ap@fountbox.com")
	ctx := context.Background()
	if _, err := c.Connect(ctx, worker, "ap@fountbox.com", "pat@smithcpa.com"); !errors.Is(err, send.ErrOff) {
		t.Fatalf("before mail-send is on: %v", err)
	}
	state.Store(&sendState{State: "on"})
	if _, err := c.Connect(ctx, worker, "ap@fountbox.com", "pat@smithcpa.com"); err != nil {
		t.Fatal(err)
	}
	if len(d.got) != 1 || d.from[0] != "ap@fountbox.com" || !strings.HasPrefix(string(d.got[0]), "DKIM-Signature:") {
		t.Fatalf("delivered %d from %v", len(d.got), d.from)
	}
}

func TestNoConnectorWithSendingOff(t *testing.T) {
	cfg, _ := sendConfig(t)
	cfg.SendEnabled = false
	sender, _ := newSender(cfg, fakeRouting{})
	if c := newConnector(cfg, transmitterOf(sender), connectRouting{}, nil); c != nil {
		t.Fatal("a connector with sending off")
	}
}
