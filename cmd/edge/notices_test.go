package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
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
			if startNotices(ctx, cfg, sender, q) {
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
	if !startNotices(ctx, cfg, sender, q) {
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
