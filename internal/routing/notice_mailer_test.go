package routing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/header"
	"github.com/fount-labs/fount-mail-edge/internal/notice"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type recordingDeliverer struct {
	status send.Status
	msgs   [][]byte
}

func (d *recordingDeliverer) Deliver(_ context.Context, _ string, rcpts []string, data []byte) []send.Result {
	d.msgs = append(d.msgs, data)
	out := make([]send.Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = send.Result{Recipient: r, Status: d.status}
	}
	return out
}

// The queue, notice.Mailer and an owner's reply together: the proof mail goes
// out once, its Reply-To proves the owner, and a dead domain doesn't stay queued.
func TestOwnerNoticesThroughTheMailer(t *testing.T) {
	f := newOwnerFixture(t)
	ctx := context.Background()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	d := &recordingDeliverer{status: send.Sent}
	m, err := notice.New(notice.Options{
		MailDomain: "@fountbox.com",
		Signers:    []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: key}},
		Deliverer:  d,
		License:    f.s.LicenseOf,
		Now:        f.clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, f.id, 1, "jane@example.com")
	if r, err := f.s.DrainNotices(ctx, m, "@fountbox.com"); err != nil || r.Sent != 1 {
		t.Fatalf("drain: %+v %v", r, err)
	}
	fields, _, err := header.Split(d.msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	replyTo := strings.Trim(strings.TrimSpace(header.Get(fields, "reply-to")[0].Value()), "<>")
	next := &countingStorer{}
	if _, err := f.s.ProofIntake(next).Put(ctx, store.Envelope{Recipient: replyTo}, []byte("yes")); err != nil {
		t.Fatalf("proof reply to the sent Reply-To: %v", err)
	}
	if !f.s.OwnerProven(f.id, f.hash("jane@example.com")) {
		t.Fatal("replying to the sent proof mail didn't prove the owner")
	}
	if st, _ := f.s.Status(ctx, replyTo); st != smtp.RecipientAccepting {
		t.Fatal("reply address stopped accepting")
	}

	d.status = send.Permanent
	f.set(t, f.id, 2, "jane@example.com", "bob@dead.example")
	if r, err := f.s.DrainNotices(ctx, m, "@fountbox.com"); err != nil || r.Dropped != 2 {
		t.Fatalf("drain to a dead domain: %+v %v", r, err)
	}
	if ns := pending(t, f.s); len(ns) != 0 {
		t.Fatalf("undeliverable notices still queued: %+v", ns)
	}
}
