package deviceapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// inviteOut is a Transmitter that sends to everyone and counts it.
type inviteOut struct {
	mu    sync.Mutex
	calls [][]string
}

func (o *inviteOut) Transmit(_ context.Context, _ string, rcpts []string, _ []byte) ([]send.Result, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, rcpts)
	var out []send.Result
	for _, r := range rcpts {
		out = append(out, send.Result{Recipient: r, Status: send.Sent})
	}
	return out, nil
}

func (o *inviteOut) n() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.calls)
}

// memSent is send.SentRecords in memory.
type memSent struct {
	mu   sync.Mutex
	recs map[string]*send.SentRecord
}

func (m *memSent) key(mailboxID []byte, id string) string {
	return fmt.Sprintf("%x/%s", mailboxID, send.NormalizeMessageID(id))
}

func (m *memSent) Load(_ context.Context, mailboxID []byte, id string) (*send.SentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.recs[m.key(mailboxID, id)]; r != nil {
		c := *r
		return &c, nil
	}
	return nil, nil
}

func (m *memSent) Save(_ context.Context, mailboxID []byte, r *send.SentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *r
	m.recs[m.key(mailboxID, r.MessageID)] = &c
	return nil
}

func (m *memSent) Delete(_ context.Context, mailboxID []byte, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.recs, m.key(mailboxID, id))
	return nil
}

// inviteFixture is a coordinator fixture whose edge sends, through a real
// send.Service over its routing data, to an Outbox that sends to anyone.
type inviteFixture struct {
	*coordFixture
	out     *inviteOut
	records *memSent
}

func newInviteFixture(t *testing.T) *inviteFixture {
	f := &inviteFixture{coordFixture: newCoordFixture(t), out: &inviteOut{}, records: &memSent{recs: map[string]*send.SentRecord{}}}
	f.opts.Sender = &send.Service{
		Policy:  send.NewPolicy(send.PolicyOptions{Directory: f.rt, MailDomain: "@fountbox.com", Proven: f.rt.OwnerProven}),
		Out:     f.out,
		Records: f.records,
	}
	f.api = New(f.opts)
	return f
}

func inviteMessage(from, to, id string, extra ...string) []byte {
	h := []string{
		"From: " + from,
		"To: " + to,
		"Subject: Join Smith CPA in Fount",
		"Date: Thu, 19 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + id + ">",
		"MIME-Version: 1.0",
	}
	h = append(h, extra...)
	if !slicesContainPrefix(extra, "Content-Type:") {
		h = append(h, "Content-Type: text/plain; charset=utf-8")
	}
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\nOpen this link: https://fount.sh/join#fi1.x\r\n")
}

func slicesContainPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func (f *inviteFixture) invite(c coordinatorKey, mailboxHex string, raw []byte) *httptest.ResponseRecorder {
	body, _ := json.Marshal(inviteRequest{MailboxID: mailboxHex, Message: raw})
	return f.serve(genRequest(f.t, c.priv, c.id, "POST", "/coordinator/invite", body, strconv.FormatUint(c.gen, 10)))
}

// An enrolled worker's coordinator mails an invite to someone who isn't an
// owner, and the worker's /sent/query finds it, marked an invite. /send to the
// same address is still refused.
func TestCoordinatorInviteToNonOwner(t *testing.T) {
	f := newInviteFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	c1 := f.coordinator(1)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")

	raw := inviteMessage("ap@fountbox.com", "ann@firm.com", "inv1@fountbox.com")
	rec := f.invite(c1, mb.idHex, raw)
	wantCode(t, rec, http.StatusOK, "")
	var out struct{ Results []send.Result }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Results) != 1 || out.Results[0].Status != send.Sent || out.Results[0].Recipient != "ann@firm.com" {
		t.Fatalf("body %s", rec.Body)
	}
	// A retry is answered from the record, not sent again.
	wantCode(t, f.invite(c1, mb.idHex, raw), http.StatusOK, "")
	if f.out.n() != 1 {
		t.Fatalf("%d transmits, want 1", f.out.n())
	}

	q, _ := json.Marshal(sentQuery{MessageIDs: []string{"<inv1@fountbox.com>"}})
	rec = f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/sent/query", q, "1"))
	wantCode(t, rec, http.StatusOK, "")
	var got struct{ Records []send.SentStatus }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Records) != 1 {
		t.Fatalf("query %s", rec.Body)
	}
	if r := got.Records[0]; r.State != send.SentDone || r.Kind != send.KindInvite || len(r.Results) != 1 || r.Results[0].Recipient != "ann@firm.com" {
		t.Fatalf("record %+v", r)
	}
	// A reboot reads the durable record, kind and all.
	f.opts.Sender.(*send.Service).Dedupe = send.NewDedupe(send.DedupeOptions{Records: f.records})
	rec = f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/sent/query", q, "1"))
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Records[0].Kind != send.KindInvite {
		t.Fatalf("after a reboot: %s", rec.Body)
	}

	// The worker's own /send to the same address is refused: invites are the
	// coordinator's alone.
	sendBody, _ := json.Marshal(sendRequest{Message: inviteMessage("ap@fountbox.com", "ann@firm.com", "plain@fountbox.com")})
	wantCode(t, f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/send", sendBody, "1")), http.StatusForbidden, "")
	if f.out.n() != 1 {
		t.Fatal("/send to a non-owner went out")
	}
}

// Only the current generation's key mails an invite: not the worker's own
// keys, no signature, an older generation's, or for a worker not enrolled.
func TestCoordinatorInviteNeedsTheCurrentGeneration(t *testing.T) {
	f := newInviteFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	c1, c2 := f.coordinator(1), f.coordinator(2)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	raw := inviteMessage("ap@fountbox.com", "ann@firm.com", "inv1@fountbox.com")
	body, _ := json.Marshal(inviteRequest{MailboxID: mb.idHex, Message: raw})

	// Unsigned.
	req := genRequest(t, c1.priv, c1.id, "POST", "/coordinator/invite", body, "1")
	req.Header.Del("Fount-Signature")
	wantCode(t, f.serve(req), http.StatusUnauthorized, "")
	// The worker's address key, or the mailbox key, aren't the coordinator's.
	wantCode(t, f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/coordinator/invite", body, "1")), http.StatusUnauthorized, "")
	wantCode(t, f.serve(genRequest(t, mb.mailbox, mb.idHex, "POST", "/coordinator/invite", body, "1")), http.StatusUnauthorized, "")
	// A key that no certificate names.
	stranger := f.coordinator(1)
	wantCode(t, f.invite(stranger, mb.idHex, raw), http.StatusConflict, codeStaleGeneration)
	// A worker that isn't enrolled.
	wantCode(t, f.invite(c1, other.idHex, inviteMessage("other@fountbox.com", "ann@firm.com", "inv2@fountbox.com")), http.StatusConflict, codeNotCoordinated)

	// Once generation 2 has spoken, generation 1 is stale.
	wantCode(t, f.claim(c2), http.StatusOK, "")
	wantCode(t, f.invite(c1, mb.idHex, raw), http.StatusConflict, codeStaleGeneration)
	if f.out.n() != 0 {
		t.Fatalf("%d sent", f.out.n())
	}
	wantCode(t, f.invite(c2, mb.idHex, raw), http.StatusOK, "")
	if f.out.n() != 1 {
		t.Fatal("the current generation's invite wasn't sent")
	}
}

// An invite is one plain-text message to one address outside the mail domain,
// from the worker itself, and each worker has InvitesPerDay.
func TestCoordinatorInviteShapeAndCap(t *testing.T) {
	f := newInviteFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	c1 := f.coordinator(1)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	wantCode(t, f.enroll(other, c1), http.StatusOK, "")

	refused := map[string][]byte{
		"two recipients": inviteMessage("ap@fountbox.com", "ann@firm.com, bo@firm.com", "r1@fountbox.com"),
		"a Cc":           inviteMessage("ap@fountbox.com", "ann@firm.com", "r2@fountbox.com", "Cc: bo@firm.com"),
		"html":           inviteMessage("ap@fountbox.com", "ann@firm.com", "r3@fountbox.com", "Content-Type: text/html"),
		"multipart":      inviteMessage("ap@fountbox.com", "ann@firm.com", "r4@fountbox.com", `Content-Type: multipart/mixed; boundary="b"`),
		"a worker":       inviteMessage("ap@fountbox.com", "close@fountbox.com", "r5@fountbox.com"),
	}
	for name, raw := range refused {
		rec := f.invite(c1, mb.idHex, raw)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), codeInviteRefused) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	big := inviteMessage("ap@fountbox.com", "ann@firm.com", "r6@fountbox.com")
	big = append(big, []byte(strings.Repeat(strings.Repeat("a", 70)+"\r\n", send.MaxInviteBytes/72+1))...)
	wantCode(t, f.invite(c1, mb.idHex, big), http.StatusBadRequest, codeInviteRefused)
	// From another worker than the one named.
	wantCode(t, f.invite(c1, mb.idHex, inviteMessage("other@fountbox.com", "ann@firm.com", "r7@fountbox.com")), http.StatusForbidden, "")
	if f.out.n() != 0 {
		t.Fatalf("%d refused invites went out", f.out.n())
	}

	for i := range send.InvitesPerDay {
		wantCode(t, f.invite(c1, mb.idHex, inviteMessage("ap@fountbox.com", "ann@firm.com", fmt.Sprintf("cap%d@fountbox.com", i))), http.StatusOK, "")
	}
	rec := f.invite(c1, mb.idHex, inviteMessage("ap@fountbox.com", "ann@firm.com", "over@fountbox.com"))
	wantCode(t, rec, http.StatusTooManyRequests, codeInviteLimit)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// A refused invite leaves no record, so the coordinator sees "none".
	q, _ := json.Marshal(sentQuery{MessageIDs: []string{"over@fountbox.com"}})
	if body := f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/sent/query", q, "1")).Body.String(); !strings.Contains(body, `"state":"none"`) {
		t.Fatalf("query after the cap: %s", body)
	}
	// The budget is per worker.
	wantCode(t, f.invite(c1, other.idHex, inviteMessage("other@fountbox.com", "ann@firm.com", "o1@fountbox.com")), http.StatusOK, "")
	if f.out.n() != send.InvitesPerDay+1 {
		t.Fatalf("%d sent", f.out.n())
	}
}

// A paused worker sends no invites either.
func TestCoordinatorInvitePaused(t *testing.T) {
	f := newInviteFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	c1 := f.coordinator(1)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	wantCode(t, f.lapse(c1, mb.idHex, ""), http.StatusOK, "")
	wantCode(t, f.invite(c1, mb.idHex, inviteMessage("ap@fountbox.com", "ann@firm.com", "p@fountbox.com")), http.StatusForbidden, "")
}
