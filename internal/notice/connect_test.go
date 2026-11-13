package notice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// fakeConnectRouting hashes addresses like routing.Store (lowercase, trimmed) and
// stands a plain hash in for the connect MAC.
type fakeConnectRouting struct{ mb routing.Mailbox }

func (fakeConnectRouting) MailboxID(a string) []byte {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(a))))
	return h[:]
}

func (fakeConnectRouting) LicenseOf(id []byte) ([]byte, bool) { return []byte("lic"), true }

func (r fakeConnectRouting) Snapshot(id []byte) (routing.Mailbox, bool) { return r.mb, true }

func (r fakeConnectRouting) ConnectMAC(id []byte, owner string, issued int64) []byte {
	h := sha256.New()
	h.Write(id)
	h.Write(r.MailboxID(owner))
	_ = binary.Write(h, binary.BigEndian, issued)
	return h.Sum(nil)[:16]
}

const worker = "accountant.smithcpa@fountbox.com"

func newConnector(t *testing.T, out send.Transmitter, on func() bool, clk *clock) *Connector {
	t.Helper()
	c, err := NewConnector(ConnectOptions{MailDomain: "@fountbox.com", Out: out, Routing: fakeConnectRouting{}, On: on, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func signingOutbox(d *fakeDeliverer, clk *clock) *send.Outbox {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return &send.Outbox{MailDomain: "@fountbox.com", Deliverer: d, Now: clk.now,
		Signers: []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: key}}}
}

func TestConnectMailShape(t *testing.T) {
	d := &fakeDeliverer{}
	clk := &clock{time.Unix(1_800_000_000, 0)}
	c := newConnector(t, signingOutbox(d, clk), nil, clk)
	id := fakeConnectRouting{}.MailboxID(worker)
	exp, err := c.Connect(context.Background(), id, " Accountant.SmithCPA@fountbox.com", "Pat@SmithCPA.com ")
	if err != nil {
		t.Fatal(err)
	}
	if exp != clk.t.Add(routing.ConnectLifetime) {
		t.Fatalf("expires %v", exp)
	}
	if len(d.got) != 1 {
		t.Fatalf("%d deliveries", len(d.got))
	}
	g := d.got[0]
	if g.from != worker || len(g.rcpts) != 1 || g.rcpts[0] != "pat@smithcpa.com" {
		t.Fatalf("envelope %q %v", g.from, g.rcpts)
	}
	f, body := fields(t, g.data)
	if f[0].Name != "DKIM-Signature" || !strings.Contains(f[0].Value(), "d=fountbox.com") {
		t.Fatalf("not DKIM signed first: %q", f[0].Name)
	}
	if !strings.Contains(strings.ToLower(f[0].Value()), "message-id") {
		t.Fatalf("DKIM doesn't sign the Message-ID: %s", f[0].Value())
	}
	mac := fakeConnectRouting{}.ConnectMAC(id, "pat@smithcpa.com", clk.t.Unix())
	wantID := routing.ConnectID(clk.t.Unix(), mac, "fountbox.com")
	for name, want := range map[string]string{
		"from":                      `"accountant.smithcpa at Fount" <` + worker + ">",
		"to":                        "<pat@smithcpa.com>",
		"subject":                   "Your Fount worker accountant.smithcpa is ready: reply to start",
		"date":                      clk.t.UTC().Format(time.RFC1123Z),
		"message-id":                wantID,
		"auto-submitted":            "auto-generated",
		"mime-version":              "1.0",
		"content-type":              "text/plain; charset=utf-8",
		"content-transfer-encoding": "7bit",
	} {
		if got := value(t, f, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !strings.HasPrefix(wantID, fmt.Sprintf("<c.%d.", clk.t.Unix())) {
		t.Fatalf("Message-ID %s", wantID)
	}
	want := "You asked Fount to connect this email address to your worker, accountant.smithcpa (" + worker + ").\r\n\r\n" +
		"Reply to this email to finish. You don't need to write anything. After that, you can email work to " + worker + ".\r\n\r\n" +
		"If you didn't ask for this, ignore this email and nothing changes.\r\n\r\n" +
		"-- \r\n" +
		"Fount runs AI workers you can email. fount.sh\r\n"
	if string(body) != want {
		t.Fatalf("body %q", body)
	}
	if bytes.Contains(g.data, []byte("Reply-To")) {
		t.Fatal("a reply must go to the worker itself")
	}
}

func TestConnectRefusesAnotherWorkersAddress(t *testing.T) {
	d := &fakeDeliverer{}
	clk := &clock{time.Unix(1_800_000_000, 0)}
	c := newConnector(t, signingOutbox(d, clk), nil, clk)
	id := fakeConnectRouting{}.MailboxID(worker)
	for _, addr := range []string{
		"other.smithcpa@fountbox.com",
		"accountant.smithcpa@example.com",
		"Accountant <" + worker + ">",
		worker + ", other.smithcpa@fountbox.com",
		"",
	} {
		if _, err := c.Connect(context.Background(), id, addr, "pat@smithcpa.com"); !errors.Is(err, ErrConnectNotWorker) {
			t.Errorf("%q: %v", addr, err)
		}
	}
	if _, err := c.Connect(context.Background(), nil, worker, "pat@smithcpa.com"); !errors.Is(err, ErrConnectNotWorker) {
		t.Errorf("no mailbox id: %v", err)
	}
	if len(d.got) != 0 {
		t.Fatal("sent")
	}
}

func TestConnectRefusesABadOwner(t *testing.T) {
	d := &fakeDeliverer{}
	clk := &clock{time.Unix(1_800_000_000, 0)}
	c := newConnector(t, signingOutbox(d, clk), nil, clk)
	id := fakeConnectRouting{}.MailboxID(worker)
	for _, owner := range []string{
		"other.smithcpa@fountbox.com",
		"Pat <pat@smithcpa.com>",
		"pat@smithcpa.com, mallory@example.com",
		"pat@smithcpa.com\r\nBcc: mallory@example.com",
		"pat",
		"",
	} {
		if _, err := c.Connect(context.Background(), id, worker, owner); !errors.Is(err, ErrConnectBadOwner) {
			t.Errorf("%q: %v", owner, err)
		}
	}
	if len(d.got) != 0 {
		t.Fatal("sent")
	}
}

func TestConnectLimits(t *testing.T) {
	d := &fakeDeliverer{}
	clk := &clock{time.Unix(1_800_000_000, 0)}
	c := newConnector(t, signingOutbox(d, clk), nil, clk)
	ctx := context.Background()
	id := fakeConnectRouting{}.MailboxID(worker)
	for range ConnectPerOwnerPerHour {
		if _, err := c.Connect(ctx, id, worker, "pat@smithcpa.com"); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.Connect(ctx, id, worker, "PAT@smithcpa.com")
	var lim *ConnectLimitError
	if !errors.As(err, &lim) || !errors.Is(err, ErrConnectLimited) || lim.Wait <= 0 {
		t.Fatalf("over the per-owner cap: %v", err)
	}
	// Another owner has their own budget, until the license's runs out.
	n := ConnectPerOwnerPerHour
	for i := 0; n < ConnectPerLicensePerDay; i++ {
		if _, err := c.Connect(ctx, id, worker, fmt.Sprintf("o%d@example.com", i/ConnectPerOwnerPerHour)); err != nil {
			t.Fatalf("connect %d: %v", n, err)
		}
		n++
	}
	if _, err := c.Connect(ctx, id, worker, "fresh@example.com"); !errors.As(err, &lim) || lim.Wait < time.Hour {
		t.Fatalf("over the license cap: %v", err)
	}
	if len(d.got) != ConnectPerLicensePerDay {
		t.Fatalf("%d sent, want %d", len(d.got), ConnectPerLicensePerDay)
	}
}

func TestConnectWithSendingOff(t *testing.T) {
	clk := &clock{time.Unix(1_800_000_000, 0)}
	id := fakeConnectRouting{}.MailboxID(worker)

	d := &fakeDeliverer{}
	c := newConnector(t, signingOutbox(d, clk), func() bool { return false }, clk)
	for range ConnectPerOwnerPerHour + 1 {
		if _, err := c.Connect(context.Background(), id, worker, "pat@smithcpa.com"); !errors.Is(err, send.ErrOff) {
			t.Fatalf("gate shut: %v", err)
		}
	}
	if len(d.got) != 0 {
		t.Fatal("sent with sending off")
	}

	out := &offTransmitter{}
	c = newConnector(t, out, nil, clk)
	if _, err := c.Connect(context.Background(), id, worker, "pat@smithcpa.com"); !errors.Is(err, send.ErrOff) || out.calls != 1 {
		t.Fatalf("signer off: %v", err)
	}
}

func TestConnectUndelivered(t *testing.T) {
	for _, st := range []send.Status{send.Permanent, send.Temporary} {
		clk := &clock{time.Unix(1_800_000_000, 0)}
		c := newConnector(t, signingOutbox(&fakeDeliverer{status: st}, clk), nil, clk)
		_, err := c.Connect(context.Background(), fakeConnectRouting{}.MailboxID(worker), worker, "pat@smithcpa.com")
		if !errors.Is(err, ErrConnectUndelivered) {
			t.Errorf("%s: %v", st, err)
		}
	}
}

func TestNewConnectorNeedsItsParts(t *testing.T) {
	out := &offTransmitter{}
	for name, o := range map[string]ConnectOptions{
		"no domain":  {Out: out, Routing: fakeConnectRouting{}},
		"bad domain": {MailDomain: "fountbox.com", Out: out, Routing: fakeConnectRouting{}},
		"no out":     {MailDomain: "@fountbox.com", Routing: fakeConnectRouting{}},
		"no routing": {MailDomain: "@fountbox.com", Out: out},
	} {
		if _, err := NewConnector(o); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestConnectRefusesAPausedOrLapsedWorker(t *testing.T) {
	clk := &clock{time.Unix(1_800_000_000, 0)}
	id := fakeConnectRouting{}.MailboxID(worker)
	for name, c := range map[string]struct {
		mb   routing.Mailbox
		want error
	}{
		"paused": {routing.Mailbox{Paused: true}, send.ErrPaused},
		"lapsed": {routing.Mailbox{EntitlementExp: clk.t.Unix() - 1}, send.ErrLapsed},
	} {
		d := &fakeDeliverer{}
		conn, err := NewConnector(ConnectOptions{MailDomain: "@fountbox.com", Out: signingOutbox(d, clk), Routing: fakeConnectRouting{mb: c.mb}, Now: clk.now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Connect(context.Background(), id, worker, "pat@smithcpa.com"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if len(d.got) != 0 {
			t.Errorf("%s: sent mail", name)
		}
	}
}
