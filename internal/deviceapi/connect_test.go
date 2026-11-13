package deviceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/header"
	"github.com/fount-labs/fount-mail-edge/internal/notice"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// recordingOut is a Transmitter that makes the signer's own handoff check and
// keeps what it was handed.
type recordingOut struct {
	mu  sync.Mutex
	got [][]byte
}

func (o *recordingOut) Transmit(_ context.Context, from string, rcpts []string, raw []byte) ([]send.Result, error) {
	if err := send.CheckHandoff("@fountbox.com", from, rcpts, raw); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, raw)
	return []send.Result{{Recipient: rcpts[0], Status: send.Sent}}, nil
}

func (o *recordingOut) last(t *testing.T) []byte {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.got) == 0 {
		t.Fatal("nothing sent")
	}
	return o.got[len(o.got)-1]
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type connectFixture struct {
	t     *testing.T
	rt    *routing.Store
	api   *API
	out   *recordingOut
	clk   *testClock
	mb    mbox
	nonce int
}

func newConnectFixture(t *testing.T) *connectFixture {
	t.Helper()
	f := &connectFixture{t: t, out: &recordingOut{}, clk: &testClock{t: time.Now()}}
	blobs := newMemBlobs()
	if err := routing.Initialize(context.Background(), blobs, []byte("test-routing-data-key")); err != nil {
		t.Fatal(err)
	}
	rt, err := routing.New(context.Background(), blobs, []byte("test-routing-data-key"), []byte("test-mac-key"), routing.WithClock(f.clk.now))
	if err != nil {
		t.Fatal(err)
	}
	f.rt = rt
	c, err := notice.NewConnector(notice.ConnectOptions{MailDomain: "@fountbox.com", Out: f.out, Routing: rt, Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	f.api = New(Options{Store: store.NewDiscard(), Resolver: NewKeyResolver(rt), Mutator: rt, MailDomain: "@fountbox.com", Connector: c})
	f.mb = createMbox(t, rt, "worker@fountbox.com", "lic-1")
	return f
}

func (f *connectFixture) do(mb mbox, method, path string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	f.nonce++
	rec := httptest.NewRecorder()
	f.api.ServeHTTP(rec, signedRequest(f.t, mb.owner, mb.idHex, method, path, raw, time.Now(), "c"+strconv.Itoa(f.nonce)))
	return rec
}

// connect asks for a connect mail and returns the Message-ID the owner would reply to.
func (f *connectFixture) connect(mb mbox, address, owner string) string {
	f.t.Helper()
	rec := f.do(mb, "POST", "/connect", map[string]string{"address": address, "owner": owner})
	if rec.Code != http.StatusAccepted {
		f.t.Fatalf("POST /connect: %d %s", rec.Code, rec.Body)
	}
	fields, _, err := header.Split(f.out.last(f.t))
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.TrimSpace(header.Get(fields, "message-id")[0].Value())
}

type proofBody struct {
	Owner     string `json:"owner"`
	MessageID string `json:"messageId"`
}

func (f *connectFixture) put(mb mbox, version uint64, owners []string, proofs ...proofBody) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(mb, "PUT", "/routing", map[string]any{"version": version, "owners": owners, "proofs": proofs})
}

func (f *connectFixture) owner(mb mbox, addr string) (routing.Owner, bool) {
	m, _ := f.rt.Snapshot(mb.id)
	for _, o := range m.OwnerState {
		if bytes.Equal(o.Hash, f.rt.MailboxID(addr)) {
			return o, true
		}
	}
	return routing.Owner{}, false
}

func TestConnectRoute(t *testing.T) {
	f := newConnectFixture(t)
	rec := f.do(f.mb, "POST", "/connect", map[string]string{"address": "worker@fountbox.com", "owner": "pat@smithcpa.com"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 {
		t.Fatalf("body %s", rec.Body)
	}
	if exp, _ := out["expiresAt"].(float64); int64(exp) != f.clk.now().Add(routing.ConnectLifetime).Unix() {
		t.Fatalf("expiresAt %v", out["expiresAt"])
	}
	raw := f.out.last(t)
	fields, _, _ := header.Split(raw)
	id := strings.TrimSpace(header.Get(fields, "message-id")[0].Value())
	issued, mac, ok := routing.ParseConnectID(id, "@fountbox.com")
	if !ok || issued != f.clk.now().Unix() || !bytes.Equal(mac, f.rt.ConnectMAC(f.mb.id, "pat@smithcpa.com", issued)) {
		t.Fatalf("Message-ID %s", id)
	}
	// The device must learn the Message-ID only from the owner's reply.
	local, _, _ := strings.Cut(strings.Trim(id, "<>"), "@")
	macPart := local[strings.LastIndex(local, ".")+1:]
	for _, secret := range []string{id, local, macPart} {
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(fmt.Sprint(rec.Header()), secret) {
			t.Fatalf("the response leaks %q", secret)
		}
	}
	if from := strings.TrimSpace(header.Get(fields, "from")[0].Value()); from != "<worker@fountbox.com>" {
		t.Fatalf("From %s", from)
	}
}

func TestConnectRouteErrors(t *testing.T) {
	f := newConnectFixture(t)
	createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	for name, c := range map[string]struct {
		body map[string]string
		code int
	}{
		"another worker's address": {map[string]string{"address": "other@fountbox.com", "owner": "pat@smithcpa.com"}, http.StatusNotFound},
		"an address elsewhere":     {map[string]string{"address": "worker@example.com", "owner": "pat@smithcpa.com"}, http.StatusNotFound},
		"an owner in the domain":   {map[string]string{"address": "worker@fountbox.com", "owner": "other@fountbox.com"}, http.StatusBadRequest},
		"two owners":               {map[string]string{"address": "worker@fountbox.com", "owner": "pat@smithcpa.com, m@example.com"}, http.StatusBadRequest},
		"a display name":           {map[string]string{"address": "worker@fountbox.com", "owner": "Pat <pat@smithcpa.com>"}, http.StatusBadRequest},
		"no owner":                 {map[string]string{"address": "worker@fountbox.com"}, http.StatusBadRequest},
	} {
		if rec := f.do(f.mb, "POST", "/connect", c.body); rec.Code != c.code {
			t.Errorf("%s: %d, want %d: %s", name, rec.Code, c.code, rec.Body)
		}
	}
	if len(f.out.got) != 0 {
		t.Fatal("a refused connect sent mail")
	}

	// Signed by the request-signing key, not the owner-change key.
	raw, _ := json.Marshal(map[string]string{"address": "worker@fountbox.com", "owner": "pat@smithcpa.com"})
	rec := httptest.NewRecorder()
	f.api.ServeHTTP(rec, signedRequest(t, f.mb.sign, f.mb.idHex, "POST", "/connect", raw, time.Now(), "wrong-key"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", rec.Code)
	}
}

func TestConnectRouteLimit(t *testing.T) {
	f := newConnectFixture(t)
	body := map[string]string{"address": "worker@fountbox.com", "owner": "pat@smithcpa.com"}
	for range notice.ConnectPerOwnerPerHour {
		if rec := f.do(f.mb, "POST", "/connect", body); rec.Code != http.StatusAccepted {
			t.Fatalf("%d", rec.Code)
		}
	}
	rec := f.do(f.mb, "POST", "/connect", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra <= 0 {
		t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	// Connect mails aren't new owners: the license can still add five today.
	owners := []string{"jane@example.com"}
	if rec := f.put(f.mb, 1, owners); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	for i := range routing.DefaultNewOwnersPerDay {
		owners = append(owners, fmt.Sprintf("o%d@example.com", i))
		if rec := f.put(f.mb, uint64(i+2), owners); rec.Code != http.StatusOK {
			t.Fatalf("new owner %d: %d", i, rec.Code)
		}
	}
}

func TestConnectRouteWithSendingOff(t *testing.T) {
	rt, _ := newRoutingStore(t)
	mb := createMbox(t, rt, "worker@fountbox.com", "lic-1")
	off, _ := notice.NewConnector(notice.ConnectOptions{MailDomain: "@fountbox.com", Out: &recordingOut{}, Routing: rt,
		On: func() bool { return false }})
	for name, c := range map[string]Connector{"no connector": nil, "mail-send off": off} {
		api := New(Options{Store: store.NewDiscard(), Resolver: NewKeyResolver(rt), Mutator: rt, MailDomain: "@fountbox.com", Connector: c})
		raw, _ := json.Marshal(map[string]string{"address": "worker@fountbox.com", "owner": "pat@smithcpa.com"})
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, signedRequest(t, mb.owner, mb.idHex, "POST", "/connect", raw, time.Now(), "off-"+name))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d, want 503", name, rec.Code)
		}
	}
}

func TestPutRoutingWithAConnectProof(t *testing.T) {
	f := newConnectFixture(t)
	id := f.connect(f.mb, "worker@fountbox.com", "Pat@SmithCPA.com")
	f.clk.add(time.Hour)
	// The device may hand back the Message-ID with or without its brackets.
	rec := f.put(f.mb, 1, []string{"pat@smithcpa.com"}, proofBody{"pat@smithcpa.com", strings.Trim(id, "<>")})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	o, ok := f.owner(f.mb, "pat@smithcpa.com")
	if !ok || o.ProvedAt != f.clk.now().Unix() {
		t.Fatalf("pat: %+v %v", o, ok)
	}
	if ns, _ := f.rt.PendingNotices("@fountbox.com"); len(ns) != 0 {
		t.Fatalf("a connected owner was queued mail: %+v", ns)
	}

	// A second owner, connected the same way: proved, waiting, and announced.
	id = f.connect(f.mb, "worker@fountbox.com", "bob@example.com")
	if rec := f.put(f.mb, 2, []string{"pat@smithcpa.com", "bob@example.com"}, proofBody{"bob@example.com", id}); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	ns, _ := f.rt.PendingNotices("@fountbox.com")
	if len(ns) != 1 || ns[0].Kind != routing.NoticeNewOwner || ns[0].To != "pat@smithcpa.com" || ns[0].About != "bob@example.com" {
		t.Fatalf("notices %+v", ns)
	}
	if o, _ := f.owner(f.mb, "bob@example.com"); o.ProvedAt == 0 || o.ActiveAt == 0 {
		t.Fatalf("bob: %+v", o)
	}
}

func TestPutRoutingRefusesABadConnectProof(t *testing.T) {
	f := newConnectFixture(t)
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	pat := f.connect(f.mb, "worker@fountbox.com", "pat@smithcpa.com")
	elsewhere := f.connect(other, "other@fountbox.com", "bob@example.com")
	bob := f.connect(f.mb, "worker@fountbox.com", "bob@example.com")
	if rec := f.put(f.mb, 1, []string{"jane@example.com"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	flip := func(id string) string {
		at := strings.Index(id, "@")
		c := byte('a')
		if id[at-1] == 'a' {
			c = 'b'
		}
		return id[:at-1] + string(c) + id[at:]
	}
	owners := []string{"jane@example.com", "pat@smithcpa.com", "bob@example.com"}
	cases := map[string][]proofBody{
		"another worker's proof": {{"bob@example.com", elsewhere}},
		"another owner's proof":  {{"bob@example.com", pat}},
		"a tampered mac":         {{"pat@smithcpa.com", flip(pat)}},
		"an owner not listed":    {{"carol@example.com", pat}},
		"another domain":         {{"pat@smithcpa.com", strings.Replace(pat, "fountbox.com", "example.com", 1)}},
		"not a connect id":       {{"pat@smithcpa.com", "<abc@fountbox.com>"}},
		"one bad among good":     {{"pat@smithcpa.com", pat}, {"bob@example.com", flip(bob)}},
	}
	check := func(name string, proofs []proofBody, owners []string) {
		t.Helper()
		before, _ := f.rt.Snapshot(f.mb.id)
		rec := f.put(f.mb, 2, owners, proofs...)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "connect proof invalid or expired") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if after, _ := f.rt.Snapshot(f.mb.id); fmt.Sprint(before) != fmt.Sprint(after) {
			t.Errorf("%s: the record changed", name)
		}
	}
	for name, proofs := range cases {
		check(name, proofs, owners)
	}
	check("an owner not in the list", []proofBody{{"bob@example.com", bob}}, []string{"jane@example.com"})

	f.clk.add(routing.ConnectLifetime + time.Second)
	check("expired", []proofBody{{"pat@smithcpa.com", pat}}, owners)
}
