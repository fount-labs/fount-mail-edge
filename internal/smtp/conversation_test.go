package smtp

// An end-to-end conversation harness: a real TLS client speaks the whole SMTP
// exchange — PROXY header, greeting, EHLO, STARTTLS, handshake with the attested
// cert, MAIL/RCPT/DATA — against a live listener. The fuzz and property tests
// cover the parsers and invariants in isolation; this exercises the STARTTLS
// state machine and the "answer 250 only after the store confirms" contract that
// only a full conversation reaches (design §6, §7).

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/limit"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const (
	testHostname = "mx.fountbox.com"
	testDomain   = "fountbox.com"
)

// --- test doubles ----------------------------------------------------------

type staticCert struct{ c tls.Certificate }

func (s staticCert) Current() (*tls.Certificate, bool) { return &s.c, true }

func testCertSource(t *testing.T) CertSource {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testHostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{testHostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return staticCert{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}}
}

type putRecord struct {
	recipient, sender string
	raw               []byte
}

type captureStore struct {
	mu   sync.Mutex
	puts []putRecord
	err  error // when set, Put fails (the store-not-confirmed path)
}

func (c *captureStore) Put(_ context.Context, recipient, sender string, raw []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return "", c.err
	}
	c.puts = append(c.puts, putRecord{recipient, sender, append([]byte(nil), raw...)})
	return "msg-" + strconv.Itoa(len(c.puts)), nil
}

func (c *captureStore) last() (putRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.puts) == 0 {
		return putRecord{}, false
	}
	return c.puts[len(c.puts)-1], true
}

func (c *captureStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.puts)
}

// mapRecipients is a RecipientChecker backed by a fixed table; an address not in
// the table is Unknown (no catch-all).
type mapRecipients map[string]RecipientStatus

func (m mapRecipients) Status(_ context.Context, recipient string) (RecipientStatus, error) {
	if st, ok := m[strings.ToLower(recipient)]; ok {
		return st, nil
	}
	return RecipientUnknown, nil
}

func newTestServer(t *testing.T, store Storer, rc RecipientChecker, maxBytes int64) string {
	t.Helper()
	return serve(t, Options{
		Hostname:   testHostname,
		Domain:     testDomain,
		Certs:      testCertSource(t),
		Store:      store,
		Recipients: rc,
		MaxBytes:   maxBytes,
		Deadline:   5 * time.Second,
	})
}

// serve binds 127.0.0.1:0, runs the server on it, and returns the address. It
// lets a test supply full Options (e.g. tiny byte budgets) beyond newTestServer's
// common shape.
func serve(t *testing.T, o Options) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(o)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	return ln.Addr().String()
}

// --- conversation helper ---------------------------------------------------

type convo struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// dial opens a connection, sends the single PROXY header the gateway prepends,
// and consumes the 220 greeting.
func dial(t *testing.T, addr string) *convo {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := &convo{t: t, conn: conn, r: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	c.send("PROXY TCP4 198.51.100.7 203.0.113.1 40000 25")
	c.expect("220")
	return c
}

func (c *convo) send(format string, a ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.conn, format+"\r\n", a...); err != nil {
		c.t.Fatalf("send %q: %v", fmt.Sprintf(format, a...), err)
	}
}

// expect reads a (possibly multiline) reply and asserts the final line starts
// with code. It returns the whole reply joined by newlines so a caller can check
// advertised extensions.
func (c *convo) expect(code string) string {
	c.t.Helper()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read reply (want %s): %v (so far: %q)", code, err, strings.Join(lines, "\n"))
		}
		trimmed := strings.TrimRight(line, "\r\n")
		lines = append(lines, trimmed)
		if len(trimmed) < 4 || trimmed[3] == ' ' { // SMTP: '-' continues, ' ' ends
			break
		}
	}
	full := strings.Join(lines, "\n")
	if !strings.HasPrefix(lines[len(lines)-1], code) {
		c.t.Fatalf("want reply %s, got %q", code, full)
	}
	return full
}

// startTLS runs EHLO + STARTTLS and upgrades the connection, leaving the convo
// speaking TLS. It returns the plaintext EHLO reply so a caller can assert what
// was advertised before the upgrade.
func (c *convo) startTLS() string {
	c.t.Helper()
	c.send("EHLO client.example")
	reply := c.expect("250")
	c.send("STARTTLS")
	c.expect("220")
	tc := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, ServerName: testHostname})
	if err := tc.Handshake(); err != nil {
		c.t.Fatalf("tls handshake: %v", err)
	}
	c.conn = tc
	c.r = bufio.NewReader(tc)
	return reply
}

// --- tests -----------------------------------------------------------------

func TestConversationStoresMessage(t *testing.T) {
	store := &captureStore{}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 4096)

	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<worker@fountbox.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	// A line beginning ".." is dot-stuffed on the wire; the stored body must undo it.
	fmt.Fprint(c.conn, "Subject: hi\r\n\r\nBody line\r\n..dotted\r\n.\r\n")
	c.expect("250")
	c.send("QUIT")
	c.expect("221")

	rec, ok := store.last()
	if !ok {
		t.Fatal("no message stored after a 250")
	}
	if rec.recipient != "worker@fountbox.com" {
		t.Fatalf("recipient = %q", rec.recipient)
	}
	if rec.sender != "sender@elsewhere.com" {
		t.Fatalf("sender = %q", rec.sender)
	}
	want := "Subject: hi\r\n\r\nBody line\r\n.dotted\r\n"
	if string(rec.raw) != want {
		t.Fatalf("stored body = %q, want %q", rec.raw, want)
	}
}

// Before TLS the server offers STARTTLS; after the upgrade it must not re-offer
// it, and it advertises SIZE instead.
func TestEHLOAdvertisesSTARTTLSOnlyBeforeTLS(t *testing.T) {
	addr := newTestServer(t, &captureStore{}, mapRecipients{}, 4096)
	c := dial(t, addr)

	plain := c.startTLS()
	if !strings.Contains(plain, "STARTTLS") {
		t.Fatalf("plaintext EHLO must advertise STARTTLS, got %q", plain)
	}
	c.send("EHLO client.example")
	secure := c.expect("250")
	if strings.Contains(secure, "STARTTLS") {
		t.Fatalf("post-TLS EHLO must not re-advertise STARTTLS, got %q", secure)
	}
	if !strings.Contains(secure, "SIZE") {
		t.Fatalf("post-TLS EHLO must advertise SIZE, got %q", secure)
	}
}

// MAIL/RCPT/DATA before STARTTLS are refused with 530 (TLS is mandatory, §6).
func TestMailBeforeSTARTTLSRejected(t *testing.T) {
	addr := newTestServer(t, &captureStore{}, mapRecipients{}, 4096)
	c := dial(t, addr)
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<a@elsewhere.com>")
	c.expect("530")
}

// RCPT applies the no-catch-all and entitlement rules (§4, §6): unknown and
// expired both bounce 550, only an accepting address gets 250.
func TestRecipientStatusEnforced(t *testing.T) {
	addr := newTestServer(t, &captureStore{}, mapRecipients{
		"live@fountbox.com": RecipientAccepting,
		"dead@fountbox.com": RecipientExpired,
	}, 4096)
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")

	c.send("RCPT TO:<nobody@fountbox.com>") // not in the table
	c.expect("550")
	c.send("RCPT TO:<dead@fountbox.com>") // entitlement lapsed
	c.expect("550")
	c.send("RCPT TO:<elsewhere@notours.com>") // wrong domain
	c.expect("550")
	c.send("RCPT TO:<live@fountbox.com>") // accepting
	c.expect("250")
}

// A body past MaxBytes is refused 552 and nothing is stored.
func TestMessageTooLargeRejected(t *testing.T) {
	store := &captureStore{}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 64)
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<worker@fountbox.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	fmt.Fprint(c.conn, strings.Repeat("A", 200)+"\r\n.\r\n")
	c.expect("552")
	if _, ok := store.last(); ok {
		t.Fatal("an over-size message must not be stored")
	}
}

// startData runs a conversation up to the DATA prompt.
func (c *convo) startData() {
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<worker@fountbox.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
}

// expectClosed fails unless the server has closed the connection.
func (c *convo) expectClosed(t *testing.T) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Fatalf("connection still open, read %q", line)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection still open")
	}
}

// Text past an overrun must not run as commands. Before, MAIL/RCPT/DATA inside an
// oversize body became a new transaction under this connection's source IP.
func TestOverrunClosesConnection(t *testing.T) {
	store := &captureStore{}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting, "other@fountbox.com": RecipientAccepting}, 64)
	c := dial(t, addr)
	c.startData()
	fmt.Fprint(c.conn, strings.Repeat("A", 200)+"\r\nMAIL FROM:<x@elsewhere.com>\r\nRCPT TO:<other@fountbox.com>\r\nDATA\r\nhidden\r\n.\r\n")
	c.expect("552")
	c.expectClosed(t)
	if n := store.count(); n != 0 {
		t.Fatalf("stored %d messages from an overrun", n)
	}
}

// A bare line ending can't close a message, and the text after it can't become a
// second transaction.
func TestBareNewlinesInDataRejected(t *testing.T) {
	const hidden = "MAIL FROM:<x@elsewhere.com>\r\nRCPT TO:<worker@fountbox.com>\r\nDATA\r\nhidden\r\n.\r\n"
	for name, ending := range map[string]string{
		"LF dot CRLF":   "first\n.\r\n",
		"CRLF dot LF":   "first\r\n.\n",
		"LF dot LF":     "first\n.\n",
		"bare CR":       "fir\rst\r\n.\r\n",
		"CR dot CRLF":   "first\r.\r\n",
		"bare LF alone": "first\nsecond\r\n.\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			store := &captureStore{}
			addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 4096)
			c := dial(t, addr)
			c.startData()
			fmt.Fprint(c.conn, ending+hidden)
			c.expect("554")
			c.expectClosed(t)
			if n := store.count(); n != 0 {
				t.Fatalf("stored %d messages", n)
			}
		})
	}
}

// A message exactly at the cap fits, and one byte more doesn't.
func TestSizeCapBoundary(t *testing.T) {
	line := strings.Repeat("A", 62) + "\r\n" // 64 bytes
	for _, tc := range []struct {
		body string
		want string
	}{
		{line, "250"},
		{"x" + line, "552"},
	} {
		store := &captureStore{}
		addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 64)
		c := dial(t, addr)
		c.startData()
		fmt.Fprint(c.conn, tc.body+".\r\n")
		c.expect(tc.want)
	}
}

// A dot-stuffed line ending exactly at the cap fits once unstuffed.
func TestDotStuffedLineAtCap(t *testing.T) {
	store := &captureStore{}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 64)
	c := dial(t, addr)
	c.startData()
	body := "." + "." + strings.Repeat("A", 61) + "\r\n" // 64 bytes unstuffed
	fmt.Fprint(c.conn, body+".\r\n")
	c.expect("250")
	if got, ok := store.last(); !ok || len(got.raw) != 64 {
		t.Fatalf("stored %d bytes, ok=%v", len(got.raw), ok)
	}
}

// Only the first recipient can be accepted, so a sender is never told 250 for a
// recipient that won't be stored.
func TestSecondRecipientDeferred(t *testing.T) {
	store := &captureStore{}
	addr := newTestServer(t, store, mapRecipients{"one@fountbox.com": RecipientAccepting, "two@fountbox.com": RecipientAccepting}, 4096)
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<one@fountbox.com>")
	c.expect("250")
	c.send("RCPT TO:<two@fountbox.com>")
	if got := c.expect("452"); !strings.Contains(got, "4.5.3") {
		t.Fatalf("reply = %q", got)
	}
	c.send("DATA")
	c.expect("354")
	fmt.Fprint(c.conn, "body\r\n.\r\n")
	c.expect("250")
	if got, _ := store.last(); got.recipient != "one@fountbox.com" {
		t.Fatalf("stored for %q", got.recipient)
	}

	// The sender's retry of the second recipient goes through on the same connection.
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<two@fountbox.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	fmt.Fprint(c.conn, "body\r\n.\r\n")
	c.expect("250")
	if got, _ := store.last(); got.recipient != "two@fountbox.com" {
		t.Fatalf("stored for %q", got.recipient)
	}
	if n := store.count(); n != 2 {
		t.Fatalf("stored %d, want 2", n)
	}
}

// A failed store ends the transaction, so a retry can name its recipient again.
func TestFailedStoreEndsTransaction(t *testing.T) {
	store := &captureStore{err: errors.New("s3 unavailable")}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 4096)
	c := dial(t, addr)
	c.startData()
	fmt.Fprint(c.conn, "body\r\n.\r\n")
	c.expect("452")
	c.send("RCPT TO:<worker@fountbox.com>")
	c.expect("250")
}

// countingReader serves one long line with no LF and counts what was taken. It
// ends rather than running forever, so a read with no cap fails its test instead
// of filling this machine's memory.
type countingReader struct{ n int64 }

func (r *countingReader) Read(p []byte) (int, error) {
	if r.n >= 64<<20 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'A'
	}
	r.n += int64(len(p))
	return len(p), nil
}

// The line cap has to stop the read, not check it afterwards: a peer that never
// sends LF would otherwise fill memory before the check ever ran.
func TestLineCapStopsTheRead(t *testing.T) {
	src := &countingReader{}
	se := &session{r: bufio.NewReader(src)}
	if _, err := se.readLine(); !errors.Is(err, errLineTooLong) {
		t.Fatalf("err = %v", err)
	}
	if src.n > 2*maxLineBytes {
		t.Fatalf("read %d bytes for a %d byte cap", src.n, maxLineBytes)
	}
}

func TestLongestCommandLineAccepted(t *testing.T) {
	line := strings.Repeat("A", maxLineBytes-2) + "\r\n"
	se := &session{r: bufio.NewReader(strings.NewReader(line))}
	if got, err := se.readLine(); err != nil || len(got) != maxLineBytes-2 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	se = &session{r: bufio.NewReader(strings.NewReader("A" + line))}
	if _, err := se.readLine(); !errors.Is(err, errLineTooLong) {
		t.Fatalf("err = %v", err)
	}
}

// DATA is bounded the same way: an endless line stops at the message cap.
func TestDataCapStopsTheRead(t *testing.T) {
	const maxBytes = 1 << 20
	src := &countingReader{}
	se := &session{s: &Server{opt: Options{MaxBytes: maxBytes}}, r: bufio.NewReader(src)}
	if _, err := se.readData(); !errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if src.n > maxBytes+2*4096 {
		t.Fatalf("read %d bytes for a %d byte cap", src.n, maxBytes)
	}
}

// When the store does not confirm the write, the edge must answer 452 (retry),
// never 250 — a 250 the sender trusts means the mail is durably stored (§7).
func TestStoreFailureDoesNotAck(t *testing.T) {
	store := &captureStore{err: errors.New("s3 unavailable")}
	addr := newTestServer(t, store, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 4096)
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	c.send("MAIL FROM:<sender@elsewhere.com>")
	c.expect("250")
	c.send("RCPT TO:<worker@fountbox.com>")
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	fmt.Fprint(c.conn, "body\r\n.\r\n")
	c.expect("452")
}

// A routing write that lost a race with another edge asks for a retry, with 451.
func TestStoreConflictAsksForARetry(t *testing.T) {
	st := &captureStore{err: fmt.Errorf("sequence: %w", store.ErrConflict)}
	addr := newTestServer(t, st, mapRecipients{"worker@fountbox.com": RecipientAccepting}, 4096)
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")
	if got := c.deliver("sender@elsewhere.com", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "451") {
		t.Fatalf("reply = %q, want 451", got)
	}
}

// A connection with no PROXY header (the gateway always prepends one) is dropped
// without a greeting (§6).
func TestMissingProxyHeaderDropped(t *testing.T) {
	addr := newTestServer(t, &captureStore{}, mapRecipients{}, 4096)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Send a command that is not a valid PROXY header; the server closes.
	if _, err := fmt.Fprint(conn, "EHLO client.example\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("server must not greet a connection without a PROXY header")
	}
}

// deliver runs MAIL/RCPT/DATA for a one-line body from the given sender and
// returns the DATA reply code's first line, so a test can assert 250 vs 452.
func (c *convo) deliver(from, to, body string) string {
	c.t.Helper()
	c.send("MAIL FROM:<%s>", from)
	c.expect("250")
	c.send("RCPT TO:<%s>", to)
	c.expect("250")
	c.send("DATA")
	c.expect("354")
	fmt.Fprintf(c.conn, "%s\r\n.\r\n", body)
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read DATA reply: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// A source IP that pushes more than its byte budget in the window is answered
// 452 (retry later), not 250, and the over-budget message is never stored (§6).
func TestPerIPByteBudgetThrottles(t *testing.T) {
	store := &captureStore{}
	addr := serve(t, Options{
		Hostname:   testHostname,
		Domain:     testDomain,
		Certs:      testCertSource(t),
		Store:      store,
		Recipients: mapRecipients{"worker@fountbox.com": RecipientAccepting},
		MaxBytes:   4096,
		Deadline:   5 * time.Second,
		PerIP:      limit.New(0, 10), // 10-byte budget, no refill in-test
	})
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")

	// "body" + CRLF is 6 bytes: the first fits the 10-byte budget, the second
	// (another 6) exceeds the remaining 4 and is refused.
	if got := c.deliver("s@a.example", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "250") {
		t.Fatalf("first message reply = %q, want 250", got)
	}
	if got := c.deliver("s@a.example", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "452") {
		t.Fatalf("over-budget message reply = %q, want 452", got)
	}
	if n := store.count(); n != 1 {
		t.Fatalf("stored %d messages, want 1 (the over-budget one must not be stored)", n)
	}
}

// The per-sender-domain budget is keyed on the envelope sender's domain, so two
// senders in the same domain share it while a different domain is unaffected.
func TestPerSenderDomainByteBudgetThrottles(t *testing.T) {
	store := &captureStore{}
	addr := serve(t, Options{
		Hostname:   testHostname,
		Domain:     testDomain,
		Certs:      testCertSource(t),
		Store:      store,
		Recipients: mapRecipients{"worker@fountbox.com": RecipientAccepting},
		MaxBytes:   4096,
		Deadline:   5 * time.Second,
		PerSender:  limit.New(0, 10),  // shared 10-byte budget per sender domain
		PerIP:      limit.New(0, 1e9), // keep the IP budget out of the way
	})
	c := dial(t, addr)
	c.startTLS()
	c.send("EHLO client.example")
	c.expect("250")

	if got := c.deliver("alice@flood.example", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "250") {
		t.Fatalf("first message reply = %q, want 250", got)
	}
	// A different local part, same domain: the domain budget is already spent.
	if got := c.deliver("bob@flood.example", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "452") {
		t.Fatalf("same-domain over-budget reply = %q, want 452", got)
	}
	// A different domain has its own budget and still delivers.
	if got := c.deliver("carol@other.example", "worker@fountbox.com", "body"); !strings.HasPrefix(got, "250") {
		t.Fatalf("different-domain reply = %q, want 250", got)
	}
}
