package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// rig runs the relay behind the real gatewaytls listener, with a fake resolver
// and a dialer that records what it was asked and connects every allowed
// address to one local echo server.
type rig struct {
	addr       string
	serverPin  gatewaytls.Pin
	clientCert tls.Certificate // the edge's, made the way the edge makes it

	mu      sync.Mutex
	dialed  []string
	lookups map[string]int
}

func newRig(t *testing.T, names func(name string, n int) []string, maxConns int) *rig {
	t.Helper()
	_, relayKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := send.RelayClientCert(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, _ := x509.ParseCertificate(clientCert.Certificate[0])
	server := selfSigned(t)

	echo := listen(t)
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	r := &rig{serverPin: gatewaytls.PinOf(server.Leaf.RawSubjectPublicKeyInfo), clientCert: clientCert, lookups: map[string]int{}}
	relay := &Relay{
		MaxConns: maxConns,
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			r.mu.Lock()
			r.lookups[host]++
			n := r.lookups[host]
			r.mu.Unlock()
			var out []netip.Addr
			for _, s := range names(host, n) {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, nil
		},
		Dial: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
			r.mu.Lock()
			r.dialed = append(r.dialed, ap.String())
			r.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", echo.Addr().String())
		},
	}
	inner := listen(t)
	ln := gatewaytls.Listen(inner, &tls.Config{Certificates: []tls.Certificate{server}},
		[]gatewaytls.Pin{gatewaytls.PinOf(clientLeaf.RawSubjectPublicKeyInfo)})
	go func() { _ = relay.Serve(ln) }()
	r.addr = inner.Addr().String()
	return r
}

// edge is the edge's real relay client (internal/send/relay.go), so these tests
// hold the relay to the contract the edge dials with.
func (r *rig) edge() *send.Relay {
	return &send.Relay{Addr: r.addr, ClientCert: r.clientCert, Pins: []gatewaytls.Pin{r.serverPin}}
}

func (r *rig) dials() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dialed...)
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

var dns = map[string][]string{
	"mx.smithcpa.com":        {"93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"},
	"dns.google":             {"8.8.8.8"},
	"cloudflare-dns.com":     {"104.16.249.249"},
	"mta-sts.smithcpa.com":   {"93.184.215.15"},
	"inside.example.com":     {"10.0.0.5"},
	"mixed.example.com":      {"93.184.215.16", "127.0.0.1"},
	"metadata.example.com":   {"169.254.169.254"},
	"metadata6.example.com":  {"fd00:ec2::254"},
	"mapped.example.com":     {"::ffff:172.31.0.2"},
	"mta-sts.inside.example": {"192.168.1.10"},
}

func static(name string, _ int) []string { return dns[name] }

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
	}
}

func TestRelaysWhatTheEdgeAsksFor(t *testing.T) {
	r := newRig(t, static, 8)
	for addr, want := range map[string]string{
		"mx.smithcpa.com:25":       "93.184.215.14:25",
		"MX.smithcpa.com.:25":      "93.184.215.14:25",
		"8.8.4.4:25":               "8.8.4.4:25",
		"dns.google:443":           "8.8.8.8:443",
		"cloudflare-dns.com:443":   "104.16.249.249:443",
		"mta-sts.smithcpa.com:443": "93.184.215.15:443",
	} {
		before := len(r.dials())
		c, err := r.edge().DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		roundTrip(t, c, "EHLO mx1.fountbox.com\r\n")
		c.Close()
		if got := r.dials()[before:]; len(got) != 1 || got[0] != want {
			t.Errorf("%s dialed %v, want [%s]", addr, got, want)
		}
	}
}

func TestRefusesBeforeDialing(t *testing.T) {
	r := newRig(t, static, 8)
	for _, addr := range []string{
		"example.com:443",            // 443 only to DoH and MTA-STS
		"8.8.8.8:443",                // not by address either
		"127.0.0.1:25",               // loopback literal
		"[::1]:25",                   //
		"169.254.169.254:25",         // EC2 metadata
		"[fd00:ec2::254]:25",         // EC2 metadata over IPv6
		"inside.example.com:25",      // resolves to a private address
		"mixed.example.com:25",       // one private answer refuses the name
		"metadata.example.com:25",    // resolves to the metadata service
		"metadata6.example.com:25",   //
		"mapped.example.com:25",      // IPv4-mapped private
		"mta-sts.inside.example:443", // an allowed name that resolves inside
	} {
		_, err := r.edge().DialContext(context.Background(), "tcp", addr)
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s: %v, want 403", addr, err)
		}
	}
	if got := r.dials(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

// A name that answers public once and private after (DNS rebinding) is looked
// up once, and only that checked address is dialed.
func TestRebindingDialsTheCheckedAddress(t *testing.T) {
	rebind := func(name string, n int) []string {
		if n == 1 {
			return []string{"93.184.215.20"}
		}
		return []string{"127.0.0.1"}
	}
	r := newRig(t, rebind, 8)
	c, err := r.edge().DialContext(context.Background(), "tcp", "rebind.example.com:25")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := r.dials(); len(got) != 1 || got[0] != "93.184.215.20:25" {
		t.Fatalf("dialed %v", got)
	}
	r.mu.Lock()
	n := r.lookups["rebind.example.com"]
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("looked up %d times", n)
	}
	// The next connection sees the private answer and is refused.
	if _, err := r.edge().DialContext(context.Background(), "tcp", "rebind.example.com:25"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("second lookup: %v, want 403", err)
	}
}

// raw opens mutual TLS as the edge would, and returns the connection for a
// hand-written request.
func (r *rig) raw(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", r.addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{r.clientCert},
		InsecureSkipVerify: true, // a test; the edge pins the server key
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func status(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" {
			break
		}
	}
	return strings.TrimSpace(line)
}

func TestRequestShape(t *testing.T) {
	r := newRig(t, static, 8)
	for req, want := range map[string]string{
		"CONNECT mx.smithcpa.com:587 HTTP/1.1\r\nHost: mx.smithcpa.com:587\r\n\r\n":         "HTTP/1.1 403 Forbidden",
		"GET http://mx.smithcpa.com:25/ HTTP/1.1\r\nHost: x\r\n\r\n":                        "HTTP/1.1 400 Bad Request",
		"CONNECT mx.smithcpa.com:25\r\n\r\n":                                                "HTTP/1.1 400 Bad Request",
		"CONNECT mx.smithcpa.com:25 HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 40) + "\r\n": "HTTP/1.1 400 Bad Request",
		"CONNECT " + strings.Repeat("a", 5000) + ":25 HTTP/1.1\r\n\r\n":                     "HTTP/1.1 400 Bad Request",
	} {
		c := r.raw(t)
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		if got := status(t, bufio.NewReader(c)); got != want {
			t.Errorf("%.40q: %q, want %q", req, got, want)
		}
	}
	if got := r.dials(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

// Bytes sent right behind the request, before the 200, still reach upstream.
func TestPipelinedBytesReachUpstream(t *testing.T) {
	r := newRig(t, static, 8)
	c := r.raw(t)
	if _, err := io.WriteString(c, "CONNECT mx.smithcpa.com:25 HTTP/1.1\r\nHost: mx.smithcpa.com:25\r\n\r\nEHLO early\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if got := status(t, br); got != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", got)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "EHLO early\r\n" {
		t.Fatalf("echo %q, %v", line, err)
	}
}

func TestOnlyThePinnedEdgeGetsIn(t *testing.T) {
	r := newRig(t, static, 8)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := send.RelayClientCert(otherKey)
	for name, cfg := range map[string]*tls.Config{
		"another key":           {MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{other}},
		"no client certificate": {MinVersion: tls.VersionTLS13},
		"TLS 1.2":               {MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{r.clientCert}},
	} {
		cfg.InsecureSkipVerify = true
		c, err := tls.Dial("tcp", r.addr, cfg)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			// TLS 1.3 client auth fails after the client's handshake returns, on
			// the first read.
			_, _ = io.WriteString(c, "CONNECT mx.smithcpa.com:25 HTTP/1.1\r\n\r\n")
			_, err = c.Read(make([]byte, 1))
			c.Close()
		}
		if err == nil {
			t.Errorf("%s: got a reply", name)
		}
	}
	// The edge's client refuses a relay whose key it hasn't pinned.
	e := r.edge()
	e.Pins = []gatewaytls.Pin{{1}}
	if _, err := e.DialContext(context.Background(), "tcp", "mx.smithcpa.com:25"); err == nil {
		t.Error("edge accepted an unpinned relay")
	}
	if got := r.dials(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

func TestMaxConns(t *testing.T) {
	r := newRig(t, static, 1)
	held, err := r.edge().DialContext(context.Background(), "tcp", "mx.smithcpa.com:25")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, held, "x")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.edge().DialContext(ctx, "tcp", "mx.smithcpa.com:25"); err == nil {
		t.Fatal("a second stream got through with MaxConns 1")
	}
	held.Close()
	// The slot frees once the first stream ends.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := r.edge().DialContext(context.Background(), "tcp", "mx.smithcpa.com:25")
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never freed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
