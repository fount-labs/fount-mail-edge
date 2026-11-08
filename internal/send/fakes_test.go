package send

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

// testCA issues certificates the deliverer trusts through Deliverer.Roots.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) leaf(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeMX is a small SMTP server. It refuses RCPT for any local part "nobody".
type fakeMX struct {
	ln       net.Listener
	cert     tls.Certificate
	noTLS    bool
	mu       sync.Mutex
	received [][]byte
	rcpts    []string
	plainCmd []string // commands seen before STARTTLS
}

func newFakeMX(t *testing.T, cert tls.Certificate) *fakeMX {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMX{ln: ln, cert: cert}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *fakeMX) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	w := func(s string) { io.WriteString(c, s+"\r\n") }
	w("220 mx ready")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		if !secure {
			m.mu.Lock()
			m.plainCmd = append(m.plainCmd, cmd)
			m.mu.Unlock()
		}
		up := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if !secure && !m.noTLS {
				w("250-mx\r\n250-SIZE 1000000\r\n250 STARTTLS")
			} else {
				w("250-mx\r\n250 SIZE 1000000")
			}
		case up == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{m.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, r, secure = tc, bufio.NewReader(tc), true
			w = func(s string) { io.WriteString(c, s+"\r\n") }
		case strings.HasPrefix(up, "MAIL FROM:"):
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			if strings.Contains(up, "<NOBODY@") {
				w("550 5.1.1 no such user")
				continue
			}
			m.mu.Lock()
			m.rcpts = append(m.rcpts, cmd[len("RCPT TO:"):])
			m.mu.Unlock()
			w("250 ok")
		case up == "DATA":
			w("354 go")
			var data []byte
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data = append(data, strings.TrimPrefix(l, ".")...)
			}
			m.mu.Lock()
			m.received = append(m.received, data)
			m.mu.Unlock()
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("500 what")
		}
	}
}

// fakeRelay is the gateway's relay: TLS 1.3 with a pinned server key, a client
// key it checks against clientPin, then CONNECT to a name in routes.
type fakeRelay struct {
	ln        net.Listener
	cert      tls.Certificate
	routes    map[string]string // "host:port" -> local address
	clientPin gatewaytls.Pin
	mu        sync.Mutex
	asked     []string
}

func newFakeRelay(t *testing.T, cert tls.Certificate, clientPin gatewaytls.Pin, routes map[string]string) *fakeRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelay{ln: ln, cert: cert, routes: routes, clientPin: clientPin}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRelay) serve(raw net.Conn) {
	defer raw.Close()
	c := tls.Server(raw, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{f.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if pinOf(leaf) != f.clientPin {
				return io.ErrUnexpectedEOF
			}
			return nil
		},
	})
	if err := c.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	f.mu.Lock()
	f.asked = append(f.asked, req.Host)
	f.mu.Unlock()
	target, ok := f.routes[req.Host]
	if !ok {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	go io.Copy(up, br)
	io.Copy(c, up)
}

type fakeResolver struct {
	mx  map[string][]MX
	txt map[string][]string
}

func (r fakeResolver) MX(_ context.Context, d string) ([]MX, error) {
	if v, ok := r.mx[d]; ok {
		return v, nil
	}
	return nil, ErrNoRecord
}

func (r fakeResolver) TXT(_ context.Context, n string) ([]string, error) {
	if v, ok := r.txt[n]; ok {
		return v, nil
	}
	return nil, ErrNoRecord
}

func pinOf(c *x509.Certificate) gatewaytls.Pin { return gatewaytls.PinOf(c.RawSubjectPublicKeyInfo) }

func leafOf(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x
}
