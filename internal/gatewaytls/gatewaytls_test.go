package gatewaytls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func newCert(t *testing.T) tls.Certificate {
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// exchange serves one connection through Listen and returns what the server read
// and what the client saw back. A refused client must never reach the read.
func exchange(t *testing.T, pins []Pin, client *tls.Config) (served string, reply string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, &tls.Config{Certificates: []tls.Certificate{newCert(t)}}, pins)
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if n > 0 {
			_, _ = c.Write([]byte("ok"))
		}
		got <- string(buf[:n])
	}()

	client.InsecureSkipVerify = true // the attested tunnel proves the enclave
	conn, err := tls.Dial("tcp", inner.Addr().String(), client)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("PROXY TCP4 1.2.3.4"))
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		reply = string(buf[:n])
	}
	return <-got, reply
}

func TestPinnedGatewayIsServed(t *testing.T) {
	gw := newCert(t)
	pins := []Pin{PinOf(newCert(t).Leaf.RawSubjectPublicKeyInfo), PinOf(gw.Leaf.RawSubjectPublicKeyInfo)}
	served, reply := exchange(t, pins, &tls.Config{Certificates: []tls.Certificate{gw}})
	if served != "PROXY TCP4 1.2.3.4" || reply != "ok" {
		t.Fatalf("served=%q reply=%q", served, reply)
	}
}

// An unpinned key and a client with no certificate read nothing: the edge must
// not see a PROXY header before the peer is proven.
func TestUnprovenPeerIsNeverRead(t *testing.T) {
	pins := []Pin{PinOf(newCert(t).Leaf.RawSubjectPublicKeyInfo)}
	for name, client := range map[string]*tls.Config{
		"unpinned key":   {Certificates: []tls.Certificate{newCert(t)}},
		"no certificate": {},
	} {
		t.Run(name, func(t *testing.T) {
			if served, reply := exchange(t, pins, client); served != "" || reply != "" {
				t.Fatalf("served=%q reply=%q", served, reply)
			}
		})
	}
}

// A plaintext PROXY line on the port (what an unwrapped HAProxy hop would send)
// isn't TLS, so it's dropped unread.
func TestPlaintextIsNeverRead(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, &tls.Config{Certificates: []tls.Certificate{newCert(t)}}, []Pin{{1}})
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(make([]byte, 64))
		got <- n
	}()
	conn, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 25 25\r\n"))
	if n := <-got; n > 0 {
		t.Fatalf("read %d plaintext bytes", n)
	}
}

func TestParsePins(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("CD", 32)
	pins, err := ParsePins(" " + a + ", " + b + ",")
	if err != nil || len(pins) != 2 {
		t.Fatalf("pins=%d err=%v", len(pins), err)
	}
	if hex.EncodeToString(pins[0][:]) != a {
		t.Fatalf("pin[0]=%x", pins[0])
	}
	for _, bad := range []string{"", " , ", "abcd", "PLACEHOLDER", strings.Repeat("z", 64)} {
		if _, err := ParsePins(bad); err == nil {
			t.Fatalf("ParsePins(%q) accepted", bad)
		}
	}
}
