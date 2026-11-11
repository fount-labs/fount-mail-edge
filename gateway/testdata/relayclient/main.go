// Command relayclient drives the gateway relay for test-relay.sh with the edge's
// own relay client (internal/send.Relay), over the real network.
//
//	relayclient setup DIR   writes DIR/server.pem (a stand-in gateway key) and
//	                        DIR/edge.key, and prints the edge key's pin
//	relayclient check ADDR DIR
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
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

func main() {
	switch {
	case len(os.Args) == 3 && os.Args[1] == "setup":
		setup(os.Args[2])
	case len(os.Args) == 4 && os.Args[1] == "check":
		os.Exit(check(os.Args[2], os.Args[3]))
	default:
		log.Fatal("usage: relayclient setup DIR | check ADDR DIR")
	}
}

func setup(dir string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	must(os.WriteFile(filepath.Join(dir, "server.pem"), out, 0o600))

	_, edge, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	edgeDER, err := x509.MarshalPKCS8PrivateKey(edge)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "edge.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edgeDER}), 0o600))
	spki, err := x509.MarshalPKIXPublicKey(edge.Public())
	must(err)
	pin := gatewaytls.PinOf(spki)
	fmt.Println(hex.EncodeToString(pin[:]))
}

func check(addr, dir string) int {
	serverPEM, err := os.ReadFile(filepath.Join(dir, "server.pem"))
	must(err)
	block, _ := pem.Decode(serverPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	must(err)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "edge.key"))
	must(err)
	kb, _ := pem.Decode(keyPEM)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	must(err)
	cert, err := send.RelayClientCert(k.(ed25519.PrivateKey))
	must(err)
	relay := &send.Relay{Addr: addr, ClientCert: cert, Pins: []gatewaytls.Pin{gatewaytls.PinOf(leaf.RawSubjectPublicKeyInfo)}}

	failed := 0
	report := func(ok bool, format string, a ...any) {
		tag := "ok  "
		if !ok {
			tag = "FAIL"
			failed++
		}
		fmt.Printf("%s %s\n", tag, fmt.Sprintf(format, a...))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// HTTPS through the relay, validated from this end, as the edge fetches DoH
	// and MTA-STS policies.
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: relay.DialContext}}
	for _, u := range []string{
		"https://dns.google/resolve?name=gmail.com&type=MX",
		"https://cloudflare-dns.com/dns-query?name=gmail.com&type=MX",
		"https://mta-sts.gmail.com/.well-known/mta-sts.txt",
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			report(false, "%s: %v", u, err)
			continue
		}
		resp.Body.Close()
		report(resp.StatusCode == 200, "%s: %s", u, resp.Status)
	}

	// Port 25 is allowed; whether it connects depends on the network this test
	// runs on (many block outbound 25), so a dial failure (502) also passes.
	c, err := relay.DialContext(ctx, "tcp", "gmail-smtp-in.l.google.com:25")
	switch {
	case err == nil:
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		report(strings.HasPrefix(line, "220"), "gmail-smtp-in.l.google.com:25: %q", strings.TrimSpace(line))
	case strings.Contains(err.Error(), "502"):
		report(true, "gmail-smtp-in.l.google.com:25: allowed, but this network can't reach port 25 (%v)", err)
	default:
		report(false, "gmail-smtp-in.l.google.com:25: %v", err)
	}

	for _, a := range []string{
		"example.com:443",              // not a DoH or MTA-STS host
		"127.0.0.1:25",                 // loopback
		"localhost:25",                 // a name for loopback
		"127.0.0.1.nip.io:25",          // a public DNS name that answers loopback
		"mta-sts.127.0.0.1.nip.io:443", // an allowed shape that answers loopback
		"169.254.169.254:25",           // EC2 metadata
	} {
		_, err := relay.DialContext(ctx, "tcp", a)
		report(err != nil && strings.Contains(err.Error(), "403"), "%s refused: %v", a, err)
	}

	// Another client key gets nothing.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherCert, _ := send.RelayClientCert(other)
	tc, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{otherCert}, InsecureSkipVerify: true})
	if err == nil {
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(tc, "CONNECT dns.google:443 HTTP/1.1\r\n\r\n")
		_, err = tc.Read(make([]byte, 1))
		tc.Close()
	}
	report(err != nil, "unpinned client key refused: %v", err)
	return failed
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
