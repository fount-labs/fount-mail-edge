// Command edgestub stands in for the edge's tunnelled ports so test-haproxy.sh
// can run the gateway's real HAProxy config. It uses the edge's own gatewaytls
// listener, then echoes the PROXY header back in the SMTP greeting.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: edgestub CLIENT_PEM_OUT")
	}
	server := selfSigned("edge")
	client := selfSigned("gateway")
	writeClientPEM(os.Args[1], client)
	pin := gatewaytls.PinOf(client.Leaf.RawSubjectPublicKeyInfo)
	base := &tls.Config{Certificates: []tls.Certificate{server}}

	go serveReady("127.0.0.1:2508")
	go serveACME(listen("127.0.0.1:2580", base, pin))
	serveSMTP(listen("127.0.0.1:2526", base, pin))
}

func listen(addr string, base *tls.Config, pin gatewaytls.Pin) net.Listener {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	return gatewaytls.Listen(ln, base, []gatewaytls.Pin{pin})
}

func serveReady(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ready") })
	log.Fatal(http.ListenAndServe(addr, mux))
}

func serveACME(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "acme "+r.URL.Path) })
	log.Fatal(http.Serve(ln, mux))
}

func serveSMTP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			fmt.Fprintf(c, "220 %s\r\n", strings.TrimSpace(line))
		}()
	}
}

func selfSigned(cn string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func writeClientPEM(path string, c tls.Certificate) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		log.Fatal(err)
	}
}
