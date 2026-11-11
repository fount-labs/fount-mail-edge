// Command relay is the gateway's outbound relay for the edge (design §14).
// Tinfoil's port 25 is dead, so the edge sends mail, and fetches the DNS and
// MTA-STS it checks first, through this listener.
//
// It accepts only mutual TLS 1.3 from the edge's pinned relay client key (the
// vault send keyset's relay_client_pin), reads one CONNECT request, and relays
// TCP to port 25 on a public address, or to port 443 on dns.google,
// cloudflare-dns.com or an mta-sts.* host. Names are resolved once here, every
// address is checked, and only checked addresses are dialed, with a socket-level
// check on the address actually dialed. TLS to the destination runs from the
// enclave, so the relay sees only ciphertext after the CONNECT line.
//
// It writes no logs: a destination names a recipient's mail provider.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

func main() {
	listen := flag.String("listen", ":443", "address to listen on")
	cert := flag.String("cert", filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "server.pem"),
		"PEM with the server certificate chain and its key (the gateway's client certificate, whose pin the edge has in SEND_RELAY_PINS)")
	pins := flag.String("client-pins", "", "comma-separated hex SHA-256 of the edge relay client key's SubjectPublicKeyInfo")
	maxConns := flag.Int("max-conns", 32, "open relayed streams at most")
	flag.Parse()
	// run returns only when the relay can't start or its listener fails.
	fmt.Fprintln(os.Stderr, "relay:", run(*listen, *cert, *pins, *maxConns))
	os.Exit(1)
}

func run(listen, certPath, pinList string, maxConns int) error {
	pins, err := gatewaytls.ParsePins(pinList)
	if err != nil {
		return fmt.Errorf("-client-pins: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		return fmt.Errorf("-cert: %w", err)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	base := &tls.Config{Certificates: []tls.Certificate{cert}}
	r := &Relay{MaxConns: maxConns}
	return r.Serve(gatewaytls.Listen(ln, base, pins))
}
