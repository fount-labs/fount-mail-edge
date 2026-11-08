package send

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

// Relay reaches the outside through the gateway (§14 step 3). Tinfoil's port 25
// is dead and allowlist egress can't reach arbitrary hosts, so the gateway relays
// TCP and nothing else. TLS to the recipient's server runs from the enclave,
// through the relay, so the gateway sees only ciphertext.
//
// The edge proves itself with a client key the relay pins (§14 step 4), and pins
// the relay's key in turn. Then it asks for one destination with HTTP CONNECT.
// The relay must allow only what the edge asks for here: port 25 to anything
// public, and port 443 to the DNS-over-HTTPS hosts and mta-sts.* names.
type Relay struct {
	Addr       string           // host:port of the gateway's relay listener, on the edge allowlist
	ClientCert tls.Certificate  // the relay client key (send keyset, fount-mail-send-keys.md)
	Pins       []gatewaytls.Pin // the relay's server keys
	Dialer     net.Dialer
}

var errRelayPort = errors.New("relay: only ports 25 and 443 are relayed")

// DialContext opens a relayed TCP stream to addr. It is a net.Dialer-shaped
// function, so http.Transport and the SMTP client can both use it.
func (r *Relay) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("relay: network %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if port != "25" && port != "443" {
		return nil, errRelayPort
	}
	if host == "" || strings.ContainsAny(host, " \r\n/") {
		return nil, errors.New("relay: bad host")
	}
	raw, err := r.Dialer.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	conn := tls.Client(raw, r.tlsConfig())
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay handshake: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("relay refused %s: %s", addr, resp.Status)
	}
	// Anything the relay sent past its answer belongs to the stream.
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (r *Relay) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{r.ClientCert},
		// The relay is pinned, not named: it's a VM Fount runs, with no public
		// certificate of its own.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("relay sent no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			got := gatewaytls.PinOf(leaf.RawSubjectPublicKeyInfo)
			for _, p := range r.Pins {
				if p == got {
					return nil
				}
			}
			return errors.New("relay key is not pinned")
		},
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
