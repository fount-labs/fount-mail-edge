// Package gatewaytls is the mutual-TLS layer on the edge's tunnelled ports
// (design §7). Anyone holding a tk_ key can open a tunnel, so the tunnel alone
// doesn't prove the peer is our gateway. Each gateway's client key is pinned in
// the attested config, and a connection must present one before the edge reads
// any byte of it: without this, any tunnel could write a PROXY header naming a
// fake sender IP, or start ACME early.
package gatewaytls

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Pin is the SHA-256 of a gateway client certificate's SubjectPublicKeyInfo.
type Pin [sha256.Size]byte

// ParsePins reads a comma-separated list of hex pins. An empty list is an error:
// a tunnelled port with no pins would refuse every gateway.
func ParsePins(s string) ([]Pin, error) {
	var pins []Pin
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		b, err := hex.DecodeString(f)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("gateway pin %q is not 32 hex-encoded bytes", f)
		}
		pins = append(pins, Pin(b))
	}
	if len(pins) == 0 {
		return nil, errors.New("no gateway pins")
	}
	return pins, nil
}

// PinOf returns the pin for a certificate's raw SubjectPublicKeyInfo.
func PinOf(rawSPKI []byte) Pin { return sha256.Sum256(rawSPKI) }

// Listen wraps ln so every connection must complete TLS 1.3 with a client key
// in pins. base supplies the server certificate. The handshake runs on the first
// read, so a slow peer holds only its own connection, never the accept loop.
func Listen(ln net.Listener, base *tls.Config, pins []Pin) net.Listener {
	return tls.NewListener(ln, config(base, pins))
}

func config(base *tls.Config, pins []Pin) *tls.Config {
	c := base.Clone()
	c.MinVersion = tls.VersionTLS13
	c.ClientAuth = tls.RequireAnyClientCert // the pin is the check, not a CA
	// VerifyConnection, unlike VerifyPeerCertificate, also runs on resumption.
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no gateway client certificate")
		}
		got := PinOf(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		for _, p := range pins {
			if subtle.ConstantTimeCompare(got[:], p[:]) == 1 {
				return nil
			}
		}
		return errors.New("gateway client key is not pinned")
	}
	return c
}
