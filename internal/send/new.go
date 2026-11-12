package send

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

// Options is everything a Service needs. All network access goes through Relay.
type Options struct {
	Directory  Directory
	MailDomain string // "@fountbox.com"
	Hostname   string // EHLO name
	Relay      *Relay
	Signers    []*dkim.Signer
	Proven     ProofChecker   // required: routing.Store.OwnerProven
	DoH        []string       // nil is DefaultDoH
	Roots      *x509.CertPool // nil is the system roots; tests set their own
}

// New builds the send path: the edge's own checks (Policy) in front of an Outbox.
func New(o Options) (*Service, error) {
	switch {
	case o.Directory == nil:
		return nil, errors.New("send: no routing data")
	case o.Proven == nil:
		// The owner list is only what the licensee's device wrote, so sending
		// needs the edge's own proof that each owner reads the address (§10).
		return nil, errors.New("send: no owner proof check")
	}
	out, err := NewOutbox(o)
	if err != nil {
		return nil, err
	}
	return &Service{
		Policy: NewPolicy(PolicyOptions{
			Directory:  o.Directory,
			MailDomain: o.MailDomain,
			Proven:     o.Proven,
		}),
		Out: out,
	}, nil
}

// NewOutbox builds signing and delivery alone: DNS over HTTPS, MTA-STS, and SMTP,
// each through the relay with TLS ending in the enclave. It reads only the
// relay, signers, hostname, mail domain, DoH and roots from o; mail-send, which
// has no routing data, builds one with nothing else.
func NewOutbox(o Options) (*Outbox, error) {
	switch {
	case o.Relay == nil || o.Relay.Addr == "" || len(o.Relay.Pins) == 0 || len(o.Relay.ClientCert.Certificate) == 0:
		return nil, errors.New("send: the relay needs an address, pins, and a client key")
	case len(o.Signers) == 0:
		return nil, errors.New("send: no DKIM key")
	case o.Hostname == "" || o.MailDomain == "":
		return nil, errors.New("send: hostname and mail domain are required")
	}
	endpoints := o.DoH
	if endpoints == nil {
		endpoints = DefaultDoH
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:           o.Relay.DialContext,
			TLSClientConfig:       &tls.Config{RootCAs: o.Roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConnsPerHost:   2,
		},
		CheckRedirect: noRedirects,
	}
	resolver := &DoH{Client: client, Endpoints: endpoints}
	return &Outbox{
		MailDomain: o.MailDomain,
		Signers:    o.Signers,
		Deliverer: &Deliverer{
			Hostname: o.Hostname,
			Resolver: resolver,
			STS:      &STS{Resolver: resolver, Client: client},
			Dial:     o.Relay.DialContext,
			Roots:    o.Roots,
		},
	}, nil
}

// RelayClientCert wraps the relay client key in a self-signed certificate. The
// relay pins the key, not the certificate, so a new one each boot is fine.
func RelayClientCert(key crypto.Signer) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fount-mail-edge relay client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
