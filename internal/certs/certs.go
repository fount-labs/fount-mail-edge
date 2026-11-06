// Package certs holds the SMTP serving certificate — the CA-issued cert that
// real senders validate during STARTTLS — and orchestrates its issuance.
//
// Lifecycle (design §6):
//
//   - A certificate is needed every boot, for the attested TLS key.
//   - On a process restart, a cached cert is reloaded first so a crash loop
//     doesn't burn the Let's Encrypt rate limit. (Production cache = S3; the
//     Cache interface here lets a disk cache stand in during development.)
//   - Otherwise the edge waits for the gateway's first health check (the
//     reachable signal), waits 15s so HAProxy's two checks pass, then runs ACME
//     through the gateway's HTTP-01 path, retrying with backoff.
//   - Until a cert loads, SMTP answers 421 and /ready reports not-ready.
package certs

import (
	"context"
	"crypto/tls"
	"log"
	"sync"
	"time"
)

type Manager struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func NewManager() *Manager { return &Manager{} }

// Current returns the serving certificate and whether one is loaded. SMTP must
// answer 421 and /ready must report not-ready while ok is false.
func (m *Manager) Current() (*tls.Certificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert, m.cert != nil
}

// Set installs a certificate (from ACME issuance or a cache reload).
func (m *Manager) Set(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert = cert
}

// Cache persists an issued certificate across process restarts within a boot.
// Production backs this with S3 (design §6); DiskCache stands in for dev.
type Cache interface {
	Load(host string) (*tls.Certificate, bool)
	Store(host string, cert *tls.Certificate) error
}

// IssueFunc runs one full ACME order for host and returns a certificate.
type IssueFunc func(ctx context.Context, host string) (*tls.Certificate, error)

// Timing knobs (design §6: wait 15s so HAProxy's two checks pass; back off ~3min
// between failed issuances so Let's Encrypt's 5-validations/hour isn't exhausted).
// Overridable in tests.
var (
	readyWait    = 15 * time.Second
	retryBackoff = 3 * time.Minute
)

// RunLoop drives certificate acquisition into m. It returns when a cert is
// installed or ctx is cancelled.
func RunLoop(ctx context.Context, m *Manager, cache Cache, reachable <-chan struct{}, host string, issue IssueFunc) {
	if cache != nil {
		if cert, ok := cache.Load(host); ok {
			log.Printf("certs: loaded cached certificate for %s", host)
			m.Set(cert)
			return
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-reachable:
		log.Printf("certs: gateway reachable; waiting %s for HAProxy checks", readyWait)
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(readyWait):
	}

	for attempt := 1; ; attempt++ {
		cert, err := issue(ctx, host)
		if err == nil {
			m.Set(cert)
			if cache != nil {
				if err := cache.Store(host, cert); err != nil {
					log.Printf("certs: cache store failed (non-fatal): %v", err)
				}
			}
			log.Printf("certs: certificate installed for %s", host)
			return
		}
		log.Printf("certs: issuance attempt %d failed: %v", attempt, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryBackoff):
		}
	}
}
