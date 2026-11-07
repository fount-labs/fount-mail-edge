// Package certs holds the SMTP serving certificate — the CA-issued cert that
// real senders validate during STARTTLS — and orchestrates its issuance.
//
// Lifecycle (design §6):
//
//   - A certificate is needed every boot, for the attested TLS key.
//   - On a process restart, a cached cert is reloaded first so a crash loop
//     doesn't burn the Let's Encrypt rate limit. (Production cache = S3; the
//     Cache interface here lets a disk cache stand in during development.) Only a
//     clean miss issues: a failed read says nothing about the cache, so it's retried.
//   - Otherwise the edge waits for the gateway's first health check (the
//     reachable signal), waits 15s so HAProxy's two checks pass, then runs ACME
//     through the gateway's HTTP-01 path, retrying with backoff.
//   - The loop then renews at two-thirds of the certificate's lifetime.
//   - Until a cert loads, and from just before it expires, SMTP answers 421 and
//     /ready reports not-ready.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"sync"
	"time"
)

type Manager struct {
	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

func NewManager() *Manager { return &Manager{} }

// Current returns the serving certificate and whether it can be served. SMTP must
// answer 421 and /ready must report not-ready while ok is false, which includes the
// last moments of a certificate that failed to renew.
func (m *Manager) Current() (*tls.Certificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert, m.cert != nil && servable(m.leaf)
}

// Set installs a certificate (from ACME issuance or a cache reload).
func (m *Manager) Set(cert *tls.Certificate) {
	leaf, err := leafOf(cert)
	if err != nil {
		log.Printf("certs: installed certificate won't parse: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert, m.leaf = cert, leaf
}

// renewAt is when the current certificate should be replaced, if there is one.
func (m *Manager) renewAt() (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return time.Time{}, false
	}
	life := m.leaf.NotAfter.Sub(m.leaf.NotBefore)
	return m.leaf.NotBefore.Add(life * 2 / 3), true
}

func leafOf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("empty chain")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

func servable(leaf *x509.Certificate) bool {
	return leaf != nil && time.Now().Before(leaf.NotAfter.Add(-expiryMargin))
}

// Cache persists an issued certificate across process restarts within a boot.
// Production backs this with S3 (design §6); DiskCache stands in for dev. Load
// reports a clean miss with ok false, and an error if it can't tell.
type Cache interface {
	Load(host string) (cert *tls.Certificate, ok bool, err error)
	Store(host string, cert *tls.Certificate) error
}

// IssueFunc runs one full ACME order for host and returns a certificate.
type IssueFunc func(ctx context.Context, host string) (*tls.Certificate, error)

// Timing knobs (design §6: wait 15s so HAProxy's two checks pass). Let's Encrypt
// allows 5 failed validations an hour, so the first retry waits past that, and each
// later one doubles. Overridable in tests.
var (
	readyWait    = 15 * time.Second
	retryBackoff = 15 * time.Minute
	maxBackoff   = 4 * time.Hour
	cacheRetry   = 30 * time.Second
	renewGap     = time.Hour // the least time between issuances, whatever a cert says
)

// expiryMargin stops serving a certificate this long before it expires, so a
// session can't start on one that lapses under it.
const expiryMargin = time.Hour

// RunLoop drives certificate acquisition and renewal into m until ctx is cancelled.
func RunLoop(ctx context.Context, m *Manager, cache Cache, reachable <-chan struct{}, host string, issue IssueFunc) {
	if cert := loadCached(ctx, cache, host); cert != nil {
		log.Printf("certs: loaded cached certificate for %s", host)
		m.Set(cert)
	} else {
		select {
		case <-ctx.Done():
			return
		case <-reachable:
			log.Printf("certs: gateway reachable; waiting %s for HAProxy checks", readyWait)
		}
		if !sleep(ctx, readyWait) {
			return
		}
	}

	for failures := 0; ; {
		if at, ok := m.renewAt(); ok && !sleep(ctx, time.Until(at)) {
			return
		}
		cert, err := issue(ctx, host)
		if err != nil {
			failures++
			log.Printf("certs: issuance attempt %d failed: %v", failures, err)
			if !sleep(ctx, backoff(failures, err)) {
				return
			}
			continue
		}
		failures = 0
		m.Set(cert)
		if cache != nil {
			if err := cache.Store(host, cert); err != nil {
				log.Printf("certs: cache store failed (non-fatal): %v", err)
			}
		}
		log.Printf("certs: certificate installed for %s", host)
		if !sleep(ctx, renewGap) {
			return
		}
	}
}

// loadCached returns a usable cached certificate, or nil if issuing is the right
// next step. A boot needs a certificate and Let's Encrypt allows 5 a week, so a
// read that fails keeps trying rather than spending one.
func loadCached(ctx context.Context, cache Cache, host string) *tls.Certificate {
	if cache == nil {
		return nil
	}
	for {
		cert, ok, err := cache.Load(host)
		if err == nil {
			if !ok {
				return nil
			}
			if leaf, err := leafOf(cert); err != nil || !servable(leaf) {
				log.Printf("certs: cached certificate for %s is expired or unreadable", host)
				return nil
			}
			return cert
		}
		log.Printf("certs: cache read failed, retrying: %v", err)
		if !sleep(ctx, cacheRetry) {
			return nil
		}
	}
}

// backoff is the wait after a failed issuance: doubling from retryBackoff up to
// maxBackoff, or longer if the CA asked for that.
func backoff(failures int, err error) time.Duration {
	d := maxBackoff
	if failures < 16 && retryBackoff<<(failures-1) < maxBackoff {
		d = retryBackoff << (failures - 1)
	}
	var asked interface{ RetryAfter() time.Duration }
	if errors.As(err, &asked) && asked.RetryAfter() > d {
		d = asked.RetryAfter()
	}
	return d
}

// sleep waits for d, or reports false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
