// Package certs holds the SMTP serving certificate — the CA-issued cert that
// real senders validate during STARTTLS.
//
// The full lifecycle (design §6) is:
//
//   - A certificate is needed every boot, for the attested TLS key.
//   - The edge waits for the gateway's first health check, then runs ACME
//     (HTTP-01 through the gateway), answering 421 until the cert loads.
//   - The issued cert is cached in S3 and reloaded on a process restart, so a
//     crash loop doesn't burn the Let's Encrypt rate limit.
//   - The ACME account key is CAA-pinned (accounturi), delivered by the keyserver.
//
// This minimal version provides the Manager seam and the "not ready yet"
// behaviour SMTP depends on. ACME issuance and S3 caching are M2 step-3 TODOs;
// the proven Python flow lives in ~/Desktop/code/tinfoil-port25-test and is the
// reference to port here.
package certs

import (
	"crypto/tls"
	"sync"
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

// Set installs a certificate (from ACME issuance or an S3 reload).
func (m *Manager) Set(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert = cert
}
