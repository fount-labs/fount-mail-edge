package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// memBlobs is an in-memory stand-in for the S3 client the cache writes to.
type memBlobs struct {
	mu  sync.Mutex
	m   map[string][]byte
	err error // when set, Get/Put fail (the transient-S3 path)
}

func newMemBlobs() *memBlobs { return &memBlobs{m: map[string][]byte{}} }

func (b *memBlobs) Put(_ context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.m[key] = append([]byte(nil), data...)
	return nil
}

func (b *memBlobs) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return nil, b.err
	}
	v, ok := b.m[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), v...), nil
}

// selfSigned builds a tls.Certificate for key, the shape ACME issuance returns.
func selfSigned(t *testing.T, key *ecdsa.PrivateKey, host string) *tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const cacheHost = "mail-edge.fount.sh"

// A stored chain reloads paired with the attested key, and the S3 object holds
// only the public chain — never the private key.
func TestS3CacheRoundTrip(t *testing.T) {
	key := newKey(t)
	blobs := newMemBlobs()
	c := NewS3Cache(blobs, key)

	if err := c.Store(cacheHost, selfSigned(t, key, cacheHost)); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// The cached object is the chain only: no private key leaves the enclave.
	var stored []byte
	for _, v := range blobs.m {
		stored = v
	}
	if strings.Contains(string(stored), "PRIVATE KEY") {
		t.Fatal("cached object contains a private key; the cache must store the chain only")
	}
	if !strings.Contains(string(stored), "CERTIFICATE") {
		t.Fatal("cached object has no certificate")
	}

	cert, ok := c.Load(cacheHost)
	if !ok {
		t.Fatal("Load miss after Store")
	}
	if cert.PrivateKey != key {
		t.Fatal("loaded cert not paired with the attested key")
	}
	if cert.Leaf == nil || len(cert.Certificate) != 1 {
		t.Fatalf("loaded cert malformed: leaf=%v chain=%d", cert.Leaf, len(cert.Certificate))
	}
}

// A chain cached by a previous boot (bound to a different key) is a miss, so the
// edge issues a fresh certificate for the current attested key.
func TestS3CacheRejectsForeignKey(t *testing.T) {
	oldKey := newKey(t)
	blobs := newMemBlobs()
	// A prior boot stored a chain for its own key.
	if err := NewS3Cache(blobs, oldKey).Store(cacheHost, selfSigned(t, oldKey, cacheHost)); err != nil {
		t.Fatal(err)
	}
	// This boot holds a different attested key.
	newBootKey := newKey(t)
	if _, ok := NewS3Cache(blobs, newBootKey).Load(cacheHost); ok {
		t.Fatal("loaded a chain bound to a previous boot's key")
	}
}

// An absent object and a transient S3 error are both misses (the edge issues),
// not hard failures.
func TestS3CacheMisses(t *testing.T) {
	key := newKey(t)
	if _, ok := NewS3Cache(newMemBlobs(), key).Load(cacheHost); ok {
		t.Fatal("empty cache reported a hit")
	}
	blobs := newMemBlobs()
	blobs.err = errors.New("s3 unavailable")
	if _, ok := NewS3Cache(blobs, key).Load(cacheHost); ok {
		t.Fatal("transient S3 error reported a hit")
	}
}
