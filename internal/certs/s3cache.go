package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"time"
)

// Blobs is the subset of the S3 client the certificate cache needs. The real
// s3.Client satisfies it, so certs stays decoupled from the store/s3 packages.
type Blobs interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// S3Cache persists the ACME-issued certificate chain in S3 so a crash loop
// within a boot reloads it instead of re-running ACME and burning the Let's
// Encrypt rate limit (design §6).
//
// It stores only the chain, never a private key: the serving key is the per-boot
// attested mail-tls key, held in the enclave and never written to egress. On
// Load the cached chain is paired with that key, and a chain whose leaf was
// issued for a different key — a stale chain left in S3 by a previous boot — is
// reported as a miss, so the edge issues a fresh certificate and overwrites it.
// That also means one object per host, overwritten each boot, with no buildup.
type S3Cache struct {
	blobs   Blobs
	key     *ecdsa.PrivateKey // the attested TLS key the serving cert is bound to
	timeout time.Duration
}

// NewS3Cache builds the cache over blobs, binding cached certs to the attested
// TLS key.
func NewS3Cache(blobs Blobs, key *ecdsa.PrivateKey) *S3Cache {
	return &S3Cache{blobs: blobs, key: key, timeout: 15 * time.Second}
}

func (c *S3Cache) objectKey(host string) string { return "edge/certs/" + host + ".pem" }

// Load returns the cached certificate for host paired with the attested key, or
// a miss. Any fetch or decode failure is a miss (the edge then issues), as is a
// chain whose leaf doesn't match the current key.
func (c *S3Cache) Load(host string) (*tls.Certificate, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	pemBytes, err := c.blobs.Get(ctx, c.objectKey(host))
	if err != nil {
		return nil, false // absent or transient: treat as a miss and issue
	}
	chain, leaf, err := parseChainPEM(pemBytes)
	if err != nil {
		return nil, false
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(&c.key.PublicKey) {
		return nil, false // a prior boot's chain; this boot holds a different key
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: c.key, Leaf: leaf}, true
}

// Store writes the certificate chain (no key) for host, overwriting any prior
// boot's chain.
func (c *S3Cache) Store(host string, cert *tls.Certificate) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.blobs.Put(ctx, c.objectKey(host), encodeChainPEM(cert))
}
