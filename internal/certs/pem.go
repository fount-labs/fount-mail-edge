package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// encodePEM renders a tls.Certificate's chain and private key as PEM for caching.
func encodePEM(cert *tls.Certificate) (certPEM, keyPEM []byte, err error) {
	var cbuf []byte
	for _, der := range cert.Certificate {
		cbuf = append(cbuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return cbuf, keyPEM, nil
}

// encodeChainPEM renders only the certificate chain as PEM — no private key. The
// S3 cache uses it: the serving key is the attested mail-tls key, which must
// never be written to egress (§6), so only the public chain is cached.
func encodeChainPEM(cert *tls.Certificate) []byte {
	var buf []byte
	for _, der := range cert.Certificate {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return buf
}

// parseChainPEM decodes a PEM chain into its DER blocks and parses the leaf (the
// first certificate), so the cache can pair the chain with the attested key and
// check that the leaf was issued for that key.
func parseChainPEM(b []byte) (chain [][]byte, leaf *x509.Certificate, err error) {
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			chain = append(chain, blk.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("certs: cached chain has no certificate")
	}
	leaf, err = x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("certs: parse cached leaf: %w", err)
	}
	return chain, leaf, nil
}

// ChainPEM is the chain alone as PEM, which is what crosses from mail-core to
// mail-front in a split edge.
func ChainPEM(cert *tls.Certificate) []byte { return encodeChainPEM(cert) }

// ParseChain reads a PEM chain into a certificate with no private key.
func ParseChain(b []byte) (*tls.Certificate, error) {
	chain, leaf, err := parseChainPEM(b)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: chain, Leaf: leaf}, nil
}
