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
