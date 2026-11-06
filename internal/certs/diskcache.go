package certs

import (
	"crypto/tls"
	"os"
	"path/filepath"
)

// DiskCache is a development stand-in for the production S3 certificate cache
// (design §6). It writes the issued chain + key as PEM under dir. NOT for
// production: the enclave's root is read-only and tmpfs doesn't survive a boot,
// so production must back Cache with S3.
//
// TODO(M2 step 4): S3Cache implementing Cache, using the keyserver S3 creds.
type DiskCache struct{ dir string }

func NewDiskCache(dir string) *DiskCache { return &DiskCache{dir: dir} }

func (d *DiskCache) paths(host string) (cert, key string) {
	return filepath.Join(d.dir, host+".cert.pem"), filepath.Join(d.dir, host+".key.pem")
}

func (d *DiskCache) Load(host string) (*tls.Certificate, bool) {
	certPath, keyPath := d.paths(host)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false
	}
	return &cert, true
}

func (d *DiskCache) Store(host string, cert *tls.Certificate) error {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return err
	}
	certPath, keyPath := d.paths(host)
	certPEM, keyPEM, err := encodePEM(cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}
