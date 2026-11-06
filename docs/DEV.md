# Developing the edge locally

The edge expects two things it only has inside an enclave: attested keys on disk
and keyserver secrets in the environment. For local smoke tests, supply both.

## 1. Generate dev attested keys

The runtime writes `mail-tls` (ecdsa-p256) and `mail-sign` (ed25519) as PKCS8
PEM under `/run/tinfoil/keys/<id>/private_key.pem`. macOS LibreSSL can't emit
ed25519, so generate them with Go:

```go
// go run gen.go /tmp/devkeys   (ecdsa P-256 + ed25519, PKCS8 PEM)
package main

import (
	"crypto/ecdsa"; "crypto/ed25519"; "crypto/elliptic"; "crypto/rand"
	"crypto/x509"; "encoding/pem"; "os"; "path/filepath"
)

func w(p, t string, b []byte) { os.MkdirAll(filepath.Dir(p), 0o755); f, _ := os.Create(p); defer f.Close(); pem.Encode(f, &pem.Block{Type: t, Bytes: b}) }

func main() {
	d := os.Args[1]
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalPKCS8PrivateKey(ec); w(filepath.Join(d, "mail-tls/private_key.pem"), "PRIVATE KEY", b)
	pb, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey); w(filepath.Join(d, "mail-tls/public_key.pem"), "PUBLIC KEY", pb)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	eb, _ := x509.MarshalPKCS8PrivateKey(ed); w(filepath.Join(d, "mail-sign/private_key.pem"), "PRIVATE KEY", eb)
}
```

## 2. Run

```sh
go build -o edge ./cmd/edge
EDGE_DEV=1 ATTESTED_KEY_DIR=/tmp/devkeys \
  SMTP_ADDR=:12525 DEVICE_API_ADDR=:18443 HEALTH_ADDR=:18080 ACME_CHALLENGE_ADDR=:18088 ./edge
```

`EDGE_DEV=1` fills placeholder secrets so the binary boots without a keyserver.
**Never set it in a release.** In dev, ACME is disabled (the placeholder account
key isn't a real PEM key), so `/ready` stays 503 and SMTP answers `421` — that's
correct for a boot with no CA. Other ACME knobs: `ACME_DIRECTORY` (defaults to
Let's Encrypt **staging**; set the production URL at deploy) and `CERT_CACHE_DIR`
(disk cert cache; production uses S3 instead). Probes:

```sh
curl -s localhost:18080/health                         # ok
curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/ready   # 503 until a cert loads
curl -sk https://localhost:18443/boots/x               # 501 (open route)
curl -sk -X POST https://localhost:18443/mailbox       # 401 (needs a signature)
printf 'PROXY TCP4 203.0.113.9 10.0.0.1 1 25\r\n' | nc -w1 localhost 12525   # 421 (no cert)
```

## TODO markers to resolve before a real release

- `tinfoil-config.yml`: keyserver host (`keys.fount.sh`), `GATEWAY_CLIENT_PINS`
  (the edge refuses to boot on the placeholder), and the image digest (set by the
  release workflow).
- The GitHub org (`fount-labs`) and the pinned deployment domain
  (`mail-edge.fount.containers.tinfoil.dev`) — these must match the keyserver `policy.yaml` workload
  entry in `fount-infra`. Senders never see this name; they use the MX names.
