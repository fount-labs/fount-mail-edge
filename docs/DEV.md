# Developing the edge locally

The edge expects two things it only has inside an enclave: attested keys on disk
and a vault to pull its keys from. For local smoke tests, supply the keys and set
`EDGE_DEV=1` in place of the vault.

## 1. Generate dev attested keys

The runtime writes `mail-tls` (ecdsa-p256), `mail-sign` (ed25519), and `transfer`
(x25519) as PKCS8
PEM under `/run/tinfoil/keys/<id>/private_key.pem`. macOS LibreSSL can't emit
ed25519, so generate them with Go:

```go
// go run gen.go /tmp/devkeys   (ecdsa P-256 + ed25519 + x25519, PKCS8 PEM)
package main

import (
	"crypto/ecdh"; "crypto/ecdsa"; "crypto/ed25519"; "crypto/elliptic"; "crypto/rand"
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
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xb, _ := x509.MarshalPKCS8PrivateKey(x); w(filepath.Join(d, "transfer/private_key.pem"), "PRIVATE KEY", xb)
}
```

## 2. Run

```sh
go build -o edge ./cmd/edge
EDGE_DEV=1 ATTESTED_KEY_DIR=/tmp/devkeys \
  SMTP_ADDR=:12525 DEVICE_API_ADDR=:18443 HEALTH_ADDR=:18080 ACME_CHALLENGE_ADDR=:18088 ./edge
```

`EDGE_DEV=1` fills placeholder secrets so the binary boots without a vault.
**Never set it in a release.** In dev, ACME is disabled (the placeholder account
key isn't a real PEM key), so `/ready` stays 503 and SMTP answers `421` — that's
correct for a boot with no CA. Other ACME knobs: `ACME_DIRECTORY` (defaults to
Let's Encrypt **staging**, which only dev accepts; a release sets production in
`tinfoil-config.yml`) and `CERT_CACHE_DIR` (disk cert cache; production uses S3
instead). Probes:

```sh
curl -s localhost:18080/health                         # ok
curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/ready   # 503 until a cert loads
curl -sk https://localhost:18443/boots/x               # 501 (open route)
curl -sk -X POST https://localhost:18443/mailbox       # 401 (needs a signature)
curl -s localhost:18080/boots/x                        # 501, the same API on the shim's port
printf 'PROXY TCP4 203.0.113.9 10.0.0.1 1 25\r\n' | nc -w1 localhost 12525   # 421 (no cert)
```

## ACME account and CAA

The edge validates over **HTTP-01 only** (`internal/acme`), on the ACME port the gateways
forward from public port 80. Its account key is `ACME_ACCOUNT_KEY` from the vault keyset,
which `KEYSET_COMMITMENT` pins, so every boot and every release signs with the same key and
Let's Encrypt answers `newAccount` with the same account URL. The URL changes only if the
keyset is regenerated (a new commitment) or `ACME_DIRECTORY` points at another CA.

Tinfoil has no container logs, so the edge publishes the URL on `GET /operator/status`. That
route is unauthenticated, like the rest of the status answer, and the URL is public anyway (it
goes into DNS). The edge looks the account up at boot, retrying until the CA answers, so the
URL appears even on a boot that reloads a cached certificate, and before the first order.
`acme_account` is absent until then:

```sh
go run ./cmd/edgectl status -edge <edge host>
# {
#   "routing": "serving",
#   "acme_account": "https://acme-v02.api.letsencrypt.org/acme/acct/<id>"
# }
```

Pin it with CAA, restricted to HTTP-01:

```
fountbox.com. CAA 0 issue "letsencrypt.org; accounturi=<URL>; validationmethods=http-01"
```

The record at the apex covers `mx1` and `mx2`, which have no CAA of their own. It also covers
every other name under `fountbox.com`, so any other certificate there (for example the
MTA-STS policy host) needs its own `issue` line, or the pin goes on the MX names instead.
Pin the production URL (`acme-v02`), not a staging one. Until the record is published, any
Let's Encrypt account can get a certificate for the MX names over HTTP-01, which is the
attack the pin closes: a taken-over gateway answering the challenge itself.

## Release config

`tinfoil-config.yml` holds the release's public values: the image digest (pinned by hand
from *Build Image*, see `docs/BUILD.md`), `GATEWAY_CLIENT_PINS`, `KEYSET_COMMITMENT`, and
`ENTITLEMENT_VERIFY_KEY` (the prod key since v0.2.1, so dev entitlements no longer work on the
live edge), and `RECOVERY_RP_ID`. The release workflow refuses a config
with a `PLACEHOLDER` left in it.

The vaults pin this repo (`fount-labs/fount-mail-edge`), so a fork can't get the keys. The
live edge runs at `edge.fount.containers.tinfoil.dev`. Senders never see that name; they
use the MX names.

## Sending (M3)

Sending launches dark. It needs four things, and `/operator/status` says which is missing as
`send` (`on`, or `off: <why>`), with the held send keyset's `send_keyset_commitment`:

| Gate | Set by | Off when |
|---|---|---|
| `SEND_KEYSET_COMMITMENT` | `tinfoil-config.yml`, the value vault-a's `/status` shows after `/generate-send` | Unset or empty: the edge doesn't take a send keyset, as in v0.2.3 |
| The send keyset | A vault on a release with the same commitment (fount-mail-vault `docs/SEND-KEYS.md`) | No vault had it at boot. The edge boots anyway, so mail still arrives, and takes it on its next restart |
| `SEND_ENABLED: "1"` | `tinfoil-config.yml` | Unset. A release that sets it must also set `SEND_KEYSET_COMMITMENT`, `SEND_RELAY_ADDR` (the gateway relay's `host:port`, also on the egress allowlist), `SEND_RELAY_PINS` (the relay's hex SPKI pins) and `DKIM_SELECTOR` (`f1`; Ed25519 signs as `f1e`), or it doesn't boot |
| The shim | `shim.paths` | `/send` isn't listed, and `TestShimPathsMatchDeviceAPI` keeps it off until `POST /send` is in `builtM3` |

`POST /connect` sends through the same path, so it's off (503) whenever `POST /send` is. Its
caps are 3 mails per worker and owner an hour and 20 per license a day, in memory; a connect
isn't a new owner, so `PUT /routing`'s 5 new owners a day still applies when the proof comes
back. The Message-ID key is derived from `ADDRESS_MAC_KEY`, so it needs no new secret.

At boot the edge asks each vault in turn for both keysets. A vault without the send keyset
still gives it the keyset, and the edge asks the next vault for the send keyset before booting
without one. Each key is checked against its commitment inside `wire.PullKeysets`, so a fake vault
can't hand over its own DKIM or relay key.

A release can set `SEND_KEYSET_COMMITMENT` alone first: the edge then holds the send keyset
and reports its commitment, with sending still off. That's how to check the vaults serve it
before turning anything on.
