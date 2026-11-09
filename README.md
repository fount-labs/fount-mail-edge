# fount-mail-edge

The **Fount Fleet mail edge**: a small, reproducible Go service that runs inside
a [Tinfoil](https://tinfoil.sh) confidential enclave, terminates inbound SMTP
with an attested key, stores each message encrypted to the recipient, and serves
the **Device API** to Fount's broker over the attested tunnel.

This repository is **public by design**. The build is reproducible, so an outside
party can rebuild a release and check the running enclave runs it, with
`scripts/verify-release.sh`. `v0.1.0` passed that check on 2026-11-08.
It holds **no secrets**. The edge pulls its keys after boot from a Fount Mail
vault, another enclave, which verifies this release first
(see [`fount-mail-vault`](https://github.com/fount-labs/fount-mail-vault)). No AWS
account holds them.

[`docs/DESIGN.md`](docs/DESIGN.md) is the trust model: who sees what, which keys
exist, and how a release gets them. Code comments cite its section numbers.

## What the edge does

- **Per-boot attested keys.** Three keys are generated inside the enclave each
  boot, with their public halves in the attestation, so no one outside holds them:
  - `mail-tls` (ecdsa-p256) — STARTTLS for SMTP, and the Device API TLS leaf.
  - `mail-sign` (ed25519) — signs each stored message (which key encrypted it).
  - `transfer` (x25519) — the vault seals the keyset to this.
- **Keys from the vault, checked.** The ACME, address MAC, and routing keys, and
  the S3 credentials, arrive from a vault after boot. The edge accepts only the
  keyset `KEYSET_COMMITMENT` names, and starts nothing else until it has one.
  There is deliberately no fallback to a Tinfoil-managed secret.
- **Operator changes are signed, and the edge makes them.** No person holds the
  routing keys, so `cmd/edgectl` signs a request with the operator key, and the
  edge does the work: the first routing object, the `abuse@` and `postmaster@`
  mailboxes, and restores from backup. An edge with no routing object waits for
  one instead of exiting.
- **Strict inbound SMTP.** Arrives through the gateway's attested tunnel with a
  PROXY header; STARTTLS is mandatory; unknown recipients are rejected; bare
  LF/CR are rejected; size-limited; stored whole, never MIME-parsed; `250` only
  after the store confirms the write.
- **Signed Device API.** Every request is signed by the key that call's row
  requires (`POST /mailbox` by new keys, `GET /mail` by the address key, …), over
  `method · path · sha256(body) · timestamp · nonce`. A captured request can't be
  replayed, except once across a restart: the nonce cache is in memory, and the
  timestamp window is 5 minutes. The broker reaches it through the Tinfoil
  shim, which forwards only the paths `shim.paths` in `tinfoil-config.yml` lists.
- **SPF inputs, sealed.** Each stored message carries the sending server's IP
  (from the gateway's PROXY header) and its HELO name inside the encryption, for
  the broker's SPF check. The edge keeps neither anywhere readable.
- **No addresses at rest or in logs.** Routing data holds keyed hashes, and a
  failed store logs only the error class. The edge does see addresses in memory:
  each SMTP recipient, and the addresses on `POST /address` and `PUT /routing`.

## Status — M2 edge

Real and exercised now:

- boot sequence, attested-key loading, fail-fast secret validation;
- the SMTP state machine (mutual TLS → PROXY → mandatory STARTTLS →
  recipient/size checks), with per-IP and per-sender byte budgets;
- the full Device API with real signature verification (timestamp window + nonce
  replay cache + Ed25519), including mailbox creation, the write path, and
  passkey recovery;
- **ACME (RFC 8555, HTTP-01)** for the attested TLS key, with one certificate
  covering both MX names. The vault's CAA-pinned account key signs the order,
  the attested `mail-tls` key is the cert key, and the certificate is cached (disk
  in dev, chain-only S3 in prod). The account URL, which CAA `accounturi` pins, is
  published on `/operator/status` and shown by `edgectl status`. Exercised
  end-to-end against a mock ACME server;
- **HPKE-to-address storage over S3**, the per-mailbox quota, routing data with
  signed backups, and the boot and key logs in their own Object Lock bucket;
- the **30-day retention sweep**, which writes a signed expiry record for each
  message it can verify against its boot's key. One it can't verify stays until
  the bucket's 45-day lifecycle rule deletes it with no record, and that rule isn't
  deployed yet;
- **gateway mutual TLS** on the SMTP and ACME ports, with client keys pinned in
  the attested config, tested against a local HAProxy 2.8;
- the **gateway** CloudFormation stack (`gateway/`) adapted from the proven
  port-25 probe;
- the reproducible `FROM scratch` build, with BuildKit pinned by digest, the two
  release workflows, and CI that builds on an x86 and an Arm runner and requires
  the same digest.

Not yet built or tested:

- **`shim.authenticated`, a run through a real tunnel, and the live load test.**
- **A real upload to the Object Lock bucket.** The first boot is that test.
- **Full Tinfoil attestation under `GET /boots`**, which today publishes the boot's
  signing key.
- **Key-swap detection.** The edge doesn't store key chains or check them when it
  seals, and the key and boot logs have no read path. Until both exist and the
  broker checks them, a swapped key isn't detectable.
- **The broker side of the contract**, in [`fount-broker`](https://github.com/fount-labs/fount-broker).
- **A scheduled job** that runs `scripts/verify-release.sh` on every release.

## Develop

```sh
go test ./...
go vet ./... && go build ./...
```

Boot locally (placeholder secrets, generated keys) — see `docs/DEV.md`:

```sh
EDGE_DEV=1 ATTESTED_KEY_DIR=/path/to/devkeys ./edge
```

## Build & release

Reproducible image: `scripts/build-image.sh /tmp/edge.oci` (needs Docker with
buildx). Release: run **Build Image**, pin the digest, then push a `v*` tag, which
publishes the measured release. A vault serves any release at or above its
`EDGE_MIN_TAG`. Verify any release with `scripts/verify-release.sh vX.Y.Z`, which
needs Docker, `jq`, and the Tinfoil CLI, and fails if any check can't run. Full
recipe in `docs/BUILD.md`.

## Security

Report vulnerabilities privately, as [`SECURITY.md`](SECURITY.md) describes.

## License

MIT — see [LICENSE](LICENSE).
