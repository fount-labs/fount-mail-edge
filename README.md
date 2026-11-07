# fount-mail-edge

The **Fount Fleet mail edge**: a small, reproducible Go service that runs inside
a [Tinfoil](https://tinfoil.sh) confidential enclave, terminates inbound SMTP
with an attested key, stores each message encrypted to the recipient, and serves
the **Device API** to Fount's broker over the attested tunnel.

This repository is **public by design** — reproducible builds mean an outside
party can rebuild a release and confirm the running enclave matches this source.
It holds **no secrets**. Secret *values* live in a separate AWS account and are
released to the enclave by the keyserver only after attestation
(see [`fount-infra/keyserver`](../fount-infra/keyserver)).

Design doc: `fount/docs/features/fount-fleet/fount-mail-design.md` (§6 edge, §8
Device API, §17 build/release). This repo realises M2 build steps 2–3.

## What the edge does

- **Per-boot attested keys.** Two keys are generated inside the enclave each
  boot, with their public halves in the attestation, so the keyserver never
  holds them:
  - `mail-tls` (ecdsa-p256) — STARTTLS for SMTP, and the Device API TLS leaf.
  - `mail-sign` (ed25519) — signs each stored message (which key encrypted it).
- **Keyserver secrets, fail-fast.** `ACME_ACCOUNT_KEY`, `ADDRESS_MAC_KEY`,
  `ROUTING_DATA_KEY`, `S3_*` arrive as env vars after attestation. A missing one
  aborts boot — there is deliberately no fallback to a Tinfoil-managed secret.
- **Strict inbound SMTP.** Arrives through the gateway's attested tunnel with a
  PROXY header; STARTTLS is mandatory; unknown recipients are rejected; bare
  LF/CR are rejected; size-limited; stored whole, never MIME-parsed; `250` only
  after the store confirms the write.
- **Signed Device API.** Every request is signed by the key that call's row
  requires (`POST /mailbox` by new keys, `GET /mail` by the address key, …), over
  `method · path · sha256(body) · timestamp · nonce`, so a captured request can't
  be replayed.

## Status — M2 edge

Real and exercised now:

- boot sequence, attested-key loading, fail-fast secret validation;
- the SMTP state machine (mutual TLS → PROXY → mandatory STARTTLS →
  recipient/size checks), with per-IP and per-sender byte budgets;
- the full Device API with real signature verification (timestamp window + nonce
  replay cache + Ed25519), including mailbox creation, the write path, and
  passkey recovery;
- **ACME (RFC 8555, HTTP-01)** for the attested TLS key, with one certificate
  covering both MX names. The keyserver's CAA-pinned account key signs the order,
  the attested `mail-tls` key is the cert key, and the certificate is cached (disk
  in dev, chain-only S3 in prod). Exercised end-to-end against a mock ACME server;
- **HPKE-to-address storage over S3**, the per-mailbox quota, the 30-day retention
  sweep with signed expiry records, routing data with signed backups, and the boot
  and key logs in their own Object Lock bucket;
- **gateway mutual TLS** on the SMTP and ACME ports, with client keys pinned in
  the attested config, tested against a local HAProxy 2.8;
- the **gateway** CloudFormation stack (`gateway/`) adapted from the proven
  port-25 probe;
- reproducible `FROM scratch` build + the two Tinfoil release workflows + a
  two-runner digest-comparison CI, present from the first commit.

Not yet built or tested:

- **`shim.authenticated`, a run through a real tunnel, and the live load test.**
- **A real upload to the Object Lock bucket.** The first boot is that test.
- **Full Tinfoil attestation under `GET /boots`**, which today publishes the boot's
  signing key.
- **The broker side of the contract**, in `fount-broker`.

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

Reproducible image: `scripts/build-image.sh /tmp/edge.oci` (needs the
`docker-container` buildx driver). Release via the GitHub **Tinfoil Release**
workflow (tag → measured publish on two runners → 24h public wait → keyserver
approval). Verify any release with `scripts/verify-release.sh vX.Y.Z`. Full
recipe in `docs/BUILD.md`.

## License

MIT — see [LICENSE](LICENSE).
