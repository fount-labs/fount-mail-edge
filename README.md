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

## Status — initial scaffold (M2 steps 2–3)

Real and exercised now:

- boot sequence, attested-key loading, fail-fast secret validation;
- the SMTP state machine (PROXY → mandatory STARTTLS → recipient/size checks);
- the full Device API route table with real signature verification (timestamp
  window + nonce replay cache + Ed25519), handlers stubbed at `501`;
- reproducible `FROM scratch` build + the two Tinfoil release workflows + a
  two-runner digest-comparison CI, present from the first commit.

Clearly-marked seams, not yet built:

- **ACME** issuance for the attested key via the gateway HTTP-01 path, + S3 cert
  cache (M2 step 3). Until a cert loads, SMTP answers `421` and `/ready` is 503.
- **HPKE-to-address + S3 storage** and the Device API handlers / key resolver
  (M2 step 4).
- **Pinned base-image digests** in the `Dockerfile` (`PLACEHOLDER_*`), the
  keyserver host, and the S3 egress entry — all marked and listed in `docs/DEV.md`.

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
