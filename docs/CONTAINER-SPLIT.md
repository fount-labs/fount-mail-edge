# Edge container split

Status, 2026-11-11: the owner accepted all four decisions at the end. Stage 1 (`mail-front` and
`mail-core`) is built; the vault's `send-transfer` box is vault PR #4; stage 2 (`mail-send`) waits
for that vault release. The live release still runs one `mail-edge` container: the split goes
live only when a release copies `docs/tinfoil-config.split.yml` over `tinfoil-config.yml`.

The design says that from M3, TLS, the keyserver-delivered secrets, and DKIM signing run in
separate containers, so one bug can't expose keys and mail in transit together (`fount-mail.md`,
"Blast radius"; design §6 "Container"; §10 M3). Today one process, `mail-edge`, holds all three,
plus the S3 forwarder, which holds nothing.

## What Tinfoil supports

Checked against Tinfoil's docs on 2026-11-11 ([configuration], [networking], [attested keys],
[attestation]), not assumed:

| Need | Supported? | How |
|---|---|---|
| Several containers in one enclave | Yes | `containers:` list. We already run two |
| A private key only one container can read | Yes | Each `attested-keys` entry "must be granted to exactly one container", mounted read-only at `/run/tinfoil/keys/<id>/` |
| Separate address spaces | Yes | Separate containers are separate processes. `ipc` defaults to `private`, and `ipc: none` removes `/dev/shm` |
| Container-to-container traffic | Yes | A `closed` network: members reach each other by container name, nothing else |
| Different egress per container | Yes | At most one non-`closed` network per container |
| Pick which container the shim reaches | Yes | `shim.upstream-container` (defaults to the first container) |
| Tunnel ports on a container other than the first | Yes | The enclave accepts a tunnel to any port a container publishes in `ports` |
| Attestation from more than one container | Yes | `attestation: true` per container. The document is the enclave's, so it endorses every declared key whichever container asks |

So Tinfoil can do a real split. Two limits matter:

- Traffic between containers on a `closed` network is plain TCP inside the enclave's memory. It
  never leaves the confidential VM, but it isn't separately encrypted.
- A container with `cvm_admin` could reach everything. We never set it.

## The blocker: the vault seals everything to one key

The vault seals one payload (mail keyset, S3 credentials and send keyset) to the key the edge's
attestation endorses as `transfer` (`fount-mail-vault` `internal/attest`, `transferKeyID`;
`internal/vault/transfer.go`). Whichever container holds `transfer` gets all of it. The edge can't
split the keyset from the DKIM keys on its own side without one container holding both, even for
a moment. That would be the hollow version.

The fix is in the vault. If the edge's document also endorses a second x25519 key, `send-transfer`,
the vault seals the send keyset in its own box to that key and leaves it out of the `transfer`
box. Only the send container holds `send-transfer`, so only it can open the send keyset, and the
core container can't, even though both pull through the same vault with the same document. A
document with no `send-transfer` key gets today's behaviour, so v0.3.0 edges keep working.

**Timing.** The vault's send keyset hasn't been released yet (owner actions, "F, send keys", step 2:
vault `v0.2.0`, then `v0.2.1`). If the vault change is merged before that sequence, it rides along
with those two releases and needs no extra vault release. If it lands after, it needs one more
vault release and held upgrades of both vaults.

## Proposed layout

```
          tunnel 2525/8443/8088                    shim :8080
gateway ────────────────────────▶ mail-front      Tinfoil shim ─────▶ mail-core
                                  keys: mail-tls                       keys: transfer, mail-sign
                                  net: frontlink                       attestation: true
                                       │                               net: edge (allowlist vaults),
                                       └── frontlink (closed) ────────▶     frontlink, internal, sendnet
                                                                            │            │
                                                     forwarder ◀── internal ┘            │
                                                     net: internal, storage (open)       │
                                                                                         ▼
                                                     mail-send ◀────────── sendnet (closed)
                                                     keys: send-transfer
                                                     attestation: true
                                                     net: sendnet, relay (allowlist: vaults, gateway relay)
```

- **`mail-front`** holds `mail-tls` and nothing from the vault. It terminates gateway mutual TLS
  on the tunnel ports, speaks SMTP including STARTTLS, forwards ACME HTTP-01 requests, and passes
  each message and each RCPT check to `mail-core`. It has no egress: its only network is `frontlink`. It serves the challenge and Device API ports by forwarding to core.
  This is the code that parses hostile input from the internet, so it's the one that most needs
  to be away from the keys.
- **`mail-core`** holds `transfer`, `mail-sign`, the mail keyset and the S3 credentials. It runs
  routing, sealing and storage, the Device API and `/operator` routes behind the shim, and the
  retention sweep. It pulls from the vaults and reaches S3 through the forwarder, as today.
- **`mail-send`** holds `send-transfer` and the send keyset (DKIM RSA and Ed25519, relay client
  key). `mail-core` decides who may receive (owner lists, proof, limits) and hands it a message
  and recipients. `mail-send` checks `From` and the recipient count again, signs, and delivers
  through the pinned relay. It pulls its own keys from a vault, so its egress allowlist is the
  two vaults plus the gateway relay.
- **`forwarder`** is unchanged.

All four run the same image, with a subcommand each (`front`, `core`, later `send`), as
`egress-forward` does now. Every container keeps `read_only`, no `cap_add` and no `cvm_admin`;
mail-front also gets `ipc: none`. Stage 1 refuses to boot on a wrong grant: front exits if it can
see `transfer`, `mail-sign`, `send-transfer`, any vault secret, or any vault, S3 or send
setting, and core exits if it can see `mail-tls` or `send-transfer`.

### What crosses each boundary

| Link | Calls | Notes |
|---|---|---|
| front → core | `POST /link/rcpt`, `POST /link/put`, `POST /link/csr`, `GET /link/cert?have=` | `put` carries the plaintext message, which front already saw when it terminated TLS. Core seals it. `have` tells core which leaf front holds, which core's `/ready` waits for |
| front → core | the tunnelled challenge port, forwarded | Only `GET /` and `GET /.well-known/acme-challenge/…`; `/link/` is never reachable from outside |
| front → core | the Device API's TLS port, forwarded | Only `deviceapi.Routes()`; `/operator` stays shim-only |
| core → send | `Send(from, to[], raw)`, status | Stage 2. Send answers with per-recipient results, as `send.Service` does today |

Front is always the client: core never dials front. The link (`internal/link`) is plain HTTP on
the closed `frontlink` network, which admits only the two containers the measured config names
(decision 3). Mutual TLS with per-container attested keys stays possible later, at the cost of
`attestation: true` on front.

### ACME (decision 2)

Core runs ACME and holds the account key with the keyset. Front makes the CSR for
`MAIL_HOSTNAMES` with `mail-tls` at start and posts it to core, which takes only a P-256 CSR for
exactly those names with a valid signature, and only one key per boot (a restarted front has
the same attested key). Core orders with it (`acme.Issuer.IssueCSR`), holds the chain alone,
caches it in S3 bound to the CSR's key, and front fetches the chain and pairs it with its key
only if the leaf is for that key. Core can't check that the CSR's key is the attested one
without tinfoil-go; a front that lied would only get a certificate for a key it holds anyway.

## What doesn't change

- Sending stays off. `SEND_ENABLED` still needs every send setting, `tinfoil-config.yml` sets none
  of them, the shim doesn't forward `/send`, and `TestReleaseConfigLeavesSendingOff` keeps
  checking it. The checks move to `mail-send`'s config, and the test also checks that the send
  settings appear on no other container.
- The Device API, routing format, stored message format, boot records and signatures don't
  change. The broker sees no difference.
- `mail-sign` stays with core, because it signs what core stores.

## Build order

1. Vault: seal the send keyset to `send-transfer` when the document endorses it (vault PR #4).
   Merge before vault `v0.2.0`.
2. Edge, stage 1 (built): `edge front`, `edge core`, `internal/link`, and the proposed config
   `docs/tinfoil-config.split.yml`. `edge` with no argument still runs everything in one
   container, so `tinfoil-config.yml` is unchanged and a release from `main` is safe as it is.
   Tests keep the split config in line with the live one (same settings, moved), give front only
   `mail-tls` and `frontlink`, and keep every send setting off front and the forwarder.
3. Edge, stage 2: `mail-send`, after step 1's vault release is live. It re-vendors `wire` for
   `PullSendKeyset`, moves the send settings and `send.Service` to `mail-send`, and core hands it
   messages over a second closed network.

### Turning stage 1 on

A release, so the owner's:

1. Copy `docs/tinfoil-config.split.yml` over `tinfoil-config.yml`, keeping that release's
   commitments, and pin the new image digest in all three containers.
2. Deploy held (`--hold=true`) and check before promoting: `/operator/status` answers through
   the shim (core), `/ready` passes after the certificate loads (core and front), and a test
   message through a gateway lands. One thing the docs don't settle: whether Tinfoil publishes
   `ports` for a container whose only network is `closed` (Docker doesn't for its `internal`
   networks). If the held deploy's tunnels can't reach 2525 or 8088, give mail-front an
   `allowlist` network with an empty `allow` list instead, and say so here.
3. Redeploy the gateways with the new tag, as for any edge release.

## Decisions for the owner (all accepted 2026-11-11)

1. Accept the vault change (`send-transfer`), and fold it into the pending vault `v0.2.0` release.
2. ACME in core with the account key; front only makes the CSR and holds `mail-tls`.
3. Accept plain TCP between containers on `closed` networks inside the enclave.
4. Go-ahead to build stage 1 now, or wait and build both stages together.

If the vault change is declined, the closest isolation is stage 1 alone: TLS and SMTP parsing
move away from all keyset secrets, and DKIM stays with the keyset in `mail-core`. That splits TLS
from the secrets, but not DKIM from the secrets, and public claims would have to say so.

[configuration]: https://docs.tinfoil.sh/containers/configuration
[networking]: https://docs.tinfoil.sh/containers/config-networking
[attested keys]: https://docs.tinfoil.sh/containers/attested-keys
[attestation]: https://docs.tinfoil.sh/containers/attestation
