# Edge container split: plan

Status: proposal, 2026-11-11. Nothing here is built. It waits on the owner's decisions at the end.

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
                                  net: front                           attestation: true
                                       │                               net: edge (allowlist vaults),
                                       └──── front (closed) ──────────▶     front, internal, sendnet
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
  on the tunnel ports, speaks SMTP including STARTTLS, serves ACME HTTP-01 answers, and passes
  each message and each RCPT check to `mail-core`. It has no egress: its only network is `front`.
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

All four run the same image, with a subcommand each, as `egress-forward` does now. Every container
keeps `read_only`, no `cap_add`, no `cvm_admin`, and gets `ipc: none`.

### What crosses each boundary

| Link | Calls | Notes |
|---|---|---|
| front → core | `Status(rcpt)`, `Put(envelope, raw)`, cert cache get/put | `Put` carries the plaintext message, which front already saw when it terminated TLS. Core seals it |
| core → front | cert status for `/ready` | Front answers `/ready` locally; core's `/ready` asks front |
| core → send | `Send(from, to[], raw)`, status | Send answers with per-recipient results, as `send.Service` does today |

Each link is a small HTTP API on its own closed network, which admits only the two named
containers; the measured config fixes that. If we want more than network membership, each
container can get its own attested key for the link, and each side reads the other's public half
from the enclave's own attestation document, giving mutual TLS with no shared secret. That costs
an `attestation: true` on front, so it's optional.

### ACME

Issuing needs the ACME account key (in the mail keyset) and a CSR signed with `mail-tls` (in
front). Two options:

1. **Core runs ACME** and asks front to sign the CSR. The account key stays with the keyset.
   Front exposes "sign this CSR for these hostnames", which only signs CSRs, not arbitrary data.
2. **Front runs ACME** and core hands it the account key once. Simpler, but the internet-facing
   container would then hold a CAA-pinned issuing key.

Recommendation: option 1.

## What doesn't change

- Sending stays off. `SEND_ENABLED` still needs every send setting, `tinfoil-config.yml` sets none
  of them, the shim doesn't forward `/send`, and `TestReleaseConfigLeavesSendingOff` keeps
  checking it. The checks move to `mail-send`'s config, and the test also checks that the send
  settings appear on no other container.
- The Device API, routing format, stored message format, boot records and signatures don't
  change. The broker sees no difference.
- `mail-sign` stays with core, because it signs what core stores.

## Build order

1. Vault (needs the owner's go-ahead, and a vault PR): seal the send keyset to `send-transfer`
   when the document endorses it. Merge before vault `v0.2.0`.
2. Edge, stage 1: `mail-front` and `mail-core`, with the RPC layer and tests. `tinfoil-config.yml`
   moves to the new layout in the same PR, so a release from `main` is always consistent. No
   live change until the owner tags a release.
3. Edge, stage 2: `mail-send`, after step 1's vault release is live.

Stage 1 doesn't depend on the vault, but it's the largest change to `cmd/edge` since launch and
moves every listener, so it waits for the owner's go-ahead too.

## Decisions for the owner

1. Accept the vault change (`send-transfer`), and fold it into the pending vault `v0.2.0` release.
2. ACME: option 1 (core runs it, front signs CSRs) or option 2.
3. Accept plain TCP between containers on `closed` networks inside the enclave.
4. Go-ahead to build stage 1 now, or wait and build both stages together.

If the vault change is declined, the closest isolation is stage 1 alone: TLS and SMTP parsing
move away from all keyset secrets, and DKIM stays with the keyset in `mail-core`. That splits TLS
from the secrets, but not DKIM from the secrets, and public claims would have to say so.

[configuration]: https://docs.tinfoil.sh/containers/configuration
[networking]: https://docs.tinfoil.sh/containers/config-networking
[attested keys]: https://docs.tinfoil.sh/containers/attested-keys
[attestation]: https://docs.tinfoil.sh/containers/attestation
