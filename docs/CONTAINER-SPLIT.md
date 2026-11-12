# Edge container split

Status, 2026-11-11: the owner accepted all four decisions at the end. Stage 1 (`mail-front` and
`mail-core`) is built (edge PR #20); the vault's `send-transfer` box is vault PR #4, live in vault
v0.2.1 on both vaults; stage 2 (`mail-send`) is built. The live release still runs one `mail-edge`
container: the split goes live only when a release copies `docs/tinfoil-config.split.yml` over
`tinfoil-config.yml`. **v0.4.0 did that**: `tinfoil-config.yml` is now the split config and the
separate file is gone.

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
                                                     net: sendnet, sendout (allowlist: vaults, later the relay)
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
  key). `mail-core` decides who may receive (owner lists, proof, pause, limits) and hands it a
  message and recipients. `mail-send` checks `From` and the recipients again, signs, and delivers
  through the pinned relay. It pulls its own keys from a vault, so its egress allowlist is the
  two vaults plus the relay host (added by the release that turns sending on).
- **`forwarder`** is unchanged.

All four run the same image, with a subcommand each (`front`, `core`, `send`), as
`egress-forward` does now. Every container keeps `read_only`, no `cap_add` and no `cvm_admin`;
mail-front and mail-send also get `ipc: none`. Each refuses to boot on a wrong grant: front exits
if it can see `transfer`, `mail-sign`, `send-transfer`, any vault secret, or any vault, S3 or send
setting or `SEND_LINK`; core exits if it can see `mail-tls` or `send-transfer`, or any send
setting; send exits if it can see `mail-tls`, `mail-sign` or `transfer`, any vault secret, or
any keyset, S3, ACME, tunnel or link setting (`config.SendForbidden`).

### What crosses each boundary

| Link | Calls | Notes |
|---|---|---|
| front → core | `POST /link/rcpt`, `POST /link/put`, `POST /link/csr`, `GET /link/cert?have=` | `put` carries the plaintext message, which front already saw when it terminated TLS. Core seals it. `have` tells core which leaf front holds, which core's `/ready` waits for |
| front → core | the tunnelled challenge port, forwarded | Only `GET /` and `GET /.well-known/acme-challenge/…`; `/link/` is never reachable from outside |
| front → core | the Device API's TLS port, forwarded | Only `deviceapi.Routes()`; `/operator` stays shim-only |
| core → send | `POST /link/send`, `GET /link/send/status` | `send` carries `from`, `recipients` and the raw message. Send answers with per-recipient results, or 503 while sending is off. `status` is `on` or `off: <why>`, with the held send keyset's commitment |

Front is always the client: core never dials front, and core is always mail-send's client. The
links (`internal/link`) are plain HTTP on the closed `frontlink` and `sendnet` networks, each of
which admits only the two containers the measured config names (decision 3). Mutual TLS with per-container attested keys stays possible later, at the cost of
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
  checking it. In the split the checks move to `mail-send`'s config (`config.LoadSend` keeps
  `Load`'s gates, and `newOutbox` the same gate order as `newSender`), and
  `TestSplitConfigLeavesSendingOff` checks that the send settings appear on no other container.
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
3. Edge, stage 2 (built): `edge send`, the send link, and `mail-send` in
   `docs/tinfoil-config.split.yml`. See "Stage 2" below.

## Stage 2: what was built

- `wire` is re-vendored from vault `90bac8d` (v0.2.1), for `wire.PullSendKeyset`.
- `internal/send` splits signing and delivery (`send.Outbox`, behind `send.Transmitter`) from
  the checks that need routing data (`send.Policy`). `send.Service` is Policy in front of a
  Transmitter, and owner notices (`internal/notice`) go through the same Transmitter, so there's
  still one way out. The Outbox checks again what it can see in the message
  (`send.CheckHandoff`): Parse's shape, that the sender is the message's one `From` in the mail
  domain, and that the recipients are some of its own `To` and `Cc`, none in the mail domain, at
  most 10, no repeats.
- `edge send` (`cmd/edge/mailsend.go`) loads only `send-transfer` and the send settings, pulls the
  send keyset with `wire.PullSendKeyset` from each vault in turn, retrying with backoff up to
  10 minutes until one hands it over, and serves `internal/link`'s send link on `:7026`
  (`SEND_LINK_ADDR`). It builds an Outbox only past the same gates the one-container edge uses:
  `SEND_KEYSET_COMMITMENT`, the pulled keyset, `SEND_ENABLED` (which `LoadSend` refuses without
  the relay, its pins and the DKIM selector), and a buildable relay client. Until then the link
  answers 503, which core turns into `send.ErrOff`.
- `edge core` refuses every send setting and reads `SEND_LINK` (`mail-send:7026`). With it and
  routing, `POST /send` runs the Policy in core and hands the message to mail-send. Core asks
  mail-send's status every 15 s: while it isn't `on`, `POST /send` answers 501 (`send.ErrOff`)
  before any check, so no limit is spent; owner notices start only the first time it's `on`, and
  a notice mail-send can't take stays queued without counting toward its give-up time.
  `/operator/status` shows `off: mail-send: <why>`, `off: mail-send unreachable`, or `on`, and
  mail-send's commitment.
- In core the vault leaves the send keyset out of the `transfer` box, because the enclave's
  document endorses `send-transfer`; core also sets no send commitment, so `InstallVaultKeys`
  would drop one anyway.
- `edge` alone is unchanged: one container, the Outbox in process, and it refuses `SEND_LINK`.
- `docs/tinfoil-config.split.yml` adds the `send-transfer` key, `mail-send` (`keys:
  [send-transfer]`, `attestation: true`, `ipc: none`, no ports), the closed `sendnet`, and
  `sendout`, an allowlist of the two vaults. It sets no send setting, so mail-send boots, pulls
  nothing and reports `off: SEND_KEYSET_COMMITMENT unset`. The relay host isn't in `sendout`:
  Tinfoil resolves every allowlisted name at deploy, and `out.fountbox.com` doesn't exist yet.

Not tested: a real attested pull through `send-transfer` (unit tests fake the vault), whether
Tinfoil publishes `ports` for a container whose only network is `closed` (stage 1's open
question, below), and Tinfoil egress to a non-AWS relay host from an allowlist network. The
last two were settled by a live probe on 2026-11-12: a container whose only network is `closed`
publishes `ports` that tunnels reach, and an allowlist reaches non-AWS hosts on 443.

### Turning the split on

A release, so the owner's. Stages 1 and 2 go live together: the split config has all four
containers.

1. Copy `docs/tinfoil-config.split.yml` over `tinfoil-config.yml`, keeping that release's
   commitments, and pin the new image digest in all four containers.
2. Deploy held (`--hold=true`) and check before promoting: `/operator/status` answers through
   the shim (core), `/ready` passes after the certificate loads (core and front), and a test
   message through a gateway lands. One thing the docs don't settle: whether Tinfoil publishes
   `ports` for a container whose only network is `closed` (Docker doesn't for its `internal`
   networks). If the held deploy's tunnels can't reach 2525 or 8088, give mail-front an
   `allowlist` network with an empty `allow` list instead, and say so here. `/operator/status`
   should show `send` as `off: mail-send: SEND_KEYSET_COMMITMENT unset`, which proves core reaches
   mail-send over `sendnet`.
3. Redeploy the gateways with the new tag, as for any edge release.
4. Optional, still with sending off: set only `SEND_KEYSET_COMMITMENT` on mail-send (the vaults'
   `98fcffaa…3480`). `/operator/status` should then show the commitment with
   `off: mail-send: SEND_ENABLED unset`, which proves the `send-transfer` pull end to end.

Turning sending on later is its own release: on mail-send only, `SEND_KEYSET_COMMITMENT`,
`SEND_RELAY_ADDR` (`out.fountbox.com:443`), `SEND_RELAY_PINS`, `DKIM_SELECTOR` and
`SEND_ENABLED`; the relay host added to `sendout`; and `/send` added to the shim paths.

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
