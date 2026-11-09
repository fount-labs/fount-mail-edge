# Trust model and release approval

This is the public excerpt of Fount Mail's design: who can read what, which keys exist, and
what it takes to get them. Code comments cite sections of the full design doc, which is
private, as `§N`. The headings below keep those numbers, and sections that aren't excerpted
are omitted.

## §3 Who sees what

```text
sender -> gateway VM -> attested tunnel -> edge (enclave) -> S3 (ciphertext)
                                             ^
                    Fount's broker, on the user's device: fetches, checks, decrypts
```

| Part | Runs on | Sees plaintext mail? |
|---|---|---|
| Gateway | An ordinary VM Fount runs | Not if it runs the published template, which forwards TLS untouched. Senders can't verify which it runs. It sees IPs, timing, and sizes |
| Edge | A Tinfoil enclave running a release of this repo | Briefly, while it encrypts each message |
| S3 | Fount's AWS account | No. AWS and Fount see ciphertext, sizes, and timing |
| Vaults | Tinfoil enclaves running `fount-mail-vault` | No mail. They hold the edge's long-lived keys |
| Broker | The user's device | Yes. It holds the only decryption keys |

Email isn't end-to-end encrypted. The sender's provider reads what they send, and Fount runs
the gateway and DNS that mail crosses, so Fount could end a sender's TLS before the enclave.
Strict MTA-STS and CAA make that visible in public logs afterwards. They don't prevent it.

## §4 What the server stores

| Stored | Where |
|---|---|
| Mailbox ID, a keyed hash of the address. It appears in S3 object keys | Routing data, S3 keys |
| Each address's public key, and the mailbox's request, owner-change, and passkey public keys | Routing data |
| Keyed hashes of each owner address and of the license | Routing data |
| The sequence counter per mailbox | Routing data |
| Each message, sealed to the address's key | S3, until fetched or expired |
| Each mailbox key's hash, and each boot's signing key | The write-once log bucket |

Routing data is one object, encrypted with a key only the vaults and the edge hold. No
plaintext address is stored or logged. The edge does see addresses in memory: the recipient of
each SMTP session, the address on `POST /address`, and owner addresses on `PUT /routing`.

Fount can still link things it can compute. It holds the MAC key and the licenses, so it can
link a mailbox to a license and test guessed addresses. Owner hashes are unsalted. S3 also
shows per-mailbox grouping, near-exact sizes, message counts, and receive times.

## §5 Keys

| Key | Where it comes from | Who can get it |
|---|---|---|
| TLS, message signing, transfer | Made inside the enclave each boot. The public halves are in the attestation | Nobody outside the enclave |
| ACME account, address MAC, routing data, S3 credentials | A vault, after it verifies this release | A vault, and any approved release of this repo |
| Address decryption keys | Made on the user's device | Only that device |

No edge key can decrypt stored mail. The edge accepts only the keyset that `KEYSET_COMMITMENT`
in `tinfoil-config.yml` names, and there's no fallback to a Tinfoil-managed secret.

**What an approved release can do.** Anything holding the keyset can rewrite routing data,
including the public key mail is sealed to, and test guessed addresses. It can't open mail
already stored. Detecting a swapped key on the device is planned (§9), and not built.

## §6 The edge

- STARTTLS is mandatory, and the key is the attested TLS key.
- Unknown recipients are rejected during SMTP, with no catch-all.
- Each message is stored whole and never parsed, sealed with HPKE to the address's key, with
  the envelope inside the encryption: the sender, the recipient, the sending server's IP, and
  its HELO name, so the broker can check SPF. `250` comes only after S3 confirms the write.
- Unfetched mail expires after 30 days, with a signed expiry record. A message the sweep can't
  verify stays until a 45-day bucket rule deletes it with no record.
- S3 traffic goes through a forwarder container with open egress, because Tinfoil's allowlist
  doesn't work for S3. The forwarder holds no keys and sees only TLS, but this limit comes from
  measured code rather than Tinfoil's firewall.

## §7 Gateway

Tinfoil has no public port 25, so a VM in `gateway/` accepts it and pipes it through an attested
tunnel. The edge requires mutual TLS from a pinned gateway key on every tunnelled port. Nothing
proves what a gateway runs, so no claim rests on it.

The sending server's IP comes from the PROXY header the gateway writes inside that mutual TLS,
and a connection without one is dropped. So the IP sealed with each message, and the SPF result
the broker computes from it, are only as honest as the gateway.

## §8 Device API

Every request is signed by the key its route requires, over method, path, body hash, timestamp,
and nonce. From outside, the API is reached through the Tinfoil shim, which forwards only the
paths `shim.paths` in `tinfoil-config.yml` lists. Timestamps must be within 5 minutes. The nonce cache lives in memory, so a request
captured in the 5 minutes before a restart can be replayed once after it. The route table, with
each route's signer, is `routes` in `internal/deviceapi/deviceapi.go`.

## §9 Stored messages

Each message is signed by that boot's attested signing key, and the boot's key is published
under `GET /boots/{id}`, so the broker can check a message after that enclave is gone. Each
mailbox has a sequence counter, so a missing number shows withheld or lost mail. The edge writes
a signed record for a number it spent without storing a message.

**Planned, not built:** the edge storing each mailbox's signed key chain and refusing any key
not on it, read paths for the key and boot logs, and the broker checking them. Until then, a key
swap isn't detectable, and nothing here claims it is.

## §17 Release approval

The vaults hand the keyset to any release of this repo at or above their `EDGE_MIN_TAG`, as soon
as it's published. So **the tag push is the approval**:

- Only org admins can push a `v*` tag, under a GitHub ruleset.
- *Tinfoil Release* checks the tag is on `main` and the config is filled in, then measures and
  publishes it.
- Releases are public. Fount's watcher will email on every release of either repo, once it's
  deployed, which it isn't yet. That's detection, not prevention.
- To retire a release, raise `EDGE_MIN_TAG` in a vault release.

Anyone can check a release with `scripts/verify-release.sh vX.Y.Z`. It rebuilds the image at the
tag, compares it with every digest pinned in the config, and checks the live enclave's
attestation against that tag, and it fails if any check can't run. No scheduled job runs it yet.
