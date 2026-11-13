# Mail gateway

Tinfoil has no public port 25, so a small VM accepts port 25 (and ACME HTTP-01
on port 80) and pipes both through an attested `tinfoil forward` tunnel to the
edge enclave (design §7). The gateway filters connections only. If it runs this
template, the gateway can't read TLS-protected mail. Senders can't verify that:
Fount holds the DNS and could point the MX elsewhere, strip STARTTLS, or run a
different VM. Commands before STARTTLS (EHLO, and STARTTLS itself) pass in the
clear, as in any SMTP. The edge answers `530` to `MAIL` before STARTTLS, so no
address or content crosses the gateway unencrypted.

`template.yml` is a CloudFormation stack for one gateway (adapted from the proven
port-25 probe). Deploy **two**, in separate AZs, each with its own MX record.

## What's pinned

| Input | Pin | Where |
|---|---|---|
| AMI | `ami-0951c836c26e34fc8`, AL2023 `2023.12.20261102.0` arm64, us-east-1 | `Ami` |
| Packages | `dnf --releasever=2023.12.20261102`, `haproxy-3.0.30-1.amzn2023.0.1` | `DnfRelease`, `HaproxyPackage` |
| Tinfoil CLI | `0.19.20`, tarball sha256 checked against the release's `checksums.txt` | `TinfoilCliVersion`, `TinfoilCliSha256` |
| Edge | `--repo fount-labs/fount-mail-edge@<tag>`, so the tunnel refuses every other release | `EdgeReleaseTag` |

A tag mismatch fails attestation (`code source ref "refs/tags/v0.1.0" does not
match tag "v9.9.9"`, checked against the live edge 2026-11-08). User data lives in a
launch template, so changing any parameter replaces the instance, and the
Elastic IP moves to the new one.

**Each edge release means a gateway update.** Once the edge runs the new tag, a
gateway pinned to the old one can't open new tunnels, and senders retry. Update both
gateways at once. Every release has a fresh `mail-tls` key, so it needs a new certificate, and
that one certificate validates mx1 through gateway a and mx2 through gateway b. Updating a and
waiting for it before b deadlocks ACME (found on v0.4.0):

```sh
gateway/deploy.sh a v0.6.0 & gateway/deploy.sh b v0.6.0 & wait
```

Done when both `PublicIp`s answer `220` on port 25 and the edge's `/ready` is 200.

## No access, no logs

- No key pair, no SSH, and no SSM: the role has no managed policies, and user data
  masks `amazon-ssm-agent` and `sshd`. A broken gateway gets replaced, not fixed.
- HAProxy has no `log` lines. `tinfoil forward`'s stdout goes to `/dev/null`, and
  journald is in memory only.
- The per-IP limit keeps each source IP in memory for 10 minutes. That's the only
  record of a sender, and it never leaves the VM.
- VPC flow logs are off in `fount-mail-prod`. Turning them on would be a connection
  log, so don't.

## Deploy

```sh
gateway/deploy.sh a v0.1.0    # stack fount-mail-gateway-a, us-east-1a; prints the PublicIp
gateway/deploy.sh b v0.1.0
```

**First deploy parked.** A gateway starts ACME as soon as its tunnel is up, and
HTTP-01 fails until the MX names resolve, which uses up Let's Encrypt's failed
validation limit. So deploy both with `v0.0.0`, which no release matches, set up
DNS, then redeploy with the live tag.

`EnclaveHost` is the enclave's own name, which only the gateway and keyserver
use. Senders see the MX names (`mx1.fountbox.com`, `mx2.fountbox.com`), which
resolve to the gateways. The edge's certificate covers both, so both gateways
must be up when it issues.

Each gateway has its own client certificate in Secrets Manager (`fullchain +
key` PEM). Its SPKI pin goes in `GATEWAY_CLIENT_PINS` in `tinfoil-config.yml`, so
a new gateway key means a new release. `check-pins.sh` compares both secrets
against the config, printing only public-key hashes:

```sh
gateway/check-pins.sh
```

Start the **enclave first**. A gateway that resolves the host before it exists
can cache "no such host" for up to 30 minutes.

## Connection limits

The 128-tunnel limit is per enclave, so the two gateways share it. Each holds 56
SMTP and 4 ACME connections, which leaves 8 for health checks. One IP gets 4 open
connections and 30 a minute. Timeouts are 4 minutes, under the tunnel's 5-minute
idle limit.

## Outbound relay (design §14)

Tinfoil's port 25 is dead, so the edge sends through a gateway too. `relay/` is a
small Go listener (standard library plus the edge's `gatewaytls`, about 450
lines) that the gateway builds from the same edge tag its tunnel pins, with a
sha256-pinned Go (`GoVersion`, `GoSha256`) it deletes afterwards. It only runs
when `RelayClientPins` is set, and then the security group opens `RelayPort`.

The contract is the edge's `internal/send/relay.go`, and the relay's tests dial
it with that client:

- Mutual TLS 1.3. The edge's client key must match `RelayClientPins`, which is
  `relay_client_pin` from a vault's `/status` `send_public`. The server key is
  the gateway's client key, so the edge's `SEND_RELAY_PINS` is the same value as
  `GATEWAY_CLIENT_PINS`, and `check-pins.sh` already checks it.
- One `CONNECT host:port HTTP/1.1`, then raw TCP. Port 25 goes to any public
  address. Port 443 goes only to `dns.google`, `cloudflare-dns.com` and
  `mta-sts.*`. Anything else gets `403`, a bad request `400`, and a lookup or
  dial failure `502`.
- The relay resolves a name once, refuses it if **any** answer isn't public
  (loopback, private, link-local, which holds the metadata service, CGNAT,
  multicast, documentation, NAT64, 6to4, Teredo, `fd00:ec2::254`), and dials only
  the addresses it checked, so a rebinding answer has nothing to change. A
  socket-level check refuses a non-public address or another port again on the
  address actually dialed, and systemd's `IPAddressDeny` walls off the metadata
  service a third time.
- No logs: a destination names a recipient's mail provider. At most 32 open
  streams; 10 seconds for the handshake and request, 5 minutes idle, 30 minutes
  per stream. It runs as a systemd `DynamicUser` with only `CAP_NET_BIND_SERVICE`,
  and gets the key through `LoadCredential`.

The relay doesn't use the tunnel: the edge dials it through Tinfoil's egress
allowlist, so it doesn't count against the 128-tunnel limit. TLS to the
destination runs from the enclave through the relay, so after the CONNECT line
the gateway sees only ciphertext. The gateway does see which host the edge
connects to, and resolves MX names through the VPC resolver.

`SEND_RELAY_ADDR` takes one `host:port`, so one gateway relays at a time. Using
`mx1.fountbox.com:443` needs no new DNS; the host must also be on the edge
network's `allow` list in `tinfoil-config.yml`. Both gateways run the relay, so
moving to b is an edge release that changes the name.

Sending from EC2 needs AWS to lift the port 25 limit for the Elastic IPs and set
reverse DNS for each IP naming its MX host. AWS declined both on 2026-11-11, and
an appeal is pending. The fallback is the same relay on a host of its own at a
provider that allows port 25, with its own key and pin: `relay/host/` (README,
`install.sh`, `check-pin.sh`). It doesn't depend on AWS's answer.

## Test

```sh
gateway/test-haproxy.sh
gateway/test-relay.sh    # needs network: drives the relay with the edge's client
gateway/test-relay-host.sh   # needs network: the standalone relay host (relay/host/)
go test ./gateway/relay/
```

`test-haproxy.sh` runs the config from `template.yml` with the pinned release and HAProxy, in
Docker, against `testdata/edgestub`, which uses the edge's own `gatewaytls`
listener. It checks that the PROXY header reaches the edge inside mutual TLS 1.3,
that ACME reaches the challenge port, that the per-IP rate limit holds, and that the
config has no log lines.

`test-relay.sh` renders the template's user data, runs its relay build script on
this checkout in AL2023 with 1 GiB, checks the unit with `systemd-analyze verify`,
then runs the unit's command and checks that DoH, MTA-STS and port 25 get
through, that loopback, private, metadata and other hosts get `403`, that an
unpinned key is refused, and that the relay wrote nothing.

## Security layers (design §7)

| Layer | Stops |
|---|---|
| Attested tunnel, pinned to one release | Reaching an unverified or unexpected edge |
| Tunnel key (`shim.authenticated`) | Outsiders using up the 128 tunnel slots |
| Mutual TLS 1.3 on the tunnelled ports | Fake sender IPs, bypassing limits |
| Connection limits (per-IP, 60 per gateway, timeouts under 5m) | Floods |
| Edge checks (unknown recipients, size, quotas) | Most spam |

## Untested / before production

- **The relay from a real edge.** That Tinfoil's egress allowlist lets the edge
  reach `mx1.fountbox.com:443`, and that EC2 lets port 25 out once the limit is
  lifted. `test-relay.sh` covers the relay itself, from Docker.

- **`shim.authenticated`** (undocumented): a keyless CONNECT should get `401`
  before it counts against the tunnel cap. The template takes a `tk_` key from
  `TunnelKeySecret` when it's set, and the edge release has to turn the setting on.
- **A real tunnel end to end.** `/ready` on port 8080 answered through `tinfoil
  forward` on 2026-11-08 (`503 certificate not ready`, as expected before DNS).
  SMTP and ACME through a real tunnel still need a deployed gateway.
- DNS for the mail domain: strict SPF, DMARC `p=reject`, TLS-RPT, strict
  MTA-STS, CAA (pinning the ACME account via `accounturi`), low-TTL MX. These
  live in fount-infra. The CAA record is
  `fountbox.com. CAA 0 issue "letsencrypt.org; accounturi=<URL>; validationmethods=http-01"`,
  with the URL from `edgectl status` (`acme_account`); `docs/DEV.md` covers it.
