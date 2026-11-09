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
gateway pinned to the old one can't open new tunnels, and senders retry. Update
gateway a, wait for its `PublicIp` to answer on port 25, then update b:

```sh
gateway/deploy.sh a v0.1.1
```

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

## Test

```sh
gateway/test-haproxy.sh
```

Runs the config from `template.yml` with the pinned release and HAProxy, in
Docker, against `testdata/edgestub`, which uses the edge's own `gatewaytls`
listener. It checks that the PROXY header reaches the edge inside mutual TLS 1.3,
that ACME reaches the challenge port, that the per-IP rate limit holds, and that the
config has no log lines.

## Security layers (design §7)

| Layer | Stops |
|---|---|
| Attested tunnel, pinned to one release | Reaching an unverified or unexpected edge |
| Tunnel key (`shim.authenticated`) | Outsiders using up the 128 tunnel slots |
| Mutual TLS 1.3 on the tunnelled ports | Fake sender IPs, bypassing limits |
| Connection limits (per-IP, 60 per gateway, timeouts under 5m) | Floods |
| Edge checks (unknown recipients, size, quotas) | Most spam |

## Untested / before production

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
