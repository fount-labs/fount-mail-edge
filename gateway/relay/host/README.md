# Standalone relay host

The edge's outbound relay (`gateway/relay`, design §14) on a VM of its own, at
any provider that lets port 25 out. AWS declined (2026-11-11) to lift the
port-25 limit for the gateways' account, then lifted it (2026-11-12) for the
older Fount account (277707116697, us-east-1), so the host runs there on EC2:
Elastic IP `32.200.135.24`, PTR `out.fountbox.com`, launched by
`launch-ec2.sh`. The gateway-side relay in `template.yml` stays off. Use one or
the other: the edge's `SEND_RELAY_ADDR` names one relay.

The relay is an untrusted TCP pipe. The edge does TLS to recipients itself, so
the host sees which servers the edge connects to, when, and how much, but not
the mail. It never holds anything secret except its own server key.

## What `install.sh` does

Run once as root on a fresh Debian 12 or 13 VM (amd64 or arm64), as cloud-init
user data or by hand:

| Step | Detail |
|---|---|
| No way in | Masks and then purges the SSH server, deletes `authorized_keys`, locks every password, masks the getty and serial consoles and `qemu-guest-agent`. A broken host is replaced, not fixed. |
| No logs | journald in memory only (16 MiB), `/var/log/journal` removed. The relay writes nothing, and its unit sends stdout and stderr to `/dev/null`. |
| One sending address | IPv6 off, so mail leaves from the one IPv4 address that the PTR and SPF name. |
| Firewall | nftables: drop everything in except the relay port, ICMP, DHCP replies and loopback. |
| Updates | Debian security updates install themselves and reboot at 04:00 when needed. The EC2 gateways pin packages, but they're replaced on every edge release. This host keeps its key, and replacing it costs an edge release, so it patches itself. |
| Server key | P-256, made on the host by `openssl` into `/etc/fount-relay/server.pem` (root, 0600), handed to the relay through `LoadCredential`. It never leaves the VM and isn't in the user data. A rerun keeps it. |
| Build | Fetches `EDGE_COMMIT` by hash with git (every object is checked against it), downloads Go `GO_VERSION` and checks its sha256, builds `./gateway/relay` with `-trimpath -buildid=` and `-mod=vendor`, then deletes Go and the source. |
| Relay | `fount-relay.service`: the EC2 unit's sandbox (`DynamicUser`, only `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, ...), plus a syscall filter and `IPAddressDeny=link-local multicast` around every provider's metadata service. |

It prints the server pin and the binary's sha256 at the end.

**Settings** are at the top of `install.sh` and are public. Set
`RELAY_CLIENT_PINS` to the vault's `/status` `send_public.relay_client_pin` and
commit it, so the file deployed is the committed one. `EDGE_COMMIT` is the
commit of the edge tag to build from (v0.3.0 now). It needn't follow edge
releases, since only the relay is built.

**Key choice.** The key is made on the host, so no agent, laptop or provider
API ever has it, and there's nothing to store. The cost is that a lost or
replaced host means a new pin, which means an edge release. `SEND_RELAY_PINS`
takes a list, so a planned move can put the new host's pin in one release
ahead of switching `SEND_RELAY_ADDR`. The provider can still read the disk, as
AWS can on EC2.

## Provider

Used only if the EC2 host has to move.

Port-25 policies as of 2026-11-11, from each provider's docs:

| Provider | Outbound 25 | Notes |
|---|---|---|
| OVHcloud VPS | Open by default (not Local Zones) | PTR self-service in the panel. An anti-spam system can block 25 if it sees spam. Public Cloud instances, unlike VPS, block 25. x86 only. |
| Akamai (Linode) | Blocked for accounts since 2019-11 | Support ticket with name, use case and sending domains. |
| Vultr | Blocked on new instances | Support ticket with use case, SPF/DKIM and volume. Case by case, not guaranteed. |
| Hetzner Cloud | Blocked by default | Request only after the first invoice is paid (about a month). Some requests are refused. |

**Pick an OVHcloud VPS** (US or Canada region, not a Local Zone, Debian 13, smallest size): no ticket and no wait. Linode is the second choice, because its ticket asks only for a description. Check the policy again before ordering, because these change.

## Deploy (owner)

1. Set `RELAY_CLIENT_PINS` in `install.sh` and commit it.
2. Create the VM with Debian 13 and an SSH key.
   - If the provider takes user data, paste `install.sh` in as-is.
   - Otherwise, run it once over SSH. It runs as a transient unit, so it
     survives the SSH server going away:
     ```sh
     scp gateway/relay/host/install.sh root@<ip>:/root/
     ssh root@<ip> systemd-run --unit fount-relay-install bash /root/install.sh
     ```
3. Wait a few minutes, then read the pin over the network:
   ```sh
   gateway/relay/host/check-pin.sh <ip>:443
   ```
   `ssh root@<ip>` should now fail with connection refused or a timeout.
4. At the provider, set the PTR for the IPv4 address to `out.fountbox.com`.
   Turn off any provider backups and monitoring agents (the install doesn't
   need them), and don't add a provider firewall that blocks 443 in or 25 out.
5. DNS and the edge release: see "Changes outside this host" below.
6. Reboot once from the panel and rerun `check-pin.sh <ip>:443 <pin>`. The same
   pin should come back.

## Changes outside this host

- **DNS (fount-infra `MailDnsStack`, `-c relayIp=<ip>`):** `out.fountbox.com A
  <ip>`, apex SPF `v=spf1 ip4:<ip> -all`, and the same SPF on the HELO names
  `out`, `mx1` and `mx2`. The edge says `EHLO mx1.fountbox.com` today
  (`MAIL_HOSTNAMES[0]`), which doesn't match the PTR `out.fountbox.com`.
  Receivers check that the PTR and A agree, which they do, and a HELO SPF
  pass covers `mx1`. An edge setting for the EHLO name would let it say
  `out.fountbox.com` instead.
- **PTR** at the provider: `<ip>` → `out.fountbox.com`.
- **Edge release (`tinfoil-config.yml`):** `out.fountbox.com` in
  `networks.edge.allow`; `SEND_RELAY_ADDR: "out.fountbox.com:443"`;
  `SEND_RELAY_PINS` = this host's pin (not `GATEWAY_CLIENT_PINS`).
  Tinfoil resolves allowlist names when it builds the firewall, so a new IP
  for `out` needs an edge redeploy.
- **The 443 targets stay on this host.** All of the edge's send traffic goes
  through one `send.Relay`: DoH (`dns.google`, `cloudflare-dns.com`), MTA-STS
  policies, and port 25. So this host serves the 443 CONNECT targets too. Splitting
  them would need an edge change, and there's no reason to.
- **The EC2 gateways** keep `RelayClientPins` empty, so their relay stays off.

**Untested:** whether Tinfoil's egress allowlist reaches a non-AWS host on 443,
and real port 25 from the chosen provider. Both are checked by the first
sending release. `test-relay-host.sh` covers the host itself, and from a home
network it reached `gmail-smtp-in.l.google.com:25` through the relay.

## Test

```sh
gateway/test-relay-host.sh          # Debian 13 with systemd in Docker; builds the pinned EDGE_COMMIT
LOCAL=1 gateway/test-relay-host.sh  # builds this checkout instead
```

It runs `install.sh` as cloud-init would, on an image that has an SSH server, an
authorized key and a user with a password. It checks:

- the binary matches a local build of the same commit, which shows the build is
  reproducible,
- the unit runs and passes `systemd-analyze verify`,
- the edge's own relay client gets DoH, MTA-STS and port 25 through, and gets `403`
  for loopback, private, metadata and other hosts,
- an unpinned key is refused,
- `check-pin.sh` from another container reads the pin `install.sh` printed,
- the firewall drops another listening port,
- SSH, keys, passwords and consoles are gone, and journald is in memory,
- a rerun keeps the key,
- the relay wrote nothing.
