#!/bin/bash
# Turns a fresh Debian 12 or 13 VM, on any provider that allows outbound port 25,
# into the edge's standalone outbound relay (design §14). Use this file as the
# VM's cloud-init user data, or run it once as root (README.md). It takes no
# secrets: the server key is made here and never leaves the VM.
#
# What it leaves behind:
#   - /usr/local/bin/fount-relay, built from EDGE_COMMIT with a sha256-pinned Go
#     that is deleted afterwards,
#   - a P-256 server key in /etc/fount-relay/server.pem (root, 0600), whose pin
#     goes in the edge's SEND_RELAY_PINS,
#   - fount-relay.service on RELAY_PORT, admitting only RELAY_CLIENT_PINS,
#   - an nftables firewall that lets in only RELAY_PORT,
#   - no SSH server, no authorized keys, no password logins, no consoles,
#     no guest agent, journald in memory, and IPv4 only (one sending address).
#
# It prints the server pin and the binary's sha256 at the end; check-pin.sh
# reads the pin back over the network, so no console access is needed.
set -euo pipefail

# Committed, public settings. The pin is the vault's /status
# send_public.relay_client_pin; commit it here so the deployed file is the
# committed one. Environment variables override these for tests only.
RELAY_CLIENT_PINS=${RELAY_CLIENT_PINS:-}
RELAY_PORT=${RELAY_PORT:-443}
EDGE_REPO=${EDGE_REPO:-fount-labs/fount-mail-edge}
# The commit of the edge tag to build gateway/relay from (v0.3.0). Only the
# relay is built, so this needn't follow edge releases.
EDGE_COMMIT=${EDGE_COMMIT:-257c44e5e9a9f84fbb77349e8d29d21d6ebce90f}
# Must satisfy the go line in go.mod at EDGE_COMMIT. From https://go.dev/dl/?mode=json.
GO_VERSION=${GO_VERSION:-1.27.3}
GO_SHA256_AMD64=${GO_SHA256_AMD64:-65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40}
GO_SHA256_ARM64=${GO_SHA256_ARM64:-a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49}

die() { echo "fount-relay install: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
[[ $RELAY_CLIENT_PINS =~ ^[0-9a-f]{64}(,[0-9a-f]{64})*$ ]] ||
  die "RELAY_CLIENT_PINS must be the edge relay client pin(s), 64 hex each; set it in this file"
[[ $RELAY_PORT =~ ^[0-9]+$ ]] || die "RELAY_PORT"
[[ $EDGE_COMMIT =~ ^[0-9a-f]{40}$ ]] || die "EDGE_COMMIT must be a full commit hash"
case "$(dpkg --print-architecture)" in
  amd64) goarch=amd64 gosha=$GO_SHA256_AMD64 ;;
  arm64) goarch=arm64 gosha=$GO_SHA256_ARM64 ;;
  *) die "unsupported architecture $(dpkg --print-architecture)" ;;
esac
export DEBIAN_FRONTEND=noninteractive

# --- No way in. A broken relay host gets replaced, not fixed. ---------------
# Leave sshd's own session alone if this runs over SSH: masking stops new logins,
# and the package goes once the script is done (see the end).
for u in ssh.socket ssh.service sshd.service qemu-guest-agent.service; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done
systemctl mask ssh.socket ssh.service qemu-guest-agent.service \
  getty@.service serial-getty@.service console-getty.service >/dev/null
rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
passwd -l root >/dev/null
systemctl stop 'getty@*' 'serial-getty@*' console-getty.service >/dev/null 2>&1 || true
awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | xargs -r -n1 usermod -L

# --- Nothing kept on disk about connections. ---------------------------------
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' > /etc/systemd/journald.conf.d/fount.conf
systemctl restart systemd-journald || true
rm -rf /var/log/journal

# --- One sending address: the IPv4 its PTR and SPF name. -----------------------
printf 'net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n' > /etc/sysctl.d/90-fount-relay.conf
sysctl -q -p /etc/sysctl.d/90-fount-relay.conf || true

apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl git openssl nftables unattended-upgrades

# --- Firewall: only the relay port comes in. -----------------------------------
cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset
table inet fount {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    udp dport 68 accept
    tcp dport $RELAY_PORT ct state new accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
NFT
systemctl enable nftables >/dev/null
systemctl restart nftables

# --- Security updates only, rebooting when one needs it. ----------------------
# The EC2 gateways are replaced on every edge release, so they pin packages.
# This host keeps its key across updates, and replacing it means an edge
# release, so it patches itself instead.
cat > /etc/apt/apt.conf.d/52fount-relay <<'APT'
Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
APT
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades

# --- Server key: made here, kept here. -----------------------------------------
# A new key means a new edge release (SEND_RELAY_PINS), so a rerun keeps it.
install -d -m 700 /etc/fount-relay
if [ ! -s /etc/fount-relay/server.pem ]; then
  (
    umask 077
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/key.pem" 2>/dev/null
    # The edge pins the key and ignores names and dates.
    openssl req -x509 -new -key "$work/key.pem" -subj /CN=fount-relay -days 36500 -out "$work/cert.pem" 2>/dev/null
    cat "$work/cert.pem" "$work/key.pem" > /etc/fount-relay/server.pem.new
    mv /etc/fount-relay/server.pem.new /etc/fount-relay/server.pem
  )
fi
chmod 600 /etc/fount-relay/server.pem
pin=$(openssl x509 -in /etc/fount-relay/server.pem -noout -pubkey |
  openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)

# --- Build gateway/relay from the pinned commit with the pinned Go. -----------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz"
echo "${gosha}  go${GO_VERSION}.linux-${goarch}.tar.gz" | sha256sum -c --quiet
tar -xzf "go${GO_VERSION}.linux-${goarch}.tar.gz"
if [ -n "${RELAY_SRC:-}" ]; then
  src=$RELAY_SRC # tests: a checkout instead of the pinned commit
else
  src=$work/src
  # Git checks every object against the commit hash, so the source is exactly
  # EDGE_COMMIT whoever serves it.
  git init -q "$src"
  git -C "$src" fetch -q --depth 1 "https://github.com/${EDGE_REPO}.git" "$EDGE_COMMIT"
  git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
  [ "$(git -C "$src" rev-parse HEAD)" = "$EDGE_COMMIT" ] || die "fetched the wrong commit"
fi
(cd "$src" && env -i PATH=/usr/bin:/bin HOME="$work" GOCACHE="$work/cache" GOPATH="$work/gopath" \
  GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0 \
  "$work/go/bin/go" build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /usr/local/bin/fount-relay.new ./gateway/relay)
mv /usr/local/bin/fount-relay.new /usr/local/bin/fount-relay
cd /
rm -rf "$work"
trap - EXIT

# --- The relay. Same unit as the EC2 gateway's, with its own key. ------------
cat > /etc/systemd/system/fount-relay.service <<UNIT
[Unit]
After=network-online.target nftables.service
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
ExecStart=/usr/local/bin/fount-relay -listen :$RELAY_PORT -client-pins $RELAY_CLIENT_PINS
LoadCredential=server.pem:/etc/fount-relay/server.pem
Restart=always
RestartSec=5
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=077
# The relay already refuses these; this is a second wall around every
# provider's metadata service (169.254.169.254 and the like).
IPAddressDeny=link-local multicast
LimitNOFILE=4096
StandardOutput=null
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable fount-relay >/dev/null
systemctl restart fount-relay

# --- No SSH server at all, once nothing here needs it. ------------------------
apt-get purge -y -q openssh-server >/dev/null 2>&1 || true

echo "fount-relay: server pin $pin (SEND_RELAY_PINS)"
echo "fount-relay: built $EDGE_REPO@$EDGE_COMMIT, sha256 $(sha256sum /usr/local/bin/fount-relay | cut -d' ' -f1)"
