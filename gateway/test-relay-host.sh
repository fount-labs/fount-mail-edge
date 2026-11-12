#!/bin/bash
# Runs relay/host/install.sh on Debian 13 booted with systemd in Docker, the way
# a provider's cloud-init would, then checks the standalone relay host:
#   - install.sh fetches EDGE_COMMIT by hash, builds with the pinned Go, and the
#     binary matches a build of the same commit made here (reproducible),
#   - fount-relay.service runs under systemd with its own key, and the edge's
#     relay client (internal/send.Relay) gets DoH, MTA-STS and port 25 through,
#     while loopback, private, metadata and other hosts get 403,
#   - check-pin.sh, from another container, reads the same pin install.sh
#     printed, and a port other than the relay's is dropped,
#   - no SSH server, no authorized keys, locked passwords, journald in memory,
#   - a rerun keeps the key, and the relay wrote nothing.
# Needs Docker and network access.
#
#   gateway/test-relay-host.sh          # builds the pinned EDGE_COMMIT from GitHub
#   LOCAL=1 gateway/test-relay-host.sh  # builds this checkout instead
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
host="$here/relay/host"
image=fount-relay-host-test
name=fount-relay-host-test-$$
work=$(mktemp -d)
cleanup() { docker rm -f "$name" "$name-out" >/dev/null 2>&1 || true; rm -rf "$work"; }
[ -n "${KEEP:-}" ] || trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir "$work/creds" "$work/client"

(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$work/relayclient" ./gateway/testdata/relayclient)
edgepin=$(cd "$root" && go run -mod=vendor ./gateway/testdata/relayclient setup "$work/creds")
cp "$work/creds/edge.key" "$work/client/"

# A cloud image stand-in: systemd as PID 1, an SSH server with a key in it, and a
# login user, so install.sh has something to take away.
docker build -q -t "$image" --platform linux/arm64 - >/dev/null <<'DOCKER'
FROM debian:trixie
RUN apt-get update -q && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus openssh-server openssl ca-certificates \
 && useradd -m -s /bin/bash debian && echo debian:debian | chpasswd \
 && mkdir -p /root/.ssh /home/debian/.ssh && echo "ssh-ed25519 AAAA test" | tee /root/.ssh/authorized_keys > /home/debian/.ssh/authorized_keys
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKER
src=()
env=(-e RELAY_CLIENT_PINS="$edgepin")
if [ -n "${LOCAL:-}" ]; then src=(-v "$root:/src:ro"); env+=(-e RELAY_SRC=/src); fi
# Shared mounts as on a real host, where systemd sets them itself; Docker's are
# private, which hides LoadCredential's mount from the service.
# The default bridge, not a user network: Docker's embedded DNS lives in the
# container's own nftables rules, which install.sh's `flush ruleset` replaces.
docker run -d --name "$name" --privileged --cgroupns=private \
  --platform linux/arm64 --memory 1g \
  -v "$work:/work" -v "$host:/host:ro" ${src[@]+"${src[@]}"} "$image" \
  bash -c 'mount --make-rshared / && exec /sbin/init' >/dev/null
vm() { docker exec "${env[@]}" "$name" "$@"; }
for _ in $(seq 50); do vm systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 0.2; done

ip=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$name")
vm bash /host/install.sh > "$work/install.out" 2>&1 || { cat "$work/install.out"; fail "install.sh"; }
pin=$(sed -n 's/^fount-relay: server pin \([0-9a-f]\{64\}\) .*/\1/p' "$work/install.out")
sum=$(sed -n 's/^fount-relay: built .*, sha256 \([0-9a-f]\{64\}\)$/\1/p' "$work/install.out")
[ -n "$pin" ] && [ -n "$sum" ] || { cat "$work/install.out"; fail "install.sh printed no pin or hash"; }
echo "ok   install.sh ran; server pin $pin"

if [ -z "${LOCAL:-}" ]; then
  commit=$(sed -n 's/^EDGE_COMMIT=\${EDGE_COMMIT:-\([0-9a-f]\{40\}\)}$/\1/p' "$host/install.sh")
  gover=$(sed -n 's/^GO_VERSION=\${GO_VERSION:-\(.*\)}$/\1/p' "$host/install.sh")
  mkdir "$work/src"
  git -C "$root" archive "$commit" | tar -x -C "$work/src"
  (cd "$work/src" && GOTOOLCHAIN="go$gover" GOFLAGS=-mod=vendor CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$work/local-relay" ./gateway/relay)
  localsum=$(shasum -a 256 "$work/local-relay" | cut -d' ' -f1)
  [ "$localsum" = "$sum" ] || fail "host build $sum differs from a local build of $commit ($localsum)"
  echo "ok   the host's binary matches a local build of $commit ($sum)"
fi

[ "$(vm systemctl is-active fount-relay)" = active ] || { vm journalctl -u fount-relay --no-pager -n 20 || true; fail "fount-relay not active"; }
vm systemd-analyze verify /etc/systemd/system/fount-relay.service
echo "ok   fount-relay.service active and verifies"

# The client checks the relay against its certificate, so give it only that.
vm openssl x509 -in /etc/fount-relay/server.pem -out /work/client/server.pem
vm /work/relayclient check 127.0.0.1:443 /work/client

[ "$(vm stat -c '%a %U' /etc/fount-relay/server.pem)" = "600 root" ] || fail "server.pem isn't root-only"
docker run --rm --platform linux/arm64 -v "$host:/host:ro" "$image" \
  bash -c "bash /host/check-pin.sh $ip:443 $pin" || fail "check-pin.sh"
vm systemd-run -q --unit probe-listener systemd-socket-activate -l 9999 cat
vm timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9999' || fail "the probe listener isn't up"
if docker run --rm --platform linux/arm64 "$image" timeout 3 bash -c 'exec 3<>/dev/tcp/'"$ip"'/9999' 2>/dev/null; then
  fail "the firewall let port 9999 in"
fi
echo "ok   the firewall drops a port other than the relay's"

vm bash -c '! dpkg -s openssh-server >/dev/null 2>&1' || fail "openssh-server still installed"
vm bash -c '! ls /root/.ssh/authorized_keys /home/debian/.ssh/authorized_keys 2>/dev/null' || fail "authorized_keys left"
vm passwd -S root | grep -q ' L ' || fail "root password not locked"
vm passwd -S debian | grep -q ' L ' || fail "user password not locked"
[ "$(vm systemctl is-enabled serial-getty@ttyS0.service 2>/dev/null || true)" = masked ] || fail "serial console not masked"
vm grep -q Storage=volatile /etc/systemd/journald.conf.d/fount.conf || fail "journald not volatile"
vm test ! -e /var/log/journal || fail "/var/log/journal exists"
echo "ok   no SSH server, keys, passwords or consoles; journald in memory"

vm bash /host/install.sh > "$work/install2.out" 2>&1 || { cat "$work/install2.out"; fail "rerun"; }
grep -q "server pin $pin " "$work/install2.out" || fail "a rerun changed the key"
echo "ok   a rerun keeps the key"

out=$(vm journalctl -q _SYSTEMD_UNIT=fount-relay.service -o cat)
[ -z "$out" ] || fail "the relay wrote: $out"
echo "ok   the relay wrote nothing"
