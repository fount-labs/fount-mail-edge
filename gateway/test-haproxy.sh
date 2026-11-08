#!/bin/bash
# Runs the HAProxy config from template.yml, with the pinned AL2023 release and
# HAProxy package, against edgestub (the edge's real gatewaytls listener). Checks
# both SMTP hops carry the PROXY header inside mutual TLS, ACME reaches the
# challenge port, the per-IP rate limit holds, and nothing is logged.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
param() { awk -v k="  $1:" '$0 ~ "^"k {f=1} f && /Default:/ {gsub(/"/,""); print $2; exit}' "$here/template.yml"; }
release=$(param DnfRelease)
package=$(param HaproxyPackage)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$work/edgestub" ./gateway/testdata/edgestub)
awk "/<<'CFG'/ {f=1; next} /^ *CFG\$/ {f=0} f" "$here/template.yml" | sed 's/^            //' > "$work/haproxy.cfg"
if grep -Eq '^\s*(log|option +tcplog|option +httplog)\b' "$work/haproxy.cfg"; then
  echo "FAIL: the config logs connections" >&2
  exit 1
fi

cat > "$work/run.sh" <<'SH'
set -euo pipefail
dnf install -q -y --releasever="$RELEASE" "$PACKAGE" >/dev/null
haproxy -v | head -1
/work/edgestub /etc/haproxy/gateway-client.pem 2>/work/stub.log &
for _ in $(seq 50); do [ -s /etc/haproxy/gateway-client.pem ] && break; sleep 0.1; done
haproxy -c -f /work/haproxy.cfg
haproxy -D -f /work/haproxy.cfg
ip=$(awk -v h="$(cat /etc/hostname)" '$2 == h && $1 !~ /:/ {print $1; exit}' /etc/hosts)
# The backend opens after two /ready checks 5s apart.
sleep 12

smtp() { exec 3<>"/dev/tcp/$ip/25"; line=""; read -r -t 5 line <&3 2>/dev/null || true; exec 3<&-; printf '%s' "${line%$'\r'}"; }
got=$(smtp)
case "$got" in
  "220 PROXY TCP4 $ip $ip "*" 25") echo "ok   smtp: $got" ;;
  *) echo "FAIL smtp: got '$got'"; exit 1 ;;
esac

acme=$(curl -fsS "http://$ip/.well-known/acme-challenge/t")
[ "$acme" = "acme /.well-known/acme-challenge/t" ] || { echo "FAIL acme: '$acme'"; exit 1; }
echo "ok   acme: $acme"

refused=0
for _ in $(seq 35); do [ -n "$(smtp)" ] || refused=$((refused + 1)); done
[ "$refused" -ge 4 ] || { echo "FAIL rate limit: only $refused of 35 refused"; exit 1; }
echo "ok   rate limit: $refused of 35 refused after 30 a minute"
SH

docker run --rm --platform linux/arm64 -v "$work:/work" -e RELEASE="$release" -e PACKAGE="$package" \
  "amazonlinux:$release.0" bash /work/run.sh
