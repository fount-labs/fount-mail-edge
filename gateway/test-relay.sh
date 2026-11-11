#!/bin/bash
# Renders template.yml's user data with RelayClientPins set, then, on the pinned
# AL2023 release in Docker with t4g.micro's 1 GiB:
#   - runs its relay build script on this checkout (pinned Go, sha256-checked),
#   - checks its fount-relay unit with systemd-analyze,
#   - runs the unit's ExecStart and drives it with the edge's own relay client
#     (internal/send.Relay) over the real network: DoH and MTA-STS through, port
#     25 allowed, and loopback, private, metadata and other hosts refused,
#   - and checks the relay wrote nothing.
# Needs Docker and network access.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
param() { awk -v k="  $1:" '$0 ~ "^"k {f=1} f && /Default:/ {sub(/ #.*/, ""); gsub(/"/, ""); print $2; exit}' "$here/template.yml"; }
release=$(param DnfRelease)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/creds"

(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor -o "$work/relayclient" ./gateway/testdata/relayclient)
pin=$(cd "$here/.." && go run -mod=vendor ./gateway/testdata/relayclient setup "$work/creds")

# Fn::Sub by hand: parameters, pseudo-parameters, and ${!x} back to ${x}.
awk '/Fn::Base64: !Sub \|/ {f=1; next} f && /^  [A-Za-z]/ {f=0} f' "$here/template.yml" | sed 's/^            //' > "$work/userdata.tmpl"
subs=(
  "AWS::Region=us-east-1" "EnclaveHost=$(param EnclaveHost)" "EnclaveRepo=$(param EnclaveRepo)"
  "EdgeReleaseTag=v9.9.9" "ClientCertSecret=test" "TunnelKeySecret=" "DnfRelease=$release"
  "HaproxyPackage=$(param HaproxyPackage)" "TinfoilCliVersion=$(param TinfoilCliVersion)"
  "TinfoilCliSha256=$(param TinfoilCliSha256)" "RelayClientPins=$pin" "RelayPort=$(param RelayPort)"
  "GoVersion=$(param GoVersion)" "GoSha256=$(param GoSha256)"
)
cp "$work/userdata.tmpl" "$work/userdata.sh"
for s in "${subs[@]}"; do
  k=${s%%=*} v=${s#*=}
  K=$k V=$v perl -0pi -e 's/\$\{\Q$ENV{K}\E\}/$ENV{V}/g' "$work/userdata.sh"
done
perl -pi -e 's/\$\{!/\$\{/g' "$work/userdata.sh"
if left=$(perl -ne 'print "$1\n" while /\$\{([A-Za-z]+::?[A-Za-z]*|[A-Z][A-Za-z]+)\}/g' "$work/userdata.tmpl" | sort -u | grep -vxF -f <(printf '%s\n' "${subs[@]%%=*}" V)); then
  echo "FAIL: user data names parameters this test doesn't set: $left" >&2
  exit 1
fi
bash -n "$work/userdata.sh"
echo "ok   user data renders and parses ($(( $(wc -c < "$work/userdata.sh") )) bytes; EC2 allows 16384)"
[ "$(wc -c < "$work/userdata.sh")" -lt 16384 ] || { echo "FAIL: user data too large" >&2; exit 1; }

awk "/<<'RELAYBUILD'/ {f=1; next} /^RELAYBUILD\$/ {f=0} f" "$work/userdata.sh" > "$work/fount-relay-build"
awk "/fount-relay.service <<'UNIT'/ {f=1; next} /^UNIT\$/ {f=0} f" "$work/userdata.sh" > "$work/fount-relay.service"
[ -s "$work/fount-relay-build" ] && [ -s "$work/fount-relay.service" ] || { echo "FAIL: no relay build or unit in user data" >&2; exit 1; }

cat > "$work/run.sh" <<'SH'
set -euo pipefail
dnf install -q -y --releasever="$RELEASE" systemd tar gzip >/dev/null
bash /work/fount-relay-build /src
echo "ok   built gateway/relay with the template's build script"
cp /work/fount-relay.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/fount-relay.service
echo "ok   systemd-analyze verify fount-relay.service"
cmd=$(sed -n 's/^ExecStart=//p' /work/fount-relay.service)
CREDENTIALS_DIRECTORY=/work/creds $cmd >/work/relay.out 2>&1 &
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/443) 2>/dev/null && break; sleep 0.1; done
/work/relayclient check 127.0.0.1:443 /work/creds
if [ -s /work/relay.out ]; then echo "FAIL: the relay wrote:"; cat /work/relay.out; exit 1; fi
echo "ok   the relay wrote nothing"
SH

docker run --rm --platform linux/arm64 --memory 1g -v "$work:/work" -v "$here/..:/src:ro" -e RELEASE="$release" \
  "amazonlinux:$release.0" bash /work/run.sh
