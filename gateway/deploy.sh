#!/bin/bash
# Deploys or updates one gateway stack in fount-mail-prod.
#
#   gateway/deploy.sh a v0.1.0     # tunnels to edge release v0.1.0
#   gateway/deploy.sh b v0.0.0     # parked: no release matches, so no tunnel and no ACME
set -euo pipefail
[[ $# -eq 2 && $1 =~ ^[ab]$ && $2 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 a|b vX.Y.Z" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
zone=us-east-1a; [ "$1" = b ] && zone=us-east-1b
# `cloudformation deploy` keeps a stack's previous value for any parameter not
# passed, so a changed Default would never reach a running stack. The relay's
# settings are passed from template.yml every time, so the committed pin is the
# one deployed.
param() { awk -v k="  $1:" '$0 ~ "^"k {f=1} f && /Default:/ {sub(/ #.*/, ""); gsub(/"/, ""); print $2; exit}' "$here/template.yml"; }
aws cloudformation deploy \
  --template-file "$here/template.yml" \
  --stack-name "fount-mail-gateway-$1" \
  --capabilities CAPABILITY_IAM \
  --profile "${AWS_PROFILE:-fount-mail-prod}" --region us-east-1 \
  --no-fail-on-empty-changeset \
  --parameter-overrides Zone="$zone" EdgeReleaseTag="$2" ClientCertSecret="fount-mail/gateway-$1-client" \
    RelayClientPins="$(param RelayClientPins)" RelayPort="$(param RelayPort)" \
    GoVersion="$(param GoVersion)" GoSha256="$(param GoSha256)"
aws cloudformation describe-stacks --stack-name "fount-mail-gateway-$1" \
  --profile "${AWS_PROFILE:-fount-mail-prod}" --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`PublicIp`].OutputValue' --output text
