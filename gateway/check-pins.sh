#!/bin/bash
# Checks each gateway's client certificate against GATEWAY_CLIENT_PINS in
# tinfoil-config.yml. The secret goes straight into openssl, which prints only
# the public key, so the private key is never shown or written to disk.
#
#   gateway/check-pins.sh            # profile fount-mail-prod, gateways a and b
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
profile=${AWS_PROFILE:-fount-mail-prod}
pins=$(sed -n 's/.*GATEWAY_CLIENT_PINS: "\([^"]*\)".*/\1/p' "$here/../tinfoil-config.yml")
status=0
for g in a b; do
  pin=$(aws --profile "$profile" --region us-east-1 secretsmanager get-secret-value \
      --secret-id "fount-mail/gateway-$g-client" --query SecretString --output text \
    | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -r | cut -d' ' -f1)
  if [[ ",$pins," == *",$pin,"* ]]; then
    echo "ok   gateway-$g $pin"
  else
    echo "FAIL gateway-$g $pin is not in GATEWAY_CLIENT_PINS" >&2
    status=1
  fi
done
exit $status
