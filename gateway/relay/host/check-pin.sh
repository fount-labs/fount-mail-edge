#!/bin/bash
# Reads a relay's server pin over the network, for SEND_RELAY_PINS. The relay
# sends its certificate before it asks for the edge's, so no key is needed, and
# nothing secret is read. With an expected pin, it checks against it.
#
#   gateway/relay/host/check-pin.sh out.fountbox.com:443 [expected-pin]
set -euo pipefail
[[ $# -ge 1 && $1 == *:* ]] || { echo "usage: $0 host:port [expected-pin]" >&2; exit 2; }
# s_client fails once the relay refuses the missing client key; the certificate
# came before that.
pin=$({ openssl s_client -connect "$1" -tls1_3 </dev/null 2>/dev/null || true; } |
  openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER |
  openssl dgst -sha256 -r | cut -d' ' -f1)
[[ $pin =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL no certificate from $1" >&2; exit 1; }
if [ $# -ge 2 ] && [ "$pin" != "$2" ]; then
  echo "FAIL $1 $pin, expected $2" >&2
  exit 1
fi
echo "ok   $1 $pin"
