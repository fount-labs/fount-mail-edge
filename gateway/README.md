# Mail gateway

Tinfoil has no public port 25, so a small VM accepts port 25 (and ACME HTTP-01
on port 80) and pipes both through an attested `tinfoil forward` tunnel to the
edge enclave (design §7). The gateway filters connections only — it never sees
mail content or addresses, because TLS 1.3 terminates inside the enclave.

`template.yml` is a CloudFormation stack for one gateway (adapted from the proven
port-25 probe). Deploy **two**, in separate AZs, each with its own MX record.

## Deploy

```sh
aws cloudformation deploy \
  --template-file gateway/template.yml \
  --stack-name fount-mail-gateway-a \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
      EnclaveHost=mail-edge.fount.sh \
      EnclaveRepo=fount-labs/fount-mail-edge
```

Start the **enclave first** — a gateway that resolves the host before it exists
can cache "no such host" for up to 30 minutes.

## Security layers (design §7)

| Layer | Stops |
|---|---|
| Attested tunnel | Reaching an unverified edge |
| Tunnel key (`shim.authenticated`) | Outsiders using up the 128 tunnel slots |
| Mutual TLS on the tunnelled ports | Fake sender IPs, bypassing limits |
| Connection limits (per-IP, total < 128, timeouts < 5m) | Floods |
| Edge checks (unknown recipients, size, quotas) | Most spam |

## Untested / before production

- **`shim.authenticated`** (undocumented): a keyless CONNECT should get `401`
  before it counts against the tunnel cap. Test with real senders; it needs a
  `tk_` key delivered to the VM at boot.
- **Mutual TLS** on the SMTP and device-api tunnel ports (the table's row).
- **Pin + verify** the `tinfoil-cli` tarball sha256 in user-data.
- Confirm the gateway doesn't follow a new release during the 24h release wait
  (pin with `--tag` if it does).
- DNS for the mail domain: strict SPF, DMARC `p=reject`, TLS-RPT, strict
  MTA-STS, CAA (pinning the ACME account via `accounturi`), low-TTL MX.
