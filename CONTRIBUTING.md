# Contributing

This repository is public so that Fount Fleet's mail edge can be independently
rebuilt and verified. Two rules follow from that:

1. **No secrets, ever.** Not in code, config, history, or tests. Secret *values*
   live in a separate AWS account and reach the enclave only via the keyserver
   after attestation. `tinfoil-config.yml` carries secret *names* only.
2. **Keep the build reproducible.** Prefer the standard library; pin any new
   dependency and base image by digest; don't introduce non-determinism into the
   image (timestamps, build IDs, embedded paths). CI builds on two runners and
   fails if the image digests differ.

Before opening a PR: `go vet ./... && go build ./... && go test ./...`.

Security issues: do not open a public issue — follow the disclosure process in
Fount's `/security`.
