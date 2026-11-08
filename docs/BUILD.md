# Build & release

The edge's attestation proves it matches a release that pins an image digest. It
does **not** prove what source built that image — so the build must be public and
reproducible, and a release is only approved once an outside rebuild matches
(design §17).

## Reproducible build

```sh
scripts/build-image.sh /tmp/edge.oci
```

Requires the `docker-container` buildx driver (the script creates a `fount-repro`
builder). Determinism levers, which must match across machines:

- `go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" CGO_ENABLED=0`
- `FROM scratch` final image (binary + CA roots only)
- `SOURCE_DATE_EPOCH=0`, `--provenance=false`, `--sbom=false`, fixed `--platform`,
  `--output type=oci,...,rewrite-timestamp=true`

The Dockerfile frontend and the golang base are pinned by digest in the `Dockerfile`, and
BuildKit by digest in `scripts/build-image.sh`. Keep the Go version equal to `go.mod`, and
bump any of them on purpose. CI builds on an x86 and an Arm runner and fails if the digests
differ.

## New deployment

Only the vault and the edge hold `ROUTING_DATA_KEY` and `ADDRESS_MAC_KEY`, so the edge
changes routing data itself, on requests from `cmd/edgectl` signed with the operator
key. `OPERATOR_KEY` in `tinfoil-config.yml` is its public half, the same key the vault
checks S3 imports against.

The first edge boots, pulls its keys, finds no routing object, and waits. It doesn't
exit, and `/operator/status` reports `no-routing-object`. A missing object is never
treated as a new deployment, so run this once:

```sh
go run ./cmd/edgectl init -edge <edge host> -operator-key operator.key
```

The edge then finishes booting. `init` never replaces an object. To put a lost object
back, follow `docs/RESTORE.md`.

`abuse@` and `postmaster@` must exist before real mail, and the Device API refuses
those names. Add each one with the public keys of the device that reads it:

```sh
go run ./cmd/edgectl provision -edge <edge host> -operator-key operator.key -role abuse -keys abuse.keys.json
```

The running edge adds it at once.

## Release

1. **Build** with the *Build Image* workflow, run from `main` with the version. It runs
   `scripts/build-image.sh`, pushes that exact image to GHCR with `crane`, and fails if
   the pushed digest differs from the build's.
2. **Pin the digest** it reports into both containers in `tinfoil-config.yml` (the
   forwarder runs the same image as the edge), and commit to `main`.
3. **Tag**: `git tag vX.Y.Z && git push origin vX.Y.Z`. Only org admins can create `v*`
   tags, and nothing in the workflows can. The push runs *Tinfoil Release*, which checks
   the tag is on `main` and the config has no placeholders, then measures, attests,
   publishes the GitHub release, and marks it latest so its witness renews.
4. **The tag push is the approval.** A vault hands the keyset to any release of this repo at
   or above its `EDGE_MIN_TAG`, as soon as it's published. Publication is the control,
   because it's public. Fount's watcher will email on every release of this repo and the
   vault's, once it's deployed, which it isn't yet. To retire an old release, raise
   `EDGE_MIN_TAG` in a vault release.

## Verify

```sh
scripts/verify-release.sh vX.Y.Z
```

Rebuilds at the tag, compares with every digest pinned in the config, and checks the live
attestation against that tag. It needs Docker, `jq`, and the Tinfoil CLI, and fails if any
check can't run. Set `ENCLAVE` to check a host other than the live edge. Run it for every
release. A scheduled job that runs it from a separate account isn't built yet.

## Accounts

The repo is public. A ruleset makes `v*` tags creatable only by org admins. Org admins can
also bypass it to move or delete one. A release of this repo can get the keyset from the vaults, so
the accounts that can make one need hardware keys: the vault's `docs/KEYS.md` lists
them (GitHub, the email behind it, DNS, AWS, Tinfoil).
