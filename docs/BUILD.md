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

Pin the dockerfile frontend and the golang base **by digest** in the `Dockerfile`
before the first release, and keep the Go version equal to `go.mod`.

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

## Release (two-phase, matches the proven workflow)

1. **Tag** via the GitHub *Tinfoil Release* workflow. It pushes the tag and
   dispatches the publish workflow against it.
2. **Measure & publish**: `tinfoil-release-publish.yml` runs
   `measure-image-action`, which builds, measures, attests (keyless), and creates
   the GitHub release. CI's `reproducible-build` matrix builds on two runners and
   fails if the digests differ.
3. **Pin the digest** into both containers in `tinfoil-config.yml` (the forwarder
   runs the same image as the edge) and run Tinfoil's measured-release
   workflows.
4. **Nothing to approve.** A vault hands the keyset to any release of this repo at
   or above its `EDGE_MIN_TAG`, as soon as it's published. Publication is the
   control: it's public, and `fount-infra`'s `MailWatchStack` emails on every release of
   this repo and the vault's. To retire an old release, raise
   `EDGE_MIN_TAG` in a vault release.

## Verify

```sh
scripts/verify-release.sh vX.Y.Z
```

Rebuilds at the tag, compares to the pinned digest, and checks the live
attestation. Run it for every release. A scheduled job that runs it from a separate
account isn't built yet.

## Accounts

The repo is public. A ruleset makes `v*` tags creatable only by org admins and
permanent once pushed. A release of this repo can get the keyset from the vaults, so
the accounts that can make one need hardware keys: the vault's `docs/KEYS.md` lists
them (GitHub, the email behind it, DNS, AWS, Tinfoil).
