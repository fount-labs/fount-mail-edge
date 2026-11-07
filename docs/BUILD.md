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

The edge refuses to boot without its routing object, so a lost object can't be
mistaken for a new deployment. Before the first release, run `cmd/routing-init`
once with `ROUTING_DATA_KEY` and S3 credentials. It never replaces an object that
exists. To put a lost object back, follow `docs/RESTORE.md`.

**Open (2026-11-07):** `routing-init`, `routing-provision`, and `routing-restore`
read the routing and MAC keys on an operator's machine. With the keys held only in
the vault and the edge, no operator has them, so these need to move into the edge.

`abuse@` and `postmaster@` must exist before real mail, and the Device API refuses
those names. Run `cmd/routing-provision` once for each, with the public keys of the
device that reads them.

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
   control: it's public, and an alert fires on it. To retire an old release, raise
   `EDGE_MIN_TAG` in a vault release.

## Verify

```sh
scripts/verify-release.sh vX.Y.Z
```

Rebuilds at the tag, compares to the pinned digest, and checks the live
attestation. A scheduled job in a separate account runs this per release and
alerts on a mismatch.

## Accounts

Protect tags and the default branch; require hardware keys on GitHub, AWS,
Tinfoil, and DNS.
