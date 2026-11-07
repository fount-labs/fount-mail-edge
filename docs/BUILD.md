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
once with the keyserver's `ROUTING_DATA_KEY` and S3 credentials. It never replaces
an object that exists.

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
4. **Wait 24 hours in public.** Only an exploitable security bug or mail being
   down skips this, and the release says why.
5. **Approve the tag in the keyserver** once an outside rebuild passes: add a
   `workloads:` entry (repo + tag + domain) to `fount-infra/keyserver/policy.yaml`
   under the hardware-key credential, then restart the keyserver.

## Verify

```sh
scripts/verify-release.sh vX.Y.Z
```

Rebuilds at the tag, compares to the pinned digest, and checks the live
attestation. A scheduled job in a separate account runs this per release and
alerts on a mismatch.

## Accounts

Protect tags and the default branch; require hardware keys on GitHub, AWS,
Tinfoil, and DNS; keep keyserver approval on a separate credential.
