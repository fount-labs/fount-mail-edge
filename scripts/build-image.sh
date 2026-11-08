#!/usr/bin/env bash
# Deterministic image build (design §17). Produces a bit-for-bit reproducible
# OCI image so an outside party can rebuild a release and match its digest.
#
# Usage: scripts/build-image.sh <output-dir>
#   e.g. scripts/build-image.sh /tmp/edge.oci
#
# The determinism levers:
#   SOURCE_DATE_EPOCH=0         fixed timestamps
#   --provenance=false          no provenance attestation baked into the image
#   --sbom=false                no SBOM baked in
#   --platform linux/amd64      one fixed platform
#   rewrite-timestamp=true      normalise layer timestamps
#   BUILDKIT                    one BuildKit release, by digest
# CI builds on an x86 and an Arm runner and requires the same digest.
set -euo pipefail

OUT="${1:?usage: build-image.sh <output-dir>}"
PLATFORM="${PLATFORM:-linux/amd64}"

export SOURCE_DATE_EPOCH=0

# Requires the docker-container buildx driver (not the default docker driver),
# which is what gives reproducible OCI output. BuildKit itself is pinned by digest,
# and the builder is named after it, so a bump never reuses an older builder.
# Bump it on purpose, and check the release digest still rebuilds.
BUILDKIT="moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"
BUILDER="fount-repro-buildkit-v0.34.2"
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT" >/dev/null
fi

docker buildx build \
  --builder "$BUILDER" \
  --platform "$PLATFORM" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=$OUT,tar=false,rewrite-timestamp=true" \
  .

echo "Built OCI image to $OUT"
if command -v jq >/dev/null 2>&1; then
  echo "index digest: $(jq -r '.manifests[0].digest' "$OUT/index.json")"
fi
