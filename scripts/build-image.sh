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
# These gave an identical digest twice on one machine; CI checks a second.
set -euo pipefail

OUT="${1:?usage: build-image.sh <output-dir>}"
PLATFORM="${PLATFORM:-linux/amd64}"

export SOURCE_DATE_EPOCH=0

# Requires the docker-container buildx driver (not the default docker driver),
# which is what gives reproducible OCI output.
if ! docker buildx inspect fount-repro >/dev/null 2>&1; then
  docker buildx create --name fount-repro --driver docker-container >/dev/null
fi

docker buildx build \
  --builder fount-repro \
  --platform "$PLATFORM" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=$OUT,tar=false,rewrite-timestamp=true" \
  .

echo "Built OCI image to $OUT"
if command -v jq >/dev/null 2>&1; then
  echo "index digest: $(jq -r '.manifests[0].digest' "$OUT/index.json")"
fi
