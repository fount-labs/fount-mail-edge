#!/usr/bin/env bash
# verify-release.sh vX.Y.Z (design §17)
#
# Rebuilds the edge at a release tag and compares the result against what is
# actually deployed, so an outside party can confirm the running enclave matches
# public source:
#
#   1. Rebuild the image at the tag and record its digest.
#   2. Compare that digest to every image pinned in tinfoil-config.yml at the tag.
#   3. Check the live enclave's attestation against the release at that tag, with
#      the Tinfoil CLI.
#
# It prints OK only when all three pass. Any step that fails, or can't run, exits
# non-zero.
#
#   ENCLAVE  the host to check (default edge.fount.containers.tinfoil.dev)
#   REPO     the release repo (default fount-labs/fount-mail-edge)
set -euo pipefail

VERSION="${1:?usage: verify-release.sh vX.Y.Z}"
REPO="${REPO:-fount-labs/fount-mail-edge}"
ENCLAVE="${ENCLAVE:-edge.fount.containers.tinfoil.dev}"

for tool in git docker jq tinfoil; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "::error::$tool isn't installed, so $VERSION can't be verified"
    exit 1
  }
done

TOP="$(git rev-parse --show-toplevel)"
WORKDIR="$(mktemp -d)"
cleanup() {
  git -C "$TOP" worktree remove --force "$WORKDIR/src" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== Verifying release $VERSION of $REPO on $ENCLAVE =="

git -C "$TOP" worktree add --detach "$WORKDIR/src" "refs/tags/$VERSION" >/dev/null
cd "$WORKDIR/src"

echo "-- Step 1/3: deterministic rebuild"
./scripts/build-image.sh "$WORKDIR/out.oci"
REBUILT=$(jq -r '.manifests[0].digest' "$WORKDIR/out.oci/index.json")
echo "rebuilt digest:  $REBUILT"

echo "-- Step 2/3: digests pinned in tinfoil-config.yml"
PINNED=$(grep -oE '@sha256:[0-9a-f]{64}' tinfoil-config.yml | cut -c2- | sort -u)
echo "pinned digests:  ${PINNED:-<none>}"
if [ -z "$PINNED" ] || [ "$PINNED" != "$REBUILT" ]; then
  echo "::error::the images pinned at $VERSION aren't all the rebuilt $REBUILT"
  exit 1
fi

echo "-- Step 3/3: live attestation"
if ! REPORT=$(tinfoil attestation verify -e "$ENCLAVE" -r "$REPO@$VERSION" -j); then
  echo "::error::$ENCLAVE did not verify as $REPO@$VERSION"
  exit 1
fi
STATUS=$(jq -r '.status' <<<"$REPORT")
if [ "$STATUS" != "ok" ]; then
  echo "::error::$ENCLAVE attestation status is $STATUS"
  exit 1
fi
echo "attested:        $(jq -r '.repo' <<<"$REPORT"), witness until $(jq -r '.freshness_expires_at' <<<"$REPORT")"

echo "OK: $VERSION rebuilds to the pinned digest, and $ENCLAVE runs it."
