#!/usr/bin/env bash
# verify-release.sh vX.Y.Z (design §17)
#
# Rebuilds the edge at a release tag and compares the result against what is
# actually deployed, so an outside party — or a scheduled job in a separate
# account — can confirm the running enclave matches public source:
#
#   1. Rebuild the image at the tag and record its digest.
#   2. Compare that digest to the one pinned in tinfoil-config.yml at the tag.
#   3. Compare the live attestation (via the Tinfoil CLI) to the same config.
#
# A mismatch on any step is a release-integrity failure and must alert.
set -euo pipefail

VERSION="${1:?usage: verify-release.sh vX.Y.Z}"
REPO="${REPO:-fount-labs/fount-mail-edge}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "== Verifying release $VERSION of $REPO =="

git -C "$(git rev-parse --show-toplevel)" worktree add --detach "$WORKDIR" "$VERSION"
pushd "$WORKDIR" >/dev/null

echo "-- Step 1/3: deterministic rebuild"
./scripts/build-image.sh "$WORKDIR/out.oci"
REBUILT=$(jq -r '.manifests[0].digest' "$WORKDIR/out.oci/index.json")
echo "rebuilt digest:  $REBUILT"

echo "-- Step 2/3: digest pinned in tinfoil-config.yml"
PINNED=$(grep -oE 'sha256:[0-9a-f]{64}' tinfoil-config.yml | head -1 || true)
echo "pinned digest:   ${PINNED:-<none>}"
if [ -z "$PINNED" ] || [ "sha256:${REBUILT#sha256:}" != "$PINNED" ]; then
  echo "::error::rebuilt image does not match the digest pinned at $VERSION"
  exit 1
fi

echo "-- Step 3/3: live attestation"
if command -v tinfoil >/dev/null 2>&1; then
  tinfoil attestation verify --repo "$REPO" || {
    echo "::error::live attestation did not verify against $REPO"
    exit 1
  }
else
  echo "tinfoil CLI not installed; skipping the live-attestation check"
fi

popd >/dev/null
git -C "$(git rev-parse --show-toplevel)" worktree remove "$WORKDIR" --force
echo "OK: $VERSION rebuilds to the pinned digest."
