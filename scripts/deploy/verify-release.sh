#!/usr/bin/env bash
# Verify what the release workflow published for a tag: the GitHub release page,
# the image in the registry (digest and platforms), and the build-provenance
# attestation, bound to THIS repo's release workflow at THIS tag and to the
# commit the tag names. Read-only. Fails on any mismatch.
#
# Usage: scripts/deploy/verify-release.sh <vX.Y.Z[-rc.N]>
set -euo pipefail

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=release-facts.sh
source "$HERE/release-facts.sh"

fail() { printf 'ERROR: %s\n' "$*" >&2; fm_summary "release $TAG failed verification: $*"; exit 1; }

nwo="$(gh repo view --json nameWithOwner -q .nameWithOwner)" || fail "cannot read the repo name with gh"
tag_commit="$(git rev-parse "$TAG^{commit}" 2>/dev/null)" || fail "tag $TAG is not in this checkout"

# --- the release page ---------------------------------------------------------
fm_release_page_facts "$TAG"
page="$(gh release view "$TAG" --json isDraft,isPrerelease 2>/dev/null)" || fail "no GitHub release page for $TAG"
draft="$(printf '%s' "$page" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["isDraft"]).lower())')"
pre="$(printf '%s' "$page" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["isPrerelease"]).lower())')"
[ "$draft" = "false" ] || fail "the release page of $TAG is still a draft"
case "$TAG" in
  *-*) want_pre=true ;;
  *)   want_pre=false ;;
esac
[ "$pre" = "$want_pre" ] || fail "the release page of $TAG has prerelease=$pre, expected $want_pre"

# --- the image ----------------------------------------------------------------
fm_release_image_facts "$TAG"
[ -n "${RELEASE_DIGEST:-}" ] || fail "$RELEASE_IMAGE:$(fm_release_image_tag "$TAG") is not in the registry"
for p in $RELEASE_PLATFORMS; do
  case " $RELEASE_PLATFORMS_FOUND " in
    *" $p "*) ;;
    *) fail "the image lacks platform $p (found: ${RELEASE_PLATFORMS_FOUND:-none})" ;;
  esac
done

# --- the attestation ----------------------------------------------------------
fm_release_attestation_facts "$TAG" || fail "cannot verify the build-provenance attestation of the image"
expected="https://github.com/$nwo/.github/workflows/$RELEASE_WORKFLOW@refs/tags/$TAG"
[ "$RELEASE_SIGNER" = "$expected" ] || fail "attestation signer mismatch: expected $expected, got $RELEASE_SIGNER"
[ "$RELEASE_ATTESTED_COMMIT" = "$tag_commit" ] || fail "the attestation names commit ${RELEASE_ATTESTED_COMMIT:0:12}, but $TAG is commit ${tag_commit:0:12}"

fm_summary "$TAG published: image $RELEASE_DIGEST on $RELEASE_PLATFORMS_FOUND, attestation bound to $RELEASE_WORKFLOW at the tag and to commit ${tag_commit:0:12}"
