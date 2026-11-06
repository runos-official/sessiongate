#!/usr/bin/env bash
# release-facts.sh: read-only fact printers for the Foreman release pipelines
# (.foreman/pipelines/release-rc.yml and release.yml) and the evidence step.
# Source foreman-observe.sh first (it defines fm_fact and fm_summary).
# Every lookup is guarded: a failed lookup prints "unavailable" and never fails
# the caller. Nothing here changes GitHub, the registry or the repo, and
# nothing prints a secret. Only the first block below differs between repos.

# shellcheck disable=SC2034  # the variables are read by the scripts that source this file
RELEASE_WORKFLOW="release.yml"
RELEASE_IMAGE="ghcr.io/runos-official/sessiongate"
RELEASE_PLATFORMS="linux/amd64 linux/arm64"

# The image tag is the git tag without its leading v.
fm_release_image_tag() { printf '%s' "${1#v}"; }

# fm_release_run_id <tag>: the id of the push run that the tag started, or empty.
fm_release_run_id() {
  gh run list --workflow="$RELEASE_WORKFLOW" --limit 20 \
    --json databaseId,headBranch,event \
    -q "[.[] | select(.headBranch==\"$1\" and .event==\"push\")][0].databaseId // empty" 2>/dev/null || true
}

# fm_release_run_facts <run_id>: where the run is, who built it, how it ended.
fm_release_run_facts() {
  local id="$1" json
  json="$(gh run view "$id" --json url,status,conclusion,headSha,attempt,workflowName,createdAt,updatedAt,jobs 2>/dev/null)" || json=""
  if [ -z "$json" ]; then fm_fact run_id "$id"; fm_fact workflow_run_url unavailable; return 0; fi
  fm_fact run_id "$id"
  fm_fact workflow_run_url "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')"
  fm_fact workflow_status "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
  fm_fact conclusion "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["conclusion"] or "none")')"
  fm_fact run_attempt "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["attempt"])')"
  fm_fact run_commit "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["headSha"][:12])')"
  fm_fact jobs "$(printf '%s' "$json" | python3 -c '
import json, sys
jobs = json.load(sys.stdin)["jobs"]
print(", ".join("%s=%s" % (j["name"], j["conclusion"] or j["status"]) for j in jobs)[:190])')"
}

# fm_release_image_facts <tag>: the published image, its digest, its platforms.
# Sets RELEASE_DIGEST for the caller. A multi-arch index also lists attestation
# manifests as unknown/unknown; those are not platforms.
fm_release_image_facts() {
  local ref json plats
  ref="$RELEASE_IMAGE:$(fm_release_image_tag "$1")"
  RELEASE_DIGEST="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null)" || RELEASE_DIGEST=""
  json="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' 2>/dev/null)" || json=""
  plats="$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
out = []
for m in d.get("manifests", []):
    p = m.get("platform") or {}
    if p.get("os") and p.get("os") != "unknown":
        out.append("%s/%s" % (p["os"], p["architecture"]))
print(" ".join(out))' 2>/dev/null)" || plats=""
  RELEASE_PLATFORMS_FOUND="$plats"
  fm_fact image "$ref"
  fm_fact digest "${RELEASE_DIGEST:-unavailable}"
  fm_fact platforms "${plats:-unavailable}"
}

# fm_release_attestation_facts <tag>: verify the build-provenance attestation of
# the image and print who signed it and which commit it names. Sets
# RELEASE_SIGNER and RELEASE_ATTESTED_COMMIT. Returns 1 when it cannot verify.
fm_release_attestation_facts() {
  local ref nwo json out
  ref="oci://$RELEASE_IMAGE:$(fm_release_image_tag "$1")"
  nwo="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" || nwo=""
  RELEASE_SIGNER=""; RELEASE_ATTESTED_COMMIT=""
  json="$(gh attestation verify "$ref" --repo "$nwo" --format json 2>/dev/null)" || json=""
  out="$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    c = json.load(sys.stdin)[0]["verificationResult"]["signature"]["certificate"]
except Exception:
    sys.exit(0)
print(c.get("subjectAlternativeName", ""))
print(c.get("sourceRepositoryDigest", ""))' 2>/dev/null)" || out=""
  RELEASE_SIGNER="$(printf '%s\n' "$out" | sed -n 1p)"
  RELEASE_ATTESTED_COMMIT="$(printf '%s\n' "$out" | sed -n 2p)"
  if [ -z "$RELEASE_SIGNER" ]; then fm_fact attestation unavailable; return 1; fi
  fm_fact attestation_signer "$RELEASE_SIGNER"
  fm_fact attested_commit "${RELEASE_ATTESTED_COMMIT:0:12}"
  fm_fact attestation verified
}

# fm_release_page_facts <tag>: the GitHub release page.
fm_release_page_facts() {
  local json
  json="$(gh release view "$1" --json url,isDraft,isPrerelease 2>/dev/null)" || json=""
  if [ -z "$json" ]; then fm_fact release_url unavailable; return 0; fi
  fm_fact release_url "$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')"
  fm_fact release_draft "$(printf '%s' "$json" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["isDraft"]).lower())')"
  fm_fact release_prerelease "$(printf '%s' "$json" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["isPrerelease"]).lower())')"
}
