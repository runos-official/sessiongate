#!/usr/bin/env bash
# Evidence for a release run. Read-only and always exits 0: it prints data and no
# verdict, so the agent that watches the run decides. It runs after a failure too.
#
# Prints: the tag and the commit it names, the workflow run with every job and
# step conclusion, the failed log tail when a job failed, the GitHub release
# page, the image digest and platforms, and the attestation summary.
#
# Usage: scripts/deploy/release-evidence.sh <vX.Y.Z[-rc.N]> [evidence-file]
set -uo pipefail

TAG="${1:-}"
FILE="${2:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag> [evidence-file]" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=release-facts.sh
source "$HERE/release-facts.sh"

collect() (
  set +e
  echo "== tag"
  git rev-parse "$TAG^{commit}" 2>&1
  echo "== record branch on origin"
  git ls-remote origin refs/heads/deployed 2>&1
  run_id="$(fm_release_run_id "$TAG")"
  echo "== workflow run ($RELEASE_WORKFLOW)"
  if [ -n "$run_id" ]; then
    gh run view "$run_id" 2>&1
    echo "== jobs and steps"
    gh run view "$run_id" --json jobs -q '.jobs[] | "\(.name): \(.conclusion // .status)", (.steps[] | "  \(.number) \(.name): \(.conclusion // .status)")' 2>&1
    if [ "$(gh run view "$run_id" --json conclusion -q .conclusion 2>/dev/null)" != "success" ]; then
      echo "== failed log (last 60 lines)"
      gh run view "$run_id" --log-failed 2>&1 | tail -n 60
    fi
    fm_release_run_facts "$run_id"
  else
    echo "no run found for $TAG"
    fm_fact run_id none
  fi
  echo "== release page"
  gh release view "$TAG" 2>&1 | head -n 30
  fm_release_page_facts "$TAG"
  echo "== image"
  fm_release_image_facts "$TAG"
  echo "== attestation"
  fm_release_attestation_facts "$TAG"
  if [ -n "$FILE" ]; then fm_fact evidence "$FILE"; else fm_fact evidence output; fi
  fm_summary "collected release evidence for $TAG"
)

if [ -n "$FILE" ]; then collect | tee "$FILE"; else collect; fi
exit 0
