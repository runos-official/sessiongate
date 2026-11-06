#!/usr/bin/env bash
# Watch the GitHub Actions release run that a pushed tag started, then report
# where it ran and how it ended. Read-only. Fails when the run does not succeed.
#
# Usage: scripts/deploy/watch-release.sh <vX.Y.Z[-rc.N]>
set -euo pipefail

TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=release-facts.sh
source "$HERE/release-facts.sh"

run_id=""; waited=0
while [ -z "$run_id" ] && [ "$waited" -lt 120 ]; do
  run_id="$(fm_release_run_id "$TAG")"
  [ -n "$run_id" ] && break
  sleep 10; waited=$((waited + 10))
done
if [ -z "$run_id" ]; then
  echo "no $RELEASE_WORKFLOW run found for $TAG after ${waited}s"
  fm_summary "no release run started for $TAG"
  exit 1
fi
echo "watching run $run_id of $RELEASE_WORKFLOW for $TAG (the same run the public sees in GitHub Actions)"
fm_release_run_facts "$run_id"

rc=0
gh run watch "$run_id" --exit-status >/dev/null 2>&1 || rc=$?
fm_release_run_facts "$run_id"
if [ "$rc" -ne 0 ]; then
  echo "release workflow run $run_id did not succeed; last failed log lines:"
  gh run view "$run_id" --log-failed 2>&1 | tail -n 40 || true
  fm_summary "release workflow run $run_id for $TAG did not succeed"
  exit 1
fi
fm_summary "release workflow run $run_id for $TAG succeeded"
