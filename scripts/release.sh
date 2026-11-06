#!/usr/bin/env bash
#
# RunOS Session Gate release runbook: deterministic, fail-fast, automation-friendly.
#
# Usage:
#   scripts/release.sh v0.2.0          # full release
#   scripts/release.sh v0.2.0 --check  # run every gate, stop before tag/push (no side effects)
#   make release RELEASE_VERSION=v0.2.0
#
# What it does, in order (any failure aborts before the tag is created):
#   1. Preflight   - tools present, VERSION well-formed, tag not already taken,
#                    CHANGELOG has a matching section, working tree clean & synced,
#                    CI green on the exact commit,
#                    sensitivity scan (PUBLIC repo: fail closed on secret-shaped
#                    content in the deploy payload).
#   2. Code gates  - leak gate (PUBLIC repo: whole-tree scan for credentials and
#                    un-baselined internal identifiers, cannot be skipped), then
#                    gofmt, go build ./... (CGO off, proves the static/cross build),
#                    go vet ./..., go test -race ./... (CGO on; race needs cgo).
#   3. Deploy      - tag the dev commit and push the tag + dev. main is NOT
#                    touched (the human merges main after personal verification).
#   4. CI watch    - wait for the Release workflow run for this tag to succeed.
#   5. Attest      - verify the published image's build-provenance attestation is
#                    bound to release.yml @ this repo.
#   6. Record      - only after a successful deploy, through
#                    scripts/deploy/record-release.sh: a candidate fast-forwards
#                    the `deployed` branch to the shipped commit. A FINAL
#                    fast-forwards `deployed` and then `main`, the prod record, to
#                    the commit its tag names. Fast-forward only: a diverged
#                    branch is refused and nothing is forced.
#
# Branch model: dev = local development (the tagged commit); deployed = the last
# commit that was tagged, candidate or final (advanced on success); main = the
# prod record, moved only by a final, to the final's commit. A final also needs
# main to be an ancestor of dev, which the preflight checks before any tag exists.
#
# The release publishes the artifact (image); it does NOT roll any live cluster.
# A cluster installs the version conductor is configured with.
#
set -euo pipefail

# ---- constants -------------------------------------------------------------
INTEGRATION_BRANCH="dev"
DEPLOYED_BRANCH="deployed"
PROD_BRANCH="main"
RELEASE_WORKFLOW="release.yml"
IMAGE_NAME="ghcr.io/runos-official/sessiongate"
CI_POLL_SECONDS=10

# ---- output helpers --------------------------------------------------------
GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
step() { printf "${BLUE}==>${NC} %s\n" "$1"; }
ok()   { printf "${GREEN} ok${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}  !${NC} %s\n" "$1"; }
die()  { printf "${RED}FAIL${NC} %s\n" "$1" >&2; exit 1; }

# ---- args ------------------------------------------------------------------
VERSION="${1:-}"
CHECK_ONLY="false"
[[ "${2:-}" == "--check" || "${1:-}" == "--check" ]] && CHECK_ONLY="true"
[[ "$VERSION" == "--check" ]] && VERSION=""

[[ -n "$VERSION" ]] || die "usage: scripts/release.sh vX.Y.Z [--check]"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || \
  die "VERSION must look like v0.2.0 (got '$VERSION')"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# =============================================================================
# 1. Preflight
# =============================================================================
step "Preflight ($VERSION)"
for tool in git go gh; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"

git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
NWO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
ok "repo $NWO"

git fetch --quiet --tags origin
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  die "tag $VERSION already exists locally"
fi
if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  die "tag $VERSION already exists on origin"
fi

grep -qE "^## ${VERSION//./\\.}([[:space:]]|$)" CHANGELOG.md || \
  die "CHANGELOG.md has no '## $VERSION' section (add release notes first)"
ok "CHANGELOG has a $VERSION section"

[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit or stash first"

git fetch --quiet origin "$INTEGRATION_BRANCH"
git rev-parse -q --verify "refs/heads/$INTEGRATION_BRANCH" >/dev/null || die "missing local branch: $INTEGRATION_BRANCH"
[[ "$(git rev-parse "$INTEGRATION_BRANCH")" == "$(git rev-parse "origin/$INTEGRATION_BRANCH")" ]] || \
  die "$INTEGRATION_BRANCH is not in sync with origin/$INTEGRATION_BRANCH (push or pull first)"

# CI must be green on the exact commit that gets tagged. The release workflow
# builds from the tag, so a red or missing CI run means an image nobody tested.
INTEGRATION_SHA="$(git rev-parse "origin/$INTEGRATION_BRANCH")"
CI_RESULT="$(gh run list --workflow=ci.yml --commit "$INTEGRATION_SHA" --json status,conclusion \
  -q '[.[] | select(.status=="completed")] | map(.conclusion) | if length==0 then "none" elif all(.=="success") then "success" else "failed" end' 2>/dev/null || echo "unknown")"
[[ "$CI_RESULT" == "success" ]] || \
  die "CI is not green on ${INTEGRATION_SHA:0:7} (result: $CI_RESULT). Push $INTEGRATION_BRANCH and wait for the CI workflow to pass first."
ok "CI green on ${INTEGRATION_SHA:0:7}"

DEPLOYED_EXISTS="false"
if git rev-parse -q --verify "refs/heads/$DEPLOYED_BRANCH" >/dev/null; then
  DEPLOYED_EXISTS="true"
  git fetch --quiet origin "$DEPLOYED_BRANCH" || true
  if git rev-parse -q --verify "origin/$DEPLOYED_BRANCH" >/dev/null; then
    [[ "$(git rev-parse "$DEPLOYED_BRANCH")" == "$(git rev-parse "origin/$DEPLOYED_BRANCH")" ]] || \
      die "$DEPLOYED_BRANCH is not in sync with origin/$DEPLOYED_BRANCH"
  fi
  git merge-base --is-ancestor "$DEPLOYED_BRANCH" "$INTEGRATION_BRANCH" || \
    die "$DEPLOYED_BRANCH cannot fast-forward to $INTEGRATION_BRANCH (histories diverged); reconcile manually"
fi

# A final fast-forwards main, so main must already be an ancestor of dev. Refusing
# here, before the tag, leaves no tag and no image behind when main has diverged.
if [[ "$VERSION" != *-* ]]; then
  git fetch --quiet origin "+refs/heads/$PROD_BRANCH:refs/remotes/origin/$PROD_BRANCH" || \
    die "cannot fetch $PROD_BRANCH from origin; a final fast-forwards it"
  git merge-base --is-ancestor "origin/$PROD_BRANCH" "$INTEGRATION_BRANCH" || \
    die "origin/$PROD_BRANCH is not an ancestor of $INTEGRATION_BRANCH, so $VERSION could not fast-forward it. Merge $PROD_BRANCH into $INTEGRATION_BRANCH first."
  ok "$PROD_BRANCH is an ancestor of $INTEGRATION_BRANCH: $VERSION can fast-forward it"
fi

# Base for the deploy payload = last shipped point.
if [[ "$DEPLOYED_EXISTS" == "true" ]]; then
  PAYLOAD_BASE="$DEPLOYED_BRANCH"
elif PAYLOAD_BASE="$(git describe --tags --abbrev=0 "$INTEGRATION_BRANCH" 2>/dev/null)"; then
  :
else
  PAYLOAD_BASE="$(git rev-list --max-parents=0 "$INTEGRATION_BRANCH" | tail -1)"
fi

# ---- Sensitivity scan: this is a PUBLIC repo ------------------------------
# Deterministic, fail-closed floor over the exact payload being deployed (every
# added line since the last shipped point). High-precision secret patterns only.
# Internal identifiers (lab machine names, account ids, IP address literals) are
# covered by the leak gate in section 2, which reads the whole tree. Everything
# else that needs judgment (org and customer names, context-dependent leaks) is
# the skill's reasoning audit, NOT this gate.
step "Sensitivity scan (public repo, ${PAYLOAD_BASE}..${INTEGRATION_BRANCH})"
# The files that scripts/leakcheck.config excludes (signed test vectors, which
# are credential-shaped on purpose) are left out here too, as they are there.
EXCLUDES=()
while IFS= read -r excluded; do
  [[ -n "$excluded" ]] && EXCLUDES+=(":(exclude)$excluded")
done < <(git show "$INTEGRATION_BRANCH:scripts/leakcheck.config" | sed -n 's/^exclude:[[:space:]]*//p')
ADDED_LINES="$(git diff "$PAYLOAD_BASE..$INTEGRATION_BRANCH" -- . ${EXCLUDES[@]+"${EXCLUDES[@]}"} | grep '^+' | grep -v '^+++' || true)"
# The quoted-assignment branch below matches `key: "value"`. A value that is a
# bare SCREAMING_SNAKE identifier (an env var NAME) or a run of lowercase words
# joined by hyphens (a test placeholder) cannot be a credential, so it is
# filtered out here exactly as scripts/leakcheck.py 1.0.1 filters it. Without
# that filter this floor fires on leakcheck.py's OWN comment, which documents
# the two shapes as literal examples. The provider token prefixes, the cloud key
# id and the PEM header are NEVER filtered: the filter reads the
# quoted-assignment branch alone.
read -r -d '' PLACEHOLDER_FILTER <<'PYFILTER' || true
import re, sys

CREDENTIAL = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,})"
    r"|(github_pat_[A-Za-z0-9_]{20,})"
    r"|(runos_pat_[A-Za-z0-9]{6,}\.[A-Za-z0-9]{20,})"
    r"|(xox[baprs]-[A-Za-z0-9-]{10,})"
    r"|(AKIA[0-9A-Z]{16})"
    r"|(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    r"|((api[_-]?key|secret|password|passwd|token|bearer)[\"' ]*[:=][\"' ]*[\"'][A-Za-z0-9/+_.=-]{16,}[\"'])",
    re.IGNORECASE,
)
QUOTED_VALUE = re.compile(r"[\"']([A-Za-z0-9/+_.=-]{16,})[\"']\s*$")
NOT_A_SECRET_VALUE = re.compile(r"^(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[a-z]+(?:-[a-z]+)+)$")

for number, line in enumerate(sys.stdin, 1):
    for match in CREDENTIAL.finditer(line):
        value = QUOTED_VALUE.search(match.group(0))
        if value and NOT_A_SECRET_VALUE.match(value.group(1)):
            continue
        sys.stdout.write("%d:%s" % (number, line if line.endswith("\n") else line + "\n"))
        break
PYFILTER
SECRET_HITS="$(printf '%s\n' "$ADDED_LINES" | python3 -c "$PLACEHOLDER_FILTER" || true)"
if [[ -n "$SECRET_HITS" ]]; then
  warn "secret-shaped content in the deploy payload ($PAYLOAD_BASE..$INTEGRATION_BRANCH):"
  printf '%s\n' "$SECRET_HITS" | head -20 >&2
  die "sensitivity scan failed (public repo): remove the above before releasing (or, if a confirmed false positive, narrow it in scripts/release.sh)"
fi
ok "no secret-shaped content in release payload"

# =============================================================================
# 2. Code gates (run against the dev tree that will be released)
# =============================================================================
ORIGINAL_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
git checkout --quiet "$INTEGRATION_BRANCH"

# ---- Leak gate: internal identifiers (PUBLIC repo) -------------------------
# The floor above covers CREDENTIAL shapes in the payload diff. This gate covers
# the other half of the rule, INTERNAL IDENTIFIERS (lab machine names, account
# ids, IP address literals), and it reads the WHOLE TRACKED TREE, not the diff,
# because a public repo publishes the tree and not just the newest commits.
#
# It runs here, after the checkout, and not in Preflight: the tree scan has to
# read the branch being released, so running it earlier would scan whatever
# branch the operator happened to be standing on.
#
# It is a ratchet, not a blanket ban: findings already recorded in
# scripts/leakcheck.baseline pass, anything NEW fails. That is deliberate. A
# blanket ban on a repo that already carries published violations would block
# every commit and get the gate switched off within a day.
#
# This gate CANNOT be skipped. The pre-commit hook in .githooks/ runs the same
# checker over the staged diff and CAN be skipped with --no-verify, which is why
# this one exists.
step "Leak gate (public repo, whole tree)"
command -v python3 >/dev/null 2>&1 || die "python3 is required for the leak gate"
if ! LEAK_OUTPUT="$(python3 "$REPO_ROOT/scripts/leakcheck.py" 2>&1)"; then
  printf '%s\n' "$LEAK_OUTPUT" >&2
  die "leak gate failed (public repo): remove the identifiers above before releasing. Do not hand-edit scripts/leakcheck.baseline."
fi
ok "$(printf '%s' "$LEAK_OUTPUT" | tail -1)"

# ---- Scannability gate: leakcheck must be able to READ every tracked file ---
# The gate above only fully reads UTF-8 text. Up to checker 1.1.0 it SKIPPED
# anything else in silence. From 1.2.0 it recovers printable runs from the raw
# bytes, which is best effort and not a scan: measured on 1.2.0, a token in a
# UTF-32 file and a token broken up by NUL bytes both passed it with exit 0.
#
# So a tracked file leakcheck cannot read is a hole in the gate above, and this
# turns it into a hard failure. A file that has to stay unreadable is declared
# in ALLOWED in scripts/unscannable_check.py, with a reason, by somebody who
# has read it. This gate CANNOT be skipped either.
step "Scannability gate (leakcheck must be able to read every tracked file)"
if ! SCAN_OUTPUT="$(python3 "$REPO_ROOT/scripts/unscannable_check.py" 2>&1)"; then
  printf '%s\n' "$SCAN_OUTPUT" >&2
  die "scannability gate failed (public repo): leakcheck cannot read the files above, so it did not really scan them."
fi
ok "$(printf '%s' "$SCAN_OUTPUT" | tail -1)"

step "Format"; UNFORMATTED="$(gofmt -l .)"; [[ -z "$UNFORMATTED" ]] || { printf '%s\n' "$UNFORMATTED" >&2; die "gofmt -l reported files"; }; ok "gofmt"
step "Build";  CGO_ENABLED=0 go build ./... || die "go build failed"; ok "go build"
step "Vet";    go vet ./...                  || die "go vet failed";   ok "go vet"
step "Test";   CGO_ENABLED=1 go test -race ./... || die "go test failed"; ok "go test"

if [[ "$CHECK_ONLY" == "true" ]]; then
  git checkout --quiet "$ORIGINAL_BRANCH"
  printf "${GREEN}All gates passed.${NC} --check mode: stopping before tag/push.\n"
  exit 0
fi

# =============================================================================
# 3. Deploy: tag the dev commit and push (main is NOT touched)
# =============================================================================
step "Deploy: tag $VERSION on $INTEGRATION_BRANCH"
RELEASE_SHA="$(git rev-parse --short HEAD)"
git tag "$VERSION"
git push --quiet origin "$INTEGRATION_BRANCH"
git push --quiet origin "$VERSION"
ok "tagged $VERSION at $RELEASE_SHA, pushed $INTEGRATION_BRANCH + tag (the record moves in step 6)"

# =============================================================================
# 4. Watch the Release workflow run for this tag
# =============================================================================
step "Waiting for Release workflow run for $VERSION"
RUN_ID=""; waited=0
while [[ -z "$RUN_ID" && $waited -lt 60 ]]; do
  RUN_ID="$(gh run list --workflow="$RELEASE_WORKFLOW" --limit 15 \
    --json databaseId,headBranch,event \
    -q "[.[] | select(.headBranch==\"$VERSION\" and .event==\"push\")][0].databaseId" 2>/dev/null || true)"
  [[ -n "$RUN_ID" ]] && break
  sleep "$CI_POLL_SECONDS"; waited=$((waited + CI_POLL_SECONDS))
done
[[ -n "$RUN_ID" ]] || die "could not find a Release run for $VERSION (check: gh run list --workflow=$RELEASE_WORKFLOW)"
ok "run $RUN_ID"
gh run watch "$RUN_ID" --exit-status >/dev/null 2>&1 || \
  die "Release workflow run $RUN_ID failed (inspect: gh run view $RUN_ID --log-failed)"
ok "Release workflow succeeded"

# =============================================================================
# 5. Verify build-provenance attestation on the published image
# =============================================================================
step "Verifying image attestation for $IMAGE_NAME:$VERSION"
if gh attestation verify "oci://${IMAGE_NAME}:${VERSION#v}" --repo "$NWO" >/dev/null 2>&1; then
  ok "image attestation verified"
else
  warn "could not verify image attestation automatically (verify manually: gh attestation verify oci://${IMAGE_NAME}:${VERSION#v} --repo $NWO)"
fi

# =============================================================================
# 6. Record: fast-forward `deployed`, and for a final `main`, to the shipped commit
# =============================================================================
if [[ "$VERSION" == *-* ]]; then
  RELEASE_ENV="dev";  RECORD_BRANCH="$DEPLOYED_BRANCH"
else
  RELEASE_ENV="prod"; RECORD_BRANCH="$PROD_BRANCH"
fi
step "Recording the release ($RELEASE_ENV record: $RECORD_BRANCH)"
"$REPO_ROOT/scripts/deploy/record-release.sh" advance "$VERSION" "$RELEASE_ENV" "$INTEGRATION_BRANCH" "$RECORD_BRANCH" || \
  die "the release is published but the record did not move; fix the branch named above and run: scripts/deploy/record-release.sh advance $VERSION $RELEASE_ENV $INTEGRATION_BRANCH $RECORD_BRANCH"
git checkout --quiet "$ORIGINAL_BRANCH"
ok "recorded $VERSION at $RELEASE_SHA"

printf "${GREEN}Released %s.${NC} Image: %s:%s\n" "$VERSION" "$IMAGE_NAME" "${VERSION#v}"
