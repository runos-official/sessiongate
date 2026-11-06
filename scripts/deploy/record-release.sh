#!/usr/bin/env bash
#
# Record a release on the branches that say what shipped.
#
#   deployed  the record of what was last tagged, a release candidate or a final.
#   main      the prod record. Only a FINAL on a prod target moves it, to the commit
#             that the final's tag names, fast-forward only. A candidate never does.
#
# Both branches move by a plain push of the tag's commit. A push that is not a
# fast-forward is refused by this script and by git. Nothing here forces anything,
# and nothing deletes a branch.
#
# Usage:
#   scripts/deploy/record-release.sh check   <version> <env> <integration-branch> <record-branch>
#   scripts/deploy/record-release.sh advance <version> <env> <integration-branch> <record-branch>
#
#   <env>            dev or prod: the env of the Foreman target.
#   <record-branch>  the deployed_branch of the Foreman target. A prod target holds the
#                    prod record (main). A dev target holds `deployed`, or the branch
#                    that Foreman scopes to one objective for a candidate.
#
# `check` runs BEFORE the tag. It refuses a record that does not fit the env, a final
# that is not cut from the commit a candidate shipped, and a final whose commit could
# not fast-forward main, so no tag and no image exist when the refusal happens.
# `advance` runs AFTER the release is verified and prints the facts main_before,
# main_after and main_equals_final for a final on a prod target.
set -euo pipefail

CANDIDATE_RECORD="deployed"
PROD_RECORD="main"

say() { printf 'record-release: %s\n' "$1"; }
die() { printf 'record-release: FAIL %s\n' "$1" >&2; exit 1; }
fm_fact() { local k="$1"; shift; printf '::foreman:: %s=%s\n' "$k" "$(printf %s "$*" | tr '\r\n' '  ')"; }
fm_summary() { printf '::foreman-summary:: %s\n' "$(printf %s "$*" | tr '\r\n' '  ')"; }

# remote_sha <branch>: the commit that the branch holds on origin, or nothing when it is absent.
# A transport failure dies; it never reads as "absent".
remote_sha() {
  local out rc=0
  out="$(git ls-remote --exit-code origin "refs/heads/$1" 2>/dev/null)" || rc=$?
  case "$rc" in
    0) printf '%s' "${out%%[[:space:]]*}" ;;
    2) printf '' ;;
    *) die "cannot query origin for $1 (git ls-remote exit $rc); refusing to guess" ;;
  esac
}

# advance_ff <branch> <commit>: move the branch on origin to the commit, fast-forward only.
advance_ff() {
  local branch="$1" commit="$2" before after
  before="$(remote_sha "$branch")"
  if [ "$before" = "$commit" ]; then
    say "$branch is already at ${commit:0:12}"
    return 0
  fi
  if [ -n "$before" ]; then
    git fetch --quiet origin "+refs/heads/$branch:refs/remotes/origin/$branch" \
      || die "origin has $branch but fetching it failed"
    git merge-base --is-ancestor "$before" "$commit" \
      || die "$branch on origin (${before:0:12}) is not an ancestor of ${commit:0:12}. This script only fast-forwards and never forces. Reconcile $branch by hand."
  fi
  git push --quiet origin "$commit:refs/heads/$branch" \
    || die "the push of ${commit:0:12} to $branch was refused"
  after="$(remote_sha "$branch")"
  [ "$after" = "$commit" ] || die "$branch is at ${after:0:12} on origin after the push, expected ${commit:0:12}"
  say "$branch moved from ${before:0:12} to ${commit:0:12}"
}

usage() {
  echo "usage: $0 check|advance <version> <dev|prod> <integration-branch> <record-branch>" >&2
  exit 2
}

[ $# -eq 5 ] || usage
CMD="$1"; VERSION="$2"; ENV="$3"; INTEGRATION="$4"; RECORD="$5"
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "version $VERSION must look like v1.2.3 or v1.2.3-rc.1"
case "$ENV" in dev | prod) ;; *) die "unknown target env: $ENV" ;; esac
case "$RECORD" in *'{'* | *'}'* | *' '* | '') die "the record branch '$RECORD' is not a branch name; a Foreman placeholder did not resolve" ;; esac

FINAL="true"
case "$VERSION" in *-*) FINAL="false" ;; esac

# The record must fit the env. Only a final on a prod target records on the prod record.
if [ "$FINAL" = "true" ] && [ "$ENV" = "prod" ]; then
  [ "$RECORD" = "$PROD_RECORD" ] || die "a final on a prod target records on $PROD_RECORD, but this target holds deployed_branch $RECORD. Set the target's deployed_branch to $PROD_RECORD."
else
  [ "$RECORD" != "$PROD_RECORD" ] || die "$VERSION on a $ENV target must not record on $PROD_RECORD: only a final on a prod target moves it."
fi

cmd_check() {
  if [ "$FINAL" = "false" ]; then
    say "$VERSION is a release candidate: it records on $RECORD and leaves $PROD_RECORD alone"
    return 0
  fi

  # The candidate record is `deployed` for a prod target, because the prod target's own record is main.
  local candidate_record="$RECORD"
  [ "$ENV" = "prod" ] && candidate_record="$CANDIDATE_RECORD"

  git fetch --quiet --tags origin
  local tip recorded tag found=""
  tip="$(remote_sha "$INTEGRATION")"
  [ -n "$tip" ] || die "cannot read $INTEGRATION on origin"
  recorded="$(remote_sha "$candidate_record")"
  [ -n "$recorded" ] || die "$candidate_record does not exist on origin: no release candidate has shipped yet. Cut a candidate from $INTEGRATION and validate it first."
  if [ "$recorded" != "$tip" ]; then
    echo "$candidate_record on origin is at $recorded, but $INTEGRATION is at $tip." >&2
    die "$VERSION must be cut from the commit a release candidate shipped. Cut a new candidate from $INTEGRATION, validate it, then promote that."
  fi
  for tag in $(git tag --list "${VERSION}-rc.*"); do
    if [ "$(git rev-parse "$tag^{commit}")" = "$tip" ]; then found="$tag"; fi
  done
  [ -n "$found" ] || die "no release candidate tag ${VERSION}-rc.N points at $tip, the tip of $INTEGRATION. Cut a new candidate from $INTEGRATION, validate it, then promote that."

  if [ "$ENV" = "prod" ]; then
    local prod_sha
    prod_sha="$(remote_sha "$PROD_RECORD")"
    [ -n "$prod_sha" ] || die "$PROD_RECORD does not exist on origin; this script does not create the prod record"
    git fetch --quiet origin "+refs/heads/$PROD_RECORD:refs/remotes/origin/$PROD_RECORD" \
      || die "origin has $PROD_RECORD but fetching it failed"
    git merge-base --is-ancestor "$prod_sha" "$tip" \
      || die "$PROD_RECORD on origin (${prod_sha:0:12}) is not an ancestor of $INTEGRATION (${tip:0:12}), so $VERSION could not fast-forward $PROD_RECORD. Merge $PROD_RECORD into $INTEGRATION first."
    say "$PROD_RECORD (${prod_sha:0:12}) is an ancestor of $INTEGRATION: $VERSION will fast-forward it"
  fi
  say "$VERSION will be cut from $tip, the commit $found shipped and $candidate_record records"
}

cmd_advance() {
  local commit
  git fetch --quiet --tags origin
  commit="$(git rev-parse -q --verify "refs/tags/$VERSION^{commit}")" || die "tag $VERSION does not exist; the record follows the tag"

  if [ "$FINAL" = "false" ] || [ "$ENV" = "dev" ]; then
    advance_ff "$RECORD" "$commit"
    return 0
  fi

  # A final on a prod target. `deployed` first (a no-op when the candidate already put it here),
  # then main. The facts are printed before main moves, so a refusal still shows what main held.
  advance_ff "$CANDIDATE_RECORD" "$commit"

  local before after
  before="$(remote_sha "$PROD_RECORD")"
  fm_fact main_before "${before:-absent}"
  if [ -z "$before" ]; then
    fm_fact main_equals_final false
    die "$PROD_RECORD does not exist on origin; this script does not create the prod record"
  fi
  if ! ( advance_ff "$PROD_RECORD" "$commit" ); then
    fm_fact main_after "$(remote_sha "$PROD_RECORD")"
    fm_fact main_equals_final false
    exit 1
  fi
  after="$(remote_sha "$PROD_RECORD")"
  fm_fact main_after "$after"
  if [ "$after" = "$commit" ]; then
    fm_fact main_equals_final true
  else
    fm_fact main_equals_final false
    die "$PROD_RECORD is at ${after:0:12}, not at the final's commit ${commit:0:12}"
  fi
  fm_summary "$PROD_RECORD fast-forwarded from ${before:0:12} to ${after:0:12} at $VERSION"
}

case "$CMD" in
  check) cmd_check ;;
  advance) cmd_advance ;;
  *) usage ;;
esac
