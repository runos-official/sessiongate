#!/usr/bin/env bash
# Test for record-release.sh against a local bare repository standing in for origin.
# No network, no gh, no GitHub. Every case runs the real script in a fresh clone.
#
# Usage: scripts/deploy/record-release-test.sh        (exit 0 = every case passed)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/record-release.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: want '$3', got '$2'"; fi; }
expect_ok() { local name="$1"; shift; if "$@" >"$T/out" 2>"$T/err"; then ok "$name"; else bad "$name (exit $?): $(cat "$T/err")"; fi; }
expect_err() { if grep -q "$2" "$T/err"; then ok "$1"; else bad "$1: stderr was: $(cat "$T/err")"; fi; }
expect_fail() { local name="$1"; shift; if "$@" >"$T/out" 2>"$T/err"; then bad "$name: expected a refusal, got exit 0"; else ok "$name"; fi; }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

# fixture <name>: a bare origin with main at c1, dev at c2, deployed at c2, tag v1.0.0-rc.1 at c2,
# and a working clone at $T/<name>/work. Echoes nothing; sets C1 and C2.
fixture() {
  local d="$T/$1"
  mkdir -p "$d"
  git init -q --bare "$d/origin.git"
  git init -q -b main "$d/seed"
  ( cd "$d/seed" || exit 1
    git remote add origin "$d/origin.git"
    echo one >f && git add f && git commit -q -m c1
    git push -q origin main
    git checkout -q -b dev
    echo two >f && git commit -q -am c2
    git push -q origin dev
    git push -q origin dev:refs/heads/deployed
    git tag v1.0.0-rc.1 && git push -q origin v1.0.0-rc.1 )
  C1="$(git -C "$d/seed" rev-parse main)"
  C2="$(git -C "$d/seed" rev-parse dev)"
  git clone -q "$d/origin.git" "$d/work"
}
origin_sha() { git -C "$T/$1/origin.git" rev-parse -q --verify "refs/heads/$2" 2>/dev/null || echo absent; }
run_in() { local name="$1"; shift; ( cd "$T/$name/work" && "$SCRIPT" "$@" ); }
fact() { sed -n "s/^::foreman:: $1=//p" "$T/out" | tail -1; }

# 1. A candidate checks clean on a dev target, and may not record on main.
fixture a
expect_ok   "check: a candidate on the dev record passes" run_in a check v1.0.0-rc.1 dev dev deployed
expect_fail "check: a candidate may not record on main" run_in a check v1.0.0-rc.1 dev dev main
expect_fail "check: a bad environment is refused" run_in a check v1.0.0 staging dev deployed

# 2. A final on a prod target: the record must be main, the candidate record must be at the dev tip.
fixture b
expect_ok   "check: a final on prod passes when deployed is at the dev tip and an rc tag names it" run_in b check v1.0.0 prod dev main
expect_fail "check: a prod target that records on deployed is refused" run_in b check v1.0.0 prod dev deployed
expect_fail "check: a dev final may not record on main" run_in b check v1.0.0 dev dev main
expect_ok   "check: a dev final records on its own record" run_in b check v1.0.0 dev dev deployed

# 3. A final is refused when the candidate record is behind dev, or no rc tag names the tip.
fixture c
( cd "$T/c/seed" && echo three >f && git commit -q -am c3 && git push -q origin dev )
expect_fail "check: a final is refused when dev moved after the candidate" run_in c check v1.0.0 prod dev main
expect_err "check: the refusal names the release candidate rule" "release candidate"

fixture d
( cd "$T/d/seed" && git push -q origin :refs/tags/v1.0.0-rc.1 ) && git -C "$T/d/work" tag -d v1.0.0-rc.1 >/dev/null
expect_fail "check: a final is refused when no rc tag names the dev tip" run_in d check v1.0.0 prod dev main

# 4. A final is refused before the tag when main is not an ancestor of the dev tip.
fixture e
( cd "$T/e/seed" && git checkout -q -b side main && echo side >g && git add g && git commit -q -m side && git push -q origin side:refs/heads/main -f )
expect_fail "check: a final is refused when main has diverged from dev" run_in e check v1.0.0 prod dev main
expect_err "check: the divergence message names the prod record" "could not fast-forward"

# 5. advance: a candidate moves the record it was given and never main.
fixture f
run_in f advance v1.0.0-rc.1 dev dev deployed >"$T/out" 2>"$T/err"
expect_eq "advance: a candidate leaves main alone" "$(origin_sha f main)" "$C1"
expect_eq "advance: a candidate leaves the record at the tag commit" "$(origin_sha f deployed)" "$C2"
expect_eq "advance: a candidate prints no main fact" "$(fact main_before)" ""
expect_fail "advance: a candidate may not record on main" run_in f advance v1.0.0-rc.1 dev dev main
expect_eq "advance: the refused candidate left main alone" "$(origin_sha f main)" "$C1"

# 6. advance: a final on prod fast-forwards main to the tag commit and says so.
fixture g
( cd "$T/g/work" && git fetch -q --tags origin && git tag v1.0.0 "$C2" )
run_in g advance v1.0.0 prod dev main >"$T/out" 2>"$T/err"; rc=$?
expect_eq "advance: a final on prod succeeds" "$rc" "0"
expect_eq "advance: main moved to the final's commit" "$(origin_sha g main)" "$C2"
expect_eq "advance: deployed is at the final's commit" "$(origin_sha g deployed)" "$C2"
expect_eq "advance: main_before is what main held" "$(fact main_before)" "$C1"
expect_eq "advance: main_after is the final's commit" "$(fact main_after)" "$C2"
expect_eq "advance: main_equals_final is true" "$(fact main_equals_final)" "true"
run_in g advance v1.0.0 prod dev main >"$T/out" 2>"$T/err"; rc=$?
expect_eq "advance: running it again is a no-op" "$rc" "0"
expect_eq "advance: the second run still reports main_equals_final" "$(fact main_equals_final)" "true"
expect_eq "advance: the second run reports main_before equal to main_after" "$(fact main_before)" "$C2"

# 7. advance: a diverged main is never forced.
fixture h
( cd "$T/h/work" && git fetch -q --tags origin && git tag v1.0.0 "$C2" )
( cd "$T/h/seed" && git checkout -q -b side main && echo side >g && git add g && git commit -q -m side && git push -q origin side:refs/heads/main -f )
DIVERGED="$(origin_sha h main)"
run_in h advance v1.0.0 prod dev main >"$T/out" 2>"$T/err"; rc=$?
if [ "$rc" -ne 0 ]; then ok "advance: a diverged main is refused"; else bad "advance: a diverged main was not refused"; fi
expect_eq "advance: the diverged main was not moved" "$(origin_sha h main)" "$DIVERGED"
expect_eq "advance: the refusal reports main_equals_final=false" "$(fact main_equals_final)" "false"
expect_eq "advance: the refusal still reports main_before" "$(fact main_before)" "$DIVERGED"

# 8. advance: a missing main is refused, not created.
fixture i
( cd "$T/i/work" && git fetch -q --tags origin && git tag v1.0.0 "$C2" )
git -C "$T/i/origin.git" update-ref -d refs/heads/main
expect_fail "advance: a missing main is refused" run_in i advance v1.0.0 prod dev main
expect_eq "advance: a missing main was not created" "$(origin_sha i main)" "absent"

# 9. advance: a final on a dev target records on its own record and never touches main.
fixture j
( cd "$T/j/work" && git fetch -q --tags origin && git tag v1.0.0 "$C2" )
run_in j advance v1.0.0 dev dev deployed >"$T/out" 2>"$T/err"; rc=$?
expect_eq "advance: a dev final succeeds" "$rc" "0"
expect_eq "advance: a dev final leaves main alone" "$(origin_sha j main)" "$C1"
expect_eq "advance: a dev final prints no main fact" "$(fact main_before)" ""

# 10. The record never rewinds: a record ahead of the tag commit is refused, not reset.
fixture k
( cd "$T/k/seed" && echo three >f && git commit -q -am c3 && git push -q origin dev:refs/heads/deployed )
( cd "$T/k/work" && git fetch -q --tags origin && git tag v1.0.1-rc.1 "$C2" )
expect_fail "advance: a record ahead of the tag commit is not rewound" run_in k advance v1.0.1-rc.1 dev dev deployed

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
