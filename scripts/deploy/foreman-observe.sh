#!/usr/bin/env bash
# foreman-observe.sh: read-only helpers that report facts and evidence to Foreman.
# Canonical copy: docs/templates/foreman-observe.sh in the foreman repo. Each product repo keeps
# its own copy at scripts/deploy/foreman-observe.sh and `source`s it. See docs/pipeline-observability.md.
# Safe to source under `set -euo pipefail`; the collector runs in a subshell with errors off.

fm_fact() { local k="$1"; shift; printf '::foreman:: %s=%s\n' "$k" "$(printf %s "$*" | tr '\r\n' '  ')"; }
fm_summary() { printf '::foreman-summary:: %s\n' "$(printf %s "$*" | tr '\r\n' '  ')"; }
# fm_collect_evidence <namespace> <label-selector> [health-url] [evidence-file in ${{ run_dir }}]
fm_collect_evidence() {
  if [ -n "${4:-}" ]; then _fm_evidence "$@" | tee "$4"; else _fm_evidence "$@"; fi
  return 0
}
_fm_evidence() (
  set +eu
  local ns="$1" sel="$2" url="${3:-}" file="${4:-}" k="kubectl -n $1" p c r out n=0 bad=0 rst=0
  echo "== workloads"; $k get deploy,rs,pods -l "$sel" -o wide 2>&1
  echo "== pods: images, digests, restarts"
  $k get pods -l "$sel" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{range .status.containerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{" "}{.imageID}{"; "}{end}{"\n"}{end}' 2>&1
  for p in $($k get pods -l "$sel" -o name 2>/dev/null); do
    n=$((n + 1))
    if ! $k get "$p" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then
      bad=$((bad + 1)); echo "== describe $p (not ready)"; $k describe "$p" 2>&1
    fi
    for c in $($k get "$p" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null); do
      echo "== log $p/$c (last 60 lines)"; $k logs "$p" -c "$c" --tail=60 2>&1
      r=$($k get "$p" -o jsonpath="{.status.containerStatuses[?(@.name==\"$c\")].restartCount}" 2>/dev/null)
      case "$r" in ''|*[!0-9]*) r=0;; esac
      rst=$((rst + r))
      if [ "$r" -gt 0 ]; then echo "== previous log $p/$c (last 60 lines)"; $k logs "$p" -c "$c" --previous --tail=60 2>&1; fi
    done
  done
  echo "== events"; $k get events --sort-by=.lastTimestamp 2>&1 | tail -30
  echo "== top"; $k top pods -l "$sel" 2>&1
  if [ -n "$url" ]; then
    echo "== health $url"; out=$(curl -sS -m 10 -w '\n%{http_code} %{time_total}' "$url" 2>&1); echo "$out"
    fm_fact health_status "$(printf %s "$out" | tail -n1 | cut -d' ' -f1)"
  fi
  fm_fact pods "$n"; fm_fact pods_not_ready "$bad"; fm_fact restarts "$rst"
  if [ -n "$file" ]; then fm_fact evidence "$file"; else fm_fact evidence output; fi
  fm_summary "collected evidence for $n pods in $ns"
)
