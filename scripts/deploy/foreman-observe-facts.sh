#!/usr/bin/env bash
# foreman-observe-facts.sh: fact printers shared by the deploy, promote and rollback scripts and by
# the pipelines that run steps inline. Source foreman-observe.sh first (it defines fm_fact).
# Read-only. Every lookup is guarded, so a failed lookup prints an empty or "unavailable" value and
# never fails a deploy. Nothing here prints a secret.

# fm_image_facts <image:tag> <cache_hit true|false>
# cache_hit is true when the tag was already in the registry and no build ran.
fm_image_facts() {
  local ref="$1" hit="$2" dg sz
  dg="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null)" || dg=""
  if [ "$hit" = "false" ]; then
    sz="$(docker image inspect "$ref" --format '{{.Size}}' 2>/dev/null)" || sz=""
  else
    sz="not_built"
  fi
  fm_fact image "$ref"
  fm_fact digest "${dg:-unavailable}"
  fm_fact size "${sz:-unavailable}"
  fm_fact cache_hit "$hit"
}

# fm_apply_facts <file holding the output of kubectl apply>
fm_apply_facts() {
  local f="$1"
  fm_fact created "$(grep -c ' created$' "$f" 2>/dev/null || true)"
  fm_fact changed "$(grep -c ' configured$' "$f" 2>/dev/null || true)"
  fm_fact unchanged "$(grep -c ' unchanged$' "$f" 2>/dev/null || true)"
}

# fm_rollout_facts <namespace> <deployment> <label-selector> <duration_s>
fm_rollout_facts() {
  local ns="$1" dep="$2" sel="$3" dur="$4" d u r rs
  d="$(kubectl get deployment "$dep" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null)" || d=""
  u="$(kubectl get deployment "$dep" -n "$ns" -o jsonpath='{.status.updatedReplicas}' 2>/dev/null)" || u=""
  r="$(kubectl get deployment "$dep" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" || r=""
  rs="$(kubectl get pods -n "$ns" -l "$sel" -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}' 2>/dev/null | awk '{s+=$1} END{print s+0}')" || rs=""
  fm_fact desired "${d:-0}"
  fm_fact updated "${u:-0}"
  fm_fact ready "${r:-0}"
  fm_fact restarts "${rs:-0}"
  fm_fact duration_s "$dur"
}

# fm_health_facts <url>  (one request, no retry, no verdict; the gate keeps its own retry loop)
fm_health_facts() {
  local url="$1" out
  out="$(curl -sS -m 10 -o /dev/null -w '%{http_code} %{time_total} %{size_download}' "$url" 2>/dev/null)" || out=""
  fm_fact url "$url"
  fm_fact status "$(printf %s "$out" | awk '{print $1}')"
  fm_fact latency_ms "$(printf %s "$out" | awk '{printf "%d", $2 * 1000}')"
  fm_fact body_bytes "$(printf %s "$out" | awk '{print $3}')"
}
