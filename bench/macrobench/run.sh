#!/usr/bin/env bash
set -euo pipefail

# Resolve this script's directory for portable, relative paths
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# Always source the bootstrap-generated env file first if it exists, so its values take precedence
if [ -f "$SCRIPT_DIR/.macrobench.env" ]; then
  # shellcheck source=/dev/null
  . "$SCRIPT_DIR/.macrobench.env"
fi

GITLAB_URL=${GITLAB_URL:-http://localhost:8089}
PAT=${GITLAB_PAT:-}
PROJECT_ID=${PROJECT_ID:-}
COMMITS=${COMMITS:-3}
SNAPSHOT_ID=${SNAPSHOT_ID:-bench-$(date +%s)}
JUSTIFICATION=${JUSTIFICATION:-"macrobench test"}
USE_REBOUND=${USE_REBOUND:-1}
# Control whether the deploy_k8s macrobenchmark job runs
USE_K8S_BASELINE=${USE_K8S_BASELINE:-1}
# Default output location: prefer $REBOUND_HOME/o if REBOUND_HOME is set, otherwise keep prior behavior
if [ -z "${OUT:-}" ]; then
  if [ -n "${REBOUND_HOME:-}" ]; then
    mkdir -p "${REBOUND_HOME}/o" >/dev/null 2>&1 || true
    if [ "$USE_REBOUND" = "1" ]; then
      OUT="${REBOUND_HOME}/o/results-rebound.csv"
    else
      OUT="${REBOUND_HOME}/o/results-baseline.csv"
    fi
  else
    if [ "$USE_REBOUND" = "1" ]; then
      OUT="${SCRIPT_DIR}/results-rebound.csv"
    else
      OUT="${SCRIPT_DIR}/results-baseline.csv"
    fi
  fi
fi
RUN_AUDIT_LINEAGE=${RUN_AUDIT_LINEAGE:-1}
LINEAGE_TAIL=${LINEAGE_TAIL:-100}
DEBUG=${DEBUG:-1}
TRIALS=${TRIALS:-1}

# Note on GitLab tag-triggered pipelines and metrics collection:
# - This script keys all waits, manual job plays, and metrics collection to the
#   exact pipeline created by each commit it pushes (see pipeline_by_sha and the
#   stored pipeline_id variables like "pipe").
# - When the baseline "create_release" job runs, GitLab may create a tag for the
#   snapshot if it doesn't exist. Creating that tag can trigger a second "tag"
#   pipeline where rules:changes don’t apply, so all build jobs may run there.
# - That extra pipeline has a different pipeline ID and is never referenced by
#   this script. Results are collected only from the targeted pipeline_id, so
#   metrics are unaffected. You can safely ignore the extra pipeline in the UI.

say(){ echo "[run] $*"; }
dbg(){ if [ "${DEBUG}" = "1" ]; then echo "[debug] $*" >&2; fi }
require_pat(){ if [ -z "$PAT" ]; then echo "Set GITLAB_PAT"; exit 1; fi }

# Verify API is reachable and token is valid
check_api(){
  local resp body code
  resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/user")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" != "200" ]; then
    echo "[run] GitLab API /user failed (HTTP $code). Body: $(echo "$body" | tr '\n' ' ' | cut -c1-300)" >&2
    exit 1
  fi
}

# Ensure a CI/CD variable exists (or update it) at the project level
ensure_project_variable(){
  local pid=$1; local key=$2; local value=$3
  # Try update first (PUT); if it fails with 404, create (POST)
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --request PUT \
    --header "PRIVATE-TOKEN: ${PAT}" \
    --header 'Content-Type: application/json' \
    --data "{\"value\":\"${value}\"}" \
    "${GITLAB_URL}/api/v4/projects/${pid}/variables/${key}")
  if [ "$code" = "404" ]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" --request POST \
      --header "PRIVATE-TOKEN: ${PAT}" \
      --header 'Content-Type: application/json' \
      --data "{\"key\":\"${key}\",\"value\":\"${value}\"}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/variables")
  fi
  if [ "$code" != "200" ] && [ "$code" != "201" ]; then
    echo "Failed to set project variable ${key} (HTTP $code)" >&2; exit 1
  fi
}

project_info(){
  curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${1}" 2>/dev/null
}

find_project(){
  if [ -n "$PROJECT_ID" ]; then echo "$PROJECT_ID"; return; fi
  local resp body code pid
  # Prefer path-based lookup (root/sample-app)
  resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" \
    "${GITLAB_URL}/api/v4/projects/root%2Fsample-app")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" = "200" ]; then
    pid=$(echo "$body" | jq -r '.id // empty')
    if [ -n "$pid" ]; then echo "$pid"; return; fi
  fi
  # Fallback to search
  resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" \
    "${GITLAB_URL}/api/v4/projects?owned=true&search=sample-app")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" = "200" ]; then
    pid=$(echo "$body" | jq -r 'if type=="array" and length>0 then .[0].id else empty end')
    if [ -n "$pid" ]; then echo "$pid"; return; fi
  fi
  echo "[run] Could not find project (HTTP $code). Body: $(echo "$body" | tr '\n' ' ' | cut -c1-300)" >&2
  echo ""
}

pipeline_by_sha(){
  local pid=$1; local sha=$2
  local tries=60
  while [ $tries -gt 0 ]; do
    local resp body code pl
    resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/pipelines?sha=${sha}")
    body=$(echo "$resp" | sed '$d')
    code=$(echo "$resp" | tail -n1)
    if [ "$code" = "200" ]; then
      pl=$(echo "$body" | jq -r 'if type=="array" and length>0 then .[0].id else empty end')
      if [ -n "$pl" ]; then echo "$pl"; return 0; fi
    fi
    sleep 1; tries=$((tries-1))
  done
  echo ""
}

wait_pipeline(){
  local pid=$1; local pipeline_id=$2
  for i in {1..300}; do
    # Primary: check pipeline status
    local resp body code s
    resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}")
    body=$(echo "$resp" | sed '$d')
    code=$(echo "$resp" | tail -n1)
    if [ "$code" = "200" ]; then
      s=$(echo "$body" | jq -r '.status // empty')
      # Treat typical terminal states as done; include 'manual' and 'blocked' (manual action required)
      dbg "wait_pipeline: pipeline=$pipeline_id status=$s (poll $i)"
      if [[ "$s" =~ ^(success|failed|canceled|skipped|manual|blocked)$ ]]; then echo "$s"; return 0; fi
    fi
    # Fallback: if there are no non-manual jobs still pending/running, consider pipeline effectively "manual"
    local jresp jbody jcode incomplete
    jresp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs")
    jbody=$(echo "$jresp" | sed '$d')
    jcode=$(echo "$jresp" | tail -n1)
    if [ "$jcode" = "200" ]; then
      local nm_total nm_active
      nm_total=$(echo "$jbody" | jq -r 'if type=="array" then [ .[] | select(.status != null and .status != "manual") ] | length else 0 end')
      nm_active=$(echo "$jbody" | jq -r 'if type=="array" then [ .[] | select(.status != null and .status != "manual" and (.status|test("^(pending|running|created|waiting_for_resource|preparing)$"))) ] | length else 0 end')
      dbg "wait_pipeline: nm_total=$nm_total nm_active=$nm_active"
      if [ "$nm_active" -eq 0 ]; then echo manual; return 0; fi
    fi
    sleep 2
  done
  echo timeout
}

# Wait until all non-manual jobs in the pipeline are finished (success/failed/canceled/skipped)
wait_nonmanual_jobs(){
  local pid=$1; local pipeline_id=$2
  for i in {1..600}; do
    local resp body code
    resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs")
    body=$(echo "$resp" | sed '$d')
    code=$(echo "$resp" | tail -n1)
    if [ "$code" != "200" ]; then sleep 2; continue; fi
    local nm_total nm_active
    nm_total=$(echo "$body" | jq -r 'if type=="array" then [ .[] | select(.status != null and .status != "manual") ] | length else 0 end')
    nm_active=$(echo "$body" | jq -r 'if type=="array" then [ .[] | select(.status != null and .status != "manual" and (.status|test("^(pending|running|created|waiting_for_resource|preparing)$"))) ] | length else 0 end')
    dbg "wait_nonmanual_jobs: pipeline=$pipeline_id nm_total=$nm_total nm_active=$nm_active (poll $i)"
    if [ "$nm_active" -eq 0 ]; then echo complete; return 0; fi
    sleep 2
  done
  echo timeout
}

pipeline_duration(){
  local pid=$1; local pipeline_id=$2
  local d
  d=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}" | jq -r .duration)
  if [ -z "$d" ] || [ "$d" = "null" ]; then
    # Fallback: sum durations of non-manual jobs
    local resp body code
    resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs")
    body=$(echo "$resp" | sed '$d')
    code=$(echo "$resp" | tail -n1)
    if [ "$code" = "200" ]; then
      d=$(echo "$body" | jq -r 'if type=="array" then [ .[] | select(.status != null and .status != "manual") | (.duration // 0) ] | add else 0 end')
    else
      d=0
    fi
  fi
  echo "$d"
}

collect_job_metrics(){
  local pid=$1; local pipeline_id=$2; local label=$3
  local resp body code
  resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" != "200" ]; then
    echo "[run] jobs API failed (HTTP $code). Body: $(echo "$body" | tr '\n' ' ' | cut -c1-200)" >&2
    return 0
  fi
  echo "$body" | jq -r --arg label "$label" '
    if type=="array" then
      .[]
      | (try select(type=="object") catch empty)
      | [ (now|todate), $label, (try .id catch null), (try .name catch null), (try (.duration // 0) catch 0) ]
      | select(.[2] != null and .[3] != null)
      | @csv
    else empty end'
}

play_job(){
  local pid=$1; local pipeline_id=$2; local job_name=$3; shift 3
  # find job id by name in this pipeline
  local job_id
  job_id=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs" \
    | jq -r --arg n "$job_name" 'if type=="array" then .[] | select(type=="object" and (.name? == $n)) | .id else empty end' \
    | head -n1)
  if [ -z "$job_id" ]; then
    say "Job $job_name not found in pipeline $pipeline_id" >&2
    echo not_found
    return 1
  fi
  local vars_json=""
  if [ $# -ge 1 ]; then
    vars_json="$1"; shift
  fi
  # play job (optionally with variables). For GitLab's play endpoint, variables must be sent
  # as multipart form fields: job_variables_attributes[][key]=K, job_variables_attributes[][value]=V
  # JSON bodies are ignored by many versions for this endpoint.
  local resp body code
  if [ -n "$vars_json" ] && [ "$vars_json" != "null" ]; then
    # Build repeated --form args from the provided JSON object
    # Expecting vars_json to be an object: {KEY: VALUE, ...}
    # Use an array to safely pass multiple --form flags
    local -a form_args
    while IFS=$'\x1f' read -r k v; do
      # shellcheck disable=SC2206
      form_args+=(--form "job_variables_attributes[][key]=${k}")
      form_args+=(--form "job_variables_attributes[][value]=${v}")
    done < <(echo "$vars_json" | jq -r 'to_entries[] | "\(.key)\u001F\(.value)"')
    dbg "play_job: sending variables for $job_name -> $(echo "$vars_json" | jq -c '.')"
    resp=$(curl -s -w "\n%{http_code}" --request POST --header "PRIVATE-TOKEN: ${PAT}" \
      "${form_args[@]}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}/play")
  else
    resp=$(curl -s -w "\n%{http_code}" --request POST --header "PRIVATE-TOKEN: ${PAT}" \
      "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}/play")
  fi
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" != "200" ] && [ "$code" != "201" ]; then
    echo play_failed
    say "Failed to play job $job_name (id=$job_id) HTTP $code Body: $(echo "$body" | tr '\n' ' ' | cut -c1-200)" >&2
    return 1
  fi
  # wait for job to finish
  for i in {1..300}; do
    st=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}" | jq -r '.status // empty')
    if [[ "$st" =~ ^(success|failed|canceled)$ ]]; then echo "$st"; return 0; fi
    sleep 2
  done
  echo timeout
}

# Lookup a job id in a pipeline by name
job_id_by_name(){
  local pid=$1; local pipeline_id=$2; local job_name=$3
  curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/pipelines/${pipeline_id}/jobs" \
    | jq -r --arg n "$job_name" 'if type=="array" then .[] | select(type=="object" and (.name? == $n)) | .id else empty end' \
    | head -n1
}

# Fetch the raw job trace text
job_trace(){
  local pid=$1; local job_id=$2
  curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}/trace"
}

# Cancel a manual job (useful to unblock later stages)
cancel_job(){
  local pid=$1; local pipeline_id=$2; local job_name=$3
  local job_id
  job_id=$(job_id_by_name "$pid" "$pipeline_id" "$job_name")
  if [ -z "$job_id" ]; then
    dbg "cancel_job: job $job_name not found in pipeline $pipeline_id"
    echo not_found
    return 0
  fi
  # Only skip if job is currently manual
  local st
  st=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}" | jq -r '.status // empty')
  if [ "$st" != "manual" ]; then
    dbg "cancel_job: job $job_name (id=$job_id) status=$st; nothing to do"
    echo "$st"
    return 0
  fi
  local resp body code
  resp=$(curl -s -w "\n%{http_code}" --request POST --header "PRIVATE-TOKEN: ${PAT}" \
    "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}/cancel")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" != "200" ] && [ "$code" != "201" ]; then
    say "Failed to cancel job $job_name (id=$job_id) HTTP $code Body: $(echo "$body" | tr '\n' ' ' | cut -c1-200)" >&2
    echo cancel_failed
    return 1
  fi
  # Wait until job reflects skipped
  for i in {1..60}; do
    st=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}" | jq -r '.status // empty')
    if [ "$st" = "canceled" ] || [ "$st" = "skipped" ]; then echo "$st"; return 0; fi
    sleep 1
  done
  echo timeout
}

# Wait until a given job in a pipeline is present and in manual (playable) state
wait_job_playable(){
  local pid=$1; local pipeline_id=$2; local job_name=$3; local tries=${4:-120}
  for i in $(seq 1 "$tries"); do
    local job_id st
    job_id=$(job_id_by_name "$pid" "$pipeline_id" "$job_name")
    if [ -n "$job_id" ]; then
      st=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${job_id}" | jq -r '.status // empty')
      dbg "wait_job_playable: job=$job_name id=$job_id status=$st (poll $i)"
      if [ "$st" = "manual" ]; then echo "$job_id"; return 0; fi
    else
      dbg "wait_job_playable: job $job_name not yet present (poll $i)"
    fi
    sleep 1
  done
  echo ""
}

clone_repo(){
  local pid=$1
  proj=$(project_info "$pid")
  http_url=$(echo "$proj" | jq -r .http_url_to_repo)
  # Extract path after scheme+host (supports http/https)
  path_part=${http_url#*://}
  path_part=${path_part#*/}
  # Derive scheme and host:port from GITLAB_URL
  hostport=${GITLAB_URL#http://}
  hostport=${hostport#https://}
  scheme=http
  [[ "$GITLAB_URL" == https://* ]] && scheme=https
  # Use PAT as HTTP password with the root username for Git over HTTPS
  local url="${scheme}://root:${PAT}@${hostport}/${path_part}"
  tmpdir=$(mktemp -d)
  git clone -q "$url" "$tmpdir/repo"
  echo "$tmpdir/repo"
}

sync_ci_config(){
  # Ensure the GitLab project's .gitlab-ci.yml matches our local template
  local repo_dir=$1
  local template="$SCRIPT_DIR/../../rebound-sample-workloads/.gitlab-ci.yml"
  if [ -f "$template" ]; then
    if [ ! -f "$repo_dir/.gitlab-ci.yml" ] || ! cmp -s "$template" "$repo_dir/.gitlab-ci.yml"; then
      say "Syncing .gitlab-ci.yml into project repo"
      cp "$template" "$repo_dir/.gitlab-ci.yml"
      pushd "$repo_dir" >/dev/null
      git add .gitlab-ci.yml
      git commit -qm "chore(ci): sync pipeline config from macrobench"
      git push -q origin main
      popd >/dev/null
    fi
  fi
}

commit_and_push(){
  local repo_dir=$1; local which=$2
  pushd "$repo_dir" >/dev/null
  if [ "$which" = "sample" ]; then
    echo "tick $(date +%s)" >> sample/bench.txt
  elif [ "$which" = "sqlite" ]; then
    mkdir -p sqlite
    echo "tick $(date +%s)" >> sqlite/bench.txt
  else
    echo "tick $(date +%s)" >> llama2.c/bench.txt
  fi
  git add .
  git commit -qm "bench: $which change $(date +%s)"
  git push -q origin main
  git rev-parse HEAD
  popd >/dev/null
}

main(){
  require_pat
  check_api
  pid=$(find_project)
  if [ -z "$pid" ]; then echo "Project not found"; exit 1; fi
  say "Using project id=$pid"
  # Derive default lineage OBJECT from the project's path_with_namespace unless overridden
  pinfo=$(project_info "$pid")
  project_path=$(echo "$pinfo" | jq -r '.path_with_namespace // empty')
  lineage_object=${LINEAGE_OBJECT:-$project_path}
  # Propagate USE_REBOUND toggle to the project so CI jobs can honor it
  ensure_project_variable "$pid" "USE_REBOUND" "$USE_REBOUND"
  # Propagate K8s macrobenchmark toggle the same way (no defaults in CI YAML)
  ensure_project_variable "$pid" "USE_K8S_BASELINE" "$USE_K8S_BASELINE"
  echo "ts,label,pipeline_id,total_s,job_id,job_name,job_s" > "$OUT"

  repo_dir=$(clone_repo "$pid")
  # Keep the GitLab project's CI config in sync with the local template so job changes take effect
  sync_ci_config "$repo_dir"

  # Track last pipeline per workload without associative arrays for portability
  LAST_PIPE_sample=""
  LAST_PIPE_llama2=""
  LAST_PIPE_sqlite=""
  # Create per-workload snapshot ids for clarity and isolation
  base_snap="$SNAPSHOT_ID"
  # Repeat full A/B/C flow for each trial; plots will average across the replicated rows.
  for trial in $(seq 1 "$TRIALS"); do
  for which in sqlite sample llama2; do
    sid="${base_snap}-t${trial}-${which}"
    rtoken=""

    # Step A: commit/push and create snapshot for this workload
    say "[$which] A: commit/push and snapshot (id=$sid)"
    sha=$(commit_and_push "$repo_dir" "$which")
    say "Commit SHA: $sha"
    pipe=$(pipeline_by_sha "$pid" "$sha")
    if [ -z "$pipe" ]; then echo "[run] No pipeline found for sha $sha." >&2; exit 1; fi
    say "Pipeline $pipe; waiting..."
    st=$(wait_pipeline "$pid" "$pipe"); dbg "pipeline $pipe terminal status: $st"
    if [[ "$st" =~ ^(manual|blocked|skipped)$ ]]; then st_jobs=complete; dbg "pipeline $pipe non-manual completion: short-circuit because pipeline=$st"; else st_jobs=$(wait_nonmanual_jobs "$pid" "$pipe"); dbg "pipeline $pipe non-manual completion: $st_jobs"; fi
  # Proceed as long as all non-manual jobs have finished; even if the pipeline is marked failed,
  # we will attempt to play manual jobs and provide clearer diagnostics if they are absent.
  if [ "$st_jobs" != "complete" ]; then echo "[run] Pipeline $pipe not ready for manual jobs (st=$st st_jobs=$st_jobs)" >&2; exit 1; fi
    # Baseline: play create_release then collect metrics; Rebound handled below
    if [ "$USE_REBOUND" != "1" ]; then
      say "[$which] play create_release (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "create_release" "$(jq -cn --arg sid "$sid" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_A" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "create_release job status: $st_job" >&2; exit 1;
      fi
      dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_A" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
    fi
  if [ "$which" = "sample" ]; then LAST_PIPE_sample="$pipe"; elif [ "$which" = "llama2" ]; then LAST_PIPE_llama2="$pipe"; else LAST_PIPE_sqlite="$pipe"; fi
    if [ "$USE_REBOUND" = "1" ]; then
      # Rebound mode: perform both the baseline release and the Rebound snapshot (measure overheads explicitly)
      say "[$which] play create_release (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "create_release" "$(jq -cn --arg sid "$sid" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_A" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "create_release job status: $st_job (rebound mode)" >&2; exit 1;
      fi
      say "[$which] play create_snapshot (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "create_snapshot" "$(jq -cn --arg sid "$sid" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        # Fallback: still collect baseline metrics so we don't lose a row
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_A" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "create_snapshot job status: $st_job" >&2; exit 1;
      fi
      cs_job_id=$(job_id_by_name "$pid" "$pipe" "create_snapshot")
      if [ -n "$cs_job_id" ]; then
        rtoken=$(job_trace "$pid" "$cs_job_id" | awk -F': ' '/^Rollback token: / {print $2}' | tail -n1)
        if [ -z "$rtoken" ]; then echo "[run] Could not extract rollback token from job $cs_job_id (pipeline $pipe)" >&2; exit 1; fi
      else
        echo "[run] Could not locate create_snapshot job in pipeline $pipe" >&2; exit 1; fi
      # Collect metrics after manual job has completed
      dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_A" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
    fi

    # Step B: commit/push and rollback to snapshot for this workload
    say "[$which] B: commit/push and rollback to $sid"
    sha=$(commit_and_push "$repo_dir" "$which")
    say "Commit SHA: $sha"
    pipe=$(pipeline_by_sha "$pid" "$sha")
    if [ -z "$pipe" ]; then echo "[run] No pipeline found for sha $sha." >&2; exit 1; fi
    say "Pipeline $pipe; waiting..."
    st=$(wait_pipeline "$pid" "$pipe"); dbg "pipeline $pipe terminal status: $st"
    if [[ "$st" =~ ^(manual|blocked|skipped)$ ]]; then st_jobs=complete; dbg "pipeline $pipe non-manual completion: short-circuit because pipeline=$st"; else st_jobs=$(wait_nonmanual_jobs "$pid" "$pipe"); dbg "pipeline $pipe non-manual completion: $st_jobs"; fi
  if [ "$st_jobs" != "complete" ]; then echo "[run] Pipeline $pipe not ready for manual jobs (st=$st st_jobs=$st_jobs)" >&2; exit 1; fi
    if [ "$USE_REBOUND" != "1" ]; then
      say "[$which] play rollback_release (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "rollback_release" "$(jq -cn --arg sid "$sid" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_B" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "rollback_release job status: $st_job" >&2; exit 1;
      fi
      dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_B" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
    fi
  if [ "$which" = "sample" ]; then LAST_PIPE_sample="$pipe"; elif [ "$which" = "llama2" ]; then LAST_PIPE_llama2="$pipe"; else LAST_PIPE_sqlite="$pipe"; fi
    if [ "$USE_REBOUND" = "1" ]; then
  if [ -z "$rtoken" ]; then echo "[run] Missing rollback token for $which (snapshot $sid)" >&2; exit 1; fi
  say "[$which] play rollback_snapshot (SNAPSHOT_ID=$sid)"
  st_job=$(play_job "$pid" "$pipe" "rollback_snapshot" "$(jq -cn --arg sid "$sid" --arg tok "$rtoken" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, ROLLBACK_TOKEN:$tok, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_B" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "rollback job status: $st_job" >&2; exit 1;
      fi
      # Collect metrics after manual job has completed
      dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_B" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
    fi

    # Step C: commit/push and prune the snapshot for this workload
    say "[$which] C: commit/push and prune $sid"
    sha=$(commit_and_push "$repo_dir" "$which")
    say "Commit SHA: $sha"
    pipe=$(pipeline_by_sha "$pid" "$sha")
    if [ -z "$pipe" ]; then echo "[run] No pipeline found for sha $sha." >&2; exit 1; fi
    say "Pipeline $pipe; waiting..."
    st=$(wait_pipeline "$pid" "$pipe"); dbg "pipeline $pipe terminal status: $st"
    if [[ "$st" =~ ^(manual|blocked|skipped)$ ]]; then st_jobs=complete; dbg "pipeline $pipe non-manual completion: short-circuit because pipeline=$st"; else st_jobs=$(wait_nonmanual_jobs "$pid" "$pipe"); dbg "pipeline $pipe non-manual completion: $st_jobs"; fi
  if [ "$st_jobs" != "complete" ]; then echo "[run] Pipeline $pipe not ready for manual jobs (st=$st st_jobs=$st_jobs)" >&2; exit 1; fi
    if [ "$USE_REBOUND" != "1" ]; then
      say "[$which] play prune_release (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "prune_release" "$(jq -cn --arg sid "$sid" '{SNAPSHOT_ID:$sid}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "prune_release job status: $st_job" >&2; exit 1;
      fi
      dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
    fi
  if [ "$which" = "sample" ]; then LAST_PIPE_sample="$pipe"; elif [ "$which" = "llama2" ]; then LAST_PIPE_llama2="$pipe"; else LAST_PIPE_sqlite="$pipe"; fi
    if [ "$USE_REBOUND" = "1" ]; then
      # Gate prune_snapshot on prune_release success to avoid running dependent cleanup after a failure
      say "[$which] play prune_release (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "prune_release" "$(jq -cn --arg sid "$sid" '{SNAPSHOT_ID:$sid}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "prune_release job status: $st_job (rebound mode)" >&2; exit 1;
      fi
      say "[$which] play prune_snapshot (SNAPSHOT_ID=$sid)"
      st_job=$(play_job "$pid" "$pipe" "prune_snapshot" "$(jq -cn --arg sid "$sid" --arg just "$JUSTIFICATION" '{SNAPSHOT_ID:$sid, JUSTIFICATION:$just}')")
      if [ "$st_job" != "success" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
        echo "prune_snapshot job status: $st_job" >&2; exit 1;
      fi
      # If we won't run audit in this pipeline, collect metrics after prune completes
      if [ "$RUN_AUDIT_LINEAGE" != "1" ]; then
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
      fi
    fi
  done
  done

  # Audits at the end (one per workload if enabled)
  if [ "$USE_REBOUND" = "1" ] && [ "$RUN_AUDIT_LINEAGE" = "1" ]; then
  for which in sample llama2 sqlite; do
      # Pick the correct last pipeline for each workload
      if [ "$which" = "sample" ]; then
        pipe="$LAST_PIPE_sample"
      elif [ "$which" = "llama2" ]; then
        pipe="$LAST_PIPE_llama2"
      else
        pipe="$LAST_PIPE_sqlite"
      fi
      if [ -n "$pipe" ]; then
        # Unblock later stages by canceling unrelated manual jobs still pending in earlier stages
        dbg "audit: canceling unrelated manual jobs in pipeline $pipe if present"
  cancel_job "$pid" "$pipe" "create_snapshot" >/dev/null || true
  cancel_job "$pid" "$pipe" "rollback_snapshot" >/dev/null || true
        # Wait until the audit job is actually playable (stage must advance)
        say "[$which] Waiting for audit_lineage to become playable in pipeline $pipe"
        ajob_id=$(wait_job_playable "$pid" "$pipe" "audit_lineage" 180)
        if [ -z "$ajob_id" ]; then
          # If the job exists but is already completed, that's fine — just proceed to collect metrics
          ajob_id=$(job_id_by_name "$pid" "$pipe" "audit_lineage")
          if [ -n "$ajob_id" ]; then
            ast=$(curl -s --header "PRIVATE-TOKEN: ${PAT}" "${GITLAB_URL}/api/v4/projects/${pid}/jobs/${ajob_id}" | jq -r '.status // empty')
            dbg "audit_lineage current status in pipeline $pipe: $ast"
            if [[ "$ast" =~ ^(success|failed|canceled|skipped)$ ]]; then
              say "[$which] audit_lineage already completed with status=$ast; skipping play"
            else
              # Fallback: collect metrics up to this point for C phase and error out
              dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
              echo "audit_lineage did not become playable in pipeline $pipe (status=$ast)" >&2; exit 1;
            fi
          else
            # Job never appeared; collect metrics and fail to signal an issue
            dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
            echo "audit_lineage did not become playable in pipeline $pipe (job not found)" >&2; exit 1;
          fi
        else
          say "[$which] Trigger audit_lineage via manual job (OBJECT=${lineage_object:-unset}, TAIL=$LINEAGE_TAIL)"
          st_job=$(play_job "$pid" "$pipe" "audit_lineage" "$(jq -cn --arg obj "${lineage_object:-}" --arg tail "$LINEAGE_TAIL" '{OBJECT:$obj, TAIL:$tail}')")
          if [ "$st_job" != "success" ]; then
            dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
            echo "audit_lineage job status: $st_job (workload $which)" >&2; exit 1;
          fi
        fi
        # Collect metrics for the C pipeline after audit has completed to include manual job durations
        dur=$(pipeline_duration "$pid" "$pipe"); collect_job_metrics "$pid" "$pipe" "${which}_C" | awk -F, -v p="$pipe" -v t="$dur" '{print $1","$2","p","t","$3","$4","$5}' >> "$OUT"
      fi
    done
  fi

  say "Results written to $OUT"
  column -s, -t "$OUT" | sed 1q; tail -n +2 "$OUT" | column -s, -t
}

main "$@"
