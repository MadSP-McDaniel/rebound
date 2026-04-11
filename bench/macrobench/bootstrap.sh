#!/usr/bin/env bash
set -euo pipefail

GITLAB_URL=${GITLAB_URL:-http://localhost:8089}
INTERNAL_GITLAB_URL=${INTERNAL_GITLAB_URL:-http://gitlab:8089}
NET=${COMPOSE_PROJECT_NAME:-macrobench}_ci_net
# Resolve this script's directory for portable, relative paths
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# Source env file early so any defaults (e.g., GITLAB_URL) are loaded before use.
# Note: this script still mints a fresh PAT and will overwrite any existing GITLAB_PAT later.
if [ -f "$SCRIPT_DIR/.macrobench.env" ]; then
  # shellcheck source=/dev/null
  . "$SCRIPT_DIR/.macrobench.env"
fi

say() { echo "[bootstrap] $*"; }
GREEN='\033[0;32m'
NC='\033[0m'

prompt_host() {
  # Detect a default non-loopback IP if possible
  local default_ip
  default_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
  default_ip=${default_ip:-localhost}
  read -rp "[bootstrap] Enter GitLab host IP or 'localhost' [${default_ip}]: " input
  input=${input:-$default_ip}
  export GITLAB_EXTERNAL_HOST="$input"
  export GITLAB_URL="http://$GITLAB_EXTERNAL_HOST:8089"
}

wait_gitlab() {
  say "Waiting for GitLab at ${GITLAB_URL} ..."
  for i in {1..120}; do
    # Hit a public page (no auth) and bypass proxies; /users/sign_in returns 200 when Rails/NGINX are ready
    if curl -sfL --noproxy "*" "${GITLAB_URL}/users/sign_in" >/dev/null; then
      say "GitLab is up"; return 0
    fi
    sleep 2
  done
  say "GitLab did not become healthy in time"; exit 1
}

get_runner_container() {
  # Prefer the container named "gitlab-runner"; if not found, auto-detect by name pattern
  local ct=""
  local names
  names=$(docker ps --format '{{.Names}}')
  if printf '%s\n' "$names" | grep -qx "gitlab-runner"; then
    ct="gitlab-runner"
  else
    while IFS= read -r n; do
      if [[ "$n" =~ (^|-)gitlab-runner(-|$) ]]; then ct="$n"; break; fi
    done <<EOF
${names}
EOF
  fi
  echo "$ct"
}

ensure_runner_network_mode() {
  local ct=$1
  docker exec -i -e NET="${NET}" -e CLONE_URL="${INTERNAL_GITLAB_URL}" "$ct" bash -s <<'INNER'
set -euo pipefail
cfg=/etc/gitlab-runner/config.toml
if [ ! -f "$cfg" ]; then
  echo "no config.toml yet; skipping network_mode tweak"
  exit 0
fi

if ! grep -qE '^[[:space:]]*\[runners\.docker\][[:space:]]*$' "$cfg"; then
  {
    echo
    echo "  [runners.docker]"
    echo '    image = "alpine:latest"'
    echo "    network_mode = \"$NET\""
  } >> "$cfg"
else
  awk -v net="$NET" '
    BEGIN{insec=0}
    /^[[:space:]]*\[runners\.docker\][[:space:]]*$/ {print; insec=1; next}
    /^[[:space:]]*\[/ { if (insec) insec=0 }
    {
      if (insec && $0 ~ /^[[:space:]]*network_mode[[:space:]]*=/) {
        print "    network_mode = \"" net "\""; insec=2; next
      }
      print
    }
    END{ if (insec==1) print "    network_mode = \"" net "\"" }
  ' "$cfg" > /tmp/config.toml && mv /tmp/config.toml "$cfg"
fi

# Ensure clone_url points to the internal GitLab URL so the runner can fetch repos
if grep -qE '^[[:space:]]*clone_url[[:space:]]*=' "$cfg"; then
  sed -E -i "s#^[[:space:]]*clone_url[[:space:]]*=.*#  clone_url = \"$CLONE_URL\"#" "$cfg"
else
  awk -v curl="$CLONE_URL" '
    BEGIN{inrunner=0}
    /^\[\[runners\]\]/ {inrunner=1}
    {
      print
      if (inrunner && $0 ~ /^[[:space:]]*url[[:space:]]*=/) {
        print "  clone_url = \"" curl "\""; inrunner=0
      }
    }
  ' "$cfg" > /tmp/config.toml && mv /tmp/config.toml "$cfg"
fi
INNER
}

create_runner_token() {
  local pat=$1
  local token
  token=$(curl -s -X POST "${GITLAB_URL}/api/v4/user/runners" \
    --noproxy "*" \
    -H "PRIVATE-TOKEN: ${pat}" \
    -d "runner_type=instance_type&tag_list=local" | jq -r '.token')
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    say "Failed to create runner via API"; return 1
  fi
  echo "$token"
}

register_runner() {
  local token=$1
  if [ -z "$token" ]; then return 0; fi
  if [[ ! "$token" =~ ^glrt- ]]; then
    say "Runner token does not look like a glrt- token; skipping registration"; return 1
  fi
  local ct
  ct=$(get_runner_container)
  if [ -z "$ct" ]; then
    say "Could not find a running GitLab Runner container. Is the stack up?"; return 1
  fi
  # If already configured (any [[runners]] present), skip registration
  if docker exec "$ct" bash -lc 'test -f /etc/gitlab-runner/config.toml && grep -q "\[\[runners\]\]" /etc/gitlab-runner/config.toml'; then
    say "Runner appears already configured; skipping register"
  else
    say "Registering runner in container '$ct' ..."
    docker exec "$ct" bash -lc "\
      set -e; \
      gitlab-runner register --non-interactive \
        --url '${INTERNAL_GITLAB_URL}' \
        --token '${token}' \
        --executor 'docker' \
        --docker-image 'alpine:latest' \
        >/dev/null"
    say "Runner registered"
  fi
  ensure_runner_network_mode "$ct"
  say "Restarting runner container '$ct' to apply config"
  docker restart "$ct" >/dev/null
}

get_root_token() {
  # Mint a root PAT (api, read_user, write_repository) with 30-day expiry and print it
  # Prefer the container named "gitlab"; if not found, auto-detect by name pattern
  local ct=""
  # Collect running container names
  local names
  names=$(docker ps --format '{{.Names}}')
  # Exact match first
  if printf '%s\n' "$names" | grep -qx "gitlab"; then
    ct="gitlab"
  else
    # Fallback: name containing gitlab with common compose prefixes/suffixes
    while IFS= read -r n; do
      if [[ "$n" =~ (^|-)gitlab(-|$) ]]; then ct="$n"; break; fi
    done <<EOF
${names}
EOF
  fi
  if [ -z "${ct:-}" ]; then
    say "Could not find a running GitLab container. Is the stack up?"; return 1
  fi
  docker exec "$ct" bash -lc 'gitlab-rails runner "u=User.find_by_username('\''root'\''); t=u.personal_access_tokens.build(name: '\''macrobench-token'\'', scopes: [:api, :read_user, :write_repository, :create_runner, :manage_runner], expires_at: Date.today + 30); raw=SecureRandom.hex(24); t.set_token(raw); t.save!; puts raw"' 2>/dev/null
}

validate_pat() {
  local pat=$1
  # Returns 0 if valid (HTTP 200), non-zero otherwise
  local code rc
  set +e
  code=$(curl -s -o /dev/null -w "%{http_code}" --noproxy "*" --header "PRIVATE-TOKEN: ${pat}" "${GITLAB_URL}/api/v4/user")
  rc=$?
  set -e
  if [ $rc -ne 0 ]; then return 1; fi
  [ "$code" = "200" ]
}

create_project() {
  local pat=$1
  local name=${2:-sample-app}
  local resp body code pid
  resp=$(curl -s -w "\n%{http_code}" --header "PRIVATE-TOKEN: ${pat}" \
    --data-urlencode "name=${name}" \
    --data-urlencode "visibility=private" \
    "${GITLAB_URL}/api/v4/projects")
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [ "$code" = "201" ] || [ "$code" = "200" ]; then
    echo "$body" | jq -r '.id'
    return 0
  fi
  # If project exists already (e.g., rerun), fetch its id instead of failing
  pid=$(curl -s --header "PRIVATE-TOKEN: ${pat}" "${GITLAB_URL}/api/v4/projects?owned=true&search=${name}" | jq -r '.[] | select(.name=="'"$name"'") | .id' | head -n1)
  if [ -n "$pid" ]; then
    echo "$pid"; return 0
  fi
  say "Create project failed (HTTP $code). Body: $(echo "$body" | tr '\n' ' ' | cut -c1-300)"
  echo ""
}

push_sample_repo() {
  local project_id=$1
  local pat=$2
  # Allow override via SAMPLE_REPO_DIR; default to path relative to this script
  local src_dir="${SAMPLE_REPO_DIR:-$SCRIPT_DIR/../../rebound-sample-workloads}"
  if [ ! -d "$src_dir" ]; then
    say "Sample repo directory not found: $src_dir"
    say "Set SAMPLE_REPO_DIR to the path of rebound-sample-workloads and retry."
    exit 1
  fi
  local tmpdir
  tmpdir=$(mktemp -d)
  mkdir -p "$tmpdir/repo"
  cp -a "$src_dir/." "$tmpdir/repo/"
  pushd "$tmpdir/repo" >/dev/null
  # Remove any embedded git metadata (handles submodules or copied repos)
  find . -name .git -print0 2>/dev/null | xargs -0 -r rm -rf
  rm -f .gitmodules
  git init -q
  git config user.email "you@example.com"
  git config user.name "You"
  git add .
  git commit -qm "init sample workloads"
  git branch -M main
  # Derive remote URL and inject basic auth using root credentials
  proj=$(curl -s --header "PRIVATE-TOKEN: ${pat}" "${GITLAB_URL}/api/v4/projects/${project_id}")
  http_url=$(echo "$proj" | jq -r .http_url_to_repo)
  # Build remote using the host-side GITLAB_URL (supports http/https) and embed root creds
  # Extract path part after scheme+host
  path_part=${http_url#*://}
  path_part=${path_part#*/}
  # Extract host:port from GITLAB_URL and scheme
  hostport=${GITLAB_URL#http://}
  hostport=${hostport#https://}
  scheme=http
  [[ "$GITLAB_URL" == https://* ]] && scheme=https
  # Use the freshly minted PAT as the HTTP password (username=root)
  remote_url="$scheme://root:${pat}@${hostport}/${path_part}"
  git remote add origin "$remote_url" || git remote set-url origin "$remote_url"
  # Unprotect main so we can force-push on re-runs, then re-protect
  curl -s -X DELETE "${GITLAB_URL}/api/v4/projects/${project_id}/protected_branches/main" \
    -H "PRIVATE-TOKEN: ${pat}" >/dev/null 2>&1 || true
  git push -q --force -u origin main
  curl -s -X POST "${GITLAB_URL}/api/v4/projects/${project_id}/protected_branches" \
    -H "PRIVATE-TOKEN: ${pat}" \
    -d "name=main&push_access_level=40&merge_access_level=40" >/dev/null
  popd >/dev/null
}

main() {
  # Parse flags (--runner-token is optional; if omitted, runner is created via API)
  RUNNER_TOKEN=${GITLAB_RUNNER_TOKEN:-}
  while [ $# -gt 0 ]; do
    case "$1" in
      --runner-token)
        RUNNER_TOKEN=${2:-}; shift 2 ;;
      --runner-token=*)
        RUNNER_TOKEN="${1#*=}"; shift ;;
      -r)
        RUNNER_TOKEN=${2:-}; shift 2 ;;
      *)
        shift ;;
    esac
  done
  # Prompt for host if not already set
  if [ -z "${GITLAB_EXTERNAL_HOST:-}" ]; then
    prompt_host
  fi
  say "Starting Docker Compose stack..."
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
  wait_gitlab
  # Always mint a fresh PAT via gitlab-rails, ignoring any existing GITLAB_PAT
  unset GITLAB_PAT
  if ! PAT=$(get_root_token); then
    say "Failed to mint a root PAT via gitlab-rails."
    exit 1
  fi
  PAT=$(printf "%s" "${PAT}" | tr -d '\r\n')
  if [ -z "${PAT}" ] || ! validate_pat "$PAT"; then
    say "Failed to mint a working PAT programmatically. Is the GitLab container up and healthy?"
    exit 1
  fi
  echo "export GITLAB_PAT=$PAT" > "$SCRIPT_DIR/.macrobench.env"
  say "Wrote PAT to $SCRIPT_DIR/.macrobench.env."
  # Create runner via API if no token was passed
  if [ -z "${RUNNER_TOKEN:-}" ]; then
    say "Creating runner via API..."
    if ! RUNNER_TOKEN=$(create_runner_token "$PAT"); then
      exit 1
    fi
    say "Runner token obtained: ${RUNNER_TOKEN:0:16}..."
  fi
  register_runner "$RUNNER_TOKEN"
  PID=$(create_project "$PAT" "sample-app")
  if [ -z "$PID" ] || [ "$PID" = "null" ]; then
    say "Failed to create project"; exit 1
  fi
  say "Created project id=$PID"
  push_sample_repo "$PID" "$PAT"
  say "Bootstrap complete. Visit ${GITLAB_URL}/projects/${PID}"
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" ps
  echo -e "${GREEN}[bootstrap] Setup successful.${NC}"
}

main "$@"
