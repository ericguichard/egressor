#!/usr/bin/env bash
# safe-restart.sh — validate config, then reconcile singbox-server.
#
# Wrapper around `docker compose up -d singbox-server` that first runs
# `sing-box check` against the config.json that's about to be mounted. A JSON
# typo, missing key, or schema regression would otherwise only surface when
# the container starts, by which point sing-box has already died — and if the
# old container was running with the old config, recreating it replaces a
# working process with a broken one. Running check in a throwaway container
# lets us fail fast with the old container still serving traffic.
#
# Uses `up -d` (not `restart`) so compose.yaml changes — cap set, env vars,
# volume mounts — get applied on next invocation. `restart` only bounces
# the process with the existing container config; operational rollouts of
# compose edits would silently no-op with the old shape still live.
#
# Configuration via env vars (set or sourced from the repo .env):
#   SINGBOX_SERVER_DIR  Directory holding config.json + hy2.crt + hy2.key + this
#                       script's compose.yaml. Defaults to the script's own dir.
#   COMPOSE_FILE        Override the compose file used. Defaults to
#                       ${SINGBOX_SERVER_DIR}/compose.yaml.
#   COMPOSE_ENV_FILE    Optional --env-file passed to docker compose. If unset
#                       and a sibling .env exists, that's used.
#   NOTIFY              Optional path to a notification script invoked on
#                       failure with one argument: the error summary.
#                       Receives a single string. Unset = print to stderr.
#
# Exit codes:
#   0  config valid, restart issued
#   1  config invalid OR required compose env vars unresolved, restart skipped
#   2  something else went wrong (docker missing, compose error)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_SERVER_DIR="${SINGBOX_SERVER_DIR:-${SCRIPT_DIR}}"
CONFIG="${SINGBOX_SERVER_DIR}/config.json"
COMPOSE_FILE="${COMPOSE_FILE:-${SINGBOX_SERVER_DIR}/compose.yaml}"
# Compose interpolates ${PUID}/${PGID}/${SINGBOX_SERVER_DIR}/${INCOMING_IP_1}
# at parse time; without those vars resolved, mounts and `user:` collapse to
# blank, compose decides the existing container is "different", tries to
# recreate it, hits a name conflict on `singbox-server`, and the inode-fallback
# below `docker restart`s the OLD container with the OLD image — silently
# losing any image-pin bump that just happened.
# Default to the master stack .env (two levels up — this layout puts
# egressor under /opt/stack/, with the master env at /opt/stack/.env).
# Override with COMPOSE_ENV_FILE for non-standard layouts.
COMPOSE_ENV_FILE="${COMPOSE_ENV_FILE:-${SINGBOX_SERVER_DIR}/../../.env}"
NOTIFY="${NOTIFY:-}"
IMAGE="ghcr.io/sagernet/sing-box:latest"
DRY_RUN=0

[[ "${1:-}" == "--no-restart" ]] && DRY_RUN=1

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1"
  else
    echo "$1" >&2
  fi
}

# 1. Config file must exist and be non-empty — catches a truncated edit
#    that would otherwise make sing-box crash immediately on start.
if [[ ! -s "${CONFIG}" ]]; then
  notify "🚫 singbox-server safe-restart: \`${CONFIG}\` missing or empty, aborting"
  exit 1
fi

# 2. Run sing-box check inside a throwaway container. We deliberately use the
#    same image the service runs (":latest" pin follows the running stack).
#    --rm so this leaves no container behind; -v ro because check reads only.
#    The hy2 cert/key mounts match compose.yaml — `check` validates that the
#    paths referenced by config.json are readable (not just that the JSON is
#    well-formed), so missing mounts would produce a false negative.
check_output=$(docker run --rm \
  -v "${CONFIG}:/etc/sing-box/config.json:ro" \
  -v "${SINGBOX_SERVER_DIR}/hy2.crt:/etc/sing-box/hy2.crt:ro" \
  -v "${SINGBOX_SERVER_DIR}/hy2.key:/etc/sing-box/hy2.key:ro" \
  "${IMAGE}" check -c /etc/sing-box/config.json 2>&1)
check_rc=$?

if [[ ${check_rc} -ne 0 ]]; then
  # Trim to a manageable length — most notification channels limit message
  # size, and sing-box parse errors are often short but can include multi-line
  # JSON context. Take the first 400 chars and backtick-wrap for readability.
  snippet=$(echo "${check_output}" | tr '\n' ' ' | cut -c1-400)
  notify "🚫 singbox-server config invalid — restart NOT issued. Error: \`${snippet}\`"
  echo "config check FAILED:" >&2
  echo "${check_output}" >&2
  exit 1
fi

echo "config check passed"

# 3. Short-circuit if caller only wanted validation.
[[ ${DRY_RUN} -eq 1 ]] && exit 0

# 4. Config valid — reconcile via `up -d`. This recreates the container
#    if compose.yaml changed (cap set, env, mounts) and is a plain restart
#    otherwise. Two layouts are supported, detected from the env file:
#
#    a) Master-stack layout: env file declares COMPOSE_PROJECT_NAME and
#       (typically) COMPOSE_FILE, indicating egressor is embedded in a
#       larger compose project (e.g. /opt/stack/.env with PROJECT_NAME=aio
#       and COMPOSE_FILE pointing at a master compose with `include:`s).
#       In that case we MUST run compose from the master root with no
#       `-f` override — passing `-f path/to/this/compose.yaml` while
#       PROJECT_NAME=aio is loaded makes compose treat the singular
#       service file as the entire project and remove every other
#       container in the stack. (Yes, learned this the hard way.)
#
#    b) Standalone layout: env file has no PROJECT_NAME / FILE override.
#       Run with explicit `-f` and `--env-file` pointing at this service's
#       compose.yaml. This is what a public egressor deploy looks like.
#
#    Both modes scope the operation to `singbox-server` via the trailing
#    service argument so `up -d` only acts on this service even when the
#    master compose includes many.
master_root=""
if [[ -f "${COMPOSE_ENV_FILE}" ]] && \
   grep -qE '^(COMPOSE_PROJECT_NAME|COMPOSE_FILE)=' "${COMPOSE_ENV_FILE}"; then
  master_root="$(dirname "${COMPOSE_ENV_FILE}")"
fi
run_compose() {
  if [[ -n "${master_root}" ]]; then
    ( cd "${master_root}" && docker compose --profile singbox-server "$@" )
  else
    local args=( --profile singbox-server -f "${COMPOSE_FILE}" )
    [[ -f "${COMPOSE_ENV_FILE}" ]] && args+=( --env-file "${COMPOSE_ENV_FILE}" )
    docker compose "${args[@]}" "$@"
  fi
}

# 4a. Pre-flight: probe interpolation. The hazard documented in the header
#     comment is that an empty SINGBOX_SERVER_DIR / INCOMING_IP_1 /
#     PUID / PGID makes compose see a "different" container shape, fail to
#     recreate on the `singbox-server` name conflict, and the inode-fallback
#     below docker-restarts the OLD container — silently undoing any
#     image-pin bump that just landed in compose.yaml. `compose config` does
#     the same interpolation `up -d` will, without touching state, and emits
#     one `WARN[...] The "FOO" variable is not set.` per unresolved var to
#     stderr. Parse those, fail closed before a single byte reaches Docker.
required_vars='SINGBOX_SERVER_DIR|INCOMING_IP_1|PUID|PGID'
probe_stderr=$(run_compose config singbox-server 2>&1 >/dev/null)
unresolved=$(echo "${probe_stderr}" \
  | awk -F'"' '/variable is not set/ {print $2}' \
  | grep -E "^(${required_vars})$" \
  | sort -u | tr '\n' ' ')
unresolved="${unresolved% }"
if [[ -n "${unresolved}" ]]; then
  notify "🚫 singbox-server safe-restart: compose env vars unresolved — \`${unresolved}\`. Restart NOT issued, running container untouched. Set them in \`${COMPOSE_ENV_FILE}\` (see egressor/docs/quickstart.md) or export in your shell, then re-run."
  exit 1
fi

id_before=$(docker inspect singbox-server -f '{{.Id}}' 2>/dev/null || true)
run_compose up -d singbox-server
id_after=$(docker inspect singbox-server -f '{{.Id}}' 2>/dev/null || true)

# Force-restart if `up -d` was a no-op (container ID unchanged). sing-box's
# config.json, hy2.crt, and hy2.key are *single-file bind mounts*, which pin
# the host inode at container-create time — rewriting the file on disk leaves
# the running process with the old content still mapped. `up -d` only
# recreates when compose.yaml/env changed, so cert rotations + config edits
# would silently land on disk but not in the container. `docker restart`
# re-resolves the bind-mount inode. See docs/hazards.md.
if [[ -n "${id_before}" && "${id_before}" == "${id_after}" ]]; then
  echo "up -d was a no-op; issuing docker restart to refresh bind-mount inodes"
  docker restart singbox-server
fi
