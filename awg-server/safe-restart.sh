#!/usr/bin/env bash
# safe-restart.sh — validate awg-server config, then reconcile the container.
#
# Wrapper around `docker compose --profile awg-server up -d awg-server` that
# first sanity-checks the rendered awg0.conf. Unlike sing-box, amneziawg-go
# doesn't ship a non-destructive `check` subcommand — wg-quick syntax is
# too forgiving for a real schema validation — so this script verifies
# structure: the file must have an [Interface] block with at minimum
# PrivateKey + ListenPort + Address, plus zero-or-more [Peer] blocks each
# with PublicKey + AllowedIPs. That catches the most common rotation
# failure (truncated render, dangling token).
#
# Uses `up -d` (not `restart`) so compose.yaml changes — cap set, env vars,
# digest pin — get applied. The bind-mount inode pinning that bites
# singbox-server (single-file mounts; see hazards.md) bites awg-server
# the same way: an in-place edit of awg0.conf without a container
# recreate leaves the running process with the old inode still mapped.
# Force-restart on no-op covers that.
#
# Configuration:
#   SINGBOX_SERVER_DIR  Repo root reference; awg-server/ is a sibling of
#                       singbox-server/. Falls back to <script-dir>/.. if
#                       unset (the in-repo layout). The compose file is
#                       resolved relative to this dir.
#   COMPOSE_FILE        Override the compose file. Defaults to the
#                       awg-server/compose.yaml next to this script.
#   COMPOSE_ENV_FILE    Optional --env-file. Falls back to a sibling .env.
#   NOTIFY              Optional notification script invoked on failure.
#
# Exit codes:
#   0  config valid, restart issued
#   1  config invalid OR required compose env vars unresolved, restart skipped
#   2  something else went wrong (docker missing, compose error)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWG_SERVER_DIR="${AWG_SERVER_DIR:-${SCRIPT_DIR}}"
CONFIG="${AWG_SERVER_DIR}/config/awg0.conf"
COMPOSE_FILE="${COMPOSE_FILE:-${AWG_SERVER_DIR}/compose.yaml}"
# Compose interpolates ${SINGBOX_SERVER_DIR} and ${VNIC_PRIMARY_IP} at
# parse time; without those resolved, the awg0.conf bind-mount path and
# port-bind collapse to blank, compose decides the existing container is
# "different", tries to recreate, hits a name conflict, and the inode-
# fallback below `docker restart`s the OLD container with the OLD image —
# silently losing any image bump. The pre-flight probe below catches this.
# Default to the master stack .env (two levels up — this layout puts
# egressor under /opt/stack/, with the master env at /opt/stack/.env).
# Override with COMPOSE_ENV_FILE for non-standard layouts. The repo-level
# /opt/stack/egressor/.env is intentionally NOT used — it can be
# incomplete (missing VNIC_PRIMARY_IP for example).
COMPOSE_ENV_FILE="${COMPOSE_ENV_FILE:-${AWG_SERVER_DIR}/../../.env}"
NOTIFY="${NOTIFY:-}"
DRY_RUN=0

[[ "${1:-}" == "--no-restart" ]] && DRY_RUN=1

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1"
  else
    echo "$1" >&2
  fi
}

# 1. Config must exist and be non-empty.
if [[ ! -s "${CONFIG}" ]]; then
  notify "🚫 awg-server safe-restart: \`${CONFIG}\` missing or empty, aborting"
  exit 1
fi

# 2. Structural check: [Interface] section with PrivateKey + ListenPort.
#    Address is intentionally NOT required — `awg setconf` rejects it (wg-quick
#    field), so the rendered config carries it as a comment / out-of-band only;
#    the container entrypoint sets the address via `ip addr add`. Empty-peer-set
#    is allowed (a freshly-rendered config with no AWG devices yet still passes;
#    the container starts but accepts no handshakes). awk is in coreutils — no
#    extra dependency.
awk_out=$(awk '
  /^\[Interface\]/ { in_iface=1; in_peer=0; next }
  /^\[Peer\]/      { in_iface=0; in_peer=1; peers++; have_pubkey=0; have_allowed=0; next }
  in_iface && /^[[:space:]]*PrivateKey[[:space:]]*=/  { have_priv=1 }
  in_iface && /^[[:space:]]*ListenPort[[:space:]]*=/  { have_port=1 }
  in_peer  && /^[[:space:]]*PublicKey[[:space:]]*=/   { have_pubkey=1 }
  in_peer  && /^[[:space:]]*AllowedIPs[[:space:]]*=/  { have_allowed=1 }
  in_peer  && /^\[/ { if (!have_pubkey || !have_allowed) bad_peer=1 }
  END {
    if (!have_priv)  print "missing [Interface] PrivateKey"
    if (!have_port)  print "missing [Interface] ListenPort"
    if (bad_peer)    print "a [Peer] block is missing PublicKey or AllowedIPs"
  }
' "${CONFIG}")

if [[ -n "${awk_out}" ]]; then
  notify "🚫 awg-server config invalid — restart NOT issued: ${awk_out}"
  echo "config check FAILED:" >&2
  echo "${awk_out}" >&2
  exit 1
fi

echo "config check passed"

# 3. Short-circuit if caller only wanted validation.
[[ ${DRY_RUN} -eq 1 ]] && exit 0

# 4. Reconcile via `up -d`. Two layouts supported, detected from the env
#    file (mirror of singbox-server/safe-restart.sh — see that script for
#    the longer rationale):
#
#    a) Master-stack: env file declares COMPOSE_PROJECT_NAME / COMPOSE_FILE.
#       Run from the master root without `-f` override, scoped to awg-server
#       via the trailing service arg. Required to avoid wiping unrelated
#       containers when the master project is loaded under a single name.
#
#    b) Standalone: env file has no project override. Use explicit `-f` +
#       `--env-file` against this service's compose.yaml.
master_root=""
if [[ -f "${COMPOSE_ENV_FILE}" ]] && \
   grep -qE '^(COMPOSE_PROJECT_NAME|COMPOSE_FILE)=' "${COMPOSE_ENV_FILE}"; then
  master_root="$(dirname "${COMPOSE_ENV_FILE}")"
fi
run_compose() {
  if [[ -n "${master_root}" ]]; then
    ( cd "${master_root}" && docker compose --profile awg-server "$@" )
  else
    local args=( --profile awg-server -f "${COMPOSE_FILE}" )
    [[ -f "${COMPOSE_ENV_FILE}" ]] && args+=( --env-file "${COMPOSE_ENV_FILE}" )
    docker compose "${args[@]}" "$@"
  fi
}

# 4a. Pre-flight: probe interpolation. Mirror of the singbox-server guard
#     (see that script for the longer rationale). If SINGBOX_SERVER_DIR or
#     VNIC_PRIMARY_IP is unresolved, the awg0.conf mount path and the port
#     bind collapse to "", compose recreate-fails on the name conflict, and
#     the inode-fallback docker-restarts the OLD container — silently
#     undoing any image-pin bump that just landed in compose.yaml.
required_vars='SINGBOX_SERVER_DIR|VNIC_PRIMARY_IP'
probe_stderr=$(run_compose config awg-server 2>&1 >/dev/null)
unresolved=$(echo "${probe_stderr}" \
  | awk -F'"' '/variable is not set/ {print $2}' \
  | grep -E "^(${required_vars})$" \
  | sort -u | tr '\n' ' ')
unresolved="${unresolved% }"
if [[ -n "${unresolved}" ]]; then
  notify "🚫 awg-server safe-restart: compose env vars unresolved — \`${unresolved}\`. Restart NOT issued, running container untouched. Set them in \`${COMPOSE_ENV_FILE}\` (see egressor/docs/quickstart.md) or export in your shell, then re-run."
  exit 1
fi

id_before=$(docker inspect awg-server -f '{{.Id}}' 2>/dev/null || true)
run_compose up -d awg-server
id_after=$(docker inspect awg-server -f '{{.Id}}' 2>/dev/null || true)

# Force-restart if `up -d` was a no-op. Single-file bind mount on
# config/awg0.conf pins the inode at create time; an in-place rewrite
# without recreate leaves the running process with the old config still
# mapped. See docs/hazards.md.
if [[ -n "${id_before}" && "${id_before}" == "${id_after}" ]]; then
  echo "up -d was a no-op; issuing docker restart to refresh bind-mount inode"
  docker restart awg-server
fi
