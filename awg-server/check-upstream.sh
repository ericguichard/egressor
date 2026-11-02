#!/usr/bin/env bash
# check-upstream.sh — compare the running awg-server's amneziawg-go +
# amneziawg-tools versions against upstream master HEAD and report when
# a newer commit exists. Designed for source-built deployments (the ARM-
# host path that can't pull amneziavpn/amneziawg-go from Docker Hub) —
# `bump-image.sh` handles the digest-pin upgrade for registry-pulled
# deployments and is the right tool there.
#
# What it checks:
#   - amnezia-vpn/amneziawg-go master HEAD commit date vs the container's
#     `amneziawg-go --version` output (which the daemon stamps with the
#     upstream commit date in the form 0.0.YYYYMMDD).
#   - amnezia-vpn/amneziawg-tools master HEAD commit date vs the container's
#     `awg --version` (also a date-stamped form).
#
# What it doesn't do: actually rebuild the image. That's `rebuild-local.sh`
# in this same directory (build + read new Id + rewrite the @sha256:... pin
# in compose.yaml + safe-restart) — or `bump-image.sh` for registry-pulled
# deployments where upstream publishes amneziavpn/amneziawg-go for your
# platform (amd64 only as of 2026-04).
#
# Sibling: a weekly remote agent (the `awg-upstream-check` routine) opens
# a GitHub issue at ericguichard/egressor when this same comparison flags
# a newer upstream — that's the user-facing notification path. This script
# is the local-host equivalent for ad-hoc operator checks.
#
# Configuration:
#   AWG_CONTAINER  Container name. Defaults to `awg-server` (the egressor-
#                  managed name). Set to `amneziawg` for legacy deploys.
#   NOTIFY         Optional notification script invoked with one arg
#                  (the report). Unset = print to stdout.
#   QUIET_OK       If set, suppress the "up to date" output (useful for
#                  cron). Newer-than-current always emits.

set -u

AWG_CONTAINER="${AWG_CONTAINER:-awg-server}"
NOTIFY="${NOTIFY:-}"
QUIET_OK="${QUIET_OK:-}"

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1"
  fi
}

# Helper: extract the YYYYMMDD date from a version string of the form
# `<tool> 0.0.YYYYMMDD` or `<tool> v<major>.<minor>.YYYYMMDD`. Returns
# empty string if no match — caller should treat that as "unknown".
extract_date() {
  echo "$1" | grep -oE '20[0-9]{6}' | head -1
}

# Query GitHub's REST API for the default branch's HEAD commit date.
# Returns YYYYMMDD. Falls back to empty on API failure (rate limits, etc).
upstream_head_date() {
  local repo="$1"
  curl -fsSL "https://api.github.com/repos/${repo}/commits?per_page=1" 2>/dev/null \
    | grep -oE '"date":\s*"20[0-9]{2}-[0-9]{2}-[0-9]{2}' \
    | head -1 \
    | grep -oE '20[0-9]{6}' \
    | head -1 \
    || echo ""
}
# Note: the regex collapses YYYY-MM-DD into YYYYMMDD via the trailing grep —
# avoids depending on jq. If the API output format changes, this breaks
# silently → empty result → "unknown" branch below, no false-positive
# bump alerts.

if ! docker inspect "${AWG_CONTAINER}" >/dev/null 2>&1; then
  notify "🚫 awg-server upstream check: container \`${AWG_CONTAINER}\` not running"
  exit 2
fi

go_ver=$(docker exec "${AWG_CONTAINER}" amneziawg-go --version 2>&1 | head -1)
tools_ver=$(docker exec "${AWG_CONTAINER}" awg --version 2>&1 | head -1)
go_cur=$(extract_date "${go_ver}")
tools_cur=$(extract_date "${tools_ver}")

go_up=$(upstream_head_date amnezia-vpn/amneziawg-go)
tools_up=$(upstream_head_date amnezia-vpn/amneziawg-tools)

bumps=()
if [[ -n "${go_cur}" && -n "${go_up}" && "${go_up}" -gt "${go_cur}" ]]; then
  bumps+=("amneziawg-go: ${go_cur} → ${go_up}")
fi
if [[ -n "${tools_cur}" && -n "${tools_up}" && "${tools_up}" -gt "${tools_cur}" ]]; then
  bumps+=("amneziawg-tools: ${tools_cur} → ${tools_up}")
fi

if [[ ${#bumps[@]} -eq 0 ]]; then
  if [[ -z "${QUIET_OK}" ]]; then
    echo "amneziawg-go up to date (${go_cur:-unknown})"
    echo "amneziawg-tools up to date (${tools_cur:-unknown})"
  fi
  exit 0
fi

# Format the bump report. Multi-line so notification channels with
# markdown render readably; the call sites concatenate with separators.
report=$'⬆️ AmneziaWG upstream has newer commits:\n'
for line in "${bumps[@]}"; do
  report+="  - ${line}"$'\n'
done
report+=$'\nRebuild: `./rebuild-local.sh` (run from this dir — does the docker build, updates the @sha256:... pin, and safe-restarts).'
notify "${report}"
exit 0
