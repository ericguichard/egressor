#!/usr/bin/env bash
# check-upstream.sh — compare the running singbox-server's sing-box
# version against SagerNet/sing-box's latest GitHub release and report
# when a newer one exists. Mirrors awg-server/check-upstream.sh's shape.
#
# What it checks:
#   - The container's `sing-box version` output (semver, e.g. 1.13.10).
#   - The latest non-prerelease tag on github.com/SagerNet/sing-box.
#   - If `latest` > `current`, emit a bump report with the rebuild command.
#
# What it doesn't do: actually run the bump. That's bump-image.sh
# in this same directory, which pulls the new digest from ghcr, validates
# with `sing-box check` against the live config, and rewrites compose.yaml
# + safe-restarts. Auto-bumping defeats the digest-pin philosophy (see
# docs/architecture.md).
#
# Configuration:
#   SINGBOX_CONTAINER  Container name. Defaults to `singbox-server`.
#   NOTIFY             Optional notification script invoked with one arg
#                      (the report). Unset = print to stdout.
#   QUIET_OK           If set, suppress the "up to date" output (useful for
#                      cron). Newer-than-current always emits.

set -u

SINGBOX_CONTAINER="${SINGBOX_CONTAINER:-singbox-server}"
NOTIFY="${NOTIFY:-}"
QUIET_OK="${QUIET_OK:-}"

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1"
  fi
}

# Extract a bare semver (X.Y.Z) from arbitrary input. `sing-box version`
# emits "sing-box version 1.13.10\n\nEnvironment: ..."; GitHub release tags
# are `v1.13.10`. Returns empty on no match — caller treats that as
# "unknown" and skips the comparison rather than false-positive bumping.
extract_semver() {
  echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# Query GitHub for the latest non-prerelease release tag. Falls back to
# empty on API failure. The `releases/latest` endpoint already excludes
# pre-releases, which is the right semantics here — alpha/beta builds
# shouldn't trigger a bump notification.
upstream_latest_tag() {
  local repo="$1"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
    | grep -oE '"tag_name":[[:space:]]*"[^"]+"' \
    | head -1 \
    | sed -E 's/.*"([^"]+)"$/\1/'
}

if ! docker inspect "${SINGBOX_CONTAINER}" >/dev/null 2>&1; then
  notify "🚫 singbox-server upstream check: container \`${SINGBOX_CONTAINER}\` not running"
  exit 2
fi

cur_raw=$(docker exec "${SINGBOX_CONTAINER}" sing-box version 2>&1 | head -1)
cur=$(extract_semver "${cur_raw}")

upstream_raw=$(upstream_latest_tag SagerNet/sing-box)
upstream=$(extract_semver "${upstream_raw}")

if [[ -z "${cur}" || -z "${upstream}" ]]; then
  if [[ -z "${QUIET_OK}" ]]; then
    echo "sing-box version unknown (current=${cur:-?} latest=${upstream:-?}); skipping comparison"
  fi
  exit 0
fi

# Semver comparison via `sort -V`: if the larger of {cur, upstream} is
# upstream AND they differ, upstream is newer. `sort -V` handles
# multi-digit minor/patch correctly (1.13.10 > 1.13.9, not the lex order).
newest=$(printf '%s\n%s\n' "${cur}" "${upstream}" | sort -V | tail -1)

if [[ "${cur}" == "${upstream}" || "${newest}" == "${cur}" ]]; then
  # Equal, or current is somehow newer than the published release (running
  # a self-built nightly?). Either way: no bump suggestion.
  if [[ -z "${QUIET_OK}" ]]; then
    echo "sing-box up to date (${cur} ≥ upstream ${upstream})"
  fi
  exit 0
fi

# Format the bump report. Multi-line so notification channels with
# markdown render readably.
report=$'⬆️ sing-box upstream has a newer release:\n'
report+="  - sing-box: ${cur} → ${upstream}"$'\n'
report+=$'\nRelease notes: https://github.com/SagerNet/sing-box/releases/tag/'"${upstream_raw}"
report+=$'\nBump command (registry-pulled, digest-pinned):\n'
report+=$'  ./bump-image.sh             (run from this dir — rewrites pin + safe-restart)\n'
report+=$'  ./bump-image.sh --check-only (dry-run: prints digest swap, runs `sing-box check` against the live config, no rewrite)'
notify "${report}"
exit 0
