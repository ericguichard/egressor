#!/usr/bin/env bash
# bump-image.sh — controlled upgrade of the awg-server (amneziawg-go) image.
#
# Mirrors singbox-server/bump-image.sh. The compose pins by digest
# so a Docker Hub credential compromise can't silently push a backdoor; the
# tradeoff is that legitimate upgrades require this conscious bump step.
#
# What it does:
#   1. Pulls amneziavpn/amneziawg-go:latest.
#   2. Resolves the new digest via `docker buildx imagetools inspect`
#      (the multi-arch index digest, not a single-platform manifest).
#   3. If unchanged, exits 0.
#   4. Otherwise rewrites compose.yaml + bounces awg-server via safe-restart.
#
# Suggested cadence: monthly cron, or whenever Amnezia releases a new
# amneziawg-go version (their GitHub releases page).
#
# Configuration:
#   AWG_SERVER_DIR  Defaults to <script-dir>.
#   NOTIFY          Optional notification script.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWG_SERVER_DIR="${AWG_SERVER_DIR:-${SCRIPT_DIR}}"
COMPOSE="${AWG_SERVER_DIR}/compose.yaml"
NOTIFY="${NOTIFY:-}"
IMAGE_REPO="amneziavpn/amneziawg-go"
CHECK_ONLY=0

[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

# Resolve the multi-arch index digest. `docker buildx imagetools inspect`
# always returns the index digest first, regardless of the host's native
# arch. This matters because plain `docker pull` + `docker image inspect`
# would return the per-platform manifest digest (different value) on a
# host that can pull only one arch. Pinning the index digest is what
# both x86 and ARM hosts will match against.
inspect_out=$(docker buildx imagetools inspect "${IMAGE_REPO}:latest" 2>&1) || {
  echo "buildx imagetools inspect failed:" >&2
  echo "${inspect_out}" >&2
  exit 2
}
new_digest=$(echo "${inspect_out}" | awk '/^Digest:/ {print $2; exit}')

if [[ -z "${new_digest}" || "${new_digest}" != sha256:* ]]; then
  echo "could not resolve ${IMAGE_REPO}:latest digest from inspect output" >&2
  exit 2
fi

cur_digest=$(grep -oE '@sha256:[a-f0-9]{64}' "${COMPOSE}" | head -1 | tr -d '@')

if [[ "${cur_digest}" == "${new_digest}" ]]; then
  echo "already on ${new_digest}, nothing to do"
  exit 0
fi

# Validate the new image is at least pullable on this host's arch. amneziawg-go
# is amd64-only as of 2026-04 (no arm64 manifest); a `docker pull` on an
# ARM host would fail here, surfacing the platform mismatch loudly instead
# of a runtime "no matching manifest" error post-bump.
new_ref="${IMAGE_REPO}:latest@${new_digest}"
pull_out=$(docker pull "${new_ref}" 2>&1) || {
  notify "🚫 awg image bump **ABORTED**: \`docker pull\` failed on new digest. Likely a platform-mismatch (image is amd64-only). Pin stays on old digest."
  echo "docker pull failed for new image:" >&2
  echo "${pull_out}" >&2
  exit 1
}

if [[ ${CHECK_ONLY} -eq 1 ]]; then
  echo "check-only: ${cur_digest} → ${new_digest} would apply"
  exit 0
fi

# Rewrite compose pinning. Anchored to the image line; sed -i preserves
# surrounding comments and the :latest tag form (digest replaces only the
# hex hash itself).
sed -i -E "s|^(\s*image:\s*${IMAGE_REPO}:latest@)sha256:[a-f0-9]{64}|\1${new_digest}|" "${COMPOSE}"

if ! grep -q "${new_digest}" "${COMPOSE}"; then
  notify "🚫 awg image bump **FAILED**: sed didn't update ${COMPOSE##*/} — manual intervention required"
  echo "sed didn't update compose, restore manually" >&2
  exit 2
fi

# Reconcile.
if ! "${AWG_SERVER_DIR}/safe-restart.sh"; then
  notify "🚨 awg image bump **FAILED AT RESTART**: compose has new digest but safe-restart errored. Rollback: \`sed -i 's|${new_digest}|${cur_digest}|' ${COMPOSE}\` then \`./safe-restart.sh\`"
  exit 1
fi

notify "⬆️ awg-server image bumped: \`${cur_digest:0:19}…\` → \`${new_digest:0:19}…\`. Container reconciled."
echo "bumped: ${cur_digest} → ${new_digest}"
