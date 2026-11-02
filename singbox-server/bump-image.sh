#!/usr/bin/env bash
# bump-image.sh — controlled upgrade of the sing-box server image.
#
# The singbox-server compose pins the image by digest (not :latest) so a
# compromise of ghcr.io/sagernet can't silently push a backdoor to a
# public-facing VPN. The tradeoff is that legitimate upgrades require a
# conscious step — this script.
#
# What it does:
#   1. Pulls the current :latest tag and resolves its digest.
#   2. Extracts the *currently pinned* digest from compose.yaml.
#   3. If unchanged, exits 0 quietly (nothing to do).
#   4. If different:
#      - Runs `sing-box version` against the new image to confirm it runs.
#      - Runs `sing-box check` against the live config.json against the new
#        image — catches schema-shape changes (fields deprecated between
#        versions, new required fields) before they take the server down.
#      - Rewrites compose.yaml with the new digest.
#      - Bounces singbox-server via safe-restart.sh.
#      - Notifies on success/failure if NOTIFY is set.
#
# Call from cron (suggested monthly) or manually when release notes
# warrant. `--check-only` skips the compose rewrite for dry runs.
#
# Configuration:
#   SINGBOX_SERVER_DIR  Directory holding compose.yaml + config.json + hy2.*.
#                       Defaults to this script's own dir.
#   NOTIFY              Optional notification script.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_SERVER_DIR="${SINGBOX_SERVER_DIR:-${SCRIPT_DIR}}"
COMPOSE="${SINGBOX_SERVER_DIR}/compose.yaml"
CONFIG="${SINGBOX_SERVER_DIR}/config.json"
NOTIFY="${NOTIFY:-}"
IMAGE_REPO="ghcr.io/sagernet/sing-box"
CHECK_ONLY=0

[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

# Pull the floating tag into local cache. `docker pull` will re-fetch the
# manifest even if we already have a layer cached, so this reliably
# surfaces the *current* digest of :latest without manual inspection.
pull_out=$(docker pull "${IMAGE_REPO}:latest" 2>&1) || {
  echo "docker pull failed:" >&2
  echo "${pull_out}" >&2
  exit 2
}

# Extract the digest from `docker inspect`'s RepoDigests — this is the
# canonical "what :latest resolves to right now" reference, not sensitive
# to local tag caching.
new_digest=$(docker image inspect "${IMAGE_REPO}:latest" \
  --format '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}' \
  | awk -F'@' -v r="${IMAGE_REPO}" '$1==r {print $2; exit}')

if [[ -z "${new_digest}" || "${new_digest}" != sha256:* ]]; then
  echo "could not resolve ${IMAGE_REPO}:latest digest" >&2
  exit 2
fi

# Extract the currently-pinned digest. Strip the leading `@` so the
# comparison against new_digest (which comes from awk-split-on-@) is
# apples-to-apples.
cur_digest=$(grep -oE '@sha256:[a-f0-9]{64}' "${COMPOSE}" | head -1 | tr -d '@')

if [[ "${cur_digest}" == "${new_digest}" ]]; then
  echo "already on ${new_digest}, nothing to do"
  exit 0
fi

# Validate the new image before touching compose — quicker to fail here
# than to recreate the container and then roll back. Two probes: binary
# boots (`sing-box version`), and schema-validates the live config.
new_ref="${IMAGE_REPO}:latest@${new_digest}"

ver=$(docker run --rm "${new_ref}" version 2>&1 | head -1) || {
  notify "🚫 singbox image bump **ABORTED**: \`sing-box version\` failed on new image ${new_digest:0:19}…"
  echo "new image failed to run: ${ver}" >&2
  exit 1
}

check_out=$(docker run --rm \
  -v "${CONFIG}:/etc/sing-box/config.json:ro" \
  -v "${SINGBOX_SERVER_DIR}/hy2.crt:/etc/sing-box/hy2.crt:ro" \
  -v "${SINGBOX_SERVER_DIR}/hy2.key:/etc/sing-box/hy2.key:ro" \
  "${new_ref}" check -c /etc/sing-box/config.json 2>&1)
check_rc=$?

if [[ ${check_rc} -ne 0 ]]; then
  snippet=$(echo "${check_out}" | tr '\n' ' ' | cut -c1-400)
  notify "🚫 singbox image bump **ABORTED**: new image fails \`sing-box check\` against live config. Error: \`${snippet}\`. Pin stays on old digest."
  echo "new image config check FAILED:" >&2
  echo "${check_out}" >&2
  exit 1
fi

if [[ ${CHECK_ONLY} -eq 1 ]]; then
  echo "check-only: ${cur_digest} → ${new_digest} (${ver}) would apply"
  exit 0
fi

# Rewrite compose. Anchored to the image line; sed -i keeps surrounding
# comments intact. The `@` in digests is the natural field separator;
# escape nothing since digests are hex-only.
sed -i -E "s|^(\s*image:\s*${IMAGE_REPO}:latest@)sha256:[a-f0-9]{64}|\1${new_digest}|" "${COMPOSE}"

# Verify the rewrite actually landed (sed silently no-ops on miss).
if ! grep -q "${new_digest}" "${COMPOSE}"; then
  notify "🚫 singbox image bump **FAILED**: sed didn't update ${COMPOSE##*/} — manual intervention required"
  echo "sed didn't update compose, restore manually" >&2
  exit 2
fi

# Reconcile. safe-restart.sh uses `up -d` so the new digest gets picked
# up (not just a process restart against the old container).
if ! "${SINGBOX_SERVER_DIR}/safe-restart.sh"; then
  notify "🚨 singbox image bump **FAILED AT RESTART**: compose has new digest but safe-restart errored. Check container state; rollback: \`sed -i 's|${new_digest}|${cur_digest}|' ${COMPOSE}\` then \`./safe-restart.sh\`"
  exit 1
fi

notify "⬆️ singbox image bumped: \`${cur_digest:0:19}…\` → \`${new_digest:0:19}…\` (${ver}). Container reconciled."
echo "bumped: ${cur_digest} → ${new_digest}"
echo "version: ${ver}"

# --- Persist the pin ------------------------------------------------------
# Until 2026-08-06 the script stopped here, so every successful bump left an
# uncommitted diff in the working tree of a public repo and git no longer
# described what was actually deployed. Committing here (AFTER safe-restart
# succeeded) means the pin in git always reflects a digest that has been
# validated AND is live.
#
# Deliberately conservative:
#   - commits ONLY compose.yaml, by explicit pathspec, so an unrelated edit
#     sitting in the tree is never swept into an automated commit;
#   - refuses to act on a detached HEAD or a non-main branch (someone is
#     mid-work; leave the diff for them);
#   - never rebases or force-pushes. If origin has diverged we notify and
#     stop, exactly like the sesame auto-push policy: a code repo is resolved
#     by a human;
#   - a push failure does NOT fail the run. The bump itself succeeded and the
#     container is healthy; the pin being unpushed is a bookkeeping problem,
#     and exiting non-zero here would mask that with a false "bump failed".
#     It is announced loudly instead, because an unpushed pin is invisible.
cd "${SINGBOX_SERVER_DIR}" || exit 0

branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [[ "${branch}" != "main" ]]; then
  notify "⚠️ singbox pin NOT committed: repo is on \`${branch:-detached HEAD}\`, not main. Commit \`${COMPOSE##*/}\` by hand."
  exit 0
fi

# ~25-30% of fresh TCP connections to GitHub's Frankfurt edge are blackholed
# from this host, so network verbs get the same retry treatment as sync.sh.
git_net() {
  local n=1 max=5
  while true; do
    if timeout 25 git "$@"; then return 0; fi
    if [[ "${n}" -ge "${max}" ]]; then return 1; fi
    echo "git $1: attempt ${n}/${max} failed (network), retrying in 5s" >&2
    n=$((n + 1))
    sleep 5
  done
}

if ! git commit -q -m "singbox-server: bump pinned image digest to ${ver}" \
       -m "Applied and verified by bump-image.sh: the new image passed \`sing-box version\` and \`sing-box check\` against the live config, and safe-restart.sh reconciled the container before this commit." \
       -- "${COMPOSE}"; then
  notify "⚠️ singbox pin bumped and live, but \`git commit\` failed — commit ${COMPOSE##*/} by hand."
  exit 0
fi

if ! git_net push origin main; then
  notify "⚠️ singbox pin committed locally but **PUSH FAILED** (network, or origin/main has diverged). Resolve by hand: the deployed digest is only in the local repo."
  exit 0
fi

echo "pin committed and pushed"
