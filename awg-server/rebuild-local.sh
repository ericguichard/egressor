#!/usr/bin/env bash
# rebuild-local.sh — local-build counterpart to bump-image.sh.
#
# When `bump-image.sh` is the right tool: registry-pulled deployments where
# `amneziavpn/amneziawg-go:latest` exists for your platform. As of 2026-04
# the upstream image is amd64-only, so ARM hosts can't use it and need to
# build from source. The build context lives at `awg-server/build/`
# (Dockerfile + entrypoint.sh, sibling of compose.yaml).
#
# Flow:
#   1. docker build --no-cache amneziawg:local from the build context.
#   2. Read the new image's local Id (sha256). The image is never pushed,
#      so RepoDigests is empty — Id is the only stable handle.
#   3. Update the @sha256:... pin in egressor/awg-server/compose.yaml.
#   4. safe-restart.sh to pick up the new digest.
#   5. Verify with `amneziawg-go --version` + `awg --version` from the
#      running container.
#
# When to run:
#   - check.sh's weekly remote routine opens a GitHub issue
#     when amnezia-vpn/amneziawg-go or /amneziawg-tools master HEAD is
#     newer than the embedded baseline. Closing the issue means "rebuilt"
#     or "skipping this week"; closing it without rebuilding means the
#     next render of the issue (next week) will reopen if upstream advances.
#   - On security advisories (rare for AWG; the Amnezia team announces
#     via their TG channel, not via GitHub releases).
#
# Configuration:
#   BUILD_DIR       Where the Dockerfile lives. Defaults to <script-dir>/build.
#                   Override if you keep the build context elsewhere.
#   IMAGE_TAG       Tag for the built image. Defaults to amneziawg:local.
#   AWG_SERVER_DIR  Defaults to <script-dir>; holds compose.yaml + safe-restart.sh.
#   NOTIFY          Optional notification script (Discord webhook etc.).
#
# Flags:
#   --check-only   Build + resolve new digest, print the diff, but skip the
#                  pin rewrite + restart. Mirrors bump-image.sh's flag.
#                  Note: the build still runs (that's the only way to know
#                  what the new digest would be). The new image bytes land
#                  in the local image store untagged-by-digest; compose
#                  still resolves the deployed image by its pinned @sha256
#                  so awg-server stays on the previous build.
#
# Exit codes:
#   0  rebuild + restart succeeded (or no-op: image content unchanged, or
#      --check-only completed).
#   1  build failed.
#   2  pin rewrite or restart failed.
#   3  pre-flight failed (compose.yaml unreadable, build context missing).

set -u

CHECK_ONLY=0
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
IMAGE_TAG="${IMAGE_TAG:-amneziawg:local}"
AWG_SERVER_DIR="${AWG_SERVER_DIR:-${SCRIPT_DIR}}"
COMPOSE="${AWG_SERVER_DIR}/compose.yaml"
NOTIFY="${NOTIFY:-}"

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1"
  fi
}

# Pre-flight: build context + compose readable.
if [[ ! -f "${BUILD_DIR}/Dockerfile" ]]; then
  notify "🚫 rebuild-local: \`${BUILD_DIR}/Dockerfile\` missing — set BUILD_DIR or restore the build context"
  exit 3
fi
if [[ ! -w "${COMPOSE}" ]]; then
  notify "🚫 rebuild-local: \`${COMPOSE}\` not writable — pin can't be updated"
  exit 3
fi

cur_pin=$(grep -oE 'amneziawg:local@sha256:[a-f0-9]{64}' "${COMPOSE}" | head -1)
if [[ -z "${cur_pin}" ]]; then
  notify "🚫 rebuild-local: \`${COMPOSE}\` doesn't contain an \`amneziawg:local@sha256:...\` pin to update"
  exit 3
fi
cur_digest="${cur_pin#amneziawg:local@}"

# 1. Build. --no-cache forces a fresh `git clone` of upstream so we don't
#    sit on a cached layer that hides new commits. Output to stderr lets
#    the operator see progress when run interactively.
echo "── Building ${IMAGE_TAG} from ${BUILD_DIR} (--no-cache) ────────────"
if ! (cd "${BUILD_DIR}" && docker build --no-cache -t "${IMAGE_TAG}" . ); then
  notify "❌ rebuild-local: docker build failed. Pin unchanged at ${cur_digest}; running container untouched."
  exit 1
fi

# 2. Resolve the new digest. Local-built images have no RepoDigests entry
#    (never pushed), so use Id directly — Docker's content-addressed image
#    Id is exactly what `image: tag@sha256:...` resolves against locally.
new_digest=$(docker image inspect "${IMAGE_TAG}" --format '{{.Id}}' 2>/dev/null)
if [[ -z "${new_digest}" || "${new_digest}" != sha256:* ]]; then
  notify "🚫 rebuild-local: could not resolve Id for ${IMAGE_TAG} after build. Pin unchanged."
  exit 2
fi

if [[ "${new_digest}" == "${cur_digest}" ]]; then
  notify "ℹ️ rebuild-local: rebuild produced the same digest ${new_digest} — no-op (upstream commits identical to last build)."
  exit 0
fi

# Dry-run exit point. Build done, digest resolved, diff known — stop
# before mutating compose.yaml or restarting awg-server. The new image
# bytes are now in the local image store; compose still resolves the
# deployed image by its pinned @sha256 so the running container is
# unaffected. Operator re-runs without --check-only to apply (the second
# build will produce a different digest due to timestamp variance, so
# the digest reported here is informational, not the one that ships).
if [[ ${CHECK_ONLY} -eq 1 ]]; then
  echo "check-only: ${cur_digest} → ${new_digest} would apply"
  exit 0
fi

# 3. Rewrite the pin. Use a precise regex (the @sha256:<hex> suffix on the
#    amneziawg:local line) so unrelated digest pins on other images in the
#    same compose can't accidentally match.
if ! sed -i "s|amneziawg:local@sha256:[a-f0-9]\{64\}|amneziawg:local@${new_digest}|" "${COMPOSE}"; then
  notify "🚫 rebuild-local: failed to rewrite pin in ${COMPOSE}. Image built but compose unchanged."
  exit 2
fi

# Sanity-check the rewrite landed.
if ! grep -q "amneziawg:local@${new_digest}" "${COMPOSE}"; then
  notify "🚫 rebuild-local: pin rewrite did not stick in ${COMPOSE}. Inspect manually."
  exit 2
fi

# 4. Apply via safe-restart (validates config + bounces container).
echo "── Applying via safe-restart.sh ────────────────────────────────────"
if ! "${AWG_SERVER_DIR}/safe-restart.sh"; then
  notify "🚨 rebuild-local: safe-restart.sh failed AFTER pin rewrite. Pin in compose: ${new_digest}; running container may be on the previous image. Inspect with \`docker logs awg-server\`."
  exit 2
fi

# 5. Verify the new versions (optional but cheap).
go_ver=$(docker exec awg-server amneziawg-go --version 2>&1 | head -1 || echo "<unknown>")
tools_ver=$(docker exec awg-server awg --version 2>&1 | head -1 || echo "<unknown>")

notify "✅ rebuild-local: rebuilt ${IMAGE_TAG}.
  digest: ${cur_digest} → ${new_digest}
  amneziawg-go: ${go_ver}
  amneziawg-tools: ${tools_ver}
  compose.yaml updated, awg-server restarted."
exit 0
