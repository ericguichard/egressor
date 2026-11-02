#!/usr/bin/env bash
# publish-configs-onedrive.sh — mirror freshly-rendered per-user sing-box client
# bundles from srv/p/<secret>/ to OneDrive (Desktop/Configs/<user>/singbox/).
#
# render.py writes the new client JSONs into srv/p/<secret>/ but does NOT push
# them to OneDrive. Both rotate-shortids.sh (monthly short_ids) and
# rotate-realitykey.sh (quarterly Reality keypair) call this afterward so the
# OneDrive bootstrap bundles never lag the live server — otherwise
# check-config-drift.sh flags every device daily until a manual refresh.
#
# Prints ONE summary line to stdout (✓/⚠) for the caller's Discord message.
# Always exits 0: a publish failure is a recoverable nag, not a rotation
# failure (server + served manifests are already current; live clients
# auto-update). Extracted from rotate-shortids.sh's inline block 2026-07-03 so
# the quarterly keypair rotation reuses the exact same publish path (previously
# it re-rendered but never uploaded → stale OneDrive pubkey the drift check missed).
set -uo pipefail
cd "$(dirname "$0")"

SECRETS="${SECRETS:-.secrets.yaml}"
ONEDRIVE_CONFIGS="onedrive:Desktop/Configs"
failures=()
users=0
# Iterate users→secret from .secrets.yaml; src bundle lives at srv/p/<secret>/.
while read -r user secret; do
  [[ -z "${user}" || -z "${secret}" ]] && continue
  users=$(( users + 1 ))
  src_dir="srv/p/${secret}"
  if [[ ! -d "${src_dir}" ]]; then
    failures+=("${user}(src-missing)")
    continue
  fi
  # Mirror only the orphan-prone singbox JSONs + the Windows / Linux install
  # one-liners; everything else in srv/p/<secret>/ (READMEs, AWG confs, .prev)
  # stays off OneDrive.
  if ! rclone copy "${src_dir}/" "${ONEDRIVE_CONFIGS}/${user}/singbox/" \
       --include 'egressor-*.json' \
       --include 'install-singbox.ps1' \
       --include 'install-singbox.sh' \
       --quiet 2>/dev/null; then
    failures+=("${user}(rclone)")
  fi
done < <(python3 - "${SECRETS}" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f)
for u, info in (d.get('users') or {}).items():
    s = (info or {}).get('secret')
    if s:
        print(u, s)
PY
)

if (( ${#failures[@]} > 0 )); then
  echo "⚠ OneDrive: ${#failures[@]}/${users} user(s) failed: ${failures[*]}"
else
  echo "✓ OneDrive bundles refreshed (${users} users)"
fi
exit 0
