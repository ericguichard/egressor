#!/usr/bin/env bash
# rotate-shortids.sh — monthly Reality short_id rotation for every device.
#
# Why: the Reality short_id is a secondary auth factor alongside the per-
# device UUID. Rotating it periodically cuts the blast radius of any covert
# credential leak (a log line, a screenshot, a compromised client) to at
# most one rotation interval. Zero-downtime is free: render.py's 7-day
# pending-rotation grace keeps the old short_ids live on the server, and
# clients refetch the manifest on a poll interval — any client that
# successfully polled before rotation picks up the new short_id before the
# grace window expires.
#
# Why not rotate UUIDs or passwords on the same schedule: those are the
# primary auth secret; rotating them is a more disruptive event (a client
# that hasn't applied a new profile within the 7-day grace *will* break) and should stay manual / admin-
# triggered. The short_id is cheap to rotate precisely because it's a
# secondary factor.
#
# Flow:
#   1. Edit .secrets.yaml in-place: replace every devices[].reality.short_id
#      with a fresh 16-hex-char token. One sed-grade regex pass, no YAML
#      parse/serialize round-trip (that would clobber the auto-managed-file
#      comments at the top).
#   2. Run `./render.py --server-apply -y`. This re-emits config.json with
#      the new short_ids, drops the old ones into .pending-rotations.yaml
#      with a 7-day TTL (ROTATION_TTL_HOURS), and safe-restarts singbox-server.
#   3. Notify on success AND failure (if NOTIFY is set) — success keeps
#      operators aware the cron actually fires (silent cron jobs rot).
#
# Not covered: Reality keypair rotation (that invalidates ALL clients
# atomically — no grace window possible since public_key is shared across
# users). See rotate-realitykey.sh for that.

set -uo pipefail

PROFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROFILES_DIR}"

NOTIFY="${NOTIFY:-/opt/stack/scripts/notify-discord.sh}"
SECRETS=".secrets.yaml"

# Next monthly rotation = first day of next month at 04:00 UTC. Computed
# at runtime so the notification stays accurate even if cron is changed.
NEXT_ROTATION=$(python3 -c "
import datetime
t = datetime.date.today()
y, m = (t.year + 1, 1) if t.month == 12 else (t.year, t.month + 1)
print(datetime.date(y, m, 1).isoformat())
")

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

if [[ ! -f "${SECRETS}" ]]; then
  notify "❌ **Reality short_id rotation ABORTED** (monthly tier) — \`${SECRETS}\` missing"
  exit 1
fi

# Keep the pre-rotation file as <name>.bak-shortid-<utc-ts>. If render.py
# fails or the restart goes sideways, manual rollback is
# `cp .bak-shortid-TS .secrets.yaml` + `./render.py -y`.
# The `-shortid-` infix distinguishes short_id backups from reality-key
# backups (rotate-realitykey.sh uses `.bak-reality-<ts>`), so each
# script's retention trim only touches its own family.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="${SECRETS}.bak-shortid-${STAMP}"
# Keep the 3 most recent pre-rotation backups from THIS script. Trim runs
# AFTER the new backup is created but BEFORE the rotation — so if the
# rotation fails and we `cp ${BACKUP} ${SECRETS}` to roll back, ${BACKUP}
# is still on disk. Older backups age out monthly; 3 months of history is
# enough to diff a two-step regression ("worked in February, broke in
# March, something changed in April") without accumulating unbounded files.
RETAIN=3
cp -p "${SECRETS}" "${BACKUP}" || {
  notify "❌ **Reality short_id rotation ABORTED** (monthly tier) — cp ${SECRETS} → ${BACKUP##*/} failed"
  exit 1
}

# Trim old backups: keep the RETAIN most recent matching this script's family.
# -t sorts by mtime desc; tail -n +$((RETAIN+1)) drops the newest RETAIN and
# prints the rest; xargs -r is a no-op when stdin is empty. Globs silently
# expand to nothing if no matches, so the 2>/dev/null on ls is belt-and-
# braces — ls normally succeeds on a no-match glob since bash passes the
# literal pattern through, which ls then can't stat.
ls -1t "${SECRETS}".bak-shortid-* 2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f

# In-place short_id replacement. The file has one short_id per line (at
# indent level 10 under devices.<name>.reality), so a line-oriented regex
# is unambiguous. Python handles the per-line random token generation —
# sed can't do that without a subprocess per match. Heredoc-into-stdin
# form (python3 - ...) keeps the script single-file.
python3 - "${SECRETS}" <<'PY'
import re, secrets, sys
path = sys.argv[1]
text = open(path).read()
count = [0]
def sub(m):
    count[0] += 1
    return f"{m.group(1)}{secrets.token_hex(8)}"
new_text = re.sub(r'(^(\s+)short_id:\s+)[a-f0-9]{16}\s*$',
                  sub, text, flags=re.MULTILINE)
if count[0] == 0:
    print("no short_ids matched — aborting to avoid blanking .secrets.yaml", file=sys.stderr)
    sys.exit(2)
open(path, 'w').write(new_text)
print(f"rotated {count[0]} short_ids")
PY
rc=$?
if (( rc != 0 )); then
  # Python bailed — restore from backup so we never leave .secrets.yaml
  # in a half-written state.
  cp -p "${BACKUP}" "${SECRETS}"
  notify "❌ **Reality short_id rotation FAILED** (monthly tier) — short_id regen rc=${rc}; \`.secrets.yaml\` restored from ${BACKUP##*/}"
  exit 1
fi

# Apply via the same entrypoint the operator would use by hand. -y skips
# the interactive confirmation; this re-renders both clients and server
# (server sync + safe-restart, plus updated srv/p/ content).
if ! ./render.py -y 2>&1; then
  cp -p "${BACKUP}" "${SECRETS}"
  notify "❌ **Reality short_id rotation FAILED** (monthly tier) — render.py errored; \`.secrets.yaml\` restored from ${BACKUP##*/}"
  exit 1
fi

# Count how many devices got rotated for the success message. Same regex
# as the rotator, parsed out of the backup so we report the pre-rotation
# count (== number rotated).
rotated=$(grep -cE '^\s+short_id:\s+[a-f0-9]{16}\s*$' "${BACKUP}")

# --- Publish refreshed bundles to OneDrive (shared: publish-configs-onedrive.sh) ---
# render.py writes new client JSONs under srv/p/<secret>/ but does NOT push them;
# without this every device's OneDrive `egressor-<user>-<type>.json` orphans against the live
# server and check-config-drift.sh flags it daily until manually refreshed. Failure
# is a recoverable nag, not a rotation failure (server + served manifests already
# current; live clients auto-update). Extracted 2026-07-03 into a shared script so
# the quarterly rotate-realitykey.sh reuses the EXACT same publish path (added
# 2026-05-03 after May-1 produced 9 simultaneous orphan flags — every device, user).
publish_line=$(./publish-configs-onedrive.sh)

notify "$(cat <<EOF
🔁 **Reality short_id rotation** — monthly tier (1st of every month @ 04:00 UTC)
• rotated: **${rotated}** device short_ids
• continuity: zero-downtime — old ids honoured for a 7-day grace via \`.pending-rotations.yaml\`
• clients with a profile updater pick up new ids on next poll (e.g. Windows updater, hourly + boot); clients that import manually or run without profile auto-update lose Reality once the grace lapses until re-imported by hand
• ${publish_line}
• next rotation: **${NEXT_ROTATION}** @ 04:00 UTC
EOF
)"
