#!/usr/bin/env bash
# rotate-params.sh — generate fresh AWG obfuscation params, update
# .secrets.yaml, re-render every per-user .conf + the awg-server config,
# restart awg-server.
#
# Why rotate: AWG's Jc/Jmin/Jmax/S1/S2/H1-H4 values are the obfuscation
# fingerprint. A censor that captures enough handshakes to fingerprint
# *this* deployment's specific param tuple can then signature-block it.
# Rotating periodically (and after a confirmed block) gives the deployment
# a fresh obfuscation surface. Suggested cadence: quarterly cron, or
# immediately after observing a regional throughput drop on AWG users.
#
# Cost: every AWG device must re-import its .conf after rotation.
# render.py emits one new .conf per device into srv/p/<secret>/awg-<dev>.conf;
# the per-user README links each URL so refetching is a single tap in the
# Amnezia VPN app per device — but it's NOT zero-friction (unlike sing-box's
# hourly poll, the Amnezia app doesn't auto-refresh imported .conf files).
#
# Configuration:
#   AWG_SERVER_DIR  Defaults to <script-dir>.
#   PROFILES_DIR    Path to singbox-profiles/. Defaults to a sibling of
#                   AWG_SERVER_DIR (the in-repo layout).
#   NOTIFY          Optional notification script.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWG_SERVER_DIR="${AWG_SERVER_DIR:-${SCRIPT_DIR}}"
PROFILES_DIR="${PROFILES_DIR:-${AWG_SERVER_DIR}/../singbox-profiles}"
SECRETS="${PROFILES_DIR}/.secrets.yaml"
NOTIFY="${NOTIFY:-/opt/stack/scripts/notify-discord.sh}"
DRY_RUN=0

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

if [[ ! -f "${SECRETS}" ]]; then
  echo ".secrets.yaml not found at ${SECRETS}" >&2
  exit 2
fi

# Generate a fresh tuple via Python (already a render.py dependency, so
# no new tool). Range bounds match docs/quickstart.md's documented snippet
# — keep them in sync. AWG 1.0 baseline; 2.0 adds S3/S4 + I1-I5 fields
# (handled by render.py at template-time when present in the awg block).
new_params=$(python3 - <<'PY'
import secrets
# Full documented-safe AWG 1.0 ranges (widened 2026-08-28 from the earlier
# conservative subset — a wider tuple space is a bigger haystack for a
# censor fingerprinting this deployment). Constraints kept:
#   Jc 4..128 junk packets before the handshake (handshake-only cost);
#   Jmin < Jmax <= 1280 (junk packet size, must fit a 1280 MTU);
#   S1 <= 1132, S2 <= 1188 (148+S1 / 92+S2 init/response must fit MTU),
#   and S1 + 56 != S2 (documented: otherwise init/response sizes collide);
#   H1..H4 unique in 5..2^32-1 (1..4 are WG's own message types — a
#   collision reverts to plain WG and the obfuscation does nothing).
def gen():
    yield 'Jc',   secrets.randbelow(125) + 4            # 4..128
    jmin = secrets.randbelow(661) + 40                  # 40..700
    yield 'Jmin', jmin
    yield 'Jmax', jmin + 1 + secrets.randbelow(1280 - jmin)  # Jmin+1..1280
    s1 = secrets.randbelow(1118) + 15                   # 15..1132
    yield 'S1', s1
    while True:
        s2 = secrets.randbelow(1174) + 15               # 15..1188
        if s2 != s1 + 56:
            break
    yield 'S2', s2
    hs = []
    while len(hs) < 4:
        h = secrets.randbelow(2**32 - 5) + 5             # 5..2^32-1
        if h not in hs:
            hs.append(h)
    for i, h in enumerate(hs, 1):
        yield f'H{i}', h
for k, v in gen():
    print(f'  {k}: {v}')
PY
)

if [[ ${DRY_RUN} -eq 1 ]]; then
  echo "Would replace awg.{Jc,Jmin,Jmax,S1,S2,H1..H4} in ${SECRETS} with:"
  echo "${new_params}"
  exit 0
fi

# Backup before rewrite. Pattern matches the .secrets.yaml.bak-* gitignore
# so the backup never lands in version control. The `-awgparams-` infix
# distinguishes these from rotate-shortids.sh (`-shortid-`) and
# rotate-realitykey.sh (`-reality-`) backups so each script's retention
# trim only touches its own family AND egressor:rotations can derive
# "last fire" per tier without ambiguity.
ts=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="${SECRETS}.bak-awgparams-${ts}"
cp "${SECRETS}" "${BACKUP}"
chmod 600 "${BACKUP}"

# Trim old awg-params backups beyond retention. Mirrors the pattern in
# rotate-shortids.sh / rotate-realitykey.sh — keep the 3 most recent
# from THIS rotation family.
RETAIN=3
ls -1t "${SECRETS}".bak-awgparams-* 2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f

# In-place rewrite of just the obfuscation params, preserving every other
# line. A python3 driver is more robust than sed here (handles arbitrary
# whitespace + comments around the awg block). Reads the file, replaces
# only the matched keys inside the top-level awg: section, writes back.
python3 - "${SECRETS}" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
# Capture the awg: block (top-level; first non-indented `awg:` ... up to next
# top-level key or EOF). Replace the eight obfuscation keys inside it.
import secrets
# Same generator + constraints as the dry-run block above — keep in sync.
# Full documented-safe AWG 1.0 ranges (widened 2026-08-28 from the earlier
# conservative subset — a wider tuple space is a bigger haystack for a
# censor fingerprinting this deployment). Constraints kept:
#   Jc 4..128 junk packets before the handshake (handshake-only cost);
#   Jmin < Jmax <= 1280 (junk packet size, must fit a 1280 MTU);
#   S1 <= 1132, S2 <= 1188 (148+S1 / 92+S2 init/response must fit MTU),
#   and S1 + 56 != S2 (documented: otherwise init/response sizes collide);
#   H1..H4 unique in 5..2^32-1 (1..4 are WG's own message types — a
#   collision reverts to plain WG and the obfuscation does nothing).
def gen():
    yield 'Jc',   secrets.randbelow(125) + 4            # 4..128
    jmin = secrets.randbelow(661) + 40                  # 40..700
    yield 'Jmin', jmin
    yield 'Jmax', jmin + 1 + secrets.randbelow(1280 - jmin)  # Jmin+1..1280
    s1 = secrets.randbelow(1118) + 15                   # 15..1132
    yield 'S1', s1
    while True:
        s2 = secrets.randbelow(1174) + 15               # 15..1188
        if s2 != s1 + 56:
            break
    yield 'S2', s2
    hs = []
    while len(hs) < 4:
        h = secrets.randbelow(2**32 - 5) + 5             # 5..2^32-1
        if h not in hs:
            hs.append(h)
    for i, h in enumerate(hs, 1):
        yield f'H{i}', h

m = re.search(r'^(awg:\s*\n(?:[ \t].*\n)*)', text, flags=re.MULTILINE)
if not m:
    sys.exit('rotate-params.sh: awg block not found in .secrets.yaml')
block = m.group(1)
new_block = block
for key, val in gen():
    new_block = re.sub(
        rf'^(\s+){re.escape(key)}:\s*\S+[ \t]*$',
        rf'\g<1>{key}: {val}',
        new_block,
        count=1,
        flags=re.MULTILINE,
    )
text = text[:m.start()] + new_block + text[m.end():]
open(path, 'w').write(text)
print('rewrote awg obfuscation params in', path)
PY

# Re-render every client + the awg-server config. -y skips the apply
# prompt; render.py's auto_yes still walks the rename detector cleanly
# (1:1 renames auto-apply, ambiguous abort).
if ! python3 "${PROFILES_DIR}/render.py" -y; then
  notify "🚫 **AWG obfuscation-param rotation FAILED** (manual tier) — render.py errored after \`.secrets.yaml\` was rewritten. State on disk: new secrets, stale .conf files. Restore from \`${BACKUP##*/}\` and investigate."
  exit 1
fi

# Reconcile awg-server with the new server config.
if ! "${AWG_SERVER_DIR}/safe-restart.sh"; then
  notify "🚨 **AWG obfuscation-param rotation FAILED** (manual tier) — safe-restart.sh errored. New configs written but awg-server is still on the old params. Roll back: \`cp ${BACKUP} ${SECRETS} && python3 ${PROFILES_DIR}/render.py -y && ${AWG_SERVER_DIR}/safe-restart.sh\`"
  exit 1
fi

# Count active AWG devices for the success message — one .conf per device
# under srv/p/<secret>/awg-*.conf. Operator-actionable signal: "you have N
# laptops/phones to walk through re-import."
device_count=$(find "${PROFILES_DIR}/srv/p" -maxdepth 2 -name 'awg-*.conf' 2>/dev/null | wc -l)
notify "$(cat <<EOF
🔄 **AWG obfuscation-param rotation** — manual tier (recommended quarterly, or after a regional throughput drop suggesting DPI fingerprinting)
• rotated: Jc / Jmin / Jmax / S1 / S2 / H1-H4 (eight params)
• devices to re-import: **${device_count}**
• continuity: ⚠️ flag day — no grace window (single server-side param tuple, atomic on-the-wire). Old .conf files fail handshake until replaced.
• client refresh: ❗ **manual** — Amnezia VPN app does NOT auto-refresh imported .conf files. Each device must re-download from \`https://\${PROFILE_HOST}/p/<secret>/awg-<device>.conf\` and re-import.
• cron: none (manual-only by design — re-import friction would lock users out if fired unattended)
EOF
)"
echo "rotation complete; backup at ${BACKUP}; ${device_count} devices need .conf re-import"
