#!/usr/bin/env bash
# rotate-realitykey.sh — rotate the Reality X25519 server keypair.
#
# Why: Reality's server private key is the long-lived secret that binds the
# handshake. Short_id rotation (rotate-shortids.sh) limits blast radius for
# leaked device credentials but not the server identity itself. A compromised
# private key (file disclosure, backup exposure) silently lets anyone forge
# valid Reality connections — until you rotate. Quarterly rotation shrinks
# the window.
#
# Two modes, picked automatically:
#
#   ALTERNATING (no flag day) — when a second Reality endpoint is configured:
#   `defaults.reality.server_b` in profiles.yaml (the public address clients
#   dial, e.g. `__REALITY_B_PUBLIC_IP__`) AND `INCOMING_IP_2` in the
#   environment / repo .env (the local IP the inbound binds). A Reality
#   inbound holds ONE private key, so instead of changing the key in place:
#     1. the new key starts on the OTHER endpoint (`reality-in` moves there),
#     2. the previous key keeps running on the current endpoint as
#        `reality-retiring-in` for REALITY_OVERLAP_DAYS (default 7),
#     3. clients are re-rendered to dial the new endpoint with the new key.
#   A client still running the previous profile keeps working on the old
#   endpoint until it applies the new one. This matters for mobile apps
#   (SFA/SFI), which fetch the profile on schedule but apply it only when the
#   tunnel reconnects. Run `rotate-realitykey.sh --retire` after the window
#   (daily from cron is fine: it is a no-op until the window has closed) to
#   drop the previous key. The next rotation moves back the other way.
#
#   FLAG DAY (legacy) — single endpoint. The key changes in place; clients
#   fail Reality handshakes until they APPLY a profile with the new public
#   key. Schedule when a short outage is acceptable.
#
# Usage:
#   rotate-realitykey.sh            rotate (alternating if configured)
#   rotate-realitykey.sh --retire   drop the previous key once its window closed
#   rotate-realitykey.sh --retire --force   drop it now, window or not
#
# Environment:
#   REALITY_OVERLAP_DAYS      overlap window for alternating mode (default 7)
#   REALITY_ROTATION_WEEKDAY  1-7 (Mon-Sun) if cron runs on the first such
#                             weekday of Jan/Apr/Jul/Oct, empty = the 1st;
#                             only used to print the next date
#   REALITY_ROTATION_TIME     "HH:MM" UTC for the same message (default 04:00)
#   NOTIFY                    notification hook (same as rotate-shortids.sh)
#
# Suggested cron (UTC), alternating mode:
#   0 4 1 1,4,7,10 * rotate-realitykey.sh
#   30 4 * * *       rotate-realitykey.sh --retire
#
# Safety:
#   - Refuses to run if render.py --validate fails first (current manifest
#     is broken — don't compound the problem).
#   - Alternating mode refuses a new rotation while the previous overlap
#     window is still open (two retiring keys would need three endpoints).
#   - On sing-box-generate failure, aborts before touching .secrets.yaml.
#   - Every change snapshots .secrets.yaml to .bak-reality-<UTC-ts> first.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SECRETS="${ROOT}/.secrets.yaml"
NOTIFY="${NOTIFY:-/opt/stack/scripts/notify-discord.sh}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OVERLAP_DAYS="${REALITY_OVERLAP_DAYS:-7}"
ROT_TIME="${REALITY_ROTATION_TIME:-04:00}"

MODE=rotate
FORCE=0
for arg in "$@"; do
  case "${arg}" in
    --retire) MODE=retire ;;
    --force)  FORCE=1 ;;
    -h|--help) sed -n '2,52p' "$0"; exit 0 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

# Next quarterly rotation, for the notification only. Computed at runtime so
# the message stays accurate when cron is moved.
NEXT_ROTATION=$(REALITY_ROTATION_WEEKDAY="${REALITY_ROTATION_WEEKDAY:-}" python3 -c "
import datetime, os
wd = os.environ['REALITY_ROTATION_WEEKDAY']
t = datetime.date.today()
for y in (t.year, t.year + 1):
    for m in (1, 4, 7, 10):
        d = datetime.date(y, m, 1)
        if wd:
            while d.isoweekday() != int(wd):
                d += datetime.timedelta(days=1)
        if d > t:
            print(d.isoformat()); raise SystemExit
")

# `-reality-` infix distinguishes these backups from short_id rotation
# backups (`.bak-shortid-*`), so each script's retention trim only touches
# its own family. See rotate-shortids.sh for the matching pattern.
BAK="${SECRETS}.bak-reality-${TS}"
# Keep the 3 most recent reality-key backups. Reality rotation runs
# quarterly, so 3 = 9 months of rollback history — enough to diff across
# the most recent crypto changes without unbounded growth.
RETAIN=3

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

backup_secrets() {
  # Keep mode explicitly so cp doesn't widen it (the file is 0600 by design).
  cp -p "${SECRETS}" "${BAK}"
  chmod 600 "${BAK}"
  # Trim reality-key backups beyond the retention count. Runs after the new
  # backup exists so the rollback target for *this* change is safe.
  ls -1t "${SECRETS}".bak-reality-* 2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f
}

# State helper: everything that reads or writes rotation state goes through
# render.py's own loaders, so the YAML shape and the "is the window still
# open" rule live in one place. Prints shell assignments for `eval`.
state() {
  ( cd "${ROOT}" && python3 - <<'PY'
import yaml, render
m = yaml.safe_load(render.MANIFEST.read_text()) or {}
r = (m.get('defaults') or {}).get('reality') or {}
alt = bool(r.get('server_b')) and bool(render._env_or_dotenv('INCOMING_IP_2', ''))
sh = (render.load_secrets().get('shared') or {})
ret = None
if sh.get('reality_retiring_private_key'):
    ret = {'private_key': sh['reality_retiring_private_key'],
           'expires_at': sh.get('reality_retiring_expires_at')}
print(f"ALTERNATING={int(alt)}")
print(f"ENDPOINT={sh.get('reality_endpoint', 'a')}")
print(f"HAS_RETIRING={int(ret is not None)}")
print(f"RETIRING_OPEN={int(render._reality_retiring_live(ret))}")
print(f"RETIRING_EXPIRES='{(ret or {}).get('expires_at') or ''}'")
PY
  )
}

# Rewrite rotation fields in .secrets.yaml via render.save_secrets (keeps the
# header comment). Args: KEY=VALUE pairs; an empty VALUE deletes the key.
set_shared() {
  ( cd "${ROOT}" && python3 - "$@" <<'PY'
import sys, render
data = render.load_secrets()
sh = data.setdefault('shared', {})
for kv in sys.argv[1:]:
    k, _, v = kv.partition('=')
    if v:
        sh[k] = v
    else:
        sh.pop(k, None)
render.save_secrets(data)
PY
  )
}

render_or_rollback() {
  # Re-render (clients + server), which hot-restarts singbox-server. If render
  # fails we still have the .bak; operator can roll back with:
  #   mv .secrets.yaml.bak-<TS> .secrets.yaml && ./render.py -y
  if ! "${ROOT}/render.py" -y; then
    notify "🚨 **Reality key $1 FAILED AT RENDER** — \`.secrets.yaml\` was changed but render.py errored. Rollback: \`mv ${BAK##*/} .secrets.yaml && ./render.py -y\`"
    echo "render.py failed — manual rollback required" >&2
    exit 1
  fi
}

publish() {
  # Mirror the freshly re-rendered bundles to OneDrive so the bootstrap copies
  # carry the NEW pubkey/endpoint immediately. Non-fatal: a publish miss is a
  # recoverable nag, not a rotation failure.
  "${ROOT}/publish-configs-onedrive.sh" || echo "⚠ OneDrive publish step errored (see logs)"
}

eval "$(state)"

# ---------------------------------------------------------------------------
# --retire: drop the previous key once its overlap window has closed.
# ---------------------------------------------------------------------------
if [[ "${MODE}" == retire ]]; then
  if [[ "${HAS_RETIRING}" != 1 ]]; then
    echo "no retiring Reality key — nothing to do"
    exit 0
  fi
  if [[ "${RETIRING_OPEN}" == 1 && "${FORCE}" != 1 ]]; then
    echo "retiring key still in its window (until ${RETIRING_EXPIRES}) — nothing to do (use --force to drop it now)"
    exit 0
  fi
  backup_secrets
  set_shared reality_retiring_private_key= reality_retiring_expires_at=
  render_or_rollback "retirement"
  PUBLISH_LINE=$(publish)
  notify "$(cat <<EOF
🔑 **Reality previous key retired** (endpoint switch complete)
• the previous key's inbound is gone; only the active key on endpoint **${ENDPOINT}** remains
• a client that has still not applied a profile since the rotation now fails Reality; it needs to apply its profile (mobile: VPN off → update profile → VPN on)
• ${PUBLISH_LINE}
EOF
)"
  echo "retired previous Reality key"
  exit 0
fi

# ---------------------------------------------------------------------------
# rotate
# ---------------------------------------------------------------------------

# Pre-flight: current manifest must render cleanly before we touch anything.
# A stale broken state would otherwise strand us with the old key in
# .secrets.yaml.bak and no viable render.
# --validate also fails when one of its sing-box images cannot be run (see
# check_client_plan in render.py), so the reason goes into the alert.
if ! validate_out=$("${ROOT}/render.py" --validate 2>&1); then
  validate_reason=$(printf '%s\n' "${validate_out}" | grep -v '^[[:space:]]*$' | tail -n 1 | tr -d '`' | cut -c1-300)
  notify "🚨 **Reality keypair rotation ABORTED** (quarterly tier) — pre-flight \`render.py --validate\` failed: \`${validate_reason}\`"
  echo "pre-flight validate failed — aborting" >&2
  printf '%s\n' "${validate_out}" >&2
  exit 1
fi

if [[ "${ALTERNATING}" == 1 && "${HAS_RETIRING}" == 1 ]]; then
  if [[ "${RETIRING_OPEN}" == 1 ]]; then
    notify "🚨 **Reality keypair rotation ABORTED** — the previous rotation's overlap window is still open (until ${RETIRING_EXPIRES}). Run \`rotate-realitykey.sh --retire --force\` first if you really mean to rotate again."
    echo "previous overlap window still open — aborting" >&2
    exit 1
  fi
  # Window closed but never retired (e.g. the --retire cron missed it): retire
  # as part of this rotation so the endpoints are free.
  echo "previous key's window has closed — retiring it as part of this rotation"
fi

# Generate keypair via the same image the server runs so the public-key
# format is guaranteed to match (upstream sometimes tweaks base64 padding).
GEN=$(docker run --rm ghcr.io/sagernet/sing-box:latest generate reality-keypair 2>&1) || {
  notify "🚨 **Reality keypair rotation ABORTED** (quarterly tier) — \`sing-box generate reality-keypair\` failed"
  echo "sing-box generate failed:" >&2
  echo "${GEN}" >&2
  exit 1
}

# Parse the two-line "PrivateKey: ...\nPublicKey: ..." output. Using awk
# over grep+sed keeps it single-pass and resilient to whitespace variations.
NEW_PRIV=$(awk -F': ' '/^PrivateKey/ {print $2}' <<<"${GEN}")
NEW_PUB=$(awk -F': ' '/^PublicKey/  {print $2}' <<<"${GEN}")
if [[ -z "${NEW_PRIV}" || -z "${NEW_PUB}" ]]; then
  notify "🚨 **Reality keypair rotation ABORTED** (quarterly tier) — could not parse keypair output"
  echo "parse failed, raw output:" >&2
  echo "${GEN}" >&2
  exit 1
fi

backup_secrets

if [[ "${ALTERNATING}" == 1 ]]; then
  OLD_PRIV=$(cd "${ROOT}" && python3 -c "import render; print(render.load_secrets()['shared']['reality_private_key'])")
  NEW_ENDPOINT=$([[ "${ENDPOINT}" == a ]] && echo b || echo a)
  EXPIRES=$(python3 -c "
import datetime
t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=${OVERLAP_DAYS})
print(t.replace(microsecond=0).isoformat().replace('+00:00', 'Z'))")
  set_shared \
    "reality_retiring_private_key=${OLD_PRIV}" \
    "reality_retiring_expires_at=${EXPIRES}" \
    "reality_endpoint=${NEW_ENDPOINT}" \
    "reality_private_key=${NEW_PRIV}" \
    "reality_public_key=${NEW_PUB}"
else
  # Replace the two key lines in-place. sed is fine here — keys are
  # base64-url (no / or +) and fit on one line, so no escaping gotchas.
  # Anchored to the field name + leading 2-space indent (under `shared:`) to
  # avoid collisions with any similarly-named field elsewhere.
  sed -i \
    -e "s|^  reality_public_key:.*|  reality_public_key: ${NEW_PUB}|" \
    -e "s|^  reality_private_key:.*|  reality_private_key: ${NEW_PRIV}|" \
    "${SECRETS}"
fi

# Sanity: both halves actually landed (sed succeeds even on 0 matches).
# Parsed, not grepped: YAML may quote a key that starts with '-'.
if ! (cd "${ROOT}" && NEW_PUB="${NEW_PUB}" NEW_PRIV="${NEW_PRIV}" python3 -c "
import os, sys, render
sh = render.load_secrets().get('shared') or {}
sys.exit(0 if sh.get('reality_public_key') == os.environ['NEW_PUB']
         and sh.get('reality_private_key') == os.environ['NEW_PRIV'] else 1)"); then
  mv "${BAK}" "${SECRETS}"
  notify "🚨 **Reality keypair rotation ABORTED** (quarterly tier) — the new key did not land in \`.secrets.yaml\`; restored from backup"
  echo "secrets update failed — restored backup" >&2
  exit 1
fi

render_or_rollback "rotation"
PUBLISH_LINE=$(publish)

if [[ "${ALTERNATING}" == 1 ]]; then
  notify "$(cat <<EOF
🔑 **Reality keypair rotation** — quarterly tier, alternating endpoints (no flag day)
• new pubkey: \`${NEW_PUB:0:12}…\`, active on endpoint **${NEW_ENDPOINT}**; clients re-rendered to dial it
• previous key stays live on endpoint **${ENDPOINT}** until **${EXPIRES}**: clients still running the old profile keep working
• action: none for clients that apply their profile within ${OVERLAP_DAYS} days (mobile apps apply on reconnect); \`--retire\` drops the previous key after the window
• ${PUBLISH_LINE}
• next rotation: **${NEXT_ROTATION}** @ ${ROT_TIME} UTC
EOF
)"
else
  notify "$(cat <<EOF
🔑 **Reality keypair rotation** — quarterly tier
• new pubkey: \`${NEW_PUB:0:12}…\`
• continuity: ⚠️ flag day — no grace window (single server keypair). Clients fail Reality handshakes until they APPLY a profile with the new pubkey.
• other protocols (ShadowTLS / Hysteria2 / WS-CDN) are unaffected; a client whose selector is pinned to Reality needs its profile applied (mobile: VPN off → update profile → VPN on)
• ${PUBLISH_LINE}
• next rotation: **${NEXT_ROTATION}** @ ${ROT_TIME} UTC
EOF
)"
fi
echo "rotation complete"
echo "  old backup: ${BAK}"
echo "  new pubkey: ${NEW_PUB}"
