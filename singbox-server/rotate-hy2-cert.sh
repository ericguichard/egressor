#!/usr/bin/env bash
# rotate-hy2-cert.sh — rotate the Hysteria2 TLS key + cert without a flag day.
#
# Why rotate at all: hy2.crt is self-signed and every client pins its public
# key. The key is the trust anchor — whoever holds hy2.key can impersonate the
# server to clients. Periodic rotation shrinks that window.
#
# How there is no flag day: clients pin the SHA-256 of the cert's PUBLIC KEY
# (tls.certificate_public_key_sha256), and that field is a list. render.py
# publishes two entries: the key in hy2.crt (presented now) and the key in
# hy2-next.crt (presented after the next rotation). This script keeps that
# next pair one cycle ahead:
#
#     rotation N:   hy2-next.* becomes hy2.*, a fresh hy2-next.* is generated
#     rotation N+1: that one becomes hy2.*, and so on
#
# so a client that fetched its config at any time during the previous cycle
# already trusts the key the server switches to. A client that has not fetched
# for a whole cycle loses hy2 until it does; its other protocols are unaffected.
#
# Trade-off to know: the next private key sits on this host for a full cycle,
# next to the current one. Whoever copies one copies both, so a routine
# rotation does not evict them. After a suspected key leak run `--fresh`.
#
# Modes:
#   (none)        Routine rotation, steps below. Refuses to run when
#                 hy2-next.* is missing or was published too recently.
#   --bootstrap   Once per deployment (and after a restore without the next
#                 pair): generate hy2-next.* and re-render so clients start
#                 learning the next key. Server untouched, no restart.
#   --fresh       Emergency: discard hy2-next.*, generate a NEW current pair
#                 and a new next pair. This IS a flag day for hy2: clients
#                 fail the handshake until they fetch the new config.
#
# Routine rotation:
#   1. Pre-flight `render.py --validate`.
#   2. Check hy2-next.crt/.key match, were published at least
#      HY2_MIN_OVERLAP_DAYS ago, and re-issue the cert from the same key when
#      it has less than a cycle of validity left (the pin is on the key, so a
#      re-issued cert changes nothing for clients).
#   3. Baseline handshake through the live server with the CURRENT pin.
#   4. Snapshot hy2.crt/.key to .bak-<UTC-ts>, move the next pair into place.
#   5. safe-restart.sh. render.py would NOT do this: the server config names
#      the cert by path, a new cert leaves config.json byte-identical, and a
#      running container keeps the old inode of a single-file bind mount.
#   6. Handshake through the live server pinning ONLY the promoted key. On
#      failure: restore the backup, restart, put the next pair back, abort —
#      clients were never touched.
#   7. Generate a fresh hy2-next pair.
#   8. `render.py -y`: clients now get [promoted key, new next key].
#   9. Notify.
#
# Configuration (env):
#   SINGBOX_SERVER_DIR    Directory holding hy2.crt/.key, hy2-next.crt/.key
#                         and safe-restart.sh. Defaults to this script's dir.
#   SINGBOX_PROFILES_DIR  Directory holding render.py. Defaults to
#                         ../singbox-profiles relative to SINGBOX_SERVER_DIR.
#   HY2_SNI               Hostname baked into CN+SAN. Defaults to the CN of
#                         the live hy2.crt, else cloud.example.com.
#   HY2_ROTATION_MMDD     Month-day of the cron line, for the notification.
#   HY2_MIN_OVERLAP_DAYS  Minimum age of hy2-next.crt before it may be
#                         promoted (default 7): clients need time to fetch it.
#   HY2_SKIP_HANDSHAKE=1  Skip steps 3 and 6 (no docker / no curl / hairpin
#                         to the public address not possible on this host).
#   NOTIFY                Optional notification script, one string argument.

set -euo pipefail

MODE=rotate
case "${1:-}" in
  "") ;;
  --bootstrap) MODE=bootstrap ;;
  --fresh)     MODE=fresh ;;
  *) echo "usage: $0 [--bootstrap | --fresh]" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_SERVER_DIR="${SINGBOX_SERVER_DIR:-${SCRIPT_DIR}}"
SINGBOX_PROFILES_DIR="${SINGBOX_PROFILES_DIR:-$(cd "${SINGBOX_SERVER_DIR}/../singbox-profiles" && pwd)}"
NOTIFY="${NOTIFY:-/opt/stack/scripts/notify-discord.sh}"
HY2_MIN_OVERLAP_DAYS="${HY2_MIN_OVERLAP_DAYS:-7}"

CERT="${SINGBOX_SERVER_DIR}/hy2.crt"
KEY="${SINGBOX_SERVER_DIR}/hy2.key"
NEXT_CERT="${SINGBOX_SERVER_DIR}/hy2-next.crt"
NEXT_KEY="${SINGBOX_SERVER_DIR}/hy2-next.key"
RESTART="${SINGBOX_SERVER_DIR}/safe-restart.sh"
TS=$(date -u +%Y%m%dT%H%M%SZ)
BAK_CERT="${CERT}.bak-${TS}"
BAK_KEY="${KEY}.bak-${TS}"
# Keep the 3 most recent cert/key backup pairs.
RETAIN=3
# A pair is generated at one rotation, promoted at the next and presented
# until the one after: two cycles from its creation. 3 years covers two
# yearly cycles with room for a late run.
DAYS=1095
# Re-issue the next cert at promotion when it would not outlive one more
# cycle plus slack.
MIN_VALID_DAYS=400

if [[ -z "${HY2_SNI:-}" ]]; then
  HY2_SNI=$(openssl x509 -in "${CERT}" -noout -subject -nameopt multiline 2>/dev/null \
            | sed -n 's/^ *commonName *= *//p' | head -n 1)
  HY2_SNI="${HY2_SNI:-cloud.example.com}"
fi

# Next yearly rotation date for the notification, @ 05:00 UTC. HY2_ROTATION_MMDD
# must match the month-day of the cron line that runs this script (default 04-01,
# the original schedule).
HY2_ROTATION_MMDD="${HY2_ROTATION_MMDD:-04-01}"
NEXT_ROTATION=$(HY2_ROTATION_MMDD="${HY2_ROTATION_MMDD}" python3 -c "
import datetime, os
m, d = (int(x) for x in os.environ['HY2_ROTATION_MMDD'].split('-'))
t = datetime.date.today()
candidate = datetime.date(t.year, m, d)
if candidate <= t: candidate = datetime.date(t.year + 1, m, d)
print(candidate.isoformat())
")

notify() {
  if [[ -n "${NOTIFY}" && -x "${NOTIFY}" ]]; then
    "${NOTIFY}" "$1" || true
  else
    echo "$1" >&2
  fi
}

abort() {  # abort "<what failed>" — notify and exit 1
  notify "🚨 **Hysteria2 cert rotation ABORTED** (${MODE}) — $1"
  echo "ABORTED: $1" >&2
  exit 1
}

# Generation happens in a 0700 temp dir so a failed openssl never touches the
# live files and a fresh key is never group/world-readable.
TMPDIR_ROT=$(umask 077 && mktemp -d)
trap 'rm -rf "${TMPDIR_ROT}"' EXIT

# base64(SHA-256(SubjectPublicKeyInfo)) — the value clients pin.
pin_of_cert() {
  openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary | openssl enc -base64
}
pin_of_key() {
  openssl pkey -in "$1" -pubout -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64
}

pair_matches() {  # pair_matches <cert> <key>
  local c k
  c=$(pin_of_cert "$1") || return 1
  k=$(pin_of_key "$2") || return 1
  [[ -n "${c}" && "${c}" == "${k}" ]]
}

# Give a pair the owner of the live cert (singbox-server runs as the
# bind-mount owner and must read both) and the usual modes.
fix_perms() {  # fix_perms <cert> <key>
  chmod 644 "$1"
  chmod 600 "$2"
  if [[ -f "${CERT}" ]]; then
    chown "$(stat -c '%u' "${CERT}"):$(stat -c '%g' "${CERT}")" "$1" "$2" 2>/dev/null || true
  fi
}

# ECDSA P-256: smaller on the wire than RSA for the same margin, which matters
# for hy2's QUIC handshake. The SAN is kept although key-pinning clients do not
# validate the hostname: a client on the PEM fallback (sing-box < 1.13) does,
# and Go ignores the CN (docs/hazards.md #1).
issue_cert() {  # issue_cert <key> <cert-out>   (self-signed from an existing key)
  openssl req -x509 -new -key "$1" -out "$2" -days "${DAYS}" \
    -subj "/CN=${HY2_SNI}" -addext "subjectAltName=DNS:${HY2_SNI}" >/dev/null 2>&1
}

generate_pair() {  # generate_pair <cert-dest> <key-dest>
  local c="${TMPDIR_ROT}/gen.crt" k="${TMPDIR_ROT}/gen.key"
  rm -f "${c}" "${k}"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "${k}" >/dev/null 2>&1 \
    && issue_cert "${k}" "${c}" || return 1
  pair_matches "${c}" "${k}" || return 1
  fix_perms "${c}" "${k}"
  # Same filesystem as the destination only by luck; mv is still safe (it
  # copies then unlinks), and nothing reads the next pair while it lands.
  mv "${k}" "$2"
  mv "${c}" "$1"
}

# Handshake through the live server pinning ONLY <pin>. Builds a one-outbound
# config from a rendered client file, runs it in a throwaway container with a
# loopback proxy inbound and fetches a URL through it.
#   0 = traffic passed, 1 = it did not, 2 = the test could not be run.
handshake() {  # handshake <pin>
  [[ "${HY2_SKIP_HANDSHAKE:-0}" == 1 ]] && return 2
  command -v docker >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 || return 2
  local dir="${TMPDIR_ROT}/hs" name="hy2-rotate-test-$$" image port rc=1
  rm -rf "${dir}"; mkdir -p "${dir}"
  PIN="$1" OUT="${dir}/c.json" SRV="${SINGBOX_PROFILES_DIR}/srv/p" python3 - <<'PY' || return 2
import glob, json, os, sys
for path in sorted(glob.glob(os.path.join(os.environ['SRV'], '*', '*.json'))):
    try:
        cfg = json.load(open(path))
    except Exception:
        continue
    hy = [o for o in cfg.get('outbounds', []) if o.get('type') == 'hysteria2']
    if not hy:
        continue
    out = hy[0]
    tls = out['tls']
    tls.pop('certificate', None)
    tls['certificate_public_key_sha256'] = [os.environ['PIN']]
    json.dump({'log': {'level': 'warn'},
               'inbounds': [{'type': 'mixed', 'tag': 'in', 'listen': '0.0.0.0', 'listen_port': 2080}],
               'outbounds': [out], 'route': {'final': out['tag']}},
              open(os.environ['OUT'], 'w'))
    sys.exit(0)
sys.exit(1)
PY
  chmod 644 "${dir}/c.json"
  image=$(docker inspect singbox-server --format '{{.Config.Image}}' 2>/dev/null) || image=ghcr.io/sagernet/sing-box:latest
  docker rm -f "${name}" >/dev/null 2>&1 || true
  docker run -d --name "${name}" -v "${dir}:/c:ro" -p 127.0.0.1::2080 \
    --entrypoint sing-box "${image}" run -c /c/c.json -D /tmp >/dev/null 2>&1 || return 2
  port=$(docker port "${name}" 2080/tcp 2>/dev/null | head -n 1 | sed 's/.*://')
  if [[ -z "${port}" ]]; then docker rm -f "${name}" >/dev/null 2>&1; return 2; fi
  for _ in 1 2 3 4; do
    sleep 3
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 \
              -x "socks5h://127.0.0.1:${port}" https://www.gstatic.com/generate_204)" == 204 ]]; then
      rc=0; break
    fi
  done
  docker rm -f "${name}" >/dev/null 2>&1 || true
  rm -rf "${dir}"
  return "${rc}"
}

validate_or_abort() {
  local out reason
  # --validate also fails when one of its sing-box images cannot be run, so
  # the reason goes into the alert.
  if ! out=$("${SINGBOX_PROFILES_DIR}/render.py" --validate 2>&1); then
    reason=$(printf '%s\n' "${out}" | grep -v '^[[:space:]]*$' | tail -n 1 | tr -d '`' | cut -c1-300)
    printf '%s\n' "${out}" >&2
    abort "pre-flight \`render.py --validate\` failed: \`${reason}\`"
  fi
}

render_or_report() {  # render_or_report "<rollback hint>"
  if ! "${SINGBOX_PROFILES_DIR}/render.py" -y; then
    notify "🚨 **Hysteria2 cert rotation FAILED AT RENDER** (${MODE}) — $1"
    echo "render.py failed" >&2
    exit 1
  fi
  # Same follow-up as the other rotation tiers: refresh the off-host bootstrap
  # copies, which would otherwise keep the previous pins. Optional and
  # non-fatal (the script is a no-op where no remote is configured).
  if [[ -x "${SINGBOX_PROFILES_DIR}/publish-configs-onedrive.sh" ]]; then
    (cd "${SINGBOX_PROFILES_DIR}" && ./publish-configs-onedrive.sh) || true
  fi
}

backup_current() {
  cp -p "${CERT}" "${BAK_CERT}"
  cp -p "${KEY}"  "${BAK_KEY}"
  # Trim old backup pairs beyond RETAIN (cert and key independently: they
  # rotate in lockstep, so the most-recent-N sets line up).
  ls -1t "${CERT}".bak-* 2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f
  ls -1t "${KEY}".bak-*  2>/dev/null | tail -n +$((RETAIN + 1)) | xargs -r rm -f
}

restart_server() {
  [[ -x "${RESTART}" ]] || return 1
  "${RESTART}" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# --bootstrap: publish a next key, touch nothing else.
# ---------------------------------------------------------------------------
if [[ "${MODE}" == bootstrap ]]; then
  if [[ -e "${NEXT_CERT}" || -e "${NEXT_KEY}" ]]; then
    echo "hy2-next already exists in ${SINGBOX_SERVER_DIR} — nothing to bootstrap" >&2
    exit 1
  fi
  [[ -f "${CERT}" && -f "${KEY}" ]] || { echo "no hy2.crt/hy2.key yet — generate them first (docs/quickstart.md)" >&2; exit 1; }
  validate_or_abort
  generate_pair "${NEXT_CERT}" "${NEXT_KEY}" || abort "openssl failed generating the next pair; nothing changed"
  render_or_report "the next pair exists but clients were not re-rendered. Re-run \`render.py -y\`; or undo with \`rm ${NEXT_CERT} ${NEXT_KEY}\`"
  echo "bootstrap complete"
  echo "  next key pin: $(pin_of_cert "${NEXT_CERT}")"
  echo "  A rotation is seamless only for clients that have FETCHED a config"
  echo "  rendered after this point. Leave at least ${HY2_MIN_OVERLAP_DAYS} days before the first rotation."
  exit 0
fi

# ---------------------------------------------------------------------------
# --fresh: emergency, new current pair + new next pair. Flag day for hy2.
# ---------------------------------------------------------------------------
if [[ "${MODE}" == fresh ]]; then
  validate_or_abort
  backup_current
  rm -f "${NEXT_CERT}" "${NEXT_KEY}"
  generate_pair "${CERT}" "${KEY}"           || abort "openssl failed generating the current pair. Restore: \`cp -p ${BAK_CERT} ${CERT} && cp -p ${BAK_KEY} ${KEY}\`"
  generate_pair "${NEXT_CERT}" "${NEXT_KEY}" || abort "openssl failed generating the next pair; the new current pair is in place but NOT live. Re-run with --bootstrap after \`${RESTART}\`"
  restart_server || abort "safe-restart.sh failed after the swap; the server may still present the old cert. Restore: \`cp -p ${BAK_CERT} ${CERT} && cp -p ${BAK_KEY} ${KEY} && ${RESTART}\`"
  render_or_report "new keys are live on the server but clients were not re-rendered. Re-run \`render.py -y\`"
  notify "$(cat <<EOF
🔐 **Hysteria2 key REPLACED (--fresh)** — flag day for hy2
• both the current and the pre-generated next key were discarded
• clients fail hy2 handshakes until they fetch the new config; Reality / ShadowTLS / WS-CDN are unaffected
• new current pin: \`$(pin_of_cert "${CERT}")\`
• next routine rotation: **${NEXT_ROTATION}** @ 05:00 UTC
EOF
)"
  echo "fresh rotation complete (flag day for hy2)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Routine rotation.
# ---------------------------------------------------------------------------
validate_or_abort

[[ -f "${NEXT_CERT}" && -f "${NEXT_KEY}" ]] \
  || abort "no hy2-next pair in ${SINGBOX_SERVER_DIR}: clients trust the current key only, so rotating now would be a flag day. Run \`$0 --bootstrap\`, wait ${HY2_MIN_OVERLAP_DAYS}+ days, then rotate (or \`--fresh\` to accept the flag day)"
pair_matches "${NEXT_CERT}" "${NEXT_KEY}" \
  || abort "hy2-next.crt and hy2-next.key do not belong together; live cert untouched"

next_age_days=$(( ( $(date +%s) - $(stat -c '%Y' "${NEXT_CERT}") ) / 86400 ))
if (( next_age_days < HY2_MIN_OVERLAP_DAYS )); then
  abort "hy2-next.crt was published ${next_age_days} day(s) ago, under the ${HY2_MIN_OVERLAP_DAYS}-day minimum (HY2_MIN_OVERLAP_DAYS): clients may not have fetched its pin yet"
fi

NEW_PIN=$(pin_of_cert "${NEXT_CERT}")
OLD_PIN=$(pin_of_cert "${CERT}")

# The pin is on the key: a cert re-issued from the same key is the same
# identity to every client, with a fresh validity window.
if ! openssl x509 -in "${NEXT_CERT}" -noout -checkend $((MIN_VALID_DAYS * 86400)) >/dev/null 2>&1; then
  issue_cert "${NEXT_KEY}" "${TMPDIR_ROT}/reissued.crt" && pair_matches "${TMPDIR_ROT}/reissued.crt" "${NEXT_KEY}" \
    || abort "could not re-issue the next cert from its key; live cert untouched"
  fix_perms "${TMPDIR_ROT}/reissued.crt" "${NEXT_KEY}"
  mv "${TMPDIR_ROT}/reissued.crt" "${NEXT_CERT}"
fi

# Baseline: is the handshake test usable on this host at all? If the CURRENT
# pin cannot pass, a failure after the swap would prove nothing.
hs_usable=0
if handshake "${OLD_PIN}"; then hs_usable=1; fi

backup_current
mv "${NEXT_CERT}" "${CERT}"
mv "${NEXT_KEY}"  "${KEY}"

rollback() {  # put everything back as it was before the swap
  mv "${CERT}" "${NEXT_CERT}"
  mv "${KEY}"  "${NEXT_KEY}"
  cp -p "${BAK_CERT}" "${CERT}"
  cp -p "${BAK_KEY}"  "${KEY}"
  restart_server || true
}

if ! restart_server; then
  rollback
  abort "safe-restart.sh failed after the swap; previous cert restored and the next pair put back. Clients were not touched"
fi

verified="not run (HY2_SKIP_HANDSHAKE, no docker/curl, or the baseline through this host failed)"
if (( hs_usable )); then
  if handshake "${NEW_PIN}"; then
    verified="handshake with the promoted key passed"
  else
    rollback
    abort "the server did not complete a handshake with the promoted key after the restart; previous cert restored and the next pair put back. Clients were not touched"
  fi
fi

generate_pair "${NEXT_CERT}" "${NEXT_KEY}" \
  || abort "the promoted key is LIVE and verified, but openssl failed generating the following next pair. Run \`$0 --bootstrap\` to create it"

# Clients already trust the promoted key; this render only moves the pin list
# forward to [promoted, new next].
render_or_report "the promoted key is live and clients already trust it, but the new next pin was not published. Re-run \`render.py -y\`"

expiry=$(openssl x509 -in "${CERT}" -noout -enddate | cut -d= -f2)
notify "$(cat <<EOF
🔐 **Hysteria2 cert rotation** — yearly tier
• now presenting the key published since the previous rotation (${next_age_days} days ago): no flag day for clients that fetched a config in that time
• server check: ${verified}
• cert valid until: **${expiry}**
• current pin: \`${NEW_PIN:0:16}…\` · next pin published: \`$(pin_of_cert "${NEXT_CERT}" | cut -c1-16)…\`
• a client that has not fetched for the whole cycle loses hy2 until it does; Reality / ShadowTLS / WS-CDN are unaffected
• next rotation: **${NEXT_ROTATION}** @ 05:00 UTC
EOF
)"
echo "rotation complete"
echo "  server check:      ${verified}"
echo "  cert valid until:  ${expiry}"
echo "  current pin:       ${NEW_PIN}"
echo "  next pin:          $(pin_of_cert "${NEXT_CERT}")"
echo "  backup:            ${BAK_CERT} + ${BAK_KEY}"
