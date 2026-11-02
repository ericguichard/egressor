#!/usr/bin/env bash
# install-singbox.sh
# ------------------------------------------------------------------
# One-shot installer for sing-box on a Linux desktop as a systemd
# service, plus a systemd timer that pulls a fresh config from
# __PROFILE_HOST__ every hour and restarts the service when it changes.
# Linux counterpart of install-singbox.ps1 (Windows/NSSM) — same
# contract, same served URLs, same updater semantics.
#
# WHAT it sets up:
#   1. the sing-box binary — from the DISTRO PACKAGE where one exists
#      (Arch Linux: `extra/sing-box`, which ships the upstream
#      sing-box.service + the `sing-box` system user), else from the
#      GitHub release tarball into /usr/local/bin + our own copy of the
#      upstream unit ("release mode")
#   2. /etc/sing-box/config.json                 (initial fetch, validated)
#   3. /usr/local/lib/egressor/update-config.sh  (auto-updater)
#   4. /etc/egressor/updater.env                 (updater parameters)
#   5. systemd service  sing-box.service         (auto-start, restart on crash)
#   6. systemd timer    egressor-update.timer    (at boot + hourly)
#
# WHY a distro package first: on Arch the package tracks upstream within
# a day, ships the hardened upstream unit (runs as the unprivileged
# `sing-box` user with ambient CAP_NET_ADMIN) and pacman owns the
# binary lifecycle, so the updater only has to manage the config. The
# release-mode fallback exists for distros without a package; there the
# updater also tracks the server-published version like Windows does.
#
# Usage (any shell, needs sudo):
#   curl -fsSL https://__PROFILE_HOST__/p/<USER_SECRET>/install-singbox.sh -o /tmp/sb.sh
#   sudo bash /tmp/sb.sh
#
# Re-running is SAFE: the previous config is kept as config.json.prev,
# the service is restarted, the timer re-registered.
# ------------------------------------------------------------------

set -euo pipefail

# --- Remote profile (per-user secret in the path) -------------------
# Values between __..__ are substituted by generate-installer.sh per user.
REMOTE_URL='https://__PROFILE_HOST__/p/__USER_SECRET__/__CONFIG_FILENAME__'
# Plain-text file with the sing-box version the server publishes (written
# by publish-version.sh every 5 min; honours the operator's fleet pin).
# Used only in release mode — in package mode the distro owns the binary.
VERSION_URL='https://__PROFILE_HOST__/mirror/sing-box-version.txt'
# Optional notification webhook (Discord-shaped JSON POST: {"content": ...}).
# Empty string disables notifications — typically reserved for admin users.
WEBHOOK_URL='__INSTALL_WEBHOOK_URL__'

# --- Fixed paths ----------------------------------------------------
CONFIG_DIR=/etc/sing-box
CONFIG=$CONFIG_DIR/config.json
STATE_DIR=/var/lib/sing-box          # sing-box -D: cache.db, downloaded UI + rule-sets
EGRESSOR_ETC=/etc/egressor
UPDATER_ENV=$EGRESSOR_ETC/updater.env
UPDATER_DIR=/usr/local/lib/egressor
UPDATER=$UPDATER_DIR/update-config.sh
EGRESSOR_STATE=/var/lib/egressor     # fail counter, WG endpoint snapshot
SVC=sing-box
TIMER=egressor-update
RELEASE_BIN=/usr/local/bin/sing-box  # release mode only; package mode uses /usr/bin/sing-box

log()  { printf '[install-singbox] %s\n' "$*"; }
die()  { printf '[install-singbox] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo bash $0"
command -v systemctl >/dev/null || die "systemd is required (no systemctl found)"
command -v curl >/dev/null || die "curl is required"

# curl with retries: 3 attempts, 5 s apart, fail on HTTP errors so a 404
# page never lands where a binary or config is expected.
fetch() { curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 15 --max-time "${3:-60}" -o "$2" "$1"; }

# --- 1. sing-box binary ----------------------------------------------
# Package mode (pacman) or release mode (GitHub tarball). Recorded in
# updater.env so the updater knows whether the binary is its business.
BINARY_MODE=release
if command -v pacman >/dev/null; then
    BINARY_MODE=package
    log "Arch Linux detected: installing sing-box from the official repos"
    # --needed = no-op when already current; no -Sy (partial-upgrade hazard —
    # if the package index is stale, `pacman -Syu` first and re-run).
    pacman -S --needed --noconfirm sing-box \
        || die "pacman could not install sing-box. Run 'sudo pacman -Syu', then re-run this installer."
    SB_BIN=$(command -v sing-box) || die "sing-box not on PATH after pacman install"
else
    log "No supported package manager: installing the release tarball"
    case "$(uname -m)" in
        x86_64)  SB_ARCH=amd64 ;;
        aarch64) SB_ARCH=arm64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
    tmpv=$(mktemp)
    fetch "$VERSION_URL" "$tmpv" 15
    SB_VERSION=$(tr -d '[:space:]' < "$tmpv"); rm -f "$tmpv"
    [[ $SB_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || die "VERSION_URL returned non-semver '$SB_VERSION'"
    tarball="sing-box-$SB_VERSION-linux-$SB_ARCH.tar.gz"
    tmpd=$(mktemp -d)
    log "Downloading $tarball"
    fetch "https://github.com/SagerNet/sing-box/releases/download/v$SB_VERSION/$tarball" "$tmpd/$tarball" 300
    tar -xzf "$tmpd/$tarball" -C "$tmpd"
    newbin=$(find "$tmpd" -type f -name sing-box | head -1)
    [[ -n $newbin ]] || die "tarball did not contain a sing-box binary"
    chmod 0755 "$newbin"
    "$newbin" version >/dev/null || die "downloaded sing-box fails its own smoke test"
    # Unprivileged service user, same as the upstream sysusers entry.
    getent group sing-box >/dev/null || groupadd --system sing-box
    id -u sing-box >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin -g sing-box sing-box
    [[ -f $RELEASE_BIN ]] && cp -f "$RELEASE_BIN" "$RELEASE_BIN.prev"
    install -m 0755 "$newbin" "$RELEASE_BIN"
    rm -rf "$tmpd"
    SB_BIN=$RELEASE_BIN
    # Verbatim upstream unit (release/config/sing-box.service) with the
    # binary path swapped; -C loads every *.json in /etc/sing-box.
    cat > /etc/systemd/system/sing-box.service <<UNIT
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
User=sing-box
StateDirectory=sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=$RELEASE_BIN -D $STATE_DIR -C $CONFIG_DIR run
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
UNIT
fi
log "sing-box binary: $SB_BIN ($("$SB_BIN" version | head -1))"

# --- 2. Initial config fetch + validation ----------------------------
# Validate BEFORE touching the service — a broken config means a
# crash-loop on first start, which we'd rather catch here.
mkdir -p "$CONFIG_DIR" "$EGRESSOR_ETC" "$UPDATER_DIR" "$EGRESSOR_STATE"
tmpcfg=$(mktemp)
log "Fetching initial config from $REMOTE_URL"
fetch "$REMOTE_URL" "$tmpcfg" 30
log "Validating with sing-box check"
"$SB_BIN" check -c "$tmpcfg" || die "sing-box check rejected the fetched config"
# The unit runs `-C /etc/sing-box`, which MERGES every *.json in the dir.
# The package ships a placeholder config.json (a shadowsocks inbound on
# :8080) under that exact name — overwriting it is the point; any OTHER
# json there would silently merge into ours, so refuse to guess.
extra=$(find "$CONFIG_DIR" -maxdepth 1 -name '*.json' ! -name config.json | head -3)
[[ -z $extra ]] || die "other JSON files in $CONFIG_DIR would be merged into the config by sing-box -C: $extra — move them away and re-run"
[[ -f $CONFIG ]] && cp -f "$CONFIG" "$CONFIG.prev"
# Readable by the service user only (the file carries the credentials).
install -m 0640 -o root -g sing-box "$tmpcfg" "$CONFIG"; rm -f "$tmpcfg"
log "Installed $CONFIG"

# --- 3. Updater parameters ------------------------------------------
cat > "$UPDATER_ENV" <<ENV
# Written by install-singbox.sh — re-run the installer to change these.
REMOTE_URL='$REMOTE_URL'
VERSION_URL='$VERSION_URL'
WEBHOOK_URL='$WEBHOOK_URL'
BINARY_MODE='$BINARY_MODE'
SB_BIN='$SB_BIN'
ENV
chmod 0600 "$UPDATER_ENV"

# --- 4. Updater script (run hourly by the timer) --------------------
# Written verbatim (quoted heredoc: nothing expands here). Every parameter
# comes from updater.env so the script itself is user-agnostic.
cat > "$UPDATER" <<'UPDATER_EOF'
#!/usr/bin/env bash
# update-config.sh — hourly egressor config refresh (systemd timer).
# Mirrors the Windows update-config.ps1 contract:
#   * pre-flight: a real HTTP GET of the version file through the tunnel;
#     unreachable -> skip silently (offline / tunnel not up). A raw TCP probe
#     is useless here: under sing-box the profile host is a fakeip the TUN
#     answers locally, so a connect always "succeeds".
#   * config: fetch, sha256-compare, `sing-box check`, swap (keep .prev),
#     restart. A restart that does not come back rolls the config back to
#     .prev and restarts again (a remote user has no admin at hand).
#   * binary: release mode only — follow VERSION_URL (package mode leaves
#     the binary to the distro package manager).
#   * WG endpoint DNS drift: sing-box resolves WireGuard peer hostnames at
#     startup only, so a moved dynamic-DNS name needs a restart.
#   * alert damper: a run failure pages (webhook) only after 3 consecutive
#     failed runs; any effective run resets the counter.
# Does NOT self-update: re-run the installer to pick up a newer version of
# this script. Logs go to the journal (journalctl -u egressor-update).
set -uo pipefail
source /etc/egressor/updater.env

CONFIG_DIR=/etc/sing-box; CONFIG=$CONFIG_DIR/config.json
STATE=/var/lib/egressor; mkdir -p "$STATE"
FAILCOUNT_FILE=$STATE/update-fail-count
WG_CACHE=$STATE/wg-endpoint-ips
FAIL_ALERT_THRESHOLD=3
HOST_TAG="[linux $(hostname)]"
RELEASE_BIN=/usr/local/bin/sing-box

log()    { printf '%s %s\n' "$(date -u '+%F %T')" "$*"; }
notify() {
    [[ -n ${WEBHOOK_URL:-} ]] || return 0
    local body; body=$(printf '{"content": "%s %s"}' "$HOST_TAG" "${*//\"/\\\"}")
    curl -fsS -m 10 -H 'Content-Type: application/json' -d "$body" "$WEBHOOK_URL" >/dev/null 2>&1 \
        || log "notify: failed"
}
fetch() { curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 15 --max-time "${3:-60}" -o "$2" "$1"; }
get_failcount() { [[ -f $FAILCOUNT_FILE ]] && tr -dc '0-9' < "$FAILCOUNT_FILE" || echo 0; }
set_failcount() { echo "$1" > "$FAILCOUNT_FILE"; }
reachable()     { curl -fs -m 15 -o /dev/null "$VERSION_URL"; }   # -s only: a failed probe is the expected offline case, keep the journal quiet

# Returns 0 if the config was replaced (restart needed), 1 if unchanged/rejected.
update_config() {
    local tmp new old
    tmp=$(mktemp) || return 2
    if ! fetch "$REMOTE_URL" "$tmp" 30; then rm -f "$tmp"; return 2; fi
    new=$(sha256sum "$tmp" | cut -c1-64)
    old=$([[ -f $CONFIG ]] && sha256sum "$CONFIG" | cut -c1-64 || echo none)
    if [[ $new == "$old" ]]; then
        log "config: no change (sha256 ${new:0:8})"; rm -f "$tmp"; return 1
    fi
    # A config that crashed the service was rolled back and kept as
    # .rejected; do not re-apply the identical bytes every hour (it would
    # flap crash/rollback until the server serves something else).
    if [[ -f $CONFIG.rejected && $new == "$(sha256sum "$CONFIG.rejected" | cut -c1-64)" ]]; then
        log "config: served config (${new:0:8}) is the one rolled back earlier; skipping until it changes"
        rm -f "$tmp"; return 1
    fi
    if ! "$SB_BIN" check -c "$tmp" >/dev/null 2>&1; then
        log "config: FAIL sing-box check rejected fetched config; keeping current"
        notify "config update FAILED: sing-box check rejected fetched config; keeping current"
        rm -f "$tmp"; return 1
    fi
    [[ -f $CONFIG ]] && cp -f "$CONFIG" "$CONFIG.prev"
    install -m 0640 -o root -g sing-box "$tmp" "$CONFIG"; rm -f "$tmp"
    log "config: replaced (sha256 ${old:0:8} -> ${new:0:8})"
    notify "config updated (${old:0:8} -> ${new:0:8})"
    return 0
}

# Release mode only. Fails soft: a binary-upgrade problem must never break
# an otherwise-working VPN. Returns 0 if the binary was replaced.
update_binary() {
    [[ ${BINARY_MODE:-release} == release ]] || return 1
    local tmpv want have arch tarball tmpd newbin
    tmpv=$(mktemp); fetch "$VERSION_URL" "$tmpv" 15 || { rm -f "$tmpv"; return 1; }
    want=$(tr -d '[:space:]' < "$tmpv"); rm -f "$tmpv"
    [[ $want =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || { log "binary: non-semver version '$want'; skipping"; return 1; }
    have=$("$SB_BIN" version 2>/dev/null | awk '/^sing-box version/ {print $3; exit}')
    [[ $want != "$have" ]] || return 1
    case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) return 1 ;; esac
    tarball="sing-box-$want-linux-$arch.tar.gz"; tmpd=$(mktemp -d)
    log "binary: $have -> $want (downloading $tarball)"
    if ! fetch "https://github.com/SagerNet/sing-box/releases/download/v$want/$tarball" "$tmpd/$tarball" 300; then
        log "binary: download failed; keeping $have"; rm -rf "$tmpd"; return 1
    fi
    tar -xzf "$tmpd/$tarball" -C "$tmpd" 2>/dev/null
    newbin=$(find "$tmpd" -type f -name sing-box | head -1); chmod 0755 "$newbin" 2>/dev/null
    if [[ -z $newbin ]] || ! "$newbin" version >/dev/null 2>&1; then
        log "binary: smoke-test failed on downloaded binary; skipping"
        notify "binary upgrade to $want FAILED: downloaded binary smoke-test failed"
        rm -rf "$tmpd"; return 1
    fi
    # Schema compatibility: the CURRENT config must still parse under the
    # new binary, or the restart would crash-loop.
    if ! "$newbin" check -c "$CONFIG" >/dev/null 2>&1; then
        log "binary: $want rejects the current config; keeping $have"
        notify "binary upgrade to $want SKIPPED: new version rejects the current config"
        rm -rf "$tmpd"; return 1
    fi
    cp -f "$RELEASE_BIN" "$RELEASE_BIN.prev" 2>/dev/null
    install -m 0755 "$newbin" "$RELEASE_BIN"; rm -rf "$tmpd"
    log "binary: upgraded $have -> $want"
    notify "binary upgraded $have -> $want"
    return 0
}

# Returns 0 when a WireGuard peer hostname resolves differently than at the
# last run. Peer hostnames are the only non-IP `"address"` strings in the
# rendered config (TUN/endpoint addresses are CIDR literals; proxies use
# `"server"`), which keeps this dependency-free (no jq/python needed).
wg_endpoint_drift() {
    local drift=1 names n ip cached
    [[ -f $CONFIG ]] || return 1
    names=$(grep -oE '"address": *"[^"]+"' "$CONFIG" | sed -E 's/.*"([^"]+)"$/\1/' \
            | grep -vE '^[0-9.]+(/[0-9]+)?$' | grep -vE '^\[?[0-9a-fA-F:]+\]?(/[0-9]+)?$' | sort -u)
    [[ -n $names ]] || return 1
    touch "$WG_CACHE"
    while read -r n; do
        [[ -n $n ]] || continue
        ip=$(getent ahostsv4 "$n" 2>/dev/null | awk '{print $1; exit}')
        [[ -n $ip ]] || continue          # unresolvable now: not a drift, just skip
        cached=$(awk -v h="$n" '$1==h {print $2}' "$WG_CACHE")
        if [[ -n $cached && $cached != "$ip" ]]; then
            log "wg: endpoint $n moved $cached -> $ip"; drift=0
        fi
        { grep -v "^$n " "$WG_CACHE"; echo "$n $ip"; } > "$WG_CACHE.new" && mv "$WG_CACHE.new" "$WG_CACHE"
    done <<< "$names"
    return $drift
}

restart_service() {
    systemctl restart sing-box; sleep 3
    systemctl is-active --quiet sing-box
}

update_pass() {
    local cfg=1 bin=1 dns=1 rc
    update_config; rc=$?; [[ $rc -eq 2 ]] && return 2; cfg=$rc
    update_binary && bin=0
    wg_endpoint_drift && dns=0
    if [[ $cfg -eq 0 || $bin -eq 0 || $dns -eq 0 ]]; then
        if restart_service; then
            log "sing-box restarted (cfg=$((1-cfg)) bin=$((1-bin)) dns=$((1-dns)))"
            [[ $dns -eq 0 && $cfg -ne 0 && $bin -ne 0 ]] && notify "sing-box restarted: WG endpoint DNS drift detected"
        else
            log "sing-box did NOT come back after restart"
            if [[ $cfg -eq 0 && -f $CONFIG.prev ]]; then
                cp -f "$CONFIG" "$CONFIG.rejected"; install -m 0640 -o root -g sing-box "$CONFIG.prev" "$CONFIG"
                if restart_service; then
                    log "rolled back to config.json.prev (new config kept as config.json.rejected)"
                    notify "new config crashed sing-box; ROLLED BACK to the previous config (kept as config.json.rejected)"
                    return 0
                fi
            fi
            notify "service did NOT reach active after restart (cfg=$((1-cfg)) bin=$((1-bin)) dns=$((1-dns)))"
            return 1
        fi
    fi
    return 0
}

# Pre-flight gate: no working path to the profile host -> nothing this run
# can do; skip silently, the next hourly run self-heals.
if ! reachable; then
    sleep 30
    if ! reachable; then
        log "pre-flight: profile host unreachable (2 probes 30s apart); skipping run (offline / tunnel not up)"
        exit 0
    fi
fi

if update_pass; then
    (( $(get_failcount) == 0 )) || { log "recovered after $(get_failcount) consecutive failed run(s)"; set_failcount 0; }
    exit 0
fi
# Transient-failure damper: one more full pass after 30 s.
log "first pass failed; retrying full pass in 30s"
sleep 30
if update_pass; then
    log "second pass succeeded after transient first-pass failure"
    set_failcount 0; exit 0
fi
n=$(( $(get_failcount) + 1 )); set_failcount "$n"
log "updater run failed (consecutive failures: $n)"
if (( n >= FAIL_ALERT_THRESHOLD )); then
    notify "updater failed $n consecutive runs (journalctl -u egressor-update on the machine)"
fi
exit 1
UPDATER_EOF
chmod 0755 "$UPDATER"

# --- 5. Timer + service units for the updater -----------------------
cat > /etc/systemd/system/$TIMER.service <<UNIT
[Unit]
Description=egressor: refresh the sing-box config from the profile server
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATER
# Two 30 s waits + retries inside; never let a hung fetch pile up runs.
TimeoutStartSec=15min
UNIT
cat > /etc/systemd/system/$TIMER.timer <<UNIT
[Unit]
Description=egressor: hourly sing-box config refresh

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# --- 6. Enable + start ----------------------------------------------
systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1 || true
if systemctl is-active --quiet "$SVC"; then
    log "Restarting $SVC with the new config"; systemctl restart "$SVC"
else
    log "Starting $SVC"; systemctl start "$SVC"
fi
systemctl enable --now "$TIMER.timer" >/dev/null
sleep 3
if systemctl is-active --quiet "$SVC"; then
    log "$SVC is active (mode: $BINARY_MODE)"
else
    systemctl --no-pager -l status "$SVC" || true
    die "$SVC did not reach active — see: journalctl -u $SVC -n 50"
fi

log "Done."
log "  dashboard : http://127.0.0.1:9090/ui  (API secret is in your README)"
log "  status    : systemctl status $SVC"
log "  logs      : journalctl -u $SVC -f"
log "  updater   : systemctl start $TIMER.service   # force a config check now"
log "              journalctl -u $TIMER              # its log"
[[ $BINARY_MODE == package ]] && log "  binary    : managed by pacman (sudo pacman -Syu upgrades sing-box)"
exit 0
