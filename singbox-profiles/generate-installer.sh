#!/bin/bash
# generate-installer.sh — produce a per-user install-singbox.ps1 (Windows)
# or, with --linux, install-singbox.sh (Linux/systemd) from the shared
# template. Called once per user+type; writes into that user's served
# directory so the one-liner URL
#   https://${PROFILE_HOST}/p/<secret>/install-singbox.ps1   (Windows)
#   https://${PROFILE_HOST}/p/<secret>/install-singbox.sh    (Linux)
# pulls an installer already pre-configured with their secret path,
# config filename, and (optionally) a notification webhook URL.
#
# Why a generator instead of a single dynamic script: the installer has
# to know which user it is BEFORE fetching anything (to pick the right
# config URL). PowerShell scripts downloaded to $env:TEMP lose knowledge
# of their source URL, so we bake it in at generation time instead.
#
# Usage:
#   generate-installer.sh [--linux] <user> <config-filename> [webhook-url]
#
# Example:
#   generate-installer.sh alice egressor-alice-windows.json   "$WEBHOOK"
#   generate-installer.sh bob   egressor-bob-windows.json
#   generate-installer.sh dave egressor-dave-windows.json
#   generate-installer.sh --linux dave egressor-dave-linux.json

set -euo pipefail

PROFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS=$PROFILES_DIR/secrets.txt

# --linux (added 2026-09-02) selects the bash/systemd template and output name;
# the placeholder set is identical, so the sed pass below is shared.
TEMPLATE=$PROFILES_DIR/templates/install-singbox.template.ps1
OUT_NAME=install-singbox.ps1
if [[ ${1:-} == --linux ]]; then
    TEMPLATE=$PROFILES_DIR/templates/install-singbox.template.sh
    OUT_NAME=install-singbox.sh
    shift
fi

user=${1:?usage: $0 [--linux] <user> <config-filename> [webhook-url]}
cfg=${2:?usage: $0 [--linux] <user> <config-filename> [webhook-url]}
webhook=${3:-}
# PROFILE_HOST: same env var render.py reads. Required — falls back to a
# placeholder hostname so accidental no-env runs produce an obviously-broken
# URL rather than a silently-wrong one.
profile_host=${PROFILE_HOST:-profile.example.com}

# Resolve secret from the authoritative mapping. We look up by exact
# user match so a typo here fails loud instead of silently matching the
# wrong person's directory.
secret=$(awk -v u="$user" '$1==u {print $2}' "$SECRETS")
if [[ -z "$secret" ]]; then
    echo "generate-installer: no secret found for user '$user' in $SECRETS" >&2
    exit 1
fi

out=$PROFILES_DIR/srv/p/$secret/$OUT_NAME
if [[ ! -d "$(dirname "$out")" ]]; then
    echo "generate-installer: served dir $(dirname "$out") missing" >&2
    exit 1
fi

# sed -e chain with '|' delimiter so URLs don't collide with '/' in the
# value. Placeholders are the literal tokens used in the template.
# __INSTALL_WEBHOOK_URL__ is distinct from __WEBHOOK_URL__: the latter
# lives inside the embedded here-string AND inside the runtime
# .Replace('__WEBHOOK_URL__', $WEBHOOK_URL) call. Substituting it at
# generation time would rewrite that .Replace to .Replace('', ...) for
# users with no webhook, which PowerShell rejects ("oldValue length 0").
sed \
    -e "s|__PROFILE_HOST__|$profile_host|g" \
    -e "s|__USER_SECRET__|$secret|g" \
    -e "s|__CONFIG_FILENAME__|$cfg|g" \
    -e "s|__INSTALL_WEBHOOK_URL__|$webhook|g" \
    "$TEMPLATE" > "$out"

echo "generate-installer: wrote $out (user=$user cfg=$cfg host=$profile_host template=$(basename "$TEMPLATE") webhook=$([[ -n "$webhook" ]] && echo yes || echo no))"
