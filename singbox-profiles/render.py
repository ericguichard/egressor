#!/usr/bin/env python3
"""
singbox-profiles generator.

Reads profiles.yaml and renders per-device client configs, installers, and
(eventually) server-side user blocks. Composition is dict-level: each fragment
function returns a Python dict describing a piece of the final sing-box JSON,
and the composer merges them. Comments live in fragment source for humans
reading this file; output JSON is pure JSON (no comments).

See profiles.yaml for the schema and CLI examples.
"""
import argparse
import datetime
import difflib
import ipaddress  # AWG endpoint bypass rule: literal-IP vs hostname match (frag_route)
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import jsonschema
import yaml


# Schema for profiles.yaml — validated at manifest load time so typos fail
# loudly with a precise path instead of sliding through to a cryptic
# `sing-box check` error buried in rendered output. Kept deliberately loose
# on unknown keys (additionalProperties stays default-allow) because the
# renderer reads a fixed set and ignores the rest; the schema guards the
# positive shape, not the negative.
PROFILES_SCHEMA = {
    'type': 'object',
    'required': ['defaults', 'users'],
    'properties': {
        'defaults': {
            'type': 'object',
            'properties': {
                'utls_fingerprint': {'type': 'string'},
                'reality': {'type': 'object', 'required': ['server', 'server_port', 'handshake_sni', 'flow']},
                'ws-cf':   {'type': 'object', 'required': ['host', 'path', 'port']},
                'shadowtls': {'type': 'object', 'required': ['server_port', 'version', 'sni', 'shadowsocks_method']},
                'hy2':       {'type': 'object', 'required': ['server_port', 'sni']},
                # Optional list of CIDRs (e.g. the server's public IPs) that
                # should always route Direct from a client to avoid TUN
                # hairpin loops on hy2's outer QUIC. Omit / leave empty for
                # single-host deployments where the proxy hostname only
                # resolves to one IP that's already covered by other rules.
                'proxy_server_ips': {'type': 'array', 'items': {'type': 'string'}},
                # Optional SIP hub bypass: the Asterisk hub's host + the SIP/RTP
                # port ranges that must reach it Direct (a proxy cannot relay UDP
                # back to its own host — see the rule emission for the story).
                'sip_hub': {'type': 'object', 'required': ['hosts', 'port_ranges'],
                            'properties': {'hosts': {'type': 'array', 'items': {'type': 'string'}},
                                           'port_ranges': {'type': 'array', 'items': {'type': 'string'}},
                                           # Android package ids of the softphone(s): the whole app
                                           # goes Direct on mobile devices (push proxy, STUN, RTP —
                                           # none of which is host/port-addressable).
                                           'android_packages': {'type': 'array', 'items': {'type': 'string'}}}},
            },
        },
        'users': {
            'type': 'object',
            'patternProperties': {
                # Usernames: lowercase a-z, 2–24 chars. Narrow enough to catch
                # accidental capitals or whitespace that would then become
                # directory / URL path segments.
                '^[a-z][a-z0-9_-]{1,23}$': {
                    'type': 'object',
                    'required': ['countries', 'protocols', 'devices'],
                    'properties': {
                        'countries': {
                            'type': 'array',
                            'items': {'enum': ['cn', 'ru', 'ir']},
                        },
                        'protocols': {
                            'type': 'array',
                            # 'awg' is valid here but never emits a sing-box
                            # outbound — AWG lives in a standalone wg-quick
                            # .conf consumed by the Amnezia VPN app, not in
                            # the sing-box profile (deliberate two-app split,
                            # see docs/architecture.md). Including 'awg' in
                            # protocols flips per-device awg-<dev>.conf
                            # emission and the matching server-side [Peer]
                            # blocks; nothing in the sing-box outbound list
                            # changes.
                            'items': {'enum': ['reality', 'ws-cf', 'shadowtls', 'hy2', 'awg']},
                            'minItems': 1,
                        },
                        # Stage-3 hook: country-derived selector default can be
                        # overridden per-user. Schema-validated here in stage 1
                        # so .yaml authors can't typo. AWG is a valid value but
                        # picking it as preferred for the sing-box selector
                        # would be a no-op (AWG isn't a sing-box outbound) —
                        # documented in the schema, not enforced, since stage 3
                        # will be the one wiring this into selector emission.
                        'preferred_protocol': {
                            'enum': ['reality', 'ws-cf', 'shadowtls', 'hy2', 'awg'],
                        },
                        'admin': {'type': 'boolean'},
                        # Route Tailscale's CGNAT range (100.64.0.0/10) through
                        # 🔀 Proxy so the phone can reach tailnet peers (and the
                        # laptop reverse-tunnel) DPI-resistantly via the
                        # docker-host relay. Declared here so a typo fails fast.
                        'tailnet': {'type': 'boolean'},
                        # Per-user uTLS fingerprint. Structural (chosen by
                        # operator to spread JA3/JA4 signatures across the
                        # household), not a secret — lives in profiles.yaml,
                        # not in .secrets.yaml. Enum-gated to catch typos
                        # and block sing-box values that wouldn't pass
                        # `sing-box check` anyway.
                        'utls_fingerprint': {
                            'enum': ['chrome', 'firefox', 'safari', 'ios', 'android',
                                     'edge', 'random', 'randomized', '360', 'qq'],
                        },
                        # Per-user ShadowTLS SNI override. If unset, the
                        # renderer picks from defaults.shadowtls.sni_pool
                        # via hash(username) — stable and automatic. Set
                        # this to pin a specific SNI for a user (useful
                        # if one pool member becomes unreliable). Must be
                        # a hostname; not enum-gated because the pool is
                        # fully operator-controlled.
                        'shadowtls_sni': {'type': 'string'},
                        'home': {
                            'type': 'object',
                            'properties': {
                                'country': {'type': 'string'},
                                'home_egress_countries': {'type': 'array', 'items': {'type': 'string'}},
                                'home_egress_tlds':      {'type': 'array', 'items': {'type': 'string'}},
                            },
                        },
                        'devices': {
                            'type': 'array',
                            'minItems': 1,
                            'items': {
                                'type': 'object',
                                'required': ['type', 'name'],
                                'properties': {
                                    # mac (added 2026-07-29): macOS running SFM
                                    # (brew cask / GitHub-releases app — the Mac
                                    # App Store has no listing). Config shape is
                                    # mobile-like (GUI app importing a remote
                                    # profile), minus mobile-only extras: no NTP
                                    # block, no per-protocol solo files, tailnet
                                    # selector defaults Direct like windows.
                                    # linux (added 2026-09-02): a Linux desktop
                                    # running the CLI sing-box under systemd
                                    # (distro package where one exists, e.g.
                                    # Arch's `extra/sing-box`; GitHub release
                                    # tarball otherwise). Windows-shaped config
                                    # (clash_api dashboard; the hourly
                                    # systemd-timer refresh fetches through 🔀 Proxy),
                                    # minus the wintun/NSSM specifics. Installed
                                    # by the generated install-singbox.sh.
                                    'type': {'enum': ['mobile', 'windows', 'mac', 'linux']},
                                    'name': {'type': 'string', 'pattern': '^[a-z0-9][a-z0-9_-]*$'},
                                    # Optional pin of this device's AWG IPv4
                                    # address (CIDR, /32 convention). If omitted
                                    # the renderer auto-allocates from
                                    # .secrets.yaml's awg.subnet via a stable
                                    # hash of "<uname>/<dev_name>" so adding a
                                    # new device doesn't reshuffle existing
                                    # peers. Only meaningful when the user has
                                    # 'awg' in protocols.
                                    'awg_address': {'type': 'string'},
                                    # Embedded Tailscale endpoint (sing-box
                                    # 1.12+, added here 2026-08-15): the device
                                    # joins the tailnet as a native node from
                                    # INSIDE sing-box — no second VPN slot
                                    # needed, which is the whole point on
                                    # Android (the OS gives exactly one).
                                    # Requires user-level tailnet:true (the
                                    # endpoint becomes a 🔗 Tailnet selector
                                    # member) and an operator-supplied
                                    # tailscale_auth_key in .secrets.yaml
                                    # under this device (never auto-gen'd:
                                    # it is minted in the tailnet admin
                                    # console, external state like the
                                    # reality keypair).
                                    'tailscale': {'type': 'boolean'},
                                    # How the tsnet endpoint's OWN control/
                                    # DERP dials leave the device. 'direct'
                                    # (default) = protected raw path — the
                                    # Android-proven choice. 'proxy' = ride
                                    # 🔀 Proxy: makes the node reachable on
                                    # networks that block Tailscale entirely
                                    # (break-glass inbound), at the cost of
                                    # depending on the tunnel being up.
                                    'tailscale_detour': {'enum': ['direct', 'proxy']},
                                    # Oldest sing-box core this device runs,
                                    # as "<major>.<minor>". Gates fields a
                                    # newer core needs and an older one
                                    # rejects at decode ("unknown field").
                                    # Defaults per type, see CORE_MIN_DEFAULT.
                                    # The file is validated on the first
                                    # release of this version (v<core_min>.0),
                                    # so a version with no stable release yet
                                    # fails `--validate` until it ships.
                                    'core_min': {'type': 'string', 'pattern': r'^1\.\d+$'},
                                },
                            },
                        },
                    },
                },
            },
            # No user outside the pattern is allowed — catches capitalised
            # usernames that would otherwise render into the served directory
            # tree with case inconsistency.
            'additionalProperties': False,
        },
    },
}


def _validate_manifest_schema(manifest):
    """
    Raise a precise SystemExit with a JSONPath-like location when profiles.yaml
    doesn't match the schema. Better signal than sing-box check's post-render
    errors which point at generated output, not the source.
    """
    try:
        jsonschema.validate(manifest, PROFILES_SCHEMA)
    except jsonschema.ValidationError as e:
        loc = '/'.join(str(p) for p in e.absolute_path) or '<root>'
        sys.exit(f'profiles.yaml schema error at {loc}: {e.message}')


ROOT = Path(__file__).parent.resolve()
MANIFEST = ROOT / 'profiles.yaml'
SECRETS = ROOT / '.secrets.yaml'     # credentials (auto-managed, 0600)
HOME_WG_DIR = ROOT / 'home_wg'       # externally-generated WG .conf files
EXIT_WG_DIR = ROOT / 'exit_wg'       # extra WG exits: exit_wg/<exit>/<user>-<device>.conf
SRV = ROOT / 'srv' / 'p'
TEMPLATE_INSTALLER = ROOT / 'templates' / 'install-singbox.template.ps1'
GENERATE_INSTALLER = ROOT / 'generate-installer.sh'
SECRETS_FILE = ROOT / 'secrets.txt'  # user → secret mapping (kept for compat)

# Server sync paths. Default layout: this renderer at <repo>/singbox-profiles/,
# the docker-compose stack at <repo>/singbox-server/. Override SINGBOX_SERVER_DIR
# to point elsewhere (e.g. for a deployment where the two halves don't sit in
# the same repo).
SERVER_DIR = Path(os.environ.get('SINGBOX_SERVER_DIR', str(ROOT.parent / 'singbox-server'))).resolve()
SERVER_CONFIG = SERVER_DIR / 'config.json'
SERVER_TEMPLATE = ROOT / 'templates' / 'singbox-server.template.jsonc'
# Per-user README templates, one subdir per language. Section files use the
# same __TOKEN__ replace idiom as the other templates here. Adding a language
# = drop a sibling subdir with translations; en/ is the canonical fallback.
README_TEMPLATE_DIR = ROOT / 'templates' / 'readme'

# Per-language labels for the Python-built credentials block. Labels only —
# never the credential values themselves. To add a language, copy the en/
# block and translate. Keys missing from a non-en entry fall through to en
# (lookups go via README_LABELS[lang].get(k, README_LABELS['en'][k])).
README_LABELS = {
    'en': {
        'profile_url': 'Profile URL',
        'server': 'Server',
        'clash_secret': 'clash secret',
        'password': 'password',
        'shared_devices_paren': '(shared across your devices)',
        'server_user_paren': '(server:user)',
    },
    'ru': {
        'profile_url': 'URL профиля',
        'server': 'Сервер',
        # technical identifier — kept English so it matches whatever's in the
        # Windows installer / dashboard UI strings.
        'clash_secret': 'clash secret',
        'password': 'пароль',
        'shared_devices_paren': '(общий для всех твоих устройств)',
        # "server:user" is the colon-separated format identifier, not prose.
        'server_user_paren': '(server:user)',
    },
}
SERVER_RESTART = SERVER_DIR / 'safe-restart.sh'
# Optional .env file consulted for host-wide vars (VNIC bind IPs etc.) when
# they're not already set in the process environment. Defaults to <repo>/.env;
# override via EGRESSOR_ENV_FILE (CLEARWAY_ENV_FILE still honoured — pre-rename
# deploys). Process-env always wins so docker-compose --env-file passes
# through transparently.
ENV_FILE = Path(os.environ.get('EGRESSOR_ENV_FILE',
                               os.environ.get('CLEARWAY_ENV_FILE',
                                              str(ROOT.parent / '.env'))))


def _env_or_dotenv(key, default=None):
    """Resolve a single env var: process env first, then repo-level .env file,
    else `default`. Used by config-init paths that need to pick up vars set in
    .env even when render.py wasn't invoked with the env exported (e.g. a bare
    `python3 render.py` from any shell). _read_env is the strict variant for
    required vars; this is the optional-with-fallback variant."""
    if key in os.environ:
        return os.environ[key]
    if ENV_FILE.exists():
        for raw in ENV_FILE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            if k.strip() == key:
                return v.strip().strip('"').strip("'")
    return default


# Public hostname that serves per-user profile directories under /p/<secret>/.
# Used in README URLs, the Windows installer one-liner, and secrets.txt header.
# Resolved with .env fallback (matches the pattern other host-wide vars use)
# so a bare `python3 render.py` from any shell picks up the right value
# without needing the operator to remember to export PROFILE_HOST first —
# previously the absence of the env var silently rendered URLs against
# `profile.example.com`. To change it: update PROFILE_HOST in the repo-level
# .env, the Traefik Host() rule in singbox-server/compose.yaml, and the DNS
# A record, then re-run ./render.py to regenerate READMEs + installers.
PROFILE_HOST = _env_or_dotenv('PROFILE_HOST', 'profile.example.com')


def _read_env(keys):
    """Resolve a set of vars from the process environment first, falling back
    to the repo-level .env file. Used to substitute host-wide vars (VNIC IPs)
    into the server template. Exits if any requested key is unresolved — we
    don't want a silent bind to the literal placeholder at render time."""
    found = {k: os.environ[k] for k in keys if k in os.environ}
    missing = set(keys) - set(found)
    if missing and ENV_FILE.exists():
        for raw in ENV_FILE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            k = k.strip()
            if k in missing:
                # Strip surrounding quotes if any; keep inner content as-is.
                v = v.strip().strip('"').strip("'")
                found[k] = v
        missing = set(keys) - set(found)
    if missing:
        sys.exit(
            f'env vars missing (set in process env or {ENV_FILE}): {sorted(missing)}'
        )
    return found


def _substitute_public_ip_placeholders(*data_objects):
    """Walk YAML-loaded data, swap __VNIC_*_PUBLIC_IP__ string tokens with
    values from the repo .env, return substituted *copies* — originals stay
    placeholder-form so save_secrets persists the source-of-truth shape and
    OCI public-IP rotation is a single .env edit + render.

    Mirrors the __INCOMING_IP_1__ pattern in render_server_text, but
    operates at YAML load time on the user-facing config files (profiles.yaml,
    .secrets.yaml) rather than on the server template. No-op if no
    placeholders are present, so test fixtures with literal TEST-NET IPs
    render without needing env vars set. Lazy env lookup means env vars are
    only required when the data actually references them.
    """
    PLACEHOLDER_TO_VAR = {
        '__VNIC_PRIMARY_PUBLIC_IP__':   'VNIC_PRIMARY_PUBLIC_IP',
        '__VNIC_SECONDARY_PUBLIC_IP__': 'VNIC_SECONDARY_PUBLIC_IP',
        # Optional second Reality endpoint (defaults.reality.server_b) used by
        # the alternating keypair rotation; see reality_client_server().
        '__REALITY_B_PUBLIC_IP__':      'REALITY_B_PUBLIC_IP',
    }

    def _scan(node, found):
        if isinstance(node, dict):
            for v in node.values():
                _scan(v, found)
        elif isinstance(node, list):
            for v in node:
                _scan(v, found)
        elif isinstance(node, str):
            for p in PLACEHOLDER_TO_VAR:
                if p in node:
                    found.add(p)

    found = set()
    for obj in data_objects:
        _scan(obj, found)
    if not found:
        return list(data_objects)

    env = _read_env({PLACEHOLDER_TO_VAR[p] for p in found})
    mapping = {p: env[PLACEHOLDER_TO_VAR[p]] for p in found}

    def _sub(node):
        if isinstance(node, dict):
            return {k: _sub(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_sub(v) for v in node]
        if isinstance(node, str):
            for p, v in mapping.items():
                if p in node:
                    node = node.replace(p, v)
        return node

    return [_sub(obj) for obj in data_objects]


# Hysteria2 TLS cert (self-signed; CN/SAN should be a plausible cover
# hostname for your deployment. Keep the SAN: a client on the PEM-pin
# fallback still validates the hostname, see docs/hazards.md #1).
# Read at render time: every client's hy2 outbound pins the SHA-256 of this
# cert's public key (tls.certificate_public_key_sha256) instead of the
# insecure:true fallback.
HY2_CERT = SERVER_DIR / 'hy2.crt'
# The cert the NEXT rotation will put in place, generated one cycle ahead by
# rotate-hy2-cert.sh. Its public-key hash is published next to the current
# one, so every client already trusts the next key when the server starts
# presenting it and the rotation needs no flag day. Absent on a deployment
# that has not run `rotate-hy2-cert.sh --bootstrap` yet: clients then pin the
# current key only and the next rotation IS a flag day (main() warns).
HY2_NEXT_CERT = SERVER_DIR / 'hy2-next.crt'
PENDING_ROTATIONS = ROOT / '.pending-rotations.yaml'
# Grace for rotated-out credentials (short_ids, per-user creds): they stay live on
# the server for this long after leaving the manifest. 7 days (was 2h): mobile
# clients (SFA/SFI 1.14) poll hourly but APPLY a fetched profile only on
# reconnect, so a 2h window let a phone that had fetched the new profile still
# run the old one past expiry and lose the tunnel. The env override lets an
# operator shorten it for a deliberate fast retirement. The TTL is stamped
# when an entry is ADDED, so set it on the render that removes the credential:
#   ROTATION_TTL_HOURS=2 ./render.py -y   (then --server-apply after 2h)
# Entries actually leave on the first render AFTER expiry (see
# compute_rotation_plan), so the effective window is "at least" this long.
ROTATION_TTL_HOURS = int(os.environ.get('ROTATION_TTL_HOURS', '168'))

# AWG paths. awg-server/ is a sibling of singbox-server/ — separate container,
# separate config, deliberate isolation (see docs/architecture.md). Override
# EGRESSOR_AWG_SERVER_DIR for non-standard layouts (CLEARWAY_AWG_SERVER_DIR
# still honoured — pre-rename deploys); defaults match the in-repo layout used
# by tests + the production deploy.
AWG_SERVER_DIR = Path(os.environ.get('EGRESSOR_AWG_SERVER_DIR',
                                     os.environ.get('CLEARWAY_AWG_SERVER_DIR',
                                                    str(ROOT.parent / 'awg-server')))).resolve()
AWG_SERVER_CONFIG = AWG_SERVER_DIR / 'config' / 'awg0.conf'
AWG_CLIENT_TEMPLATE = ROOT / 'templates' / 'awg-client.conf.template'
AWG_SERVER_TEMPLATE = ROOT / 'templates' / 'awg-server.conf.template'
AWG_SERVER_RESTART = AWG_SERVER_DIR / 'safe-restart.sh'

# AWG obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4) and keypair / subnet /
# port / endpoint live in .secrets.yaml under the top-level `awg:` block.
# Required keys are validated up-front in load_manifest so a partial config
# fails loud rather than silently rendering a half-functional .conf.
AWG_REQUIRED_KEYS = (
    'subnet', 'port', 'endpoint_host',
    'server_private_key', 'server_public_key',
    'Jc', 'Jmin', 'Jmax', 'S1', 'S2',
    'H1', 'H2', 'H3', 'H4',
)

# Country metadata. Each restricted country lives in its own
# `data/countries/<iso>.yaml` so adding/editing one is a self-contained
# change. The loader builds the same `COUNTRY` dict the rest of the
# renderer consumes — shape is back-compat with the old in-line literal.
# "uk" is a user-facing alias for geoip-gb (ISO), handled separately
# in the home-egress code path.
def _load_countries():
    countries = {}
    for path in sorted((ROOT / 'data' / 'countries').glob('*.yaml')):
        iso = path.stem
        countries[iso] = yaml.safe_load(path.read_text())
    return countries

COUNTRY = _load_countries()


# Protocols whose outbound speaks TLS through Go's crypto/tls and
# therefore benefits from a per-user uTLS fingerprint (JA3/JA4
# decorrelation across users). Hysteria2 is omitted: it runs over QUIC
# with its own TLS impl and uTLS doesn't apply.
TLS_PROTOCOLS = {'reality', 'ws-cf', 'shadowtls'}


def _warn_unused_shadowtls_sni(users):
    """Soft check: user sets `shadowtls_sni` but doesn't have `shadowtls`
    in their protocols. Dead config — likely a leftover from a removed
    protocol. Harmless, doesn't error."""
    for name, user in users.items():
        if name.startswith('_'):
            continue
        if not user.get('shadowtls_sni'):
            continue
        if 'shadowtls' in user.get('protocols', []):
            continue
        print(f"warning: user {name!r} has 'shadowtls_sni' set but no "
              f"'shadowtls' protocol — field is unused",
              file=sys.stderr)


def _check_mobile_shadowtls_sni(users, defaults):
    """Hard check: mobile sing-box (SFA/SFI) silently fails ShadowTLS
    after one probe when the SNI comes from `defaults.shadowtls.sni_pool`
    (see hazards.md #2 / project_shadowtls_mobile_pooled_sni_break).
    Mobile users with shadowtls must carry a per-user `shadowtls_sni`
    override so they pin a known-good SNI instead of getting a hash-pick
    from the pool. Single-`sni` deployments (no pool) are unaffected
    and stay quiet. Exits non-zero with the full list of offenders."""
    pool = (defaults.get('shadowtls') or {}).get('sni_pool') or []
    if not pool:
        return
    bad = []
    for name, user in users.items():
        if name.startswith('_'):
            continue
        if 'shadowtls' not in user.get('protocols', []):
            continue
        if user.get('shadowtls_sni'):
            continue
        # mac included conservatively: the break is confirmed on SFA (Android)
        # and presumed on SFI; SFM shares the sing-box-for-apple codebase with
        # SFI, and a silently-dead ShadowTLS path is worse than losing one
        # user's SNI-pool decorrelation. Only Windows desktop is confirmed
        # to tolerate pooled SNIs. linux is excluded like windows: it runs
        # the same CLI core binary (no app-layer TLS wrapper), so the pooled
        # SNI behaves as on the Windows NSSM service.
        if any(d.get('type') in ('mobile', 'mac') for d in user.get('devices', [])):
            bad.append(name)
    if bad:
        for name in bad:
            print(f"error: user {name!r} has shadowtls + a mobile/mac device "
                  f"but no per-user 'shadowtls_sni' override; non-Windows "
                  f"sing-box breaks on pool-picked SNIs after one probe",
                  file=sys.stderr)
        sys.exit(1)


def _warn_unused_utls_fingerprint(users):
    """Inverse of the hard check: warn (don't error) when a user sets
    `utls_fingerprint` but has no TLS-bearing protocol. The field is
    harmless but dead — uTLS doesn't apply to Hysteria2 (QUIC), so the
    setting won't shape any ClientHello. Likely an editing mistake or
    leftover from a removed protocol."""
    for name, user in users.items():
        if name.startswith('_'):
            continue
        if not user.get('utls_fingerprint'):
            continue
        if set(user.get('protocols', [])) & TLS_PROTOCOLS:
            continue
        print(f"warning: user {name!r} has 'utls_fingerprint' set but no "
              f"TLS-bearing protocol — field is unused (uTLS doesn't apply "
              f"to hy2)",
              file=sys.stderr)


def _check_per_user_utls_fingerprint(users):
    """Hard check: a user with any TLS-bearing protocol must have a
    per-user `utls_fingerprint`. Without it, all such users collapse to
    `defaults.utls_fingerprint` and share one ClientHello signature —
    defeating the JA3/JA4 decorrelation the field exists for. Exits
    non-zero with the full list of offenders so they can be fixed in
    one pass."""
    bad = []
    for name, user in users.items():
        if name.startswith('_'):
            continue
        if user.get('utls_fingerprint'):
            continue
        tls_protos = sorted(set(user.get('protocols', [])) & TLS_PROTOCOLS)
        if tls_protos:
            bad.append((name, tls_protos))
    if bad:
        for name, tls_protos in bad:
            print(f"error: user {name!r} has TLS protocol(s) {tls_protos} "
                  f"but no per-user 'utls_fingerprint' (required for "
                  f"JA3/JA4 decorrelation)",
                  file=sys.stderr)
        sys.exit(1)


def _warn_missing_hy2_next(users):
    """A hy2 deployment without a pre-generated next cert publishes one pin
    only, so its next cert rotation breaks hy2 on every client until each has
    fetched a new config. Warn; never fail a render over it."""
    if HY2_NEXT_CERT.exists() or not any('hy2' in u.get('protocols', []) for u in users.values()):
        return
    print(f'WARNING: {HY2_NEXT_CERT.name} not found next to {HY2_CERT.name}: hy2 clients pin '
          'the current key only, so the next cert rotation is a flag day. '
          'Run singbox-server/rotate-hy2-cert.sh --bootstrap once.', file=sys.stderr)


def _warn_missing_recommended_protocols(users):
    """Soft per-country protocol check. Prints a stderr warning when a
    user is missing a protocol that any of their countries recommends.
    Doesn't filter — operator may know better (e.g. testing a narrower
    protocol set, or excluding one for a specific user). Edit the
    `protocols.recommended` list in data/countries/<iso>.yaml to change
    what fires."""
    for name, user in users.items():
        if name.startswith('_'):
            continue
        user_protos = set(user.get('protocols', []))
        recommended_by = {}  # protocol → list of countries that recommend it
        for cc in user.get('countries', []):
            for p in (COUNTRY.get(cc, {}).get('protocols') or {}).get('recommended', []):
                recommended_by.setdefault(p, []).append(cc)
        missing = {p: ccs for p, ccs in recommended_by.items() if p not in user_protos}
        if missing:
            details = ', '.join(f"{p} (recommended for {','.join(ccs)})"
                                for p, ccs in sorted(missing.items()))
            print(f"warning: user {name!r} missing recommended protocol(s): {details}",
                  file=sys.stderr)

# Home-egress countries are expected to be ISO-2 country codes that SagerNet
# ships a geoip rule-set for. Maps user-facing label → ISO-2 code when the
# two differ (today: only `uk` → `gb`, since user-facing ccTLD is .uk but
# the ISO 3166-1 alpha-2 code is gb and SagerNet's rule-set is geoip-gb).
# Other entries should use their own ISO code as the user-facing label.
HOME_COUNTRY_ISO_OVERRIDE = {'uk': 'gb'}


def home_country(cc):
    """
    Build the geoip+tld entry for an ISO-2 home-egress country code.
    Always emits:
      geoip tag = 'geoip-<iso>'   (ISO-2 after uk→gb style overrides)
      tlds      = [cc]            (user-facing label — used for domain_suffix)
      url       = SagerNet 'geoip-<iso>.srs'

    Arbitrary TLDs (gTLDs, brand TLDs, political-bloc labels like `eu`) go in
    `home.home_egress_tlds`, not here — that field is domain_suffix-only.
    """
    iso = HOME_COUNTRY_ISO_OVERRIDE.get(cc, cc)
    return {
        'geoip': f'geoip-{iso}',
        'tlds':  [cc],
        'url':   f'https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-{iso}.srs',
    }

# Shared DNS blocklists. `heavy: True` marks rule-sets too large for
# memory-capped clients: iOS runs the packet tunnel inside a Network
# Extension with a hard ~50MB ceiling, and hagezi-tif alone is ~13MB
# compiled (multiples of that decoded), which kills the extension at
# startup with an opaque "internal error" (observed 2026-07-29 on
# sing-box VT TestFlight / 1.14-beta; the same config runs fine on
# Android/Windows/Linux). `mobile` devices therefore skip heavy
# rule-sets — the type spans Android too, where the trim is not
# strictly needed, but a phone losing the TIF list only loses some
# DNS-level threat blocking, not connectivity, and one uniform rule
# beats an OS field nobody else needs. Desktop types (windows, mac,
# linux) keep the full set.
BLOCKLIST_RULESETS = [
    {'tag': 'hagezi-tif',     'url': 'https://cdn.jsdelivr.net/gh/razaxq/dns-blocklists-sing-box@rule-set/hagezi-tif.srs', 'update_interval': '6h', 'heavy': True},
    {'tag': 'hagezi-adblock', 'url': 'https://cdn.jsdelivr.net/gh/razaxq/dns-blocklists-sing-box@rule-set/hagezi-pro.srs', 'update_interval': '12h'},
]


# Oldest sing-box core a device of each type is assumed to run when its
# manifest entry carries no `core_min`. The config has to decode on the
# OLDEST core a device may still run, and a field added in a later minor is
# a hard decode error there, so the default is the floor, not the current
# release. Phones follow the store / TestFlight builds, which are all 1.14+
# (1.14 is also where SFA/SFI started polling the remote profile). Desktops
# stay on the 1.13 floor: the Windows updater installs whatever version the
# operator publishes, which may be an older pinned one (hazards.md #24), and
# the standalone macOS client does not carry a 1.13 install over to 1.14
# (new application, see the upstream 1.14 migration notes). Raise a single
# device with `core_min` once it is known to be on a newer core.
CORE_MIN_DEFAULT = {'mobile': '1.14', 'windows': '1.13', 'mac': '1.13', 'linux': '1.13'}

# Tag of the explicit HTTP client that fetches remote rule-sets on 1.14+.
RULESET_HTTP_CLIENT = 'rule-set-fetch'


# Per-protocol solo files are for alternate clients, whose embedded core is
# not the device's and is not known here, so they keep the oldest field set.
CORE_SOLO_FLOOR = '1.13'

# Images `sing-box check` runs in. Every rendered client file is checked on
# the first release of its floor (the oldest core that must decode it) and on
# the current release (what an up-to-date device runs).
CORE_CHECK_REPO = 'ghcr.io/sagernet/sing-box'
CORE_CHECK_CURRENT = f'{CORE_CHECK_REPO}:latest'


def _core_tuple(version):
    return tuple(map(int, version.split('.')))


def core_at_least(device, version):
    """True when the device's minimum sing-box core is >= `version`
    ("<major>.<minor>"), i.e. a field added in `version` is safe to emit."""
    have = device.get('core_min') or CORE_MIN_DEFAULT[device['type']]
    return _core_tuple(have) >= _core_tuple(version)


def core_floor(user, device):
    """Oldest sing-box core the file rendered for (user, device) must decode
    on. Decides both what compose() may emit and which image validates it."""
    if user.get('_original_protocols'):
        return CORE_SOLO_FLOOR
    return device.get('core_min') or CORE_MIN_DEFAULT[device['type']]


def emits(user, device, version):
    """True when a field added in sing-box `version` may go into the file
    rendered for (user, device)."""
    return _core_tuple(core_floor(user, device)) >= _core_tuple(version)


def blocklist_rulesets(device):
    """Blocklist rule-sets applicable to this device: mobile skips `heavy`
    entries (iOS NE memory cap — see the BLOCKLIST_RULESETS note)."""
    if device['type'] == 'mobile':
        return [rs for rs in BLOCKLIST_RULESETS if not rs.get('heavy')]
    return list(BLOCKLIST_RULESETS)

# Domains that always route via 🔒 Trusted (never via a Direct country alias).
# Sourced from data/trusted_domains.txt so the list can be edited without
# touching code. One suffix per line; `#` comments and blank lines are ignored.
def _load_trusted_domains():
    path = ROOT / 'data' / 'trusted_domains.txt'
    out = []
    for raw in path.read_text().splitlines():
        line = raw.split('#', 1)[0].strip()
        if line:
            out.append(line)
    return out

TRUSTED_DOMAINS = _load_trusted_domains()

# IPs of our own proxy servers — always Direct to avoid tunnel loops.
# Populated from defaults.proxy_server_ips in profiles.yaml at manifest load
# time; the empty default keeps single-VPS deployments working without explicit
# config (the route rule below only fires if this list is non-empty).
PROXY_SERVER_IPS = []


# ---------------------------------------------------------------------------
# Fragment functions. Each returns a fragment of the final JSON.
# ---------------------------------------------------------------------------

def frag_log():
    return {'log': {'level': 'warn', 'timestamp': True}}


def frag_ntp(device):
    """
    NTP — keeps sing-box's clock aligned for Reality's ±90s handshake window.
    Only emitted on mobile devices (phones drift after airplane mode / bad
    cell towers). Windows has reliable w32time, macOS has timed (resyncs
    on wake) and Linux desktops run systemd-timesyncd/chrony, so no desktop
    type needs it.

    Server: pool.ntp.org. No explicit detour — sing-box 1.12+ rejects a
    detour that points to a bare direct outbound ("detour to an empty
    direct outbound makes no sense") and crashes at init. Omitting detour
    yields the same behavior (NTP rides the default direct path, outside
    the tunnel) without tripping the check. See docs/hazards.md.
    """
    if device['type'] != 'mobile':
        return {}
    return {'ntp': {
        'enabled': True,
        'server': 'pool.ntp.org',
        'server_port': 123,
        'interval': '30m',
    }}


def frag_inbound(device, user=None, defaults=None):
    """TUN inbound. Windows needs `interface_name` for the wintun driver;
    linux gets the same stable name so the README's `ip link` / troubleshooting
    commands can refer to it (default would be an auto-numbered tunN)."""
    tun = {
        'type': 'tun',
        'tag': 'tun-in',
        'address': ['172.16.0.1/30'],
        'auto_route': True,
        'strict_route': True,
        'mtu': 1380,
        # No `stack`: sing-box 1.15 deprecates the option (sing-tun ships its
        # own TCP/IP stack, the option is removed in 1.17) and the 1.15 iOS
        # builds carry no gVisor, so an explicit 'mixed' fails at start with
        # "gVisor is not included in this build". Omitted, 1.13/1.14 fall back
        # to their default (mixed when gVisor is built in, which every
        # official client build has), so nothing changes for them.
    }
    if device['type'] in ('windows', 'linux'):
        tun['interface_name'] = 'singbox-tun0'
    # Softphone: keep the whole app OUT of the TUN on Android (2026-09-05). The
    # route-rule form (frag_route, package_name → Direct) only decides where a
    # packet the TUN already captured is re-emitted; the app still SEES the TUN
    # as its interface, binds media to 172.16.0.1, and STUNs through the
    # tunnel — measured: Bria's SDP kept o=172.16.0.1 / c=<tunnel relay> and
    # no RTP ever reached the hub, on every call, with all three rules active.
    # exclude_package = VpnService addDisallowedApplication: the OS routes the
    # app around the VPN entirely, so local address, STUN and RTP all use the
    # real network (the state that passed the echo test with the VPN off).
    # SFA's per-app GUI merely overrides this field. Mobile only.
    sip_hub = (defaults or {}).get('sip_hub') or {}
    if sip_hub.get('android_packages') and device['type'] == 'mobile':
        tun['exclude_package'] = list(sip_hub['android_packages'])
    # AWG endpoint: keep it OUT of the TUN entirely (hazards.md #23, part 2).
    # The frag_route bypass rule alone is not enough on desktops: a packet the
    # TUN captures is re-emitted by the sing-box PROCESS, and the Amnezia app's
    # own firewall (its kill switch, and any per-process filter) only
    # whitelists Amnezia's traffic — so the AWG leg died after the first
    # handshake even with the route rule in place (2026-08-28, Windows).
    # route_exclude_address installs a more-specific route to the physical
    # interface, so Amnezia's packets never enter the TUN and leave from
    # Amnezia's own process. Only literal IPs are accepted here (no hostname
    # form), hence the ipaddress gate; hostname deployments keep just the
    # route rule. The endpoint arrives via defaults['_awg_endpoint'], set in
    # load_manifest next to manifest['_awg'].
    awg_ep = (defaults or {}).get('_awg_endpoint')
    if awg_ep and user and 'awg' in user['protocols']:
        try:
            ipaddress.ip_address(awg_ep['host'])
            tun['route_exclude_address'] = [f"{awg_ep['host']}/32"]
        except ValueError:
            pass
    return {'inbounds': [tun]}


def frag_dns(countries, has_home, home_endpoint=None, bootstrap_ip='1.1.1.1', ws_cf_host=None, device=None,
             extra_endpoints=()):
    """
    DNS block. A/AAAA → fakeip, everything else → cloudflare_doh.

    Country DoH servers (DNSPod/Yandex/Shecan) are deliberately NOT emitted.
    Earlier iterations routed `.cn`/`.ru`/`.ir` TLDs through country DoH so
    travellers would get country-local CDN edges, but (a) sing-box has no
    DNS fallback, so a single country-DoH outage took down all of that TLD
    space (produced Chrome DNS_PROBE_POSSIBLE in production), and (b) it was
    never actually buying the CDN benefit — TCP egress is the proxy server
    regardless. With fakeip the hostname is reconstructed at the outbound
    egress and the egress resolver picks the CDN edge (country-local for
    in-country Direct traffic, server-local for tunnelled traffic).

    `bootstrap_ip`: IP used by the bootstrap_dns server (cleartext UDP:53
    for the pre-tunnel WS-CDN hostname lookup). Defaults to 1.1.1.1 which
    works for every resident user. Callers set this to a country-local
    resolver (Alibaba/Yandex/Shecan) when the user's manifest entry implies
    a physical location inside one of those countries — see frag_dns
    call-site in compose().

    `ws_cf_host`: the Cloudflare-fronted hostname (defaults['ws-cf'].host)
    that must resolve via bootstrap_dns BEFORE the tunnel is up (the ws-cf
    outbound needs the CF edge IP to dial). None = ws-cf not in use; no
    bootstrap entry emitted.
    """
    # cloudflare_doh detour: 🌍 Default when Restricted exists (multi-region
    # or home-enabled users), else 🔀 Proxy (single-country residents — keeps
    # DNS simple and avoids coupling it to Restricted's default=Direct).
    cloud_detour = '🌍 Default' if (has_home or len(countries) > 1) else '🔀 Proxy'

    # bootstrap_dns: fixed-IP UDP via direct. Previously was type=local
    # (OS resolver), which on Android with Private DNS enabled sent queries
    # to the system's DoT target — and because auto_route + strict_route
    # pulls all egress back into the TUN, the query looped to 172.16.0.2:853
    # (TUN peer) and timed out after 5s before any proxy could come up.
    # Going straight to a fixed-IP resolver via direct sidesteps the system
    # resolver entirely. detour → ➡️ Direct is legal because that outbound
    # carries udp_fragment:false (non-empty, see frag_outbounds). IP comes
    # from the `bootstrap_ip` arg (see docstring).
    servers = [
        {'tag': 'bootstrap_dns', 'type': 'udp', 'server': bootstrap_ip, 'server_port': 53, 'detour': '➡️ Direct'},
        {'tag': 'fakeip-server', 'type': 'fakeip', 'inet4_range': '198.18.0.0/15'},
        {'tag': 'cloudflare_doh', 'type': 'https', 'server': '1.1.1.1', 'server_port': 443, 'path': '/dns-query', 'detour': cloud_detour},
    ]
    # Bootstrap_dns is used for proxy-server hostnames that must resolve
    # BEFORE the tunnel is up (chicken-and-egg). The WS-CDN host goes here
    # because that outbound needs it resolved to dial Cloudflare's edge.
    #
    # The home WG DDNS hostname goes here TOO (changed 2026-07-20). It used to
    # be deliberately excluded so it would resolve via cloudflare_doh "once any
    # proxy outbound is up", keeping the DDNS name off the ISP's resolver. That
    # ordering assumption is wrong and the failure is catastrophic: sing-box
    # treats WG peer-domain resolution as a HARD post-start dependency, so when
    # it cannot resolve, the entire service aborts with
    #   FATAL start service: post-start endpoint/wireguard[🏢 Home]: resolve
    #   endpoint domain for peer[0]: <host>:51820: lookup <host>:
    #   dial tcp 1.1.1.1:443: i/o timeout
    # and the supervisor (NSSM/runit) then crash-loops it. Two ways it bites:
    # the proxy is not necessarily usable that early, and on a network that
    # blackholes DoH (1.1.1.1:443) it can NEVER succeed. Observed live on a
    # Windows client whose Wi-Fi blocked DoH while ordinary system DNS worked
    # fine: sing-box had run 43 h happily but could not restart at all, taking
    # the client's VPN down until the peer was hand-pinned to a literal ip.
    # Robust startup beats hiding one hostname. Tradeoff accepted: this lookup
    # is now cleartext UDP:53 to bootstrap_ip, so the ISP can see the DDNS name.
    bootstrap_domains = [ws_cf_host] if ws_cf_host else []
    if home_endpoint:
        bootstrap_domains.append(home_endpoint)
    # Extra WG exits' DDNS names: same hard post-start dependency as 🏢 Home.
    for host in extra_endpoints:
        if host not in bootstrap_domains and not re.fullmatch(r'[0-9.:]+', host):
            bootstrap_domains.append(host)

    # Global threat/ad rejects (hagezi) plus any country-specific ones
    # (e.g. chocolate4u's iran-* lists when IR is enabled). Device-filtered:
    # a reject referencing a rule-set the route block didn't declare fails
    # `sing-box check`, so this MUST mirror frag_route's selection. device=None
    # (only the home-bootstrap unit test calls it that way) keeps the full set.
    reject_tags = [b['tag'] for b in (blocklist_rulesets(device) if device else BLOCKLIST_RULESETS)]
    for cc in countries:
        for rs in COUNTRY[cc].get('dns_reject_rulesets', []) or []:
            reject_tags.append(rs['tag'])

    rules = []
    if bootstrap_domains:
        rules.append({'domain': bootstrap_domains, 'server': 'bootstrap_dns'})
    rules.append({'rule_set': reject_tags, 'action': 'reject'})
    # NOTE: the home WG DDNS hostname used to get its own cloudflare_doh rule
    # here. It is now carried by the bootstrap_dns rule emitted above (see the
    # bootstrap_domains comment for why). That rule is FIRST, so the ordering
    # requirement still holds: the hostname must be matched before the
    # A/AAAA→fakeip rule below, otherwise fakeip would hand back 198.18.x.x and
    # the WG handshake UDP would loop back into the TUN.
    rules.append({'query_type': ['A', 'AAAA'], 'server': 'fakeip-server'})
    rules.append({'server': 'cloudflare_doh'})

    # No `strategy` set: we fakeip every A/AAAA regardless, so the
    # v4-vs-v6 preference only matters for (rare) non-A/AAAA flows that
    # actually dial by hostname. Previously pinned to `ipv4_only` as a
    # defensive default, which made iOS apps double-lookup when the AAAA
    # came back empty. Omitting it lets sing-box use its default
    # (prefer_ipv4) without suppressing AAAA outright.
    # No `independent_cache`: deprecated in sing-box 1.14 (removed 1.16); its 1.14
    # default (DNS cache keyed per-transport) is exactly the old behaviour. Removal
    # needs no replacement field, so it is valid on every core version. Safe on
    # ≤1.13 clients too: routing is static per (domain,query_type), so a shared
    # cache returns identical answers. (2026-07-19; surfaced on an Android client
    # running SFA 1.14.)
    return {'dns': {'servers': servers, 'rules': rules}}


def device_exit_endpoints(user, device):
    """Extra WireGuard exits for this device, in manifest order.

    A user may list `exits: [{name: cabin, tag: '🏡 Cabin'}, ...]` in
    profiles.yaml; each device that has exit_wg/<name>/<user>-<device>.conf
    gets one WG endpoint with that tag, offered in 🌍 Default as a manual
    pick. A device without the file simply does not get that exit. Unlike
    🏢 Home there are no route rules: nothing goes there unless chosen.
    Returns [{'tag', 'device_wg', 'peer'}] (filled by load_manifest).
    """
    found = device.get('exit_wg', {})
    # Optional `lan: [cidr, ...]` on an exit: that remote LAN is routed into
    # the exit (see frag_route), e.g. to reach the Deco app's local-only
    # screens from away. Default empty = manual pick only, as before.
    return [dict(found[e['name']], tag=e['tag'], lan=list(e.get('lan', [])))
            for e in user.get('exits', []) if e['name'] in found]


def frag_home_endpoint(home, device_wg, carrier):
    """
    🏢 Home WireGuard endpoint, detouring through `carrier` — a CONCRETE
    proxy outbound tag (hy2 / reality / …), never a selector.

    This preserves the "WG wrapped in proxy protocol" behaviour that makes
    home access work from inside hostile DPI (CN/RU/IR): `carrier` is the
    same outbound 🔀 Proxy resolves to by default (see
    proxy_selector_default), so the steady-state path is unchanged.

    A selector here is NOT usable, however convenient it looks. From
    2026-04-27 until 2026-07-20 this field was '🚇 Home Carrier' (a
    selector) to give the user a dashboard toggle between proxy-wrapped and
    raw direct WG. sing-box 1.14 refuses to resolve a selector tag as an
    endpoint detour and fails the endpoint at RUNTIME:

        endpoint/wireguard[🏢 Home]: connect to server:
        outbound detour not found: 🚇 Home Carrier

    The endpoint then never starts, so home egress silently carries nothing.
    sing-box 1.13.x resolves it fine, which is why this survived: `sing-box
    check` passes on both versions (it is a runtime resolution failure, not
    a schema error), so neither validation nor the golden tests caught it —
    the goldens simply encoded the broken pattern. Home egress had in fact
    never worked on any 1.14 client.

    Cost of the fix: the 🚇 Home Carrier raw-WG toggle is gone (that selector
    is no longer emitted). Switching a user to raw direct WG now requires a
    re-render with a different carrier, not a dashboard flip. That is the
    accepted trade for an endpoint that actually starts on every client
    version. Do NOT reintroduce a selector here without testing against a
    real 1.14+ client.

    All WG knobs are user-configurable via the manifest (see `home:` and
    `home_wg:` blocks). Only fields present in the manifest are emitted —
    optional peer knobs like pre_shared_key / reserved are skipped when
    absent so we don't emit empty strings that sing-box then rejects.
    """
    # Normalise address (accept list or scalar for legacy manifests).
    addr = device_wg['address']
    if isinstance(addr, str):
        addr = [addr]

    ep = {
        'type': 'wireguard',
        'tag': '🏢 Home',
        # Concrete outbound tag, never a selector — sing-box 1.14 fails the
        # endpoint at runtime on a selector detour. See docstring.
        'detour': carrier,
        # MTU 1280 (was 1380). The 🏢 Home WG endpoint rides inside whichever
        # protocol 🔀 Proxy resolves to (country-derived default, or the
        # user's manual pick) — so WG packets are double-encapsulated:
        # TUN(1380) → outer proxy (TLS/QUIC overhead) → WG(outer). 1380 left
        # no headroom for the outer layer and would silently fragment or
        # PMTU-blackhole large TCP payloads over Home Sites. 1280 is the
        # IPv6 minimum and safe for any nested path.
        'mtu': home.get('mtu', 1280),
        'address': addr,
        'private_key': device_wg['private_key'],
    }
    # Optional interface-level knobs
    if device_wg.get('listen_port'):
        ep['listen_port'] = device_wg['listen_port']
    if 'system' in device_wg:
        ep['system'] = device_wg['system']

    peer = {
        'address': home['endpoint'],
        'port': home['endpoint_port'],
        'public_key': home['peer_public_key'],
        'allowed_ips': home.get('allowed_ips', ['0.0.0.0/0', '::/0']),
        'persistent_keepalive_interval': home.get('persistent_keepalive_interval', 25),
    }
    # Optional peer knobs — only emit if set (empty PSK confuses sing-box).
    if home.get('peer_pre_shared_key'):
        peer['pre_shared_key'] = home['peer_pre_shared_key']
    if home.get('reserved'):
        peer['reserved'] = home['reserved']

    ep['peers'] = [peer]
    return {'endpoints': [ep]}


# Tag for the embedded Tailscale endpoint (see the device 'tailscale' schema
# note). One constant so the selector member, the route rules, and the
# endpoint itself can never drift apart (dangling-tag = sing-box check FATAL).
TS_TAG = '🧵 Tailscale'


def frag_tailscale_endpoint(user, device):
    """Embedded Tailscale node (sing-box 1.12+ tsnet endpoint).

    Joins the tailnet from inside sing-box — crucial on Android where the OS
    grants a single VPN slot and sing-box already holds it. Unlike 🏢 Home
    this endpoint has no hostname peer, so it needs NO bootstrap_dns entry:
    the control-plane connection resolves through sing-box's own DNS at
    runtime, not as a hard startup dependency.

    Returns the bare endpoint dict — compose() accumulates endpoints from all
    producers into one list (cfg.update() would silently clobber 🏢 Home's,
    the exact hazard documented at the compose() call sites).
    """
    auth_key = device.get('tailscale_auth_key')
    if not auth_key:
        # Operator-supplied external state (admin-console mint), same
        # fail-loud contract as a missing home WG conf.
        sys.exit(
            f"device {user.get('_name', '?')}/{device['name']} has tailscale: true "
            f"but no tailscale_auth_key in .secrets.yaml\n"
            f"Mint one at https://login.tailscale.com/admin/settings/keys "
            f"(single-use, NOT ephemeral) and add it under this device."
        )
    return {
        'type': 'tailscale',
        'tag': TS_TAG,
        # Node identity persists here across restarts — the auth key is only
        # consumed at first enrollment. Relative path: lands in the client's
        # working directory (app sandbox on Android).
        'state_directory': 'tailscale',
        'auth_key': auth_key,
        # user+type, matching the served-filename identity scheme: a hardware
        # swap under the same user+type keeps the tailnet hostname too.
        'hostname': f"{user['_name']}-{device['type']}",
        # CRITICAL on Android (empirically, 2026-08-15): without a detour the
        # endpoint's own control/DERP dials are raw and UNPROTECTED from the
        # VpnService TUN — they loop back into sing-box and the loop kills
        # ALL device egress. Detouring them through ➡️ Direct uses sing-box's
        # protected-socket dialer and fixes it (verified live on the phone;
        # also steadies the same flakiness observed on Windows). Dial Fields
        # here affect ONLY the endpoint's own connections, not peer traffic.
        # tailscale_detour: 'proxy' upgrades the node to BREAK-GLASS inbound:
        # control rides the proxy, so the node stays reachable on networks
        # that block Tailscale outright (where a native client and a
        # direct-detoured endpoint both die) — as long as the tunnel is up.
        # The detour names the CONCRETE outbound 🔀 Proxy defaults to, not the
        # selector itself: sing-box 1.14 refuses a selector as an endpoint
        # detour at runtime (same failure as the 🏢 Home endpoint, see
        # frag_home_endpoint), and `sing-box check` does not catch it.
        'detour': (proxy_selector_default(user, protocol_outbound_tags(user['protocols']))
                   if device.get('tailscale_detour') == 'proxy'
                   else '➡️ Direct'),
    }


def reality_client_server(d):
    """Address clients dial for Reality: endpoint A (`server`) or B (`server_b`).

    The alternating keypair rotation (rotate-realitykey.sh) never changes the
    key on a live inbound: it starts the new key on the OTHER endpoint and
    points clients there, while the old inbound keeps the old key for an
    overlap window. Clients that have not applied the new profile yet keep
    working on the old endpoint, so a rotation is no longer a flag day.
    Only Reality moves: ShadowTLS and hy2 keep using `server` (endpoint A).
    """
    if d.get('endpoint', 'a') == 'b':
        if not d.get('server_b'):
            sys.exit('reality endpoint is "b" (shared.reality_endpoint) but '
                     'defaults.reality.server_b is not set in profiles.yaml')
        return d['server_b']
    return d['server']


def frag_outbound_reality(defaults, reality, fp=None):
    d = defaults['reality']
    if fp is None:
        fp = defaults.get('utls_fingerprint', 'chrome')
    # No packet_encoding here: Reality uses flow=xtls-rprx-vision which is
    # TCP-only. The xudp tag (VLESS UDP-over-TCP multiplexing) is silently
    # ignored by Vision and only served to imply UDP support that doesn't
    # exist. UDP-bearing apps (QUIC, WireGuard-over-Reality) would have
    # appeared to work at config-load time and then silently fail at
    # runtime. Route rule below (in frag_route) rejects UDP/443 so QUIC
    # falls back to TCP cleanly across all outbounds.
    return {
        'type': 'vless', 'tag': 'reality',
        'server': reality_client_server(d), 'server_port': d['server_port'],
        'uuid': reality['uuid'],
        'flow': d['flow'],
        'tls': {
            'enabled': True,
            'server_name': d['handshake_sni'],
            'utls': {'enabled': True, 'fingerprint': fp},
            'reality': {'enabled': True, 'public_key': d['public_key'], 'short_id': reality['short_id']},
        },
    }


def frag_outbound_ws_cf(defaults, ws_cf_uuid, fp=None):
    d = defaults['ws-cf']
    if fp is None:
        fp = defaults.get('utls_fingerprint', 'chrome')
    # ECH intentionally NOT enabled. ech.enabled together with a uTLS
    # fingerprint fails every dial with `tls: malformed outer client hello`
    # before any packet leaves the client (verified on 1.13.18 and
    # 1.14.0-beta.3) — the combination silently killed this outbound
    # fleet-wide. Either knob alone works; uTLS wins: this path's cover is
    # "ordinary browser HTTPS to a Cloudflare site", and the ECH extension
    # is itself a censor tell (RST-blocked toward Cloudflare in some
    # countries), so hiding the SNI is not worth the fingerprint mismatch.
    # Re-enable only if uTLS is dropped here, or upstream makes the two
    # compose — and re-verify a real dial either way. See docs/hazards.md.
    #
    # Multiplex (smux) intentionally DISABLED. Original rationale: chatty
    # HTTP/1.1 stacks open many short TCP connections, and over WS+CF that's
    # many handshakes (CF edge → backend → sing-box); smux lets multiple
    # VLESS streams ride one WS tunnel, amortising setup cost. Removed in
    # production after Android clients started failing WS-CDN connections
    # with `process multiplex stream: read multiplex stream request: EOF`
    # right after the WS upgrade — smux handshake collapsing mid-read.
    # Cloudflare's WebSocket proxy has tightened buffering/streaming and
    # interacts poorly with smux's binary framing at min_streams=4. Re-enable
    # only after confirming the bug is fixed upstream; per-request handshake
    # overhead without multiplex is negligible on modern CF edges. See
    # docs/hazards.md.
    return {
        'type': 'vless', 'tag': 'ws-cf',
        'server': d['host'], 'server_port': d['port'],
        'uuid': ws_cf_uuid,
        # The ONLY domain-addressed outbound (the others dial the VPS IP),
        # so its server lookup must be pinned to bootstrap_dns. Outbound
        # dials resolve via route.default_domain_resolver (cloudflare_doh)
        # and BYPASS dns.rules — the `vpnws.… → bootstrap_dns` rule only
        # governs routed client queries — so without this pin, selecting
        # ws-cf as 🔀 Proxy deadlocks: the lookup rides cloudflare_doh,
        # whose detour is 🔀 Proxy = ws-cf itself ("DNS query loopback in
        # transport[cloudflare_doh]", then deadline-exceeded). Exactly the
        # scenario ws-cf exists for (all other lanes blocked) is the one
        # that looped. See docs/hazards.md #22.
        'domain_resolver': 'bootstrap_dns',
        'packet_encoding': 'xudp',
        'tls': {
            'enabled': True, 'server_name': d['host'],
            'utls': {'enabled': True, 'fingerprint': fp},
        },
        'transport': {'type': 'ws', 'path': d['path'], 'headers': {'Host': d['host']}},
    }


def frag_outbound_shadowtls(defaults, stls_pw, user_ss_pw, fp=None, sni=None):
    # SS-2022 multi-user mode: client concatenates <server_psk>:<user_psk>.
    # server_psk = defaults['shadowtls']['shadowsocks_password'] (from
    # .secrets.yaml shared.shadowsocks_password, seeded in load_manifest).
    # user_ss_pw = per-user PSK (from .secrets.yaml users.<name>.shadowsocks_password).
    # sing-box parses the colon-joined form and sends EIH for user identity.
    #
    # sni override: per-user ShadowTLS SNI. Server runs wildcard_sni:
    # authed, so the client can present any plausible Oracle hostname.
    # After auth the TLS stream becomes Shadowsocks and the client never
    # cert-validates, so cert-vs-SNI mismatch on the ServerHello doesn't
    # matter. Caller passes the pre-resolved sni; fall back to the single
    # defaults.shadowtls.sni for back-compat + disabled-pool mode.
    d = defaults['shadowtls']
    ss_pw = f"{d['shadowsocks_password']}:{user_ss_pw}"
    if fp is None:
        fp = defaults.get('utls_fingerprint', 'chrome')
    if sni is None:
        sni = d['sni']
    return [
        {
            'type': 'shadowtls', 'tag': 'shadowtls-transport',
            'server': defaults['reality']['server'], 'server_port': d['server_port'],
            'version': d['version'], 'password': stls_pw,
            'tls': {
                'enabled': True, 'server_name': sni,
                'utls': {'enabled': True, 'fingerprint': fp},
            },
        },
        {
            'type': 'shadowsocks', 'tag': 'shadowtls',
            'server': defaults['reality']['server'], 'server_port': d['server_port'],
            'method': d['shadowsocks_method'], 'password': ss_pw,
            'detour': 'shadowtls-transport',
        },
    ]


def cert_public_key_sha256(path):
    """base64(SHA-256(SubjectPublicKeyInfo DER)) of a PEM certificate: the
    value sing-box compares in tls.certificate_public_key_sha256. Same bytes
    as `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | openssl enc -base64`."""
    import base64, hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def hy2_pins():
    """Public-key pins a hy2 client must accept: the cert the server presents
    now, then the one the next rotation will present (when it exists)."""
    pins = [cert_public_key_sha256(HY2_CERT)]
    if HY2_NEXT_CERT.exists():
        nxt = cert_public_key_sha256(HY2_NEXT_CERT)
        if nxt not in pins:
            pins.append(nxt)
    return pins


def frag_outbound_hy2(defaults, pw, pin_key=True):
    d = defaults['hy2']
    # Trust anchor for the server's self-signed hy2 cert. A network-path
    # attacker cannot present their own cert and MITM the obfs'd QUIC session
    # (the old `insecure: true` mode allowed that).
    #
    # pin_key (sing-box 1.13+): pin the SHA-256 of the cert's PUBLIC KEY. The
    # field is a list, so the config carries the current key and the next one
    # (hy2_pins) and a cert rotation needs no flag day: a client that fetched
    # its config at any point in the previous cycle already trusts the key
    # the server switches to. With a key pin sing-box verifies neither the
    # chain nor `server_name` — the key alone is the anchor (measured on
    # 1.13.0, 1.13.14, 1.14.3 and 1.15.0-alpha.11 against a live server).
    #
    # Otherwise (a core older than 1.13 rejects the field): inline the PEM
    # into tls.certificate, one line per list entry. No overlap is possible
    # in that form, and hostname validation still applies, which is why the
    # cert keeps a subjectAltName (docs/hazards.md #1).
    if pin_key:
        trust = {'certificate_public_key_sha256': hy2_pins()}
    else:
        trust = {'certificate': HY2_CERT.read_text().strip().splitlines()}
    # Brutal-CC bandwidth hints. Hysteria2's custom congestion control
    # ("brutal CC") uses these as the initial BDP estimate. Without them
    # brutal ramps up slowly and cold-start throughput is much lower than
    # the link can sustain. Values are a safe household envelope: most home
    # broadband is 20-100 Mbps up / 200-1000 Mbps down. Overestimating hurts
    # (congestion collapse when the path can't actually deliver); these are
    # conservative. Tune per-device later via `hy2_up_mbps/hy2_down_mbps`
    # in profiles.yaml if needed. Server-side per-user caps are not a thing
    # in sing-box (see project_singbox_hy2_no_per_user_caps memory).
    up_mbps = d.get('up_mbps', 30)
    down_mbps = d.get('down_mbps', 200)
    out = {
        # type stays 'hysteria2' — that's the upstream sing-box outbound type
        # name (not our identifier). Tag is our short canonical 'hy2'.
        'type': 'hysteria2', 'tag': 'hy2',
        'server': defaults['reality']['server'],
        'password': pw,
        'up_mbps': up_mbps,
        'down_mbps': down_mbps,
        'obfs': {'type': 'salamander', 'password': d['obfs_salamander_password']},
        'tls': {'enabled': True, 'server_name': d['sni'], 'alpn': ['h3'], **trust},
    }
    # Port-hopping. If defaults.hy2.server_ports is set, emit
    # server_ports (a list of "low:high" range strings) and omit
    # server_port entirely — sing-box would otherwise dial server_port
    # first, defeating the per-IP UDP volume-marking mitigation that
    # port-hopping exists for. Server-side: a host iptables redirect
    # collapses the range back to defaults.hy2.server_port.
    # Without server_ports, behave as before (single-port). See
    # docs/hazards.md.
    server_ports = d.get('server_ports')
    if server_ports:
        out['server_ports'] = list(server_ports)
    else:
        out['server_port'] = d['server_port']
    return out


def protocol_outbound_tags(protocols):
    """Ordered list of the proxy outbound tags emitted by frag_outbounds.
    AWG is intentionally excluded — it doesn't ride in the sing-box profile.
    Tags are the canonical short identifiers from the protocol-naming
    convention; selector outbounds reference them by these strings."""
    tags = []
    if 'reality'   in protocols: tags.append('reality')
    if 'ws-cf'     in protocols: tags.append('ws-cf')
    if 'shadowtls' in protocols: tags.append('shadowtls')
    if 'hy2'       in protocols: tags.append('hy2')
    return tags


def proxy_selector_default(user, proxy_tags):
    """
    Pick the default value for the 🔀 Proxy selector. Order:
      1. Per-user `preferred_protocol` if set AND it's actually emitted as
         a sing-box outbound (i.e. it's in proxy_tags). 'awg' as a preferred
         value is rejected at validation time elsewhere — AWG isn't a sing-box
         outbound, so honoring it here would point the selector at a tag that
         doesn't exist.
      2. Single-country resident → that country's `protocols.default` from
         data/countries/<iso>.yaml, IF the user has it enabled.
      3. Fallback: 'hy2' if available (speed-first traveller default), else
         the first tag in proxy_tags (just emit *something* deterministic).

    Reasoning lives in docs/architecture.md (selector-default + manual escape
    hatch). No urltest is emitted — the previous design's '⚡ Fastest' urltest
    is gone, so the selector either lands on a working protocol via this
    function or the user manually flips on connection failure.
    """
    if not proxy_tags:
        # Should never happen — protocols list has minItems=1, and at least
        # one of the four sing-box-native protocols is required when no AWG.
        # If the user has only AWG, that's a profile-yaml-without-sing-box
        # scenario, but render.py still has to emit *some* config; pick a
        # placeholder that'd be obvious in dashboard if reached.
        return '➡️ Direct'

    pref = user.get('preferred_protocol')
    if pref and pref in proxy_tags:
        return pref

    countries = user.get('countries') or []
    if len(countries) == 1:
        only_cc = countries[0]
        cc_default = (COUNTRY.get(only_cc, {}).get('protocols') or {}).get('default')
        if cc_default and cc_default in proxy_tags:
            return cc_default

    if 'hy2' in proxy_tags:
        return 'hy2'
    return proxy_tags[0]


def frag_selectors(user, device, defaults):
    """
    Build all selector outbounds. As of stage 3 (the AWG rollout) the
    renderer no longer emits any urltest outbound — the previous '⚡ Fastest'
    urltest was the steady-state probe pattern that motivated swapping to
    pure selector + manual fallback. The 🔀 Proxy selector picks a
    country-derived default protocol; the user manually flips in the
    dashboard if the default breaks. See docs/architecture.md.
    """
    countries = user['countries']
    protocols = user['protocols']
    has_home = 'home' in user
    proxy_tags = protocol_outbound_tags(protocols)

    # 🔀 Proxy: protocol chooser. `default` is country-derived (see
    # proxy_selector_default). All proxy_tags are listed as outbounds so the
    # user can manually pick any enabled protocol from the dashboard.
    proxy_selector = {
        'tag': '🔀 Proxy', 'type': 'selector',
        'outbounds': list(proxy_tags),
        'default': proxy_selector_default(user, proxy_tags),
    }

    selectors = [proxy_selector]

    # 🌍 Default — catch-all proxy selector. Listed before 🏠 Home Sites
    # because most users interact with Default far more often (it's the
    # global routing knob) and dashboards render selectors in array order.
    default_outbounds = ['🔀 Proxy']
    if has_home:
        default_outbounds.append('🏢 Home')
    # Extra WG exits (user `exits:`): manual pick only, no route rules.
    default_outbounds.extend(e['tag'] for e in device_exit_endpoints(user, device))
    default_outbounds.append('➡️ Direct')
    selectors.append({
        'tag': '🌍 Default', 'type': 'selector',
        'outbounds': default_outbounds,
        'default': '🔀 Proxy',
    })

    # 🔗 Tailnet: the live switch for the tailnet-relay route (100.64/10 points
    # here from frag_route). Flip it in the app to toggle tailnet-peer reach
    # between 🔀 Proxy (relay through the docker-host over hy2; the only path
    # that works behind DPI or when native Tailscale is blocked) and ➡️ Direct
    # (hand off to this device's own Tailscale). Per-device default: a mobile
    # defaults to the relay (it loses its tailnet behind DPI), a laptop defaults
    # to Direct (it has a working native tailnet, so the relay is break-glass).
    # Runtime toggle on BOTH clients, no re-render. Gated on tailnet:true and a
    # real proxy outbound existing (so 🔀 Proxy is a valid member).
    # mac and linux deliberately fall into the else/Direct branch below: like
    # a Windows laptop they can run native Tailscale, so the relay is
    # break-glass there too.
    if user.get('tailnet') and proxy_tags:
        # With an embedded 🧵 Tailscale endpoint on this device (see
        # frag_tailscale_endpoint) the selector gains it as a MEMBER — but it
        # is deliberately NOT the default: outbound-to-peers through the
        # endpoint is broken upstream (sing-box #3755, closed unresolved;
        # confirmed live 2026-08-15 — every phone→peer TCP refused while
        # INBOUND through the endpoint worked fine). The endpoint's value is
        # inbound reachability + node presence; outbound keeps the proven
        # defaults (mobile → relay, desktop → native client). Guard must
        # stay in lockstep with compose()'s endpoint emission and
        # frag_route's inbound rules — a member tag without the endpoint is
        # a sing-box check FATAL.
        has_ts = device.get('tailscale')
        selectors.append({
            'tag': '🔗 Tailnet', 'type': 'selector',
            'outbounds': ([TS_TAG] if has_ts else []) + ['🔀 Proxy', '➡️ Direct'],
            'default': '🔀 Proxy' if device.get('type') == 'mobile' else '➡️ Direct',
        })

    # NO 🚇 Home Carrier selector (removed 2026-07-20). It existed solely as
    # the 🏢 Home endpoint's detour target, and sing-box 1.14 cannot resolve a
    # selector as an endpoint detour — the endpoint fails at runtime and home
    # egress silently carries nothing (see frag_home_endpoint). The endpoint
    # now detours straight to a concrete proxy outbound. Emitting the selector
    # anyway would leave a dashboard toggle wired to nothing, which is worse
    # than not offering it: it would read as a working control.
    if has_home:
        # 🏠 Home Sites — fallback chain points at 🌍 Default (not 🔀 Proxy
        # directly) so flipping Default to Direct/Home propagates to home-
        # country traffic too — keeps the user's "where does my traffic exit"
        # choice in one place instead of needing to flip Proxy and Home
        # Sites in lockstep.
        selectors.append({
            # Renamed 2026-10-27: was '🏠 Home Egress'; selector keeps the house icon, the endpoint uses a building (🏢 Home).
            'tag': '🏠 Home Sites', 'type': 'selector',
            # Extra WG exits (e.g. 🏡 Cabin) offered here too, just before Direct
            # (2026-10-27); still manual pick only, the default stays 🏢 Home.
            'outbounds': ['🌍 Default', '🏢 Home',
                          *(e['tag'] for e in device_exit_endpoints(user, device)),
                          '➡️ Direct'],
            'default': '🏢 Home',
        })

    # 🔒 Trusted — sensitive accounts. Default = 🔀 Proxy so banking /
    # Apple / 1Password are always tunnelled regardless of where the user
    # has Default pointed (a resident with Default=Direct still wants
    # Trusted to tunnel). 🌍 Default is the secondary option for users
    # who want Trusted to follow their global routing choice instead.
    selectors.append({
        'tag': '🔒 Trusted', 'type': 'selector',
        'outbounds': ['🔀 Proxy', '🌍 Default'],
        'default': '🔀 Proxy',
    })

    # 🚨 Restricted — country-switch for geo-behaviour. Options include
    # 🌍 Default plus every country alias the user covers.
    restricted_opts = ['🌍 Default']
    for cc in countries:
        restricted_opts.append(f"{COUNTRY[cc]['flag']} {COUNTRY[cc]['label']}")
    # Default: if user has a single country and no home → assume they're a
    # resident ("local" mode) and default Restricted to their country (Direct).
    # Otherwise → 🌍 Default (Proxy), matching traveller behaviour.
    if len(countries) == 1 and not has_home:
        only_cc = countries[0]
        default_restricted = f"{COUNTRY[only_cc]['flag']} {COUNTRY[only_cc]['label']}"
    else:
        default_restricted = '🌍 Default'

    selectors.append({
        'tag': '🚨 Restricted', 'type': 'selector',
        'outbounds': restricted_opts,
        'default': default_restricted,
    })

    # No dedicated config-fetch group. Until 2026-10-04 a `🔄 Updater` urltest
    # (auto-failover over all proxy protocols) was emitted here for windows and
    # linux, and frag_route sent PROFILE_HOST through it, so the hourly updater
    # could still fetch when the 🔀 Proxy default broke with no grace (the
    # motivating case was the Reality keypair rotation). It was removed because
    # the group itself became the fault: twice (2026-09-23 and 2026-10-02) a
    # Windows client on 1.13.14 came back from sleep with the group stuck, and
    # every dial THROUGH it hung forever (two zero-byte connections per hourly
    # run, never closed) while the very same outbound kept working under
    # 🔀 Proxy and in a direct delay test. The updater then failed silently for
    # days until the service was restarted. Its motivating case is gone: the
    # keypair now rotates with a two-phase overlap (see reality endpoints A/B),
    # and the updater's pre-flight FAULT alert reports a stranded client. The
    # profile host now takes the ordinary path (country/final rule, i.e.
    # 🔀 Proxy): still fully tunnelled, resolved server-side. If a no-grace
    # protocol break ever returns, bring failover back as a SELECTOR that the
    # updater switches through the clash API, never as a urltest: selectors
    # have no background prober to get stuck.

    return selectors


def frag_outbounds(user, device, defaults):
    """Compose the full outbounds array in canonical order."""
    # udp_fragment: false makes this outbound non-empty so bootstrap_dns
    # (below) can legally detour to it in sing-box 1.12+ (a bare direct
    # outbound fails the "detour to an empty direct outbound" validation).
    # Explicit-false matches sing-box's own default — zero behavioral
    # change versus a bare direct — we just need a field present.
    # domain_strategy was removed on outbounds in 1.12 (deprecated), so
    # this is the cleanest no-op marker available.
    out = [{'tag': '➡️ Direct', 'type': 'direct', 'udp_fragment': False}]

    # Country alias Direct outbounds (🇨🇳/🇷🇺/🇮🇷 per user.countries).
    for cc in user['countries']:
        out.append({'tag': f"{COUNTRY[cc]['flag']} {COUNTRY[cc]['label']}", 'type': 'direct'})

    # Per-user uTLS fingerprint: each user gets a stable assignment from
    # the safe-pool, so a DPI classifier fingerprinting JA3/JA4 hashes
    # sees N distinct signatures across the household rather than one
    # shared "chrome" hash tying every device together. Falls back to
    # defaults.utls_fingerprint if unset.
    fp = user.get('utls_fingerprint') or defaults.get('utls_fingerprint', 'chrome')

    # Per-user ShadowTLS SNI resolution:
    #   1. users.<name>.shadowtls_sni     — operator-assigned override
    #   2. defaults.shadowtls.sni_pool    — stable hash-picked from pool
    #   3. defaults.shadowtls.sni         — single fallback (pool disabled)
    # The hash uses the username so the assignment is reproducible across
    # runs — rerunning render.py doesn't flip who sees which cover.
    stls_sni = user.get('shadowtls_sni')
    if not stls_sni:
        pool = defaults['shadowtls'].get('sni_pool') or []
        if pool:
            stls_sni = pool[int.from_bytes(user.get('_name', '').encode(), 'big') % len(pool)]
        else:
            stls_sni = defaults['shadowtls']['sni']

    # Protocol outbounds in canonical order. AWG is absent here by design —
    # AmneziaWG never rides in the sing-box profile (separate Amnezia VPN
    # app), see docs/architecture.md.
    if 'reality'   in user['protocols']: out.append(frag_outbound_reality(defaults, device['reality'], fp=fp))
    if 'ws-cf'     in user['protocols']: out.append(frag_outbound_ws_cf(defaults, user['ws_cf_uuid'], fp=fp))
    if 'shadowtls' in user['protocols']: out.extend(frag_outbound_shadowtls(defaults, user['shadowtls_password'], user['shadowsocks_password'], fp=fp, sni=stls_sni))
    if 'hy2'       in user['protocols']: out.append(frag_outbound_hy2(defaults, user['hy2_password'], pin_key=emits(user, device, '1.13')))

    # Selectors.
    out.extend(frag_selectors(user, device, defaults))
    return {'outbounds': out}


def frag_route(user, device, defaults):
    """route block: rule_set + rules."""
    countries = user['countries']
    has_home = 'home' in user
    # Proxy-server IPs come from defaults.proxy_server_ips (list of CIDRs).
    # Falls back to the module-level PROXY_SERVER_IPS for back-compat / tests.
    proxy_server_ips = defaults.get('proxy_server_ips') or PROXY_SERVER_IPS
    proxy_tags = protocol_outbound_tags(user['protocols'])  # for the config-updater failover rule below

    rule_sets = blocklist_rulesets(device)
    # Country rule-sets (routing) + optional DNS-reject-only rule-sets
    # (declared at the route level because all rule-sets must be declared
    # there; they're only referenced by DNS rules).
    for cc in countries:
        for rs in COUNTRY[cc].get('rulesets', []):
            rule_sets.append(rs)
        blocked = COUNTRY[cc].get('blocked_ruleset')
        if blocked:
            rule_sets.append(blocked)
        for rs in COUNTRY[cc].get('dns_reject_rulesets', []) or []:
            rule_sets.append(rs)
    # Home-country geoip rule-sets (routed to 🏠 Home Sites). Every ISO-2
    # entry in home_egress_countries emits a geoip rule-set; TLD-only entries
    # live in home_egress_tlds and don't contribute here.
    if has_home:
        for cc in user['home'].get('home_egress_countries', []):
            m = home_country(cc)
            rule_sets.append({'tag': m['geoip'], 'url': m['url'], 'update_interval': '7d'})

    # No `download_detour`: the legacy per-rule-set form is deprecated in sing-box
    # 1.14 (removed 1.16). Without it the fetch uses the route's default HTTP
    # client. On a 1.14+ device that client is declared explicitly (see
    # `default_http_client` at the end of this function, detour = route.final).
    # On a 1.13 device there is no such field: the fetch falls back to
    # route.final implicitly, which is the same path. Either way it follows the
    # user's current top-level routing decision (Proxy travelling / Direct
    # resident). jsdelivr.net is CloudFlare-fronted, usually direct-reachable
    # outside CN/IR.
    emitted_rulesets = []
    for rs in rule_sets:
        emitted_rulesets.append({
            'tag': rs['tag'], 'type': 'remote', 'format': 'binary',
            'url': rs['url'],
            'update_interval': rs.get('update_interval', '7d'),
        })

    # Route rules — order matters (first-match-wins).
    rules = [
        {'port': 53, 'action': 'hijack-dns'},
        # sniff populates metadata.domain from the sniffed SNI/host header.
        # Destination override (fakeip → real hostname) happens automatically
        # via the cache_file's fakeip store; no separate override field is
        # needed in sing-box 1.13 (and attempting one is a decode error).
        {'inbound': 'tun-in', 'action': 'sniff'},
    ]
    # Proxy-server bypass MUST come before the UDP/443 reject below:
    # hy2's own outer QUIC transport is UDP/443 to the proxy server IP, which
    # gets captured by the TUN (auto_route + strict_route) and re-enters
    # route.rules. First-match-wins, so the server-IP Direct rule must
    # fire before the blanket UDP/443 reject — otherwise hy2 can't
    # establish at all. Also covers TUN hairpin loops when a proxy hostname
    # resolves to one of our IPs. Empty list = rule omitted (single-VPS
    # deployments rely on the per-protocol server hostnames being already
    # excluded by the route rules they hit before this one).
    if proxy_server_ips:
        rules.append({'ip_cidr': proxy_server_ips, 'outbound': '➡️ Direct'})
    # AWG endpoint bypass (hazards.md #23). AmneziaWG is a SEPARATE app, not a
    # sing-box outbound, so its endpoint is deliberately NOT in proxy_server_ips
    # (see the scope rule there). But on desktops (Windows, macOS) both apps can
    # run at once and sing-box owns the default route: the Amnezia app's UDP to
    # the AWG server is captured by the TUN, and because we bind AWG on UDP/443
    # for QUIC cover, the blanket UDP/443 reject just below drops it — the AWG
    # tunnel keeps handshaking for ~2 min then dies with no error on either
    # side. Sending exactly that endpoint (host + UDP port) Direct lets the two
    # coexist: sing-box keeps the default route, AWG carries whatever the user
    # points at it. General rule for every AWG-enabled user on every device
    # type — harmless where the OS enforces one VPN at a time (Android/iOS).
    # Must precede the UDP/443 reject (first-match-wins). Endpoint may be a
    # literal IP (prod: __VNIC_PRIMARY_PUBLIC_IP__ → ip_cidr) or a hostname
    # (fixtures → domain match, which relies on the sniff/DNS metadata).
    awg_ep = defaults.get('_awg_endpoint')
    if awg_ep and 'awg' in user['protocols']:
        try:
            ipaddress.ip_address(awg_ep['host'])
            match = {'ip_cidr': [f"{awg_ep['host']}/32"]}
        except ValueError:
            match = {'domain': [awg_ep['host']]}
        rules.append({**match, 'network': 'udp', 'port': awg_ep['port'], 'outbound': '➡️ Direct'})
    # SIP hub bypass (2026-09-05): the telephony hub (Asterisk, TLS 5061 + RTP
    # 10000-10100) runs on the SAME host as the sing-box server. With the phone
    # tunnelled, Bria's SIP hairpins fine (TCP), but its RTP never comes out of
    # the server-side relay — a proxy does not relay UDP whose destination is
    # its own host — while the hub's RTP to the phone lands, by accident, on the
    # relay socket Bria discovered via STUN. Net effect: one-way / no audio on
    # every call to the phone, on every line (measured with a NIC capture).
    # Only these ports go Direct — SSH/mosh to the same host deliberately keep
    # riding the proxy (the 2026-05-02 decision that dropped .221.25 from
    # proxy_server_ips stands for everything else). port_range entries are
    # ORed. `hosts` takes BOTH forms and emits one rule per entry, because the
    # two SIP flows look different to the router: signalling is dialled by
    # NAME (the softphone's registrar hostname → fake-IP under the client
    # DNS, so only a `domain` rule matches), media is sent to the LITERAL IP
    # from the SDP (only `ip_cidr` matches). One field per rule — mixing
    # domain + ip_cidr in a single rule would AND them and match nothing.
    sip_hub = defaults.get('sip_hub')
    if sip_hub:
        for host in sip_hub['hosts']:
            try:
                ipaddress.ip_address(host)
                match = {'ip_cidr': [f"{host}/32"]}
            except ValueError:
                match = {'domain': [host]}
            rules.append({**match, 'port_range': list(sip_hub['port_ranges']), 'outbound': '➡️ Direct'})
        # Mobile softphones (Bria) do not talk to the hub the way the host/port
        # rules assume: with push enabled the app's SIP rides the vendor's push
        # proxy, its reflexive address comes from the vendor's STUN servers, and
        # only then does RTP go to the hub — through a tunnel that is the hub
        # itself, the STUN answer is the tunnel relay's socket and the media
        # dead-ends (2026-09-05, measured). The only address-independent fix is
        # the app itself: Android package rule → everything the softphone does
        # goes Direct. package_name is Android-only (ignored elsewhere), so emit
        # it for mobile devices only.
        if sip_hub.get('android_packages') and device.get('type') == 'mobile':
            rules.append({'package_name': list(sip_hub['android_packages']), 'outbound': '➡️ Direct'})
    # No profile-host rule: the config/version/mirror fetches (all on
    # PROFILE_HOST) take the ordinary country/final path through 🔀 Proxy. The
    # dedicated `🔄 Updater` urltest they used until 2026-10-04 was removed (see
    # the note at the end of frag_selectors for why).
    # Tailnet relay: route Tailscale's CGNAT range (RFC 6598 100.64.0.0/10) to
    # the 🔗 Tailnet selector (see frag_selectors), a live in-app toggle between
    # 🔀 Proxy (relay via the docker-host through hy2; DPI-resistant) and
    # ➡️ Direct (hand off to the device's own Tailscale). MUST precede the
    # rules just below: ip_is_private can sweep this range Direct, and for admin
    # users the port-22 rule forces ALL ssh Direct. Either path black-holes the
    # phone reverse-tunnel behind DPI. Gated by per-user `tailnet: true`, and
    # only when the user actually has a sing-box proxy outbound to relay through
    # (awg-only users have no 🔀 Proxy / 🔗 Tailnet). See SETUP.md Phase 4b.
    if user.get('tailnet') and protocol_outbound_tags(user['protocols']):
        rules.append({'ip_cidr': ['100.64.0.0/10'], 'outbound': '🔗 Tailnet'})
    # Inbound from the embedded 🧵 Tailscale node (guard mirrors compose()'s
    # endpoint emission). Tailnet peers dialing this device's tailnet IP land
    # here as inbound connections:
    #   * port 22 → the LOCAL sshd: Termux listens on 8022 (mobile), the
    #     Windows/macOS OpenSSH on 22 — hence the per-type override port.
    #     This is what makes `ssh <device-tailnet-ip>` work with no reverse
    #     tunnel. override_* are route-action fields (1.11+); validated
    #     against the 1.13 line by sing-box check in CI — NOT the fakeip
    #     destination override the comment above warns about.
    #   * everything else → reject: peers must not be able to use the device
    #     as an exit or reach other local services implicitly. Widen
    #     deliberately if ever needed.
    if user.get('tailnet') and device.get('tailscale'):
        local_sshd = 8022 if device.get('type') == 'mobile' else 22
        rules.append({'inbound': [TS_TAG], 'network': 'tcp', 'port': 22,
                      'action': 'route', 'outbound': '➡️ Direct',
                      'override_address': '127.0.0.1', 'override_port': local_sshd})
        rules.append({'inbound': [TS_TAG], 'action': 'reject'})
    # Remote LAN of an extra WG exit (exit `lan:` in profiles.yaml) goes into
    # that exit, ALWAYS, whatever 🌍 Default says. MUST precede the
    # ip_is_private → Direct rule just below, which would otherwise keep the
    # remote LAN on the local network (2026-10-31: a router app's address
    # reservation needs to "be on the network" of the remote site).
    for ex in device_exit_endpoints(user, device):
        if ex['lan']:
            rules.append({'ip_cidr': ex['lan'], 'outbound': ex['tag']})
    rules.extend([
        # Reject QUIC (UDP/443) globally for *client app* traffic. Reality-
        # Vision, ShadowTLS, and ws-cf are all TCP-only transports; when
        # 🔀 Proxy resolves to any of them, outbound UDP/443 silently
        # black-holes (HTTP/3 hangs, browsers do the slow fallback to TCP
        # after ~a second). Rejecting here forces the immediate fallback.
        {'network': 'udp', 'port': 443, 'action': 'reject'},
        # Reject DoT (TCP/853). Android's "Private DNS" setting emits DoT
        # from the system resolver; under our auto_route+strict_route TUN
        # it surfaces as connections to 172.16.0.2:853 (the TUN peer)
        # which direct-outbound tries and fails after 5s on cellular,
        # cluttering the log at every startup. It also closes the door on
        # any app that sidesteps port-53 hijack by using DoT directly.
        # Port 53 hijack-dns (first rule) catches the resulting fallback
        # queries, so there's no capability loss — DoT-speaking apps just
        # drop to Do53 and get captured by sing-box's DNS stack.
        {'network': 'tcp', 'port': 853, 'action': 'reject'},
        {'ip_is_private': True, 'outbound': '➡️ Direct'},
        {'domain_suffix': ['local', 'lan'], 'outbound': '➡️ Direct'},
    ])

    # SSH → Direct for admin users. Placed early so it wins before any geo
    # rule sweeps port 22 into a country selector (which could Proxy it).
    if user.get('admin'):
        rules.append({'port': 22, 'outbound': '➡️ Direct'})

    # Trusted domain list — only emit if the user has ≥2 protocols or is a
    # multi-country user (where differentiating makes sense). For simple
    # single-country users, keep the rule set lean.
    # _original_protocols is set by the per-protocol solo emitter (see
    # compute_client_plan): when rendering a 1-of-N solo file from a multi-
    # protocol user, we still want Trusted-domain pinning, otherwise the
    # solo profile silently routes banking/Apple traffic through whatever
    # 🌍 Default lands on. The fallback keeps unified-file behaviour intact.
    effective_proto_count = len(user.get('_original_protocols') or user['protocols'])
    if effective_proto_count >= 2 or len(countries) > 1 or has_home:
        rules.append({'domain_suffix': TRUSTED_DOMAINS, 'outbound': '🔒 Trusted'})

    # Home-egress routing (before country rules, so home ccTLDs don't get
    # swept into country Restricted). Two sources:
    #   - home_egress_countries: ISO-2 codes → both a geoip rule and a
    #     domain_suffix entry (matching the ccTLD).
    #   - home_egress_tlds: arbitrary TLDs (eu, one, brand TLDs) → only
    #     domain_suffix, no geoip.
    if has_home:
        # broad geoip + ccTLD home egress.
        home_geoips, home_tlds = [], []
        for cc in user['home'].get('home_egress_countries', []):
            m = home_country(cc)
            home_geoips.append(m['geoip'])
            home_tlds.extend(m['tlds'])
        for tld in user['home'].get('home_egress_tlds', []):
            home_tlds.append(tld)
        if home_geoips:
            rules.append({'rule_set': home_geoips, 'outbound': '🏠 Home Sites'})
        if home_tlds:
            rules.append({'domain_suffix': home_tlds, 'outbound': '🏠 Home Sites'})

    # Firewall-blocked (CN/RU lists): route to 🌍 Default so they always tunnel
    # (never to a country alias Direct that would dead-end them).
    blocked_tags = []
    for cc in countries:
        b = COUNTRY[cc].get('blocked_ruleset')
        if b:
            blocked_tags.append(b['tag'])
    if blocked_tags:
        rules.append({'rule_set': blocked_tags, 'outbound': '🌍 Default'})

    # Country routing → 🚨 Restricted. Uses `restricted_geosite` override if
    # set (e.g. RU uses `ru-available-only-inside` — only sites that actually
    # require a RU IP), falling back to the broader `geosite` otherwise.
    # geosite stays the DNS-level matcher for routing to the country DoH.
    for cc in countries:
        m = COUNTRY[cc]
        geosite_tag = m.get('restricted_geosite') or m.get('geosite')
        tags = [t for t in [geosite_tag, m.get('geoip')] if t]
        if tags:
            rules.append({'rule_set': tags, 'outbound': '🚨 Restricted'})

    # Final (catch-all). Multi-country/home → 🌍 Default. Single-country
    # residents → 🔀 Proxy directly (matches their current "proxy by default
    # for non-local traffic" behaviour).
    final = '🌍 Default' if (has_home or len(countries) > 1) else '🔀 Proxy'

    # default_domain_resolver: cloudflare_doh (DoH-through-tunnel), NOT
    # bootstrap_dns. bootstrap is plaintext 1.1.1.1:53 and exists only
    # for the pre-tunnel WS-CDN host lookup (WS-CDN users) — no other
    # domain lookup benefits from going plaintext. Today no route rule
    # matches on domain (all use rule_set/domain_suffix/ip_cidr), so this
    # is future-proofing: the moment a `{domain: [...], outbound: ...}`
    # route rule is added, the lookup goes tunnelled by default instead
    # of leaking to the ISP.
    route = {
        'auto_detect_interface': True,
        'default_domain_resolver': 'cloudflare_doh',
        'final': final,
        'rule_set': emitted_rulesets,
        'rules': rules,
    }
    out = {'route': route}
    # Explicit HTTP client for the remote rule-set fetches (sing-box 1.14+).
    # With no `http_clients` at all, 1.14 builds an implicit client on the
    # default outbound and logs a deprecation the mobile apps show as a
    # "Deprecated" dialog; 1.16 removes the implicit form. Same path as before
    # (detour = route.final). 1.13 rejects both fields, hence the gate.
    # Per-protocol solo files stay on the 1.13 field set whatever the device
    # says (CORE_SOLO_FLOOR).
    if emits(user, device, '1.14'):
        out['http_clients'] = [{'tag': RULESET_HTTP_CLIENT, 'detour': final}]
        route['default_http_client'] = RULESET_HTTP_CLIENT
    return out


def _mobile_per_protocol_block(uname, user, secret):
    """
    Per-protocol single-outbound URL list for the alternate-client section.
    Mirrors the production emission in compute_client_plan: only fires for
    mobile devices with ≥2 protocols. Returns '' if there's nothing to
    show (single-protocol user, or all devices are non-mobile), so the
    surrounding markdown block can be conditionally suppressed.
    """
    mobile_devices = [d for d in user.get('devices', []) if d['type'] == 'mobile']
    proto_tags = protocol_outbound_tags(user.get('protocols', []))
    if not mobile_devices or len(proto_tags) < 2:
        return ''
    lines = []
    for d in mobile_devices:
        if len(mobile_devices) > 1:
            lines.append(f"\n**{d['name']}:**\n")
        lines.append('```')
        for proto in proto_tags:
            # Solo per-protocol URL: egressor-<user>-<type>-<proto>.json
            lines.append(f"https://{PROFILE_HOST}/p/{secret}/egressor-{uname}-{d['type']}-{proto}.json")
        lines.append('```')
    return '\n'.join(lines)


def _mobile_url_block(uname, user, secret):
    """
    Format the per-device remote-profile URL block for the mobile section.
    Single mobile device → one URL in a fenced code block. Multiple mobile
    devices → per-device labelled URLs. Each URL points at the device's
    `egressor-<user>-<type>.json` (user+type naming convention).
    """
    mobile_devices = [d for d in user.get('devices', []) if d['type'] == 'mobile']
    if len(mobile_devices) == 1:
        d = mobile_devices[0]
        return f"```\nhttps://{PROFILE_HOST}/p/{secret}/{device_filename(uname, d)}\n```"
    lines = []
    for d in mobile_devices:
        lines.append(f"- **{d['name']}** — `https://{PROFILE_HOST}/p/{secret}/{device_filename(uname, d)}`")
    return '\n'.join(lines)


def _load_readme_section(name, lang, tokens, fallback='en'):
    """Read templates/readme/<lang>/<name>.md.tmpl, substitute __TOKEN__
    placeholders, return text. Falls back to en/ section-by-section when the
    requested language doesn't have this section translated yet. Unresolved
    __TOKEN__ patterns are fatal (same posture as the server-template check
    elsewhere here)."""
    # Resolve lang/<name> first, fall back to en/<name>; emit clear error if
    # the section is missing entirely so a typo in the caller doesn't slip
    # through as an empty render.
    path = README_TEMPLATE_DIR / lang / f'{name}.md.tmpl'
    if not path.exists():
        path = README_TEMPLATE_DIR / fallback / f'{name}.md.tmpl'
    if not path.exists():
        sys.exit(f'README template missing: {name} (lang={lang}, fallback={fallback})')
    text = path.read_text()
    for k, v in tokens.items():
        text = text.replace(f'__{k}__', str(v))
    # Catch typos / missing tokens. The pattern is __[A-Z][A-Z0-9_]*__ — same
    # shape as the placeholders we own; markdown ** bold ** won't match.
    leftover = re.findall(r'__[A-Z][A-Z0-9_]*__', text)
    if leftover:
        sys.exit(f'README section {name!r} ({lang}) has unresolved tokens: {sorted(set(leftover))}')
    return text


def render_user_readme(uname, user, defaults):
    """
    Generate a ready-to-send Markdown README for this user. Written from
    user's perspective (not admin's), covering setup for each device, the
    dashboard secret if Windows, the AWG section if AWG is enabled, and a
    credentials summary at the end.

    Reads from the merged manifest (load_manifest already wired secrets +
    home_wg into user / device fields), so everything needed is already here.

    Localization: each section is a markdown template under
    templates/readme/<lang>/. The optional `language` field on the user
    selects the language; defaults to 'en' and falls back to en/
    section-by-section if a translation is missing. Commit 1 ships English
    only; the language field is recognised but only 'en' resolves.
    """
    # Language selection — currently 'en' and 'ru' are supported. Unknown
    # languages warn but still render (per-section fallback in
    # _load_readme_section also keeps a partial translation working: any
    # section missing from <lang>/ falls back to en/).
    lang = user.get('language', 'en')
    if lang not in ('en', 'ru'):
        print(f"warning: user {uname!r} language={lang!r} unknown, using English",
              file=sys.stderr)
        lang = 'en'

    # Title display name. `display_name` lets non-Latin-script users (e.g.
    # Cyrillic) show their actual name in the README header; falls back to
    # the capitalised user key. Doesn't affect technical identifiers like
    # device tags (`<uname>-<dev>`), which always use the lowercase key.
    uname_cap = user.get('display_name') or uname.capitalize()
    secret = user['secret']
    protocols = user.get('protocols', [])
    countries = user.get('countries', [])
    has_home = 'home' in user
    has_awg = 'awg' in protocols
    devices = user.get('devices', [])
    has_mobile = any(d['type'] == 'mobile' for d in devices)
    has_windows = any(d['type'] == 'windows' for d in devices)
    has_mac = any(d['type'] == 'mac' for d in devices)
    has_linux = any(d['type'] == 'linux' for d in devices)

    # Inline summaries spliced into main.md.tmpl as plain text.
    country_labels = ', '.join(f"{COUNTRY[c]['flag']} {COUNTRY[c]['label']}" for c in countries)
    protocol_labels = ', '.join(protocols) if protocols else 'none'
    # proxy_selector_default is the same computation the renderer uses for the
    # in-config default; surfaced here so the README matches the dashboard.
    proxy_default_tag = proxy_selector_default(user, protocol_outbound_tags(protocols))

    # Device list — built in Python (per-device shape varies with type), then
    # substituted into __DEVICE_LIST__ in main.md.tmpl.
    device_lines = []
    for d in devices:
        label = f"**{d['name']}** ({d['type']})"
        # windows + linux both expose the clash_api dashboard (frag_experimental).
        if d['type'] in ('windows', 'linux'):
            label += f" — clash secret `{d['clash_secret']}`"
        device_lines.append(f'- {label}')
    device_block = '\n'.join(device_lines)

    # Restricted-default explain — single-country vs multi-country prose. Two
    # leaf templates so translators see the single/multi distinction with
    # context instead of as opaque keys.
    if len(countries) == 1 and not has_home:
        only_cc = countries[0]
        restricted_default_explain = _load_readme_section(
            'restricted_one', lang,
            {'FLAG': COUNTRY[only_cc]['flag'], 'COUNTRY_LABEL': COUNTRY[only_cc]['label']},
        )
    else:
        restricted_default_explain = _load_readme_section('restricted_many', lang, {})

    # Per-protocol URL block — only non-empty for mobile users with ≥2
    # protocols (mirrors compute_client_plan's emission gate). Drives the
    # "If you can't install sing-box" subsection; empty suppresses the whole
    # subsection for single-protocol or non-mobile users.
    per_protocol_urls = _mobile_per_protocol_block(uname, user, secret)
    if has_mobile and per_protocol_urls:
        alternate_section = _load_readme_section(
            'alternate', lang, {'PER_PROTOCOL_URLS': per_protocol_urls},
        )
    else:
        alternate_section = ''

    # Mobile install + profile import. Sing-box official only — Hiddify-Next
    # is explicitly NOT recommended (wraps imported profiles in its own
    # urltest "Auto" group, defeating the country-derived default). The
    # alternate subsection (if any) is spliced in via __ALTERNATE_SECTION__.
    if has_mobile:
        mobile_section = _load_readme_section(
            'mobile', lang,
            {'MOBILE_URL_BLOCK': _mobile_url_block(uname, user, secret),
             'ALTERNATE_SECTION': alternate_section},
        )
    else:
        mobile_section = ''

    # Mac section — SFM imports the same remote-profile URL shape as mobile.
    # ≤1 mac device per user (collision guard), so a single fenced URL block.
    # No per-protocol solo files: SFM installs via brew/GitHub releases in any
    # region, so the alternate-client wrap-on-import fallback never applies.
    if has_mac:
        mac_dev = next(d for d in devices if d['type'] == 'mac')
        mac_url = f"https://{PROFILE_HOST}/p/{secret}/{device_filename(uname, mac_dev)}"
        mac_section = _load_readme_section(
            'mac', lang, {'MAC_URL_BLOCK': f"```\n{mac_url}\n```"},
        )
    else:
        mac_section = ''

    # Windows section — installer fetches one specific config; for users with
    # multiple windows devices that's the first one in profiles.yaml order
    # (matches apply_plan's installer regen).
    if has_windows:
        win_dev = next(d for d in devices if d['type'] == 'windows')
        windows_section = _load_readme_section(
            'windows', lang,
            {'PROFILE_HOST': PROFILE_HOST,
             'SECRET': secret,
             'WIN_FILENAME': device_filename(uname, win_dev),
             'CLASH_SECRET': win_dev['clash_secret']},
        )
    else:
        windows_section = ''

    # Linux section — same shape as Windows (installer one-liner fetches one
    # specific config; first linux device in profiles.yaml order, matching
    # apply_plan's installer regen) but the install path is a systemd service
    # + timer written by install-singbox.sh, and the sing-box binary comes from
    # the distro package where one exists (Arch) or a GitHub release tarball.
    if has_linux:
        lin_dev = next(d for d in devices if d['type'] == 'linux')
        linux_section = _load_readme_section(
            'linux', lang,
            {'PROFILE_HOST': PROFILE_HOST,
             'SECRET': secret,
             'LINUX_FILENAME': device_filename(uname, lin_dev),
             'CLASH_SECRET': lin_dev['clash_secret']},
        )
    else:
        linux_section = ''

    # AWG section — only when 'awg' in protocols. Lives in a separate Amnezia
    # VPN app rather than the sing-box client (two-app split is intentional;
    # see docs/architecture.md). Single-device users get one URL in a fenced
    # block; multi-device users get a labelled list — same shape as
    # _mobile_url_block.
    if has_awg:
        if len(devices) == 1:
            d = devices[0]
            # AWG conf URL: the SHORT `<user>-<type>.conf` alias, because the
            # app names the tunnel after the file and caps it at 15 chars
            # (see awg_short_filename); the long primary name is not importable.
            awg_url_block = f"```\nhttps://{PROFILE_HOST}/p/{secret}/{awg_short_filename(uname, d)}\n```"
        else:
            awg_url_block = '\n'.join(
                f"- **{d['name']}** ({d['type']}) — `https://{PROFILE_HOST}/p/{secret}/{awg_short_filename(uname, d)}`"
                for d in devices
            )
        awg_section = _load_readme_section('awg', lang, {'AWG_URL_BLOCK': awg_url_block})
    else:
        awg_section = ''

    # Home egress — only when 'home' in user. Leading newline baked into
    # home.md.tmpl provides the blank line between Region coverage and Home
    # egress header.
    if has_home:
        home_entries = list(user['home'].get('home_egress_countries', [])) + list(user['home'].get('home_egress_tlds', []))
        home_countries = ', '.join(e.upper() for e in home_entries)
        home_block = _load_readme_section(
            'home', lang,
            {'HOME_COUNTRIES': home_countries,
             'HOME_PHYSICAL_CC': user['home']['country'].upper()},
        )
    else:
        home_block = ''

    # Credentials block — labels are localized via README_LABELS, values
    # (URLs, UUIDs, passwords) are not. Reality short_id, UUID, PSK and the
    # `**ws-cf**`/`**hy2**`/`**ShadowTLS**`/`**Shadowsocks-2022**` protocol
    # tags stay literal — they're identifiers users see in clients and
    # admin chat, not prose.
    L = README_LABELS.get(lang, README_LABELS['en'])
    creds_lines = [
        f"- **{L['profile_url']}**: `https://{PROFILE_HOST}/p/{secret}/`",
        f"- **{L['server']}**: `{defaults['reality']['server']}`",
    ]
    for d in devices:
        reality = d.get('reality', {})
        parts = [f"  - **{uname}-{d['name']}** ({d['type']})"]
        if reality:
            parts.append(f"Reality short_id `{reality['short_id']}`, UUID `{reality['uuid']}`")
        if d['type'] in ('windows', 'linux'):
            parts.append(f"{L['clash_secret']} `{d['clash_secret']}`")
        creds_lines.append(' — '.join(parts))
    if 'ws-cf' in protocols:
        creds_lines.append(f"- **ws-cf** UUID: `{user.get('ws_cf_uuid')}` {L['shared_devices_paren']}")
    if 'hy2' in protocols:
        creds_lines.append(f"- **hy2** {L['password']}: `{user.get('hy2_password')}`")
    if 'shadowtls' in protocols:
        creds_lines.append(f"- **ShadowTLS** {L['password']}: `{user.get('shadowtls_password')}`")
        # SS-2022 multi-user EIH: client password is <server_psk>:<user_psk>.
        # Both halves shown for manual-config reference.
        creds_lines.append(
            f"- **Shadowsocks-2022** PSK: "
            f"`{defaults['shadowtls']['shadowsocks_password']}:{user.get('shadowsocks_password')}` "
            f"{L['server_user_paren']}"
        )
    creds_block = '\n'.join(creds_lines)

    # Final assembly — main.md.tmpl knows the document skeleton; sub-templates
    # have already been resolved above.
    return _load_readme_section('main', lang, {
        'UNAME_CAP': uname_cap,
        'DEVICE_COUNT': str(len(devices)),
        'DEVICE_LIST': device_block,
        'PROTOCOL_LABELS': protocol_labels,
        'COUNTRY_LABELS': country_labels or 'none',
        'HOME_BLOCK': home_block,
        'PROXY_DEFAULT': proxy_default_tag,
        'RESTRICTED_DEFAULT_EXPLAIN': restricted_default_explain,
        'MOBILE_SECTION': mobile_section,
        'MAC_SECTION': mac_section,
        'WINDOWS_SECTION': windows_section,
        'LINUX_SECTION': linux_section,
        'AWG_SECTION': awg_section,
        'CREDS_BLOCK': creds_block,
    })


def frag_experimental(device):
    """clash_api (windows + linux desktops) + cache_file (everyone)."""
    exp = {
        # No `store_rdrc`/`rdrc_timeout`: deprecated in sing-box 1.14 (removed 1.16).
        # The replacement `store_dns` is 1.14-only (a decode error on 1.13), so it
        # would have to sit behind emits(user, device, '1.14'); not emitted yet.
        # Removal only drops cross-restart reject-cache persistence —
        # blocking still works via the reject rule-sets. store_fakeip kept.
        # (2026-07-19; same 1.14 deprecation batch as frag_dns/rule-set download_detour.)
        'cache_file': {
            'enabled': True, 'path': 'cache.db', 'store_fakeip': True,
        },
    }
    if device['type'] in ('windows', 'linux'):
        exp['clash_api'] = {
            'external_controller': '127.0.0.1:9090',
            'secret': device['clash_secret'],
            'external_ui': 'metacubexd',
            'external_ui_download_url': 'https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip',
            'external_ui_download_detour': '🔀 Proxy',
        }
    return {'experimental': exp}


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------

def compose(user, device, defaults):
    """Compose the full sing-box JSON for one (user, device)."""
    has_home = 'home' in user
    cfg = {}
    cfg.update(frag_log())
    cfg.update(frag_ntp(device))
    home_endpoint = user.get('home', {}).get('endpoint') if has_home else None
    # bootstrap_ip selection: infer physical-in-country from the same signal
    # frag_dns uses for cloud_detour — single-country user with no home_egress.
    # That combo means the whole profile is tuned for living inside this
    # country (Restricted.default points at the country-alias Direct, country
    # TLDs don't route to Home Sites). The user's physical location is
    # implicit in the manifest shape, reusing it here keeps the bootstrap
    # selection in lockstep with cloud_detour and Restricted.default.
    # Multi-country and home-equipped users stay on 1.1.1.1.
    bootstrap_ip = '1.1.1.1'
    if len(user['countries']) == 1 and not has_home:
        override = COUNTRY.get(user['countries'][0], {}).get('bootstrap_dns')
        if override:
            bootstrap_ip = override
    # WS-CDN host needs pre-tunnel resolution; pass it only if this user has
    # WS-CDN enabled, otherwise no bootstrap entry is needed.
    ws_cf_host = defaults.get('ws-cf', {}).get('host') if 'ws-cf' in user.get('protocols', []) else None
    extra_hosts = [ex['peer']['endpoint'] for ex in device_exit_endpoints(user, device)]
    cfg.update(frag_dns(user['countries'], has_home, home_endpoint=home_endpoint,
                        extra_endpoints=extra_hosts,
                        bootstrap_ip=bootstrap_ip, ws_cf_host=ws_cf_host,
                        device=device))
    # Endpoints are ACCUMULATED across producers before a single assignment:
    # two fragments each returning {'endpoints': [...]} through cfg.update()
    # would silently clobber each other (🏢 Home vs 🧵 Tailscale).
    endpoints = []
    if has_home and device.get('home_wg'):
        # Carrier = the concrete outbound 🔀 Proxy defaults to, so the wrapped
        # path is unchanged while the detour stays selector-free (1.14-safe).
        home_carrier = proxy_selector_default(
            user, protocol_outbound_tags(user['protocols']))
        endpoints.extend(frag_home_endpoint(user['home'], device['home_wg'],
                                            home_carrier)['endpoints'])
    if device_exit_endpoints(user, device):
        # Same concrete carrier as 🏢 Home (selector detours fail on 1.14).
        exit_carrier = proxy_selector_default(
            user, protocol_outbound_tags(user['protocols']))
        for ex in device_exit_endpoints(user, device):
            ep = frag_home_endpoint(ex['peer'], ex['device_wg'],
                                    exit_carrier)['endpoints'][0]
            ep['tag'] = ex['tag']
            endpoints.append(ep)
    if user.get('tailnet') and device.get('tailscale'):
        endpoints.append(frag_tailscale_endpoint(user, device))
    if endpoints:
        cfg['endpoints'] = endpoints
    cfg.update(frag_inbound(device, user, defaults))  # user/defaults: AWG-endpoint TUN exclusion
    cfg.update(frag_outbounds(user, device, defaults))
    cfg.update(frag_route(user, device, defaults))
    cfg.update(frag_experimental(device))
    return cfg


# ---------------------------------------------------------------------------
# Filename + output helpers
# ---------------------------------------------------------------------------

def device_filename(uname, device):
    """
    Compute the per-device filename: `egressor-<user>-<type>.json`
    (e.g. egressor-alice-mobile.json). Keyed by USER + device TYPE, not the
    device's model name, on purpose: a hardware swap under the same user+type
    (e.g. pixel9 -> motorola) then keeps the served URL identical, so it never
    orphans a device's saved subscription (the pixel9->motorola rename-orphan
    outage is exactly what this prevents). Requires ≤1 device per type per
    user — enforced by the collision guard in compute_client_plan.
    """
    return f"egressor-{uname}-{device['type']}.json"


# WireGuard-family apps (AmneziaWG Android/iOS inherit the WireGuard rule) name
# the tunnel after the imported filename and REJECT names that do not match
# `[a-zA-Z0-9_=+.-]{1,15}` ("invalid name") before even parsing the config.
# `egressor-<user>-<type>-awg` is 20+ chars, so the primary AWG filename can
# never be imported as-is on mobile. The short copy below fits.
AWG_TUNNEL_NAME_MAX = 15


def awg_filename(uname, device):
    """Primary per-device AWG conf: `egressor-<user>-<type>-awg.conf` — mirrors
    device_filename() (user+type keyed, see there)."""
    return f"egressor-{uname}-{device['type']}-awg.conf"


def awg_short_filename(uname, device):
    """
    Import-friendly alias of awg_filename(): `<user>-<type>.conf` (no prefix,
    no `-awg` — the `.conf` extension already tells it apart from the sing-box
    `.json`). This is the URL the README advertises for AWG, because the
    mobile apps derive the tunnel name from it and cap it at
    AWG_TUNNEL_NAME_MAX chars (e.g. `charlie-windows` is exactly 15). Fails
    loud on a user/type combination that would exceed the cap rather than
    serve a file no phone can import.
    """
    stem = f"{uname}-{device['type']}"
    if len(stem) > AWG_TUNNEL_NAME_MAX:
        sys.exit(f"ERROR: AWG tunnel name {stem!r} is {len(stem)} chars; "
                 f"WireGuard/AmneziaWG apps reject names over "
                 f"{AWG_TUNNEL_NAME_MAX}. Shorten the user name in profiles.yaml.")
    return f"{stem}.conf"


def user_output_dir(user):
    return SRV / user['secret']


def emit_json(obj):
    """Canonical JSON output — stable for diffing."""
    return json.dumps(obj, indent=2, ensure_ascii=False) + '\n'


# ---------------------------------------------------------------------------
# Diff + apply
# ---------------------------------------------------------------------------

def unified_diff(a_text, b_text, a_label, b_label):
    return ''.join(difflib.unified_diff(
        a_text.splitlines(keepends=True),
        b_text.splitlines(keepends=True),
        fromfile=a_label, tofile=b_label, n=3,
    ))


# TEMPORARY migration shim (added 2026-07-26, PR #13). When True, compute_client_plan
# ALSO emits an identical-content COPY of every rendered file under its pre-rename
# legacy name (singbox-<model>.json / singbox-<model>-<proto>.json / awg-<model>.conf),
# so auto-polling clients whose saved subscription URL still points at the old name
# (the installed Windows updaters) keep fetching a VALID config across the cutover —
# crucially they self-heal THROUGH the monthly short_id rotation instead of stranding
# on a 404 (the updater has no URL fallback). Copies, not symlinks, so serving is
# independent of the web layer's symlink policy; registered in `expected` so the
# stale-prune keeps them. Must live in render.py (not the publish wrapper) because
# rotate-shortids.sh calls `./render.py -y` directly. **DROP this whole shim — the
# constant + _legacy_alias_plan() + its 3 call sites — once every device has been
# re-provisioned onto the egressor-<user>-<type> names.**
EMIT_LEGACY_ALIASES = False

# SECOND migration shim (added 2026-08-27, project rename Clearway -> Egressor).
# Same mechanism, one generation newer: every rendered file is ALSO copied under
# its `clearway-<user>-<type>[...]` name, which is the URL every device imported
# between 2026-07-26 and the rename. Unlike the singbox-<model> shim this one
# applies to ALL device types (mac included — mac devices were provisioned under
# clearway- names). **DROP once every device has been re-imported onto the
# egressor-<user>-<type> URLs** (`grep clearway- srv/p/*/README.md` is empty and
# nginx access logs show no clearway-* fetches for a full rotation cycle).
# 2026-08-28: HARD CUTOVER done — owner's call. Loki showed only three live
# pollers on clearway-* names (two mobiles and one Windows client), all
# re-provisioned by hand. Left False (not deleted) so a stranded device can be
# rescued with a one-line flip + render if one turns up.
EMIT_CLEARWAY_ALIASES = False


def _legacy_alias_plan(outdir, legacy_fname, text, uname, expected_set):
    """Build a plan entry for a legacy-named copy of a rendered file (see the
    EMIT_LEGACY_ALIASES note above) and register it in expected_set so it is not
    pruned. Content is identical to the primary file, so it stays in sync on every
    render (incl. rotation crons)."""
    legacy_path = outdir / legacy_fname
    expected_set.add(legacy_fname)
    if legacy_path.exists():
        action = 'unchanged' if legacy_path.read_text() == text else 'modify'
    else:
        action = 'create'
    return (legacy_path, text, action, uname)


def compute_client_plan(manifest):
    """Pure planning: returns list of (path, new_text, action, uname) for every
    per-device output file + per-user README + per-device awg-<dev>.conf
    (when AWG is enabled for that user). Does not print or write."""
    defaults = manifest['defaults']
    awg_state = manifest.get('_awg')  # set by load_manifest only when AWG is in use
    plan = []
    # path -> core floor of every sing-box JSON in the plan, for
    # check_client_plan (the plan tuples themselves stay 4-wide).
    floors = manifest['_core_floors'] = {}
    for uname, user in manifest['users'].items():
        uname_user = dict(user); uname_user['_name'] = uname
        outdir = user_output_dir(user)
        expected = set()
        for dev in user['devices']:
            cfg = compose(uname_user, dev, defaults)
            text = emit_json(cfg)
            fname = device_filename(uname, dev)
            # Collision guard for the user+type naming scheme: two devices of
            # the same type under one user would map to the same filename and
            # silently clobber each other. Fail loud instead (currently no
            # user has ≥2 devices of a type).
            if fname in expected:
                raise SystemExit(
                    f"filename collision: user '{uname}' has two '{dev['type']}' "
                    f"devices both mapping to {fname}. The egressor-<user>-<type> "
                    f"scheme requires at most one device per type per user.")
            path = outdir / fname
            expected.add(fname)
            floors[path] = core_floor(uname_user, dev)
            if path.exists():
                action = 'unchanged' if path.read_text() == text else 'modify'
            else:
                action = 'create'
            plan.append((path, text, action, uname))
            # Legacy-name copy (migration shim) — old unified name singbox-<model>.json.
            # mac and linux are excluded: both types postdate the 2026-07-26
            # rename, so no client can hold a legacy URL for them.
            if EMIT_LEGACY_ALIASES and dev['type'] not in ('mac', 'linux'):
                plan.append(_legacy_alias_plan(
                    outdir, f"singbox-{dev['name']}.json", text, uname, expected))
            # Pre-rename copy (migration shim #2) — clearway-<user>-<type>.json.
            if EMIT_CLEARWAY_ALIASES:
                plan.append(_legacy_alias_plan(
                    outdir, f"clearway-{uname}-{dev['type']}.json", text, uname, expected))

            # Per-protocol single-outbound profiles for mobile devices.
            # Generalises hazard #15 (Hiddify-Next wrapping the imported
            # selector in its own urltest "Auto" group) to any current or
            # future iOS client with the same wrap-on-import behaviour: if
            # the user can't install sing-box (SFI) — e.g. iOS App Stores
            # in CN/RU which have pulled the app — they fall back to a
            # different client and import the per-protocol file matching
            # their selected protocol. With only one outbound there's
            # nothing for a wrapper's urltest to switch between, so the
            # design's manual-selector contract holds even when SFI isn't
            # available. Skipped for single-protocol users (the per-
            # protocol file would be byte-identical to the unified one).
            if dev['type'] == 'mobile':
                solo_tags = protocol_outbound_tags(uname_user.get('protocols', []))
                if len(solo_tags) >= 2:
                    for proto in solo_tags:
                        solo_user = dict(uname_user)
                        # Preserve the full protocol list under a sentinel
                        # field so frag_route's Trusted-domains gate (which
                        # keys off ≥2 protocols) still fires for the solo
                        # profile of a multi-protocol user.
                        solo_user['_original_protocols'] = list(uname_user['protocols'])
                        solo_user['protocols'] = [proto]
                        solo_cfg = compose(solo_user, dev, defaults)
                        solo_text = emit_json(solo_cfg)
                        # Solo per-protocol file: egressor-<user>-<type>-<proto>.json
                        solo_fname = f"egressor-{uname}-{dev['type']}-{proto}.json"
                        solo_path = outdir / solo_fname
                        expected.add(solo_fname)
                        floors[solo_path] = core_floor(solo_user, dev)
                        if solo_path.exists():
                            solo_action = 'unchanged' if solo_path.read_text() == solo_text else 'modify'
                        else:
                            solo_action = 'create'
                        plan.append((solo_path, solo_text, solo_action, uname))
                        # Legacy-name copy (migration shim) — old solo name
                        # singbox-<model>-<proto>.json.
                        if EMIT_LEGACY_ALIASES:
                            plan.append(_legacy_alias_plan(
                                outdir, f"singbox-{dev['name']}-{proto}.json",
                                solo_text, uname, expected))
                        if EMIT_CLEARWAY_ALIASES:
                            plan.append(_legacy_alias_plan(
                                outdir, f"clearway-{uname}-{dev['type']}-{proto}.json",
                                solo_text, uname, expected))

        # Per-device AWG client config — only when the user has 'awg' in
        # protocols, one config per device (each device has its own keypair
        # and IP). Filename `egressor-<user>-<type>-awg.conf` mirrors the
        # sing-box `egressor-<user>-<type>.json` so the served-URL tree at
        # /p/<secret>/egressor-<user>-<type>-awg.conf can be fetched by the
        # Amnezia VPN app per device.
        expected_awg = set()
        if awg_state and 'awg' in user.get('protocols', []):
            for dev in user['devices']:
                awg_text = _render_awg_client_conf(
                    uname,
                    dev['name'],
                    dev,
                    awg_state['block'],
                    awg_state['addresses'][uname][dev['name']],
                )
                awg_fname = awg_filename(uname, dev)
                awg_path = outdir / awg_fname
                expected.add(awg_fname)
                expected_awg.add(awg_fname)
                if awg_path.exists():
                    action = 'unchanged' if awg_path.read_text() == awg_text else 'modify'
                else:
                    action = 'create'
                plan.append((awg_path, awg_text, action, uname))
                # Short import-friendly copy `<user>-<type>.conf` — PERMANENT
                # (not a migration shim): the mobile apps cap the tunnel name
                # at 15 chars, so this is the URL the README hands out. Same
                # copy mechanism as the legacy aliases (identical content,
                # registered in expected_awg so the prune keeps it).
                plan.append(_legacy_alias_plan(
                    outdir, awg_short_filename(uname, dev), awg_text, uname, expected_awg))
                # Legacy-name copy (migration shim) — old awg name awg-<model>.conf.
                # Registered in expected_awg so the awg stale-prune keeps it.
                # mac/linux excluded: both types postdate the rename, no
                # legacy URL exists.
                if EMIT_LEGACY_ALIASES and dev['type'] not in ('mac', 'linux'):
                    plan.append(_legacy_alias_plan(
                        outdir, f'awg-{dev["name"]}.conf', awg_text, uname, expected_awg))
                if EMIT_CLEARWAY_ALIASES:
                    plan.append(_legacy_alias_plan(
                        outdir, f'clearway-{uname}-{dev["type"]}-awg.conf',
                        awg_text, uname, expected_awg))

        # Per-user README with all setup instructions + credentials inlined.
        # The admin sends this to the user when onboarding them.
        readme_text = render_user_readme(uname, uname_user, defaults)
        readme_path = outdir / 'README.md'
        if readme_path.exists():
            action = 'unchanged' if readme_path.read_text() == readme_text else 'modify'
        else:
            action = 'create'
        plan.append((readme_path, readme_text, action, uname))

        if outdir.exists():
            # Sweep stale sing-box profiles. Glob the current `egressor-*.json`
            # names AND both legacy generations (`clearway-*.json`, pre-2026-08
            # rename; `singbox-*.json`, pre-2026-07 model-based naming). Legacy
            # names are only in `expected` while their alias shim is on, so
            # turning a shim off makes the next render prune them — the hard
            # cutover deletes the old served files rather than leaving both live.
            for existing in (list(outdir.glob('egressor-*.json')) + list(outdir.glob('clearway-*.json'))
                             + list(outdir.glob('singbox-*.json'))):
                if existing.name not in expected:
                    plan.append((existing, None, 'delete', uname))
            # Sweep stale AWG configs: current `egressor-*-awg.conf` + legacy
            # `clearway-*-awg.conf` + the older per-device `awg-*.conf` plus the
            # oldest single-per-user `awg.conf` (pre-2026-04-27). Legacy names
            # are only re-emitted while their shim is on.
            # The short `<user>-<type>.conf` aliases are swept too (a removed
            # device must not leave an importable stale copy behind).
            short_aliases = [p for t in ('mobile', 'windows', 'mac', 'linux') for p in outdir.glob(f'*-{t}.conf')]
            for existing in (list(outdir.glob('egressor-*-awg.conf')) + list(outdir.glob('clearway-*-awg.conf'))
                             + list(outdir.glob('awg-*.conf')) + short_aliases):
                if existing.name not in expected_awg:
                    plan.append((existing, None, 'delete', uname))
            stale_legacy = outdir / 'awg.conf'
            if stale_legacy.exists():
                plan.append((stale_legacy, None, 'delete', uname))

    # awg-server config emission. Real [Interface] + per-user [Peer] blocks
    # rendered from .secrets.yaml + the AWG users' derived public keys. Bind-
    # mounted into the awg-server container at /etc/amneziawg/awg0.conf.
    if awg_state:
        srv_text = _render_awg_server_config(manifest, awg_state)
        srv_path = AWG_SERVER_CONFIG
        if srv_path.exists():
            action = 'unchanged' if srv_path.read_text() == srv_text else 'modify'
        else:
            action = 'create'
        plan.append((srv_path, srv_text, action, '<awg-server>'))

    return plan


def client_plan_has_changes(plan):
    return any(a[2] in ('modify', 'create', 'delete') for a in plan)


def _short_path(path):
    """Display path as repo-relative when possible, falling back to absolute.
    The awg-server stub lives at <repo>/awg-server/config/awg0.conf, outside
    ROOT (which is singbox-profiles/), so a strict relative_to(ROOT) raises."""
    try:
        return path.relative_to(ROOT)
    except ValueError:
        try:
            return path.relative_to(ROOT.parent)
        except ValueError:
            return path


def print_client_summary(plan):
    print('── Client plan ──────────────────────────────────────────────')
    if not plan:
        print('  (nothing)')
        return
    for path, _, action, uname in plan:
        print(f'  [{action:9}] {uname:12} {_short_path(path)}')


def print_client_diffs(plan):
    for path, text, action, uname in plan:
        if action == 'modify':
            print(unified_diff(path.read_text(), text, f'a/{path.name}', f'b/{path.name}'))
        elif action == 'create':
            print(f'── new file: {_short_path(path)} ({len(text.splitlines())} lines)')
        elif action == 'delete':
            print(f'── will delete: {_short_path(path)}')


def render_all(manifest, dry_run=False, auto_yes=False):
    """Standalone client-only flow (kept for backwards compat; unused by default)."""
    plan = compute_client_plan(manifest)
    print_client_summary(plan)
    if dry_run:
        print_client_diffs(plan)
        return
    if not client_plan_has_changes(plan):
        print('Nothing to do — everything up to date.')
        return
    check_failures, unavailable = check_client_plan(manifest, plan, only_changed=True)
    _print_check_result(check_failures, unavailable)
    if check_failures:
        sys.exit('client config check failed — aborting, nothing written')
    if not auto_yes:
        if input('Show diff [y/N]? ').strip().lower() == 'y':
            print_client_diffs(plan)
        if input('Apply? [y/N] ').strip().lower() != 'y':
            print('Aborted.'); return
    apply_plan(plan, manifest)


def apply_plan(plan, manifest):
    """Write all changes. Also refresh installers + secrets.txt."""
    for path, text, action, uname in plan:
        if action == 'create' or action == 'modify':
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                shutil.copy2(path, path.with_suffix(path.suffix + '.prev'))
            path.write_text(text)
            print(f'  wrote {_short_path(path)}')
        elif action == 'delete':
            # missing_ok: the sweep plan can list the same path twice (seen
            # 2026-09-14 on a <user>/awg-windows.conf when EMIT_LEGACY_ALIASES was
            # dropped). Without this the apply loop raises mid-way and leaves
            # the tree half-written — and rotate-shortids.sh runs this -y
            # UNATTENDED every month, during a short-id rotation.
            path.unlink(missing_ok=True)
            print(f'  deleted {_short_path(path)}')

    # Refresh secrets.txt FIRST — generate-installer.sh reads this file to
    # look up each user's URL secret, so a new user's installer would fail
    # if secrets.txt wasn't yet updated.
    lines = [
        '# user -> path-secret mapping for singbox-profiles remote-profile URLs',
        f'# Full URL: https://{PROFILE_HOST}/p/<secret>/egressor-<user>-<type>.json',
        f'# Maintained by render.py — edit profiles.yaml instead.',
        '',
    ]
    for uname, user in manifest['users'].items():
        lines.append(f"{uname}\t{user['secret']}")
    SECRETS_FILE.write_text('\n'.join(lines) + '\n')
    print(f'  wrote {SECRETS_FILE.relative_to(ROOT)}')

    # Refresh installers for every windows device. generate-installer.sh
    # takes a config filename; we drive it for the primary windows device
    # per user (the first one in profiles.yaml order). Multiple-windows-
    # per-user still emits one installer; the others would need their own
    # installer URL — not yet supported. Same gap as before the post-AWG
    # filename rename, just renamed.
    # Same loop serves the linux installer (install-singbox.sh, systemd
    # service + timer) via generate-installer.sh's --linux mode; a user with
    # both types gets both installers in the same served dir.
    for uname, user in manifest['users'].items():
        for dev_type, extra_args, installer_name in (
                ('windows', [], 'install-singbox.ps1'),
                ('linux', ['--linux'], 'install-singbox.sh')):
            typed_devs = [d for d in user['devices'] if d['type'] == dev_type]
            if not typed_devs:
                # A device type that was dropped (or swapped, e.g. windows ->
                # linux) leaves its installer behind, and that stale script
                # would still fetch a config name the sweep above has since
                # pruned. Remove it so the served dir only advertises what
                # the manifest still has.
                stale = user_output_dir(user) / installer_name
                if stale.exists():
                    stale.unlink()
                    print(f'  pruned stale {installer_name} for {uname} (no {dev_type} device)')
                continue
            _regen_installer(uname, user, device_filename(uname, typed_devs[0]), extra_args)


def _regen_installer(uname, user, fname, extra_args):
    """Run generate-installer.sh for one (user, device-type). Factored out of
    apply_plan so the windows and linux installers share the webhook policy
    and the PROFILE_HOST pass-through below."""
    # PUBLIC BY CONSTRUCTION. This value is baked verbatim into the
    # generated install-singbox.ps1 / install-singbox.sh, which is served at
    # https://<PROFILE_HOST>/p/<path-secret>/install-singbox.{ps1,sh} and is
    # therefore readable by anyone who holds a profile link. It MUST be a
    # dedicated throwaway webhook on a low-value channel, never an ops one.
    # Renamed from `notify_webhook` on 2026-08-06: that name carried no hint
    # of the exposure, and an ops webhook had duly ended up here (found
    # publicly fetchable, HTTP 200, during an audit). A legacy key is now
    # ignored rather than silently reused, so a stale ops webhook cannot be
    # re-published by the next render.
    webhook = user.get('installer_webhook_public', '')
    if not webhook and user.get('notify_webhook'):
        print(f'  ! {uname}: legacy `notify_webhook` IGNORED - rename it to '
              '`installer_webhook_public` and make sure it is a throwaway '
              'webhook; this value is served publicly in the installer')
    args = [str(GENERATE_INSTALLER), *extra_args, uname, fname]
    if webhook:
        args.append(webhook)
    # Pass PROFILE_HOST through so generate-installer.sh substitutes the
    # same host into __PROFILE_HOST__ that render.py uses for README URLs.
    env = {**os.environ, 'PROFILE_HOST': PROFILE_HOST}
    label = 'linux ' if extra_args else ''
    try:
        subprocess.run(args, check=True, capture_output=True, text=True, env=env)
        print(f'  regenerated {label}installer for {uname}')
    except subprocess.CalledProcessError as e:
        print(f'  ! {label}installer regen failed for {uname}: {e.stderr}')


def _parse_wg_conf(text):
    """
    Parse a standard WireGuard .conf file (INI format). Returns a dict:
      {'interface': {k:v, ...}, 'peer': {k:v, ...}}
    Keys preserve their original case so emitters can match WG conventions.
    Supports a single [Interface] + single [Peer] section (the household
    never has multi-peer home clients).
    """
    iface, peer = {}, {}
    section = None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.strip('[]').strip().lower()
            continue
        if '=' not in line:
            continue
        k, _, v = line.partition('=')
        k, v = k.strip(), v.strip()
        target = iface if section == 'interface' else peer if section == 'peer' else None
        if target is None:
            continue
        target[k] = v
    return {'interface': iface, 'peer': peer}


def load_home_wg():
    """
    Load every home_wg/<user>-<device>.conf. Returns a nested dict:
      { 'alice': { 'pixel': {'interface': {...}, 'peer': {...}}, ... }, ... }
    Files that don't match the <user>-<device>.conf naming are skipped.
    Missing home_wg dir → empty dict (users with `home:` get errors later).
    """
    out = {}
    if not HOME_WG_DIR.is_dir():
        return out
    for f in sorted(HOME_WG_DIR.glob('*.conf')):
        stem = f.stem  # e.g. 'alice-pixel'
        if '-' not in stem:
            continue
        uname, dev_name = stem.split('-', 1)
        out.setdefault(uname, {})[dev_name] = _parse_wg_conf(f.read_text())
    return out


def _wg_iface_to_sbx(iface, peer):
    """Convert parsed WG conf dict → sing-box device-level home_wg fields
    plus user-level home block peer fields. Returns (device_wg, home_peer)."""
    ep_host, _, ep_port = peer['Endpoint'].rpartition(':')
    device_wg = {
        'address': [a.strip() for a in iface['Address'].split(',')],
        'private_key': iface['PrivateKey'],
    }
    if 'ListenPort' in iface:
        device_wg['listen_port'] = int(iface['ListenPort'])
    home_peer = {
        'endpoint': ep_host,
        'endpoint_port': int(ep_port),
        'peer_public_key': peer['PublicKey'],
        'allowed_ips': [a.strip() for a in peer.get('AllowedIPs', '0.0.0.0/0, ::/0').split(',')],
        'persistent_keepalive_interval': int(peer.get('PersistentKeepalive', 25)),
        # MTU default 1280 (was 1380) — matches the safety rationale at
        # frag_home_endpoint (line ~689): the WG endpoint rides inside the
        # outer proxy protocol so packets are double-encapsulated. 1380
        # leaves no headroom for TLS/QUIC overhead and PMTU-blackholes
        # large TCP payloads (home-country sites fail to load even though
        # the handshake completes). 1280 is the IPv6 minimum, safe nested.
        # A .conf with an explicit `MTU = ...` line still overrides this.
        'mtu': int(iface.get('MTU', 1280)),
    }
    # wg-quick spells it `PresharedKey`; the old `PreSharedKey` spelling is
    # still accepted. Before 2026-10-27 only the latter was read, so a standard
    # .conf silently lost its PSK and the peer could never handshake.
    psk = peer.get('PresharedKey') or peer.get('PreSharedKey')
    if psk:
        home_peer['peer_pre_shared_key'] = psk
    return device_wg, home_peer


def load_secrets():
    """Load .secrets.yaml; returns empty skeleton if missing."""
    if not SECRETS.exists():
        return {'users': {}}
    data = yaml.safe_load(SECRETS.read_text()) or {}
    data.setdefault('users', {})
    return data


def save_secrets(data):
    """Rewrite .secrets.yaml preserving the top-of-file comment header."""
    header_lines = []
    if SECRETS.exists():
        for line in SECRETS.read_text().splitlines():
            if line.strip().startswith('#') or line.strip() == '':
                header_lines.append(line)
            else:
                break
    if not header_lines:
        header_lines = [
            '# Auto-managed by render.py. 0600 permissions recommended.',
            '# Home WG identities live under ../home_wg/<user>-<device>.conf',
            '',
        ]
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)
    SECRETS.write_text('\n'.join(header_lines) + '\n' + body)
    # Ensure 0600 on every write.
    try:
        SECRETS.chmod(0o600)
    except OSError:
        pass


def _new_b64_key(n=32):
    """32 random bytes → base64. Used for shadowsocks/shadowtls passwords."""
    import base64
    return base64.b64encode(secrets.token_bytes(n)).decode()


def _detect_and_apply_renames(sfile, manifest, auto_yes=False):
    """
    Detect potential device renames: a device name in .secrets.yaml that has
    no counterpart in profiles.yaml (orphan) AND a device name in profiles.yaml
    that has no counterpart in .secrets.yaml (missing). When it's exactly 1:1
    for a user, treat it as a rename and move the credentials — avoids the
    "rename looks like a rotation" pitfall.

    Returns (sfile, renamed_report).
    """
    report = []
    for uname, user in manifest['users'].items():
        profile_names = {d['name'] for d in user.get('devices', [])}
        s_user = sfile.get('users', {}).get(uname, {})
        secret_names = set((s_user.get('devices', {}) or {}).keys())
        orphans  = sorted(secret_names - profile_names)
        missings = sorted(profile_names - secret_names)

        if not orphans or not missings:
            continue  # nothing to resolve for this user

        if len(orphans) == 1 and len(missings) == 1:
            old_name, new_name = orphans[0], missings[0]
            if auto_yes:
                action = 'rename'  # unambiguous 1:1 — rename is safer than rotation
            else:
                ans = input(
                    f'{uname}: "{old_name}" in .secrets.yaml has no device in profiles.yaml, '
                    f'and "{new_name}" in profiles.yaml has no credentials. '
                    f'Rename {old_name} → {new_name}? [Y/n] '
                ).strip().lower()
                action = 'rename' if ans in ('', 'y') else 'skip'
            if action == 'rename':
                s_user['devices'][new_name] = s_user['devices'].pop(old_name)
                report.append(f'  renamed {uname}/{old_name} → {uname}/{new_name} in .secrets.yaml')
        else:
            report.append(
                f'  ! {uname}: ambiguous (orphan devices: {orphans}; missing devices: {missings}). '
                f'Resolve in .secrets.yaml manually before re-running.'
            )
            if auto_yes:
                sys.exit(1)
    return sfile, report


def _autogen_missing(sfile, manifest):
    """
    Fill any missing credentials in .secrets.yaml for every user + device
    that needs them (based on their protocols / type / home flag). Returns
    (sfile, changed_summary: list of human-readable lines).

    Does NOT touch WG keys — those come from home_wg/*.conf, never auto-gen'd.
    """
    changed = []
    for uname, user in manifest['users'].items():
        s_user = sfile['users'].setdefault(uname, {})
        protocols = user.get('protocols', [])

        # User-level credentials
        def need(field, gen, label=None):
            if not s_user.get(field):
                s_user[field] = gen()
                changed.append(f'  gen {uname}.{label or field} = {s_user[field]}')

        need('secret', lambda: secrets.token_hex(16))
        if 'ws-cf' in protocols:
            need('ws_cf_uuid', lambda: str(uuid.uuid4()))
        if 'hy2' in protocols:
            need('hy2_password', lambda: secrets.token_urlsafe(22))
        if 'shadowtls' in protocols:
            need('shadowtls_password', lambda: secrets.token_urlsafe(24))
            # Per-user SS-2022 PSK (multi-user EIH mode). The server-level PSK
            # lives in shared.shadowsocks_password; this one is the per-user
            # identity key. Rotation grace applies (kind=shadowsocks_users).
            need('shadowsocks_password', lambda: _new_b64_key(32))

        # Device-level credentials
        s_user.setdefault('devices', {})
        for dev in user.get('devices', []):
            s_dev = s_user['devices'].setdefault(dev['name'], {})
            if 'reality' in protocols:
                s_dev.setdefault('reality', {})
                if not s_dev['reality'].get('uuid'):
                    s_dev['reality']['uuid'] = str(uuid.uuid4())
                    changed.append(f'  gen {uname}/{dev["name"]}.reality.uuid = {s_dev["reality"]["uuid"]}')
                if not s_dev['reality'].get('short_id'):
                    s_dev['reality']['short_id'] = secrets.token_hex(8)
                    changed.append(f'  gen {uname}/{dev["name"]}.reality.short_id = {s_dev["reality"]["short_id"]}')
            # clash_secret: every desktop type that gets a clash_api block
            # (frag_experimental) — windows and linux.
            if dev['type'] in ('windows', 'linux') and not s_dev.get('clash_secret'):
                s_dev['clash_secret'] = secrets.token_hex(24)
                changed.append(f'  gen {uname}/{dev["name"]}.clash_secret = {s_dev["clash_secret"]}')
            # AWG: per-device X25519 private key (32 random bytes, base64).
            # cryptography's X25519PrivateKey.from_private_bytes does the
            # RFC-7748 clamping internally, so any 32-byte random input is
            # equivalent to `wg genkey`. Auto-gen is safe here because
            # render.py is the sole writer of the awg-server [Peer] list —
            # the next render writes both halves atomically.
            if 'awg' in protocols and not s_dev.get('awg_private_key'):
                s_dev['awg_private_key'] = _new_b64_key(32)
                changed.append(f'  gen {uname}/{dev["name"]}.awg_private_key = {s_dev["awg_private_key"]}')

    return sfile, changed


# ---------------------------------------------------------------------------
# AWG (AmneziaWG) — validation, address allocation, per-user .conf emission.
#
# AWG never appears as a sing-box outbound (see schema comment). It runs in
# a separate awg-server container consumed by the Amnezia VPN app on the
# client side. The renderer's only AWG responsibilities are:
#   1. Validate that .secrets.yaml carries a complete `awg:` block when any
#      user has 'awg' in protocols, and that each AWG user has a private key.
#   2. Allocate stable per-user addresses from the configured subnet.
#   3. Emit per-device `awg-<dev>.conf` files into srv/p/<secret>/ via the
#      wg-quick template at templates/awg-client.conf.template.
#   4. Emit a stub awg-server config (real content arrives in stage 2).
# ---------------------------------------------------------------------------

def _awg_users(manifest):
    """Iterator over (uname, user) pairs for users with AWG enabled. Underscore
    pseudo-users (anything starting with `_`) are skipped, matching the rest of
    the renderer's convention for in-band scratch keys."""
    for uname, user in manifest['users'].items():
        if uname.startswith('_'):
            continue
        if 'awg' in (user.get('protocols') or []):
            yield uname, user


def _awg_devices(manifest):
    """Iterator over (uname, dev_name, dev) tuples for every device of every
    user with 'awg' in protocols. AWG identities are per-device (each device
    gets its own keypair, /32 address, and [Peer] block on the server) so all
    AWG emission paths walk this iterator rather than the per-user one."""
    for uname, user in _awg_users(manifest):
        for dev in user.get('devices', []):
            yield uname, dev['name'], dev


def _validate_awg_block(awg_block, sfile, manifest):
    """
    Raise SystemExit with a precise message if the AWG configuration is
    incomplete. Called only when at least one user has 'awg' in protocols
    (no AWG users → no validation needed → renderer can run without an
    `awg:` block at all, which keeps non-AWG deployments unaffected by
    stage 1's additions).
    """
    if not awg_block:
        sys.exit(
            "users have 'awg' in protocols but .secrets.yaml has no top-level "
            "`awg:` block. Add one with subnet/port/endpoint_host/server_private_key/"
            "server_public_key plus the obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4). "
            "See docs/quickstart.md for a generation snippet."
        )
    missing = [k for k in AWG_REQUIRED_KEYS if k not in awg_block]
    if missing:
        sys.exit(
            f"awg block in .secrets.yaml is missing required keys: {missing}. "
            f"All of {list(AWG_REQUIRED_KEYS)} must be present — partial configs "
            f"silently break clients (one mismatched obfuscation param times out "
            f"with no error, by AWG design)."
        )
    # subnet must parse and be large enough for the server address (.1) plus
    # at least one AWG user. /30 wouldn't fit two host addresses; /29 = 6 host
    # addrs, comfortable upper bound for the household scale egressor targets.
    try:
        net = __import__('ipaddress').ip_network(str(awg_block['subnet']), strict=False)
    except (ValueError, TypeError) as e:
        sys.exit(f'awg.subnet {awg_block["subnet"]!r} is not a valid CIDR: {e}')
    hosts = list(net.hosts())
    if len(hosts) < 2:
        sys.exit(
            f'awg.subnet {awg_block["subnet"]!r} too small ({len(hosts)} host '
            f'addrs); need at least 2 (server + 1 client). Use /29 or larger.'
        )

    # Every AWG device must have a private key in .secrets.yaml under
    # users.<n>.devices.<dev>.awg_private_key. _autogen_missing fills these
    # in if absent (render.py is the sole writer of the awg-server [Peer]
    # list, so silent rotation no longer orphans clients — the next render
    # writes both halves atomically). Validation here only fires if autogen
    # somehow failed to populate, so the message points at .secrets.yaml.
    bad = []
    for uname, dev_name, _dev in _awg_devices(manifest):
        s_dev = (sfile.get('users', {})
                      .get(uname, {})
                      .get('devices', {})
                      .get(dev_name, {}))
        if not s_dev.get('awg_private_key'):
            bad.append(f'{uname}/{dev_name}')
    if bad:
        sys.exit(
            f"AWG devices missing awg_private_key in .secrets.yaml: {bad}. "
            f"Either let render.py auto-generate them, or paste under "
            f"users.<name>.devices.<dev>.awg_private_key. The matching public "
            f"key is computed at render time."
        )


def _allocate_awg_addresses(manifest, awg_block):
    """
    Deterministic per-device IPv4 allocation inside `awg.subnet`. Reserves
    the first host address (.1) for the awg-server, then for each AWG
    device (per-user, per-device):
      - if `awg_address` is pinned on the device in profiles.yaml, validate + use it
      - otherwise hash("<uname>/<dev_name>") → starting index, linear-probe
        forward until a free slot, fail loud if the subnet is full

    Hash-based probing means adding a device mid-life doesn't reshuffle
    existing peers (each is found at the same hash position on every run).
    Sorting devices alphabetically before allocation keeps iteration order
    stable in goldens.

    Returns: (server_address, addresses) where addresses is a nested dict
    {uname: {dev_name: ip_str}}. server_address is an `ipaddress.IPv4Address`;
    ips are plain strings (used directly in the server [Peer] AllowedIPs and
    the client [Interface] Address line, both with /32 appended at use site).
    """
    import hashlib
    import ipaddress
    net = ipaddress.ip_network(str(awg_block['subnet']), strict=False)
    hosts = list(net.hosts())
    server_addr = hosts[0]   # .1 by convention; matches the [Interface] Address
                             # in awg-server.conf. Reserved — never assigned to
                             # any device, even via awg_address pin.
    available = hosts[1:]
    n = len(available)

    used = set()
    addresses = {}  # {uname: {dev_name: ip_str}}

    # Stable ordering for both passes — by (uname, dev_name).
    devices = sorted(_awg_devices(manifest), key=lambda t: (t[0], t[1]))

    # Pass 1: process pinned awg_address values first so hash-allocated peers
    # avoid them. Errors here exit immediately so the operator sees the bad
    # pin instead of a downstream "subnet full" red herring.
    for uname, dev_name, dev in devices:
        pin = dev.get('awg_address')
        if not pin:
            continue
        label = f'{uname}/{dev_name}'
        try:
            iface = ipaddress.ip_interface(pin)
            ip = iface.ip
        except ValueError as e:
            sys.exit(f'device {label!r} has invalid awg_address {pin!r}: {e}')
        if ip not in net:
            sys.exit(
                f'device {label!r} awg_address {ip} is outside awg.subnet {net} '
                f'— pin must be inside the configured subnet.'
            )
        if ip == server_addr:
            sys.exit(
                f'device {label!r} awg_address {ip} collides with the reserved '
                f'server address {server_addr}.'
            )
        if ip in used:
            sys.exit(f'device {label!r} awg_address {ip} duplicates another device.')
        used.add(ip)
        addresses.setdefault(uname, {})[dev_name] = str(ip)

    # Pass 2: hash-allocate every remaining AWG device. Hash key includes
    # both username and device name so renaming a device or adding a new one
    # doesn't perturb the others' allocations.
    for uname, dev_name, _dev in devices:
        if addresses.get(uname, {}).get(dev_name):
            continue
        key = f'{uname}/{dev_name}'.encode()
        h = int(hashlib.sha256(key).hexdigest(), 16)
        for i in range(n):
            cand = available[(h + i) % n]
            if cand not in used:
                used.add(cand)
                addresses.setdefault(uname, {})[dev_name] = str(cand)
                break
        else:
            sys.exit(
                f'awg.subnet {net} is full — cannot allocate an address for '
                f'device {uname!r}/{dev_name!r}. Increase the subnet (e.g. /23) '
                f'or remove an AWG device.'
            )

    return server_addr, addresses


def _render_awg_client_conf(uname, dev_name, dev, awg_block, address):
    """
    Substitute the per-device values + AWG block into the wg-quick client
    template. Pure string replace on __PLACEHOLDER__ tokens (matches the
    style used by singbox-server.template.jsonc and the PowerShell installer
    template).

    `address` comes from _allocate_awg_addresses; expressed as plain
    "10.66.66.20" (no CIDR) — the template appends /32 explicitly so a
    pinned awg_address in profiles.yaml that already carries /32 doesn't
    silently double up. The private key comes from the merged device dict
    (load_manifest moves it from .secrets.yaml.users.<n>.devices.<dev>
    onto dev['awg_private_key']).
    """
    if not AWG_CLIENT_TEMPLATE.exists():
        sys.exit(f'AWG client template missing: {AWG_CLIENT_TEMPLATE}')
    tpl = AWG_CLIENT_TEMPLATE.read_text()
    if not dev.get('awg_private_key'):
        sys.exit(
            f'internal: device {uname}/{dev_name} reached client-conf render '
            f'without a private key (validation should have caught this).'
        )
    subs = {
        '__USER_PRIVATE_KEY__':  dev['awg_private_key'],
        '__USER_ADDRESS__':      f'{address}/32',
        '__SERVER_PUBLIC_KEY__': awg_block['server_public_key'],
        '__SERVER_HOST__':       str(awg_block['endpoint_host']),
        '__AWG_PORT__':          str(awg_block['port']),
        '__AWG_JC__':            str(awg_block['Jc']),
        '__AWG_JMIN__':          str(awg_block['Jmin']),
        '__AWG_JMAX__':          str(awg_block['Jmax']),
        '__AWG_S1__':            str(awg_block['S1']),
        '__AWG_S2__':            str(awg_block['S2']),
        '__AWG_H1__':            str(awg_block['H1']),
        '__AWG_H2__':            str(awg_block['H2']),
        '__AWG_H3__':            str(awg_block['H3']),
        '__AWG_H4__':            str(awg_block['H4']),
    }
    for k, v in subs.items():
        if k not in tpl:
            sys.exit(f'awg-client template placeholder {k} missing from {AWG_CLIENT_TEMPLATE}')
        tpl = tpl.replace(k, v)
    return tpl


def _x25519_public_from_private(b64_private):
    """
    Derive an X25519 / WireGuard public key from a base64-encoded 32-byte
    private key. Used for both the server keypair (cross-checking that
    awg.server_public_key in .secrets.yaml matches awg.server_private_key)
    and for each user's public key (which goes into the server config's
    [Peer] block — render.py never asks the operator to compute it).

    Returns the standard wg-format base64 public key. Raises ValueError on
    a malformed or wrong-length private key — caught upstream and turned
    into a precise SystemExit so the operator sees which user's key broke.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = base64.b64decode(b64_private, validate=True)
    if len(raw) != 32:
        raise ValueError(f'expected 32-byte X25519 private key, got {len(raw)} bytes')
    pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(
        pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode('ascii')


def _render_awg_server_config(manifest, awg_state):
    """
    Render the awg-server config from the wg-quick template + per-device
    [Peer] blocks. AWG_SERVER_TEMPLATE provides the [Interface] block; this
    function appends one [Peer] per AWG device (per-user, per-device) with
    that device's derived public key + allocated /32 address.

    Each device's public key is computed from `awg_private_key` at render
    time — no second source of truth, no risk of drift between client
    .conf and server [Peer] block.
    """
    if not AWG_SERVER_TEMPLATE.exists():
        sys.exit(f'AWG server template missing: {AWG_SERVER_TEMPLATE}')
    awg_block = awg_state['block']
    addresses = awg_state['addresses']
    server_address = awg_state['server_address']

    # Build [Peer] blocks for every AWG device. Sorted by (uname, dev_name)
    # so the rendered file stays stable when peers come and go (golden-test
    # friendliness + clean diffs).
    peer_lines = []
    for uname, dev_name, dev in sorted(_awg_devices(manifest), key=lambda t: (t[0], t[1])):
        try:
            pub = _x25519_public_from_private(dev['awg_private_key'])
        except Exception as e:
            sys.exit(
                f'failed to derive AWG public key for {uname}/{dev_name}: {e}. '
                f'Check that .secrets.yaml.users.{uname}.devices.{dev_name}.'
                f'awg_private_key is a valid base64 32-byte X25519 private key.'
            )
        # PersistentKeepalive=0 server-side mitigates the WG keepalive-storm
        # bug (sing-box #3981 / wireguard-go shared upstream): an active
        # server-side keepalive on every peer causes battery drain on idle
        # mobile clients. Clients drive keepalive themselves (25s in the
        # client template) for NAT traversal — this only disables the
        # *server-initiated* keepalive. See docs/hazards.md.
        peer_lines.append(
            f'[Peer]\n'
            f'# {uname}/{dev_name}\n'
            f'PublicKey = {pub}\n'
            f'AllowedIPs = {addresses[uname][dev_name]}/32\n'
            f'PersistentKeepalive = 0\n'
        )
    peers_block = '\n'.join(peer_lines) if peer_lines else (
        '# (no AWG devices in profiles.yaml — empty peer set; awg-server will\n'
        '#  start but accept no client handshakes until devices are added.)\n'
    )

    tpl = AWG_SERVER_TEMPLATE.read_text()
    subs = {
        '__AWG_PORT__':               str(awg_block['port']),
        '__AWG_SERVER_PRIVATE_KEY__': awg_block['server_private_key'],
        '__AWG_JC__':                 str(awg_block['Jc']),
        '__AWG_JMIN__':               str(awg_block['Jmin']),
        '__AWG_JMAX__':               str(awg_block['Jmax']),
        '__AWG_S1__':                 str(awg_block['S1']),
        '__AWG_S2__':                 str(awg_block['S2']),
        '__AWG_H1__':                 str(awg_block['H1']),
        '__AWG_H2__':                 str(awg_block['H2']),
        '__AWG_H3__':                 str(awg_block['H3']),
        '__AWG_H4__':                 str(awg_block['H4']),
        '__PEERS__':                  peers_block,
    }
    for k, v in subs.items():
        if k not in tpl:
            sys.exit(f'awg-server template placeholder {k} missing from {AWG_SERVER_TEMPLATE}')
        tpl = tpl.replace(k, v)
    return tpl


def load_manifest(auto_yes=False):
    """
    Load profiles.yaml + .secrets.yaml + home_wg/*.conf, merge into one
    in-memory manifest dict, auto-generate any missing credentials, and
    persist new secrets back to .secrets.yaml.

    Merge rules:
      - credentials: .secrets.yaml overrides nothing in profiles.yaml
        (profiles.yaml shouldn't carry them any more), just provides them.
      - home_wg: the per-device home_wg block and the user-level home peer
        block (endpoint/public_key/etc.) come from home_wg/*.conf files.
      - If a user has `home:` but lacks a .conf for a device, render errors
        out with a precise message when that device is composed.
    """
    manifest = yaml.safe_load(MANIFEST.read_text())
    # Schema-validate upfront so typos ("windws", forgotten `countries`,
    # capitalised usernames) fail fast with a clear path instead of
    # cascading into a cryptic sing-box check error after full render.
    _validate_manifest_schema(manifest)
    sfile = load_secrets()
    home_wg = load_home_wg()

    # Auto-generate shared.shadowsocks_password if missing — purely symmetric,
    # safe to gen. Reality keypair + hy2 obfs are NOT auto-gen'd (paired / need
    # matching server state rotation).
    shared = sfile.setdefault('shared', {}) or {}
    if not shared.get('shadowsocks_password'):
        shared['shadowsocks_password'] = _new_b64_key(32)
        print(f'  gen shared.shadowsocks_password = {shared["shadowsocks_password"]}')
        save_secrets(sfile)
    # Server-side clash_api secret — used by the docker healthcheck and any
    # admin-side cscli-style poking. Auto-gen on first render so existing
    # installs pick it up transparently. 32-char hex matches the per-device
    # clash_secret format.
    if not shared.get('server_clash_secret'):
        shared['server_clash_secret'] = secrets.token_hex(24)
        print(f'  gen shared.server_clash_secret = {shared["server_clash_secret"]}')
        save_secrets(sfile)

    # Merge shared credentials (reality keypair, hy2 obfs password, ss PSK)
    # into defaults so the rest of the renderer sees unified state.
    if 'reality_public_key' in shared:
        manifest['defaults']['reality']['public_key'] = shared['reality_public_key']
    # reality_private_key was previously hardcoded in the server template;
    # moved to .secrets.yaml so rotate-realitykey.sh can update both halves
    # of the keypair atomically. Only used by render_server_text (clients
    # only need the public half).
    if 'reality_private_key' in shared:
        manifest['defaults']['reality']['private_key'] = shared['reality_private_key']
    # Alternating rotation state (written by rotate-realitykey.sh). `endpoint`
    # = where the ACTIVE key lives and clients dial ('a' = server /
    # INCOMING_IP_1, 'b' = server_b / INCOMING_IP_2). `retiring` =
    # the previous key, kept on the other endpoint until expires_at so
    # clients still running the previous profile keep working.
    endpoint = shared.get('reality_endpoint', 'a')
    if endpoint not in ('a', 'b'):
        sys.exit(f'shared.reality_endpoint must be "a" or "b", got {endpoint!r}')
    manifest['defaults']['reality']['endpoint'] = endpoint
    if shared.get('reality_retiring_private_key'):
        manifest['defaults']['reality']['retiring'] = {
            'private_key': shared['reality_retiring_private_key'],
            'expires_at': shared.get('reality_retiring_expires_at'),
        }
    if 'hy2_obfs_salamander_password' in shared:
        manifest['defaults']['hy2']['obfs_salamander_password'] = shared['hy2_obfs_salamander_password']
    manifest['defaults']['shadowtls']['shadowsocks_password'] = shared['shadowsocks_password']
    # Surface the server clash_api secret in defaults so render_server_text
    # can substitute it into the template without needing the full manifest.
    manifest['defaults']['server_clash_secret'] = shared['server_clash_secret']

    # Detect device renames (orphan in .secrets.yaml ↔ missing in profiles.yaml)
    # BEFORE auto-gen — otherwise the missing side would just get fresh creds
    # and the orphan would sit as dead data, effectively rotating the device's
    # credentials on a pure rename.
    sfile, rename_report = _detect_and_apply_renames(sfile, manifest, auto_yes=auto_yes)
    if rename_report:
        print('── Device renames ───────────────────────────────────────────')
        for line in rename_report:
            print(line)

    # One-shot migration: drop legacy user-level awg_private_key entries.
    # Pre-2026-04-27 layout had AWG identities per-user; the per-device
    # rewrite moves keys to devices.<dev>.awg_private_key and re-allocates
    # IPs by hash("<uname>/<dev_name>") (so IPs shift across the migration
    # too). We park the old user-level key onto the alphabetically-first
    # device — preserves one [Peer] keypair so the operator's mental model
    # of "user X had this pubkey" survives — but every AWG client still
    # needs to re-import because the per-device address has changed.
    migration_report = []
    for uname, user in manifest['users'].items():
        if 'awg' not in (user.get('protocols') or []):
            continue
        s_user = sfile.get('users', {}).get(uname)
        if not s_user or 'awg_private_key' not in s_user:
            continue
        legacy_key = s_user.get('awg_private_key')
        s_user.setdefault('devices', {})
        device_names = sorted(d['name'] for d in user.get('devices', []))
        if device_names and legacy_key:
            primary = device_names[0]
            s_dev = s_user['devices'].setdefault(primary, {})
            if not s_dev.get('awg_private_key'):
                s_dev['awg_private_key'] = legacy_key
                migration_report.append(
                    f'  parked {uname}.awg_private_key on {uname}/{primary} '
                    f'(all AWG clients still need a re-import — IPs shifted)'
                )
        del s_user['awg_private_key']
    if migration_report:
        print('── AWG per-device migration ─────────────────────────────────')
        for line in migration_report:
            print(line)

    # Auto-generate any missing credentials before merging (so we never render
    # a device with a null secret).
    sfile, gen_report = _autogen_missing(sfile, manifest)
    if gen_report:
        print('── Auto-generated credentials ───────────────────────────────')
        for line in gen_report:
            print(line)

    # Persist .secrets.yaml if renames, auto-gen, or AWG migration changed
    # anything. Each of these alone needs saving — otherwise the change would
    # be redone on next run.
    if rename_report or gen_report or migration_report:
        save_secrets(sfile)
        print(f'  wrote {SECRETS.relative_to(ROOT)}')

    # Substitute __VNIC_*_PUBLIC_IP__ placeholders in both manifest + sfile
    # from the repo .env. AFTER the last save_secrets so the on-disk YAMLs
    # keep their placeholder form — rotating a public IP is then a single
    # .env edit, not edits across two YAMLs.
    manifest, sfile = _substitute_public_ip_placeholders(manifest, sfile)

    # AWG validation + address allocation. Runs only when at least one user
    # has 'awg' in protocols; deployments without AWG never touch the awg block
    # and `.secrets.yaml` doesn't need to carry one. Errors here exit before
    # any output is written, so a partial AWG config can't half-render.
    awg_block = sfile.get('awg')
    if any(True for _ in _awg_users(manifest)):
        _validate_awg_block(awg_block, sfile, manifest)
        server_addr, awg_addresses = _allocate_awg_addresses(manifest, awg_block)
        # Stash on the manifest so downstream emit functions don't have to
        # re-load .secrets.yaml or re-allocate. Underscore prefix matches the
        # rest of the renderer's convention for in-band scratch state.
        manifest['_awg'] = {
            'block': awg_block,
            'server_address': str(server_addr),
            'addresses': awg_addresses,  # {uname: 'a.b.c.d'}
        }
        # Also expose the endpoint to the per-device sing-box composer via
        # `defaults` (the only manifest slice frag_* functions receive) so
        # frag_route can emit the AWG-endpoint bypass rule (hazards.md #23):
        # a running sing-box TUN otherwise captures the Amnezia app's UDP to
        # this host:port and its blanket UDP/443 reject silently kills AWG.
        manifest['defaults']['_awg_endpoint'] = {
            'host': str(awg_block['endpoint_host']),
            'port': int(awg_block['port']),
        }

    # Merge .secrets.yaml into manifest.users
    for uname, user in manifest['users'].items():
        s_user = sfile['users'].get(uname, {})
        # shadowsocks_password restored to per-user list 2026-04-22 after
        # switching to SS-2022 multi-user EIH. shared.shadowsocks_password is
        # still in use — but as the inbound-level server PSK, not the session key.
        # awg_private_key moved to device level 2026-04-27 (per-device AWG
        # identities — see _awg_devices); migration is handled above before
        # merge so the user-level key is gone by the time we get here.
        # `notify_webhook` is carried through only so the deprecation warning
        # above can see a legacy value; it is no longer consumed.
        for field in ('secret', 'ws_cf_uuid', 'hy2_password',
                      'shadowtls_password', 'shadowsocks_password',
                      'installer_webhook_public', 'notify_webhook'):
            if field in s_user:
                user.setdefault(field, s_user[field])
        for dev in user.get('devices', []):
            s_dev = s_user.get('devices', {}).get(dev['name'], {})
            if 'reality' in s_dev:
                dev.setdefault('reality', s_dev['reality'])
            if 'clash_secret' in s_dev:
                dev.setdefault('clash_secret', s_dev['clash_secret'])
            if 'awg_private_key' in s_dev:
                dev.setdefault('awg_private_key', s_dev['awg_private_key'])
            # Operator-supplied (minted in the Tailscale admin console) —
            # never auto-gen'd, same rationale as reality_private_key.
            if 'tailscale_auth_key' in s_dev:
                dev.setdefault('tailscale_auth_key', s_dev['tailscale_auth_key'])

    # Merge exit_wg/<exit>/<user>-<device>.conf (extra WG exits, optional per device)
    for uname, user in manifest['users'].items():
        for ex in user.get('exits', []):
            for dev in user.get('devices', []):
                f = EXIT_WG_DIR / ex['name'] / f'{uname}-{dev["name"]}.conf'
                if f.is_file():
                    conf = _parse_wg_conf(f.read_text())
                    dev_wg, peer = _wg_iface_to_sbx(conf['interface'], conf['peer'])
                    dev.setdefault('exit_wg', {})[ex['name']] = {
                        'device_wg': dev_wg, 'peer': peer}

    # Merge home_wg/*.conf into user + device blocks
    for uname, user in manifest['users'].items():
        if 'home' not in user:
            continue
        user_wg = home_wg.get(uname, {})
        for dev in user.get('devices', []):
            conf = user_wg.get(dev['name'])
            if not conf:
                sys.exit(
                    f'missing home WG config for {uname}/{dev["name"]}.\n'
                    f'Expected file: {HOME_WG_DIR}/{uname}-{dev["name"]}.conf\n'
                    f'Drop a standard WireGuard .conf file (generated on the home router) at that path and re-run.'
                )
            dev_wg, home_peer = _wg_iface_to_sbx(conf['interface'], conf['peer'])
            dev['home_wg'] = dev_wg
            # All peer fields come from the conf — overwrite anything in
            # profiles.yaml's home: block (structural-only by design).
            for k, v in home_peer.items():
                user['home'][k] = v

    return manifest


_ANSI = re.compile(r'\x1b\[[0-9;]*m')

# One container per image checks a whole directory: prints
# "<file>\t<exit code>\t<last output line>" per config.
_CHECK_LOOP = ('for f in /c/*.json; do out=$(sing-box check -c "$f" 2>&1); rc=$?; '
               'printf "%s\\t%s\\t%s\\n" "${f##*/}" "$rc" "$(printf %s "$out" | tail -n 1)"; done')


def _check_batch(image, texts):
    """Run `sing-box check` in `image` on {key: config text}. Returns
    ({key: error} for the configs the image rejects, None) or, when the
    image cannot be run at all (no docker, pull failed), ({}, reason)."""
    with tempfile.TemporaryDirectory() as tmp:
        names = {}
        for i, (key, text) in enumerate(texts.items()):
            names[f'{i}.json'] = key
            (Path(tmp) / f'{i}.json').write_text(text)
        try:
            r = subprocess.run(
                ['docker', 'run', '--rm', '-v', f'{tmp}:/c:ro',
                 '--entrypoint', 'sh', image, '-c', _CHECK_LOOP],
                capture_output=True, text=True)
        except FileNotFoundError:
            return {}, 'docker not found'
    seen, errors = set(), {}
    for line in r.stdout.splitlines():
        parts = line.split('\t', 2)
        if len(parts) == 3 and parts[0] in names:
            seen.add(parts[0])
            if parts[1] != '0':
                # The caller prints the real file name; drop the mount path.
                msg = _ANSI.sub('', parts[2]).replace(f' at /c/{parts[0]}', '').strip()
                errors[names[parts[0]]] = msg or f'exit {parts[1]}'
    if seen != set(names):
        # The loop did not report every file: the container never ran it.
        lines = _ANSI.sub('', (r.stderr or r.stdout).strip()).splitlines()
        named = [l for l in lines if 'rror' in l or 'denied' in l]
        return {}, ((named or lines)[0].strip() if lines else f'docker exit {r.returncode}')
    return errors, None


def check_client_plan(manifest, plan, only_changed=False):
    """
    `sing-box check` every sing-box JSON in a client plan on the cores that
    will have to decode it: the first release of the file's floor
    (core_floor: `core_min`, the per-type default, or the solo floor) and the
    current release. This is what catches a field emitted without its
    emits() gate: the current release accepts it, the floor image answers
    "unknown field", exactly as the device would at its next config fetch.

    Returns (failures, unavailable): failures = [(path, image, error)],
    unavailable = [(image, reason)] for images that could not be run.
    """
    floors = manifest.get('_core_floors', {})
    by_image = {}
    for path, text, action, _ in plan:
        if path not in floors or (only_changed and action == 'unchanged'):
            continue
        for image in (f'{CORE_CHECK_REPO}:v{floors[path]}.0', CORE_CHECK_CURRENT):
            by_image.setdefault(image, {})[path] = text
    failures, unavailable = [], []
    for image, texts in by_image.items():
        errors, reason = _check_batch(image, texts)
        if reason:
            unavailable.append((image, reason))
        failures.extend((path, image, err) for path, err in errors.items())
    return failures, unavailable


def _print_check_result(failures, unavailable):
    for path, image, err in failures:
        print(f'  ✗ {path.name} on {image.rsplit(":", 1)[1]}: {err}')
    for image, reason in unavailable:
        print(f'  ! could not check on {image}: {reason}')


def validate(manifest):
    """
    Render every client file and run `sing-box check` on each, on the cores
    that have to decode it (see check_client_plan). Never touches live files.
    Exits non-zero if any config fails, or if an image could not be run.
    """
    plan = compute_client_plan(manifest)
    floors = manifest['_core_floors']
    failures, unavailable = check_client_plan(manifest, plan)
    failed = {path for path, _, _ in failures}
    # With an image missing, a file that passed the others is not validated.
    mark = '?' if unavailable else '✓'
    for path in floors:
        if path not in failed:
            print(f'  {mark} {path.name} (floor {floors[path]})')
    _print_check_result(failures, unavailable)
    if failures:
        sys.exit(f'\n{len(failed)} of {len(floors)} config(s) failed validation')
    if unavailable:
        sys.exit(f'\nvalidation incomplete: {len(unavailable)} image(s) could not be run')
    print(f'\nall {len(floors)} configs valid')


# ---------------------------------------------------------------------------
# Server sync — regenerate the singbox-server config.json from
# the manifest, with rotation grace (ROTATION_TTL_HOURS) so rotated credentials stay alive
# long enough for clients (hourly poll) to fetch the new config.
# ---------------------------------------------------------------------------

def _strip_jsonc(text):
    """Strip // line comments from JSONC, preserving strings and escapes."""
    out = []
    in_str = False
    esc = False
    i = 0
    while i < len(text):
        c = text[i]
        if esc:
            esc = False; out.append(c); i += 1; continue
        if c == '\\':
            esc = True; out.append(c); i += 1; continue
        if c == '"':
            in_str = not in_str; out.append(c); i += 1; continue
        if not in_str and c == '/' and i + 1 < len(text) and text[i + 1] == '/':
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        out.append(c); i += 1
    return ''.join(out)


def load_server_config():
    """Parse the live server config.json (returns dict)."""
    if not SERVER_CONFIG.exists():
        return None
    return json.loads(_strip_jsonc(SERVER_CONFIG.read_text()))


def manifest_server_view(manifest):
    """
    Build the desired-state view from the manifest — the 5 arrays the server
    config template expects. Order is stable (users appear in manifest order).
    """
    flow = manifest['defaults']['reality']['flow']
    shadowtls, shadowsocks, hy2, reality_users, short_ids, ws_cf = [], [], [], [], [], []

    for uname, user in manifest['users'].items():
        protocols = user.get('protocols', [])
        if 'shadowtls' in protocols and user.get('shadowtls_password'):
            shadowtls.append({'name': uname, 'password': user['shadowtls_password']})
            # Per-user SS-2022 EIH entry on the shared shadowsocks inbound.
            # Parallels shadowtls_users — same set of users, different secret.
            if user.get('shadowsocks_password'):
                shadowsocks.append({'name': uname, 'password': user['shadowsocks_password']})
        if 'hy2' in protocols and user.get('hy2_password'):
            hy2.append({'name': uname, 'password': user['hy2_password']})
        if 'ws-cf' in protocols and user.get('ws_cf_uuid'):
            ws_cf.append({'name': uname, 'uuid': user['ws_cf_uuid']})
        if 'reality' in protocols:
            for dev in user.get('devices', []):
                reality_users.append({
                    'name': f"{uname}-{dev['name']}",
                    'uuid': dev['reality']['uuid'],
                    'flow': flow,
                })
                short_ids.append(dev['reality']['short_id'])

    return {
        'shadowtls_users': shadowtls,
        'shadowsocks_users': shadowsocks,
        'hy2_users': hy2,
        'reality_users': reality_users,
        'reality_short_ids': short_ids,
        'ws_cf_users': ws_cf,
    }


def server_view(server_config):
    """
    Project the current live server config.json into the same shape as
    manifest_server_view — so we can diff them.
    """
    view = {
        'shadowtls_users': [],
        'shadowsocks_users': [],
        'hy2_users': [],
        'reality_users': [],
        'reality_short_ids': [],
        'ws_cf_users': [],
    }
    if not server_config:
        return view
    for ib in server_config.get('inbounds', []):
        tag = ib.get('tag')
        if tag == 'shadowtls-in':
            view['shadowtls_users'] = ib.get('users', [])
        elif tag == 'shadowsocks-in':
            view['shadowsocks_users'] = ib.get('users', [])
        elif tag == 'hy2-in':
            view['hy2_users'] = ib.get('users', [])
        elif tag == 'reality-in':
            view['reality_users'] = ib.get('users', [])
            view['reality_short_ids'] = ib.get('tls', {}).get('reality', {}).get('short_id', [])
        elif tag == 'ws-cf-in':
            view['ws_cf_users'] = ib.get('users', [])
    return view


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def load_pending_rotations():
    """Load the rotation state file. Returns a dict of lists per credential kind."""
    blank = {
        'shadowtls_users': [], 'shadowsocks_users': [], 'hy2_users': [],
        'reality_users': [], 'reality_short_ids': [], 'ws_cf_users': [],
    }
    if not PENDING_ROTATIONS.exists():
        return blank
    data = yaml.safe_load(PENDING_ROTATIONS.read_text()) or {}
    for k in blank:
        data.setdefault(k, [])
    return data


def save_pending_rotations(pending):
    """Write the rotation state file. Omits empty categories for tidiness."""
    trimmed = {k: v for k, v in pending.items() if v}
    if not trimmed:
        if PENDING_ROTATIONS.exists():
            PENDING_ROTATIONS.unlink()
        return
    header = (
        '# Auto-managed by render.py. Tracks credentials that were removed\n'
        '# from profiles.yaml but are kept alive on the server temporarily so\n'
        f'# clients (hourly poll) can fetch and switch. TTL: {ROTATION_TTL_HOURS}h\n'
        '# per entry. After expiry, the next ./render.py --server-apply drops\n'
        '# them from the server config.\n'
        '#\n'
        '# Do not edit by hand; change profiles.yaml and re-run.\n\n'
    )
    PENDING_ROTATIONS.write_text(header + yaml.safe_dump(trimmed, sort_keys=False, allow_unicode=True))


def _item_key(kind, item):
    """
    Stable identity key for deduping entries across manifest vs pending.
    Keying uses *authentication* fields only — not `name`, which is purely
    a cosmetic audit label. Consequences:
      - Renaming a device (e.g. alice-mobile → alice-phone, same UUID) is NOT
        a rotation. The server entry is renamed, no grace period.
      - Changing a UUID/password/short_id IS a rotation. Grace applies.
    """
    if kind == 'reality_short_ids':
        return item  # string
    if kind in ('shadowtls_users', 'shadowsocks_users', 'hy2_users'):
        return ('password', item.get('password'))
    if kind in ('reality_users', 'ws_cf_users'):
        return ('uuid', item.get('uuid'))
    return json.dumps(item, sort_keys=True)


def _expired(entry, now):
    exp = entry.get('expires_at')
    if not exp:
        return False
    try:
        exp_dt = datetime.datetime.fromisoformat(exp.replace('Z', '+00:00'))
    except ValueError:
        return False
    return exp_dt <= now


def compute_rotation_plan(manifest_view, server_view_data, pending):
    """
    Compare desired (manifest) vs live (server) state, accounting for still-
    valid pending-rotation entries. Returns:
        merged_view : what the new server config should contain (desired +
                      unexpired pending)
        new_pending : updated pending state (expired dropped, newly-removed
                      items added with ROTATION_TTL_HOURS TTL, items now back in manifest
                      removed from pending)
        rotation_report : human-readable list of what's happening
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    expire_at = (now + datetime.timedelta(hours=ROTATION_TTL_HOURS))
    expire_iso = expire_at.isoformat(timespec='seconds').replace('+00:00', 'Z')

    report = []  # list of (kind, action, item, note)
    merged = {}
    new_pending = {}

    for kind in manifest_view:
        desired = manifest_view[kind]
        live = server_view_data.get(kind, [])
        pen = pending.get(kind, [])

        desired_keys = {_item_key(kind, x) for x in desired}
        live_keys    = {_item_key(kind, x) for x in live}

        # Expire old pending first. Items whose TTL passed get dropped
        # permanently — we record their keys so the "newly orphaned" scan
        # below doesn't immediately re-grace them (they're still on the live
        # server because we haven't written yet, but we WANT to drop them on
        # this write, not keep them for another full TTL).
        kept_pending = []
        just_expired_keys = set()
        for p in pen:
            key = _item_key(kind, p.get('value', p))
            if _expired(p, now):
                report.append((kind, 'expire', p.get('value', p), f'dropped (was kept since {p.get("added_at")})'))
                just_expired_keys.add(key)
            elif key in desired_keys:
                # Already back in the manifest — no longer needs grace.
                report.append((kind, 'reclaim', p.get('value', p), 'back in manifest'))
            else:
                kept_pending.append(p)

        kept_pending_keys = {_item_key(kind, p.get('value', p)) for p in kept_pending}

        # Items that were live but are neither desired, nor already in pending,
        # nor just-expired: newly rotated-out, move to pending with fresh TTL.
        for item in live:
            key = _item_key(kind, item)
            if key in desired_keys:
                continue  # still wanted
            if key in kept_pending_keys:
                continue  # already tracked
            if key in just_expired_keys:
                continue  # just expired — drop permanently, don't re-grace
            kept_pending.append({
                'value': item,
                'added_at': _now_iso(),
                'expires_at': expire_iso,
            })
            report.append((kind, 'grace-start', item, f'kept until {expire_iso}'))

        # Final merged = desired + still-valid pending (values).
        merged[kind] = list(desired) + [p['value'] for p in kept_pending]

        # Note new additions for the report.
        for item in desired:
            if _item_key(kind, item) not in live_keys:
                report.append((kind, 'add', item, 'new in manifest'))

        new_pending[kind] = kept_pending

    return merged, new_pending, report


def _fmt_json_array_for_template(items, indent=8):
    """
    Render a Python list as a JSON array with indentation matching the
    template's local context. The template places arrays at 6-space indent
    for `"users": [` and 10-space for `"short_id": [`, but when we emit them
    as `"users": [<...>]` with json.dumps we inherit no context. To keep the
    output pretty, we indent children at `indent`, close bracket aligned to
    `indent - 2`.
    """
    if not items:
        return '[]'
    child_ind = ' ' * indent
    close_ind = ' ' * (indent - 2)
    lines = [child_ind + json.dumps(x, ensure_ascii=False) for x in items]
    return '[\n' + ',\n'.join(lines) + '\n' + close_ind + ']'


def _reality_retiring_live(retiring, now=None):
    """True while a retiring key's overlap window is still open."""
    if not retiring:
        return False
    exp = retiring.get('expires_at')
    if not exp:
        return True   # no expiry recorded: keep it until retired explicitly
    now = now or datetime.datetime.now(datetime.timezone.utc)
    exp_dt = datetime.datetime.fromisoformat(str(exp).replace('Z', '+00:00'))
    return now < exp_dt


def _reality_server_parts(merged_view, defaults, host_env):
    """Listen IP of the active Reality inbound + the retiring inbound text.

    Endpoint A listens on INCOMING_IP_1, endpoint B on INCOMING_IP_2
    (read only when B is in use). The retiring inbound mirrors `reality-in`
    (same users and short_ids, so per-device rotations and their grace apply
    to both) but carries the previous private key and sits on the other
    endpoint. It is emitted as a complete array element plus trailing comma,
    or as an empty string once the window has closed. An expired entry is
    simply not rendered: `rotate-realitykey.sh --retire` then deletes it
    from .secrets.yaml.
    """
    d = defaults['reality']
    endpoint = d.get('endpoint', 'a')
    retiring = d.get('retiring')
    live = _reality_retiring_live(retiring)
    need_b = endpoint == 'b' or live
    # INCOMING_IP_1 / INCOMING_IP_2 were VNIC_SECONDARY_IP / REALITY_B_LISTEN_IP until 2026-10-25: renamed for what
    # the two addresses do (both are inbound-only), when the deployment renumbered them.
    ips = {'a': host_env['INCOMING_IP_1']}
    if need_b:
        ips['b'] = _read_env({'INCOMING_IP_2'})['INCOMING_IP_2']
    if not live:
        return ips[endpoint], ''
    other = 'a' if endpoint == 'b' else 'b'
    inbound = {
        'type': 'vless',
        'tag': 'reality-retiring-in',
        'listen': ips[other],
        'listen_port': 443,
        'users': merged_view['reality_users'],
        'tls': {
            'enabled': True,
            'server_name': d['handshake_sni'],
            'reality': {
                'enabled': True,
                'handshake': {'server': d['handshake_sni'], 'server_port': 443},
                'private_key': retiring['private_key'],
                'short_id': merged_view['reality_short_ids'],
            },
        },
    }
    body = json.dumps(inbound, indent=2, ensure_ascii=False)
    body = '\n'.join('    ' + line for line in body.splitlines())
    # The template line already supplies the first line's 4-space indent.
    comment = (f'// Previous Reality key, kept on endpoint {other} until '
               f'{retiring.get("expires_at") or "retired"} (rotate-realitykey.sh).\n')
    return ips[endpoint], comment + body + ','


SERVER_USER_VIEWS = ('shadowtls_users', 'shadowsocks_users', 'hy2_users',
                     'reality_users', 'ws_cf_users')


def _server_user_accounting(merged_view, usernames):
    """Outbounds + route rules that tag each connection with its user.

    Credential names on the server are either the user name itself or
    `<user>-<device>` (Reality). Each one gets an `auth_user` rule to the
    owner's `user:<name>` direct outbound; a name with no known owner (a
    retired user still inside a grace window) is its own owner. `usernames`
    are matched longest first so `ann-marie-pc` goes to `ann-marie`, not `ann`.
    """
    by_len = sorted(usernames, key=len, reverse=True)
    owner = {}
    for view in SERVER_USER_VIEWS:
        for entry in merged_view.get(view, []):
            name = entry['name']
            owner.setdefault(name, next(
                (u for u in by_len if name == u or name.startswith(u + '-')), name))
    outbounds = [{'tag': 'direct', 'type': 'direct'}]
    outbounds += [{'tag': f'user:{u}', 'type': 'direct'}
                  for u in dict.fromkeys(owner.values())]
    rules = [{'auth_user': [name], 'outbound': f'user:{u}'}
             for name, u in owner.items()]
    return outbounds, rules


def render_server_text(merged_view, defaults, usernames=()):
    """Substitute placeholders in the template with generated arrays + scalar
    values from profiles.yaml.defaults (SNIs, obfs password, etc.)."""
    tpl = SERVER_TEMPLATE.read_text()
    # Host-wide VNIC IPs read from process env / repo .env so the sing-box
    # listen addresses stay in sync with the compose-layer VNIC_* vars.
    host_env = _read_env({'INCOMING_IP_1'})
    reality_listen, retiring_inbound = _reality_server_parts(merged_view, defaults, host_env)
    outbounds, user_rules = _server_user_accounting(merged_view, usernames)
    subs = {
        '__OUTBOUNDS__':         _fmt_json_array_for_template(outbounds, indent=4),
        '__USER_ROUTE_RULES__':  _fmt_json_array_for_template(user_rules, indent=6),
        '__INCOMING_IP_1__': host_env['INCOMING_IP_1'],
        '__USERS_SHADOWTLS__':   _fmt_json_array_for_template(merged_view['shadowtls_users'], indent=8),
        '__USERS_SHADOWSOCKS__': _fmt_json_array_for_template(merged_view['shadowsocks_users'], indent=8),
        '__USERS_HY2__':         _fmt_json_array_for_template(merged_view['hy2_users'], indent=8),
        '__USERS_REALITY__':     _fmt_json_array_for_template(merged_view['reality_users'],   indent=8),
        '__SHORT_IDS_REALITY__': _fmt_json_array_for_template(merged_view['reality_short_ids'], indent=12),
        '__USERS_WS_CF__':       _fmt_json_array_for_template(merged_view['ws_cf_users'],    indent=8),
        # Scalar values from defaults (profiles.yaml) — single source of truth
        # for SNIs, obfs password, etc. Changing any of these in profiles.yaml
        # propagates to both client configs and the server on --server-apply.
        '__REALITY_HANDSHAKE_SNI__':    defaults['reality']['handshake_sni'],
        # Reality X25519 private key — paired with defaults.reality.public_key
        # (shared.reality_public_key in .secrets.yaml). rotate-realitykey.sh
        # generates a new pair and writes both halves atomically.
        '__REALITY_PRIVATE_KEY__':      defaults['reality']['private_key'],
        # Endpoint the active Reality inbound listens on, and the optional
        # second inbound that keeps the previous key alive during a rotation.
        '__REALITY_ACTIVE_LISTEN_IP__': reality_listen,
        '__REALITY_RETIRING_INBOUND__': retiring_inbound,
        '__SHADOWTLS_SNI__':            defaults['shadowtls']['sni'],
        '__HY2_SNI__':                  defaults['hy2']['sni'],
        '__HY2_OBFS_PASSWORD__':        defaults['hy2']['obfs_salamander_password'],
        '__SHADOWSOCKS_PASSWORD__':     defaults['shadowtls']['shadowsocks_password'],
        # Server-side clash_api auth secret (auto-gen'd into shared.server_clash_secret).
        '__SERVER_CLASH_SECRET__':      defaults['server_clash_secret'],
    }
    for k, v in subs.items():
        if k not in tpl:
            sys.exit(f'template placeholder {k} missing from {SERVER_TEMPLATE}')
        tpl = tpl.replace(k, v)
    return tpl


def compute_server_plan(manifest):
    """
    Pure planning: compute the new server config, validate with sing-box check,
    compute rotation plan. Returns a dict:
      {
        'available': bool           # template + server_config loadable
        'changed':   bool           # new config differs from live
        'new_text':  str            # rendered config.json
        'report':    list           # rotation actions for display
        'new_pending': dict         # updated pending-rotations state
        'check_ok':  bool
        'check_err': str | None
        'live_text': str            # current config.json as-is
      }
    """
    if not SERVER_TEMPLATE.exists():
        return {'available': False, 'reason': f'template missing: {SERVER_TEMPLATE}'}

    server_cfg = load_server_config()
    if server_cfg is None:
        server_cfg = {'inbounds': []}

    m_view = manifest_server_view(manifest)
    s_view = server_view(server_cfg)
    pending = load_pending_rotations()
    merged, new_pending, report = compute_rotation_plan(m_view, s_view, pending)
    new_text = render_server_text(merged, manifest['defaults'], list(manifest['users']))

    # Validate with sing-box check (mounts hy2 cert paths like safe-restart does).
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tf:
        tf.write(new_text); tmp_path = tf.name
    try:
        r = subprocess.run(
            ['docker', 'run', '--rm',
             '-v', f'{tmp_path}:/etc/sing-box/config.json:ro',
             '-v', f'{SERVER_DIR}/hy2.crt:/etc/sing-box/hy2.crt:ro',
             '-v', f'{SERVER_DIR}/hy2.key:/etc/sing-box/hy2.key:ro',
             'ghcr.io/sagernet/sing-box:latest', 'check', '-c', '/etc/sing-box/config.json'],
            capture_output=True, text=True,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    check_ok = r.returncode == 0
    check_err = None if check_ok else r.stderr.strip()

    live_text = SERVER_CONFIG.read_text() if SERVER_CONFIG.exists() else ''
    changed = (live_text != new_text)

    return {
        'available': True, 'changed': changed,
        'new_text': new_text, 'live_text': live_text,
        'report': report, 'new_pending': new_pending,
        'check_ok': check_ok, 'check_err': check_err,
    }


def print_server_summary(splan):
    print('── Server plan ──────────────────────────────────────────────')
    if not splan.get('available'):
        print(f'  (unavailable: {splan.get("reason")})')
        return
    if not splan['changed'] and not splan['report']:
        print('  (nothing — server config already matches manifest)')
        return
    if not splan['report']:
        print('  (no rotations; diff is cosmetic)')
    else:
        for kind, action, item, note in splan['report']:
            label = kind.replace('_', ' ')
            desc = item if isinstance(item, str) else item.get('name') or json.dumps(item)
            print(f'  [{action:12}] {label:22} {desc}  — {note}')
    if splan['check_ok']:
        print('  ✓ sing-box check passed')
    else:
        print(f'  ✗ sing-box check FAILED: {splan["check_err"]}')


def print_server_diff(splan):
    if not splan.get('available') or not splan['changed']:
        return
    sys.stdout.writelines(difflib.unified_diff(
        splan['live_text'].splitlines(keepends=True),
        splan['new_text'].splitlines(keepends=True),
        fromfile='a/config.json', tofile='b/config.json', n=3,
    ))


def apply_server_plan(splan):
    """Write config.json, save pending-rotations, run safe-restart, roll back on failure."""
    if not splan.get('available'):
        sys.exit(splan.get('reason', 'server plan unavailable'))
    if not splan['check_ok']:
        sys.exit(f'sing-box check failed — aborting, live server untouched: {splan["check_err"]}')

    if SERVER_CONFIG.exists():
        shutil.copy2(SERVER_CONFIG, SERVER_CONFIG.with_suffix('.json.prev'))
        SERVER_CONFIG.with_suffix('.json.prev').chmod(0o600)
    SERVER_CONFIG.write_text(splan['new_text'])
    # Reality private_key + ShadowTLS / SS / hy2 passwords live in cleartext
    # in this file. Default umask gives 0644 on write — clamp to 0600 so a
    # non-root reader on the host can't lift the secrets.
    SERVER_CONFIG.chmod(0o600)
    save_pending_rotations(splan['new_pending'])
    print(f'  wrote {SERVER_CONFIG}')

    if not SERVER_RESTART.exists():
        print(f'  ! {SERVER_RESTART} not found — restart singbox-server manually')
        return
    print(f'  running {SERVER_RESTART}...')
    r = subprocess.run([str(SERVER_RESTART)], capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr)
        prev = SERVER_CONFIG.with_suffix('.json.prev')
        if prev.exists():
            shutil.copy2(prev, SERVER_CONFIG)
            print(f'  rolled back {SERVER_CONFIG}')
        sys.exit(f'safe-restart failed (exit {r.returncode}) — rolled back')
    print('  ✓ singbox-server restarted')


def server_sync(manifest, apply_changes=False, auto_yes=False):
    """Standalone server-only flow for --server-dry-run / --server-apply."""
    print('── Validating new server config...')
    splan = compute_server_plan(manifest)
    print_server_summary(splan)
    print()
    print_server_diff(splan)
    if not splan.get('available') or not splan['check_ok']:
        sys.exit(1)
    if not splan['changed']:
        save_pending_rotations(splan['new_pending'])  # persist expiry tidies
        return
    if not apply_changes:
        print('\n(dry-run — no writes)')
        return
    if not auto_yes:
        if input('\nApply + safe-restart singbox-server? [y/N] ').strip().lower() != 'y':
            print('Aborted.'); return
    apply_server_plan(splan)


def render_combined(manifest, dry_run=False, auto_yes=False):
    """
    Default flow: compute client + server plans, show both summaries, single
    apply prompt. If one side has nothing to do it's silently skipped.
    """
    cplan = compute_client_plan(manifest)
    splan = compute_server_plan(manifest)

    print_client_summary(cplan)
    print()
    print_server_summary(splan)

    has_client = client_plan_has_changes(cplan)
    has_server = splan.get('available') and splan['changed']

    # Changed client files must decode on their floor core and on the current
    # one before anything is written: a device fetches the new file within the
    # hour and a config its core rejects takes it offline. An image that cannot
    # be run (no docker, no network to pull) is a warning, not a refusal, so a
    # credential rotation still goes out; a config an image REJECTS aborts.
    check_failures = []
    if has_client:
        check_failures, unavailable = check_client_plan(manifest, cplan, only_changed=True)
        if check_failures or unavailable:
            print('\n── Client config check ──────────────────────────────────────')
            _print_check_result(check_failures, unavailable)

    if dry_run:
        if has_client:
            print('\n── Client diffs ─────────────────────────────────────────────')
            print_client_diffs(cplan)
        if has_server:
            print('\n── Server diff ──────────────────────────────────────────────')
            print_server_diff(splan)
        return

    if splan.get('available') and not splan['check_ok']:
        sys.exit(1)
    if check_failures:
        sys.exit('client config check failed — aborting, nothing written')

    if not has_client and not has_server:
        # Still persist pending-rotation tidies (expired entries dropped).
        if splan.get('available'):
            save_pending_rotations(splan['new_pending'])
        print('\nNothing to do — everything up to date.')
        return

    if not auto_yes:
        if input('\nShow diffs [y/N]? ').strip().lower() == 'y':
            if has_client:
                print('\n── Client diffs ─────────────────────────────────────────────')
                print_client_diffs(cplan)
            if has_server:
                print('\n── Server diff ──────────────────────────────────────────────')
                print_server_diff(splan)
        scope = []
        if has_client: scope.append('client configs')
        if has_server: scope.append('server config + safe-restart')
        if input(f'\nApply {" + ".join(scope)}? [y/N] ').strip().lower() != 'y':
            print('Aborted.'); return

    if has_client:
        apply_plan(cplan, manifest)
    if has_server:
        apply_server_plan(splan)


def main():
    p = argparse.ArgumentParser(description='singbox-profiles generator — edit profiles.yaml by hand, then run this')
    p.add_argument('--validate', action='store_true', help='sing-box check every client file on its floor core and the current one, plus the server config; no writes')
    p.add_argument('--dry-run', action='store_true', help='show combined client+server plan; no writes')
    p.add_argument('-y', '--yes', action='store_true', help='apply without prompt')
    p.add_argument('--server-dry-run', action='store_true', help='show server-side diff + rotation plan only (no client); no writes')
    p.add_argument('--server-apply', action='store_true', help='apply server-side only + safe-restart singbox-server')
    args = p.parse_args()
    # load_manifest merges profiles.yaml + .secrets.yaml + home_wg/*.conf,
    # detects device renames, and auto-fills any missing credentials (written
    # back to .secrets.yaml). `auto_yes` propagates so rename prompts are
    # skipped under `-y` (unambiguous 1:1 renames auto-apply; ambiguous ones
    # abort rather than silently rotating).
    manifest = load_manifest(auto_yes=args.yes)
    _warn_missing_recommended_protocols(manifest['users'])
    _warn_missing_hy2_next(manifest['users'])
    _warn_unused_utls_fingerprint(manifest['users'])
    _warn_unused_shadowtls_sni(manifest['users'])
    _check_per_user_utls_fingerprint(manifest['users'])
    _check_mobile_shadowtls_sni(manifest['users'], manifest.get('defaults', {}))
    if args.validate:
        validate(manifest)
        # Also validate server config (in-memory), reusing compute_server_plan.
        splan = compute_server_plan(manifest)
        if splan.get('available'):
            status = '✓' if splan['check_ok'] else '✗'
            print(f'  {status} server-config: sing-box check {"passed" if splan["check_ok"] else "FAILED"}')
            if not splan['check_ok']:
                print(f'    {splan["check_err"]}')
                sys.exit(1)
        return
    if args.server_dry_run:
        server_sync(manifest, apply_changes=False)
        return
    if args.server_apply:
        server_sync(manifest, apply_changes=True, auto_yes=args.yes)
        return
    render_combined(manifest, dry_run=args.dry_run, auto_yes=args.yes)


if __name__ == '__main__':
    main()
