# Egressor

**One YAML manifest → a household's whole egress path out of a hostile network.**

[![tests](https://github.com/ericguichard/egressor/actions/workflows/test.yml/badge.svg)](https://github.com/ericguichard/egressor/actions/workflows/test.yml)
[![license: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

## The problem

You want to give a household or small team reliable internet access from
inside (or while travelling to) a country with a national firewall (for
example China, Russia or Iran). The constraints
stack up fast:

- **Commercial VPNs get fingerprinted and blocked** within weeks in these
  networks; the cat-and-mouse is permanent, not a one-time fix.
- **[sing-box](https://github.com/SagerNet/sing-box) is the durable answer**,
  but configuring it correctly for one user across phone + laptop is
  already fiddly. Doing it for five users across three countries — each
  needing different routing, different protocols depending on which
  national firewall they're behind, periodic credential rotation, and
  client configs that stay in agreement with the server — is a part-time
  job nobody signed up for.
- **Per-region routing** matters: a user in the `cn` region wants `bilibili.com`
  direct, not proxied; a user in the `ru` region wants `ru-blocked.srs` proxied and
  the rest direct; a traveller wants their banking traffic to exit from
  their home country, not the VPS.
- **Credential rotation** has to be routine, not a fire drill — but
  rotating without breaking live clients means you need a grace window
  on the server and an auto-update path on the client.

## What Egressor is

Egressor is that part-time job in code — the thing that gets everyone in
the house *out* (the name is literal). You write a YAML manifest
describing your users, their devices, and which of CN / RU / IR they
live in or visit. `./render.py` produces a per-device sing-box config
for each one (Android, iOS, Windows, macOS, Linux), a hardened docker-compose
stack for the server side, and one-liner Windows / Linux installers that
keep everything auto-updated. Onboarding the sixth user is "add a YAML
block, re-run render.py, send them a URL."

The default protocol mix — VLESS+Reality on TCP/443, Hysteria2 on UDP/443,
ShadowTLS+Shadowsocks-2022 on TCP/8443, VLESS-over-WebSocket fronted by
Cloudflare on TCP/443, plus optional AmneziaWG on UDP/51820 — gives
clients five orthogonal paths through DPI. The in-app **selector** picks
the protocol best suited to the user's region as the default; no
auto-switching probe runs in the steady state (the constant probing was
itself a fingerprint), so the user manually flips selectors in the
dashboard if their default breaks. AmneziaWG runs in the separate
[Amnezia VPN](https://amnezia.org/) app on the client side as a parallel
resilience tunnel for RU/IR users — see [`docs/architecture.md`](docs/architecture.md).

Per-user PSKs / UUIDs, per-user uTLS fingerprint randomization, optional
per-user ShadowTLS SNI, optional WireGuard "home egress" so a traveller's
home-country traffic exits from a specific home network, optional
**tailnet relay** (`tailnet: true`) that routes Tailscale's CGNAT range
through the egressor host so clients reach their tailnet peers without
putting Tailscale's own WireGuard/DERP fingerprint on the wire, optional
**SIP hub bypass** (`defaults.sip_hub`) so a softphone keeps two-way audio
when the PBX shares the proxy host: all expressed in YAML you edit by
hand. DNS-level threat-feed and ad blocking via
[Hagezi](https://github.com/hagezi/dns-blocklists) lists is on by
default. **The recommended client is the official sing-box app**
([Android](https://play.google.com/store/apps/details?id=io.nekohasekai.sfa) /
[iOS](https://sing-box.sagernet.org/clients/apple/) (store listings keep
being delisted — the official docs page tracks the current channel) /
[Android sideload](https://github.com/SagerNet/sing-box-for-android/releases)
/ [Windows via NSSM-managed service](docs/quickstart.md) / [Linux via
systemd](docs/quickstart.md), distro package on Arch) — egressor's
generated profile uses official-sing-box-only features (the no-probe
selector design specifically) that Hiddify-Next overrides with its own
auto-switcher.

## Status

Used in production by a small household network. Stable enough to run
unattended; the `singbox-server/` keep-scripts handle restart-on-config-
change, hy2 cert rotation, and image-pin bumps with rollback.

This repo extracts that household stack into something deployable from
scratch. The plumbing (renderer + composer + server template + golden
tests) is the same code; what's stripped is the household-specific data,
notification webhooks, OneDrive mirroring, and the operator-side cron
scripts that don't generalize.

## What's in the box

```
egressor/
├── Taskfile.yml              go-task entrypoint — render, verify, restart,
│                             bump, upstream check, all rotation tiers,
│                             egressor:rotations. See § Operations.
├── singbox-profiles/         renderer half
│   ├── render.py             reads profiles.yaml + .secrets.yaml + home_wg/
│   │                         emits per-device client configs (singbox + AWG),
│   │                         the singbox + awg-server configs, all in one
│   │                         pass; 7-day rotation grace for sing-box
│   │                         protocols
│   ├── profiles.example.yaml three documented user archetypes
│   ├── home_wg/              drop user-device WireGuard .conf files here
│   ├── templates/            singbox-server.template.jsonc + awg-{client,
│   │                         server}.conf.template + Windows + Linux installers
│   ├── tests/                stdlib-only golden-file tests + X25519 unit test
│   ├── generate-installer.sh per-user install-singbox.ps1 (Windows) /
│   │                         install-singbox.sh (Linux, --linux) builder
│   ├── rotate-shortids.sh   monthly Reality short_id rotation
│   └── rotate-realitykey.sh quarterly Reality keypair rotation
├── singbox-server/           server half — sing-box-native protocols
│   ├── compose.yaml          hardened (cap-drop ALL, read-only rootfs,
│   │                         no-new-privileges, mem/cpu limits, digest pin)
│   ├── safe-restart.sh       sing-box check before reconcile; restart on
│   │                         bind-mount inode change
│   ├── rotate-hy2-cert.sh    yearly hy2 self-signed cert rotation
│   └── bump-image.sh         controlled image-digest upgrade
├── awg-server/               server half — AmneziaWG (opt-in profile)
│   ├── compose.yaml          amneziavpn/amneziawg-go pinned by digest;
│   │                         NET_ADMIN unavoidable for userspace WG, balanced
│   │                         by read-only rootfs, narrow port exposure, etc.
│   ├── safe-restart.sh       structural awk validation + bind-mount inode fix
│   ├── rotate-params.sh      quarterly Jc/Jmin/Jmax/S1/S2/H1-H4 rotation
│   └── bump-image.sh         controlled image-digest upgrade
└── singbox-exporter/         optional — Prometheus exporter for sing-box clash_api
    ├── compose.yaml          host-networked, bearer-auth on /metrics,
    │                         scoped to 172.17.0.1:9097 (docker0 bridge only)
    └── exporter.py           Python stdlib only — no extra deps to maintain
```

## Quickstart

See [`docs/quickstart.md`](docs/quickstart.md) for the end-to-end walk-
through (about 30 minutes on a fresh VPS).

The short version, once prerequisites are in place:

```sh
git clone https://github.com/<your-fork>/egressor /opt/egressor
cd /opt/egressor
cp singbox-profiles/profiles.example.yaml singbox-profiles/profiles.yaml
$EDITOR .env                                # PROFILE_HOST, INCOMING_IP_1, PUID, PGID
$EDITOR singbox-profiles/profiles.yaml      # users, countries, protocols
cd singbox-server && openssl req -x509 ...  # see hazards.md #1 for the SAN-required openssl
./singbox-profiles/render.py                # auto-fills credentials, renders both halves
docker compose --profile singbox-server up -d
```

Onboarding a user is `add a YAML block + ./render.py`; users get a
per-device URL (`https://${PROFILE_HOST}/p/<secret>/`) with a generated
README and either a sing-box remote-profile URL (mobile / macOS) or a
one-liner install command (PowerShell on Windows, curl + sudo on Linux).

## Operations

Day-to-day operator tasks are exposed via [go-task](https://taskfile.dev)
in [`Taskfile.yml`](Taskfile.yml). Install:

```sh
sudo snap install task --classic     # Ubuntu/Debian
brew install go-task/tap/go-task     # macOS
```

`task -l` lists everything; the most-used are:

| Task | Purpose |
|---|---|
| `task render` | render.py with diff preview + apply prompt |
| `task render:dry` | dry-run, show what would change |
| `task render:apply` | render + apply (no prompt; cron-safe) |
| `task verify` | run all egressor sanity checks (hy2 cert window, render --validate, golden tests) |
| `task singbox:restart` / `task awg:restart` | safe-restart with config validation + bind-mount inode-safe fallback |
| `task singbox:check` / `task awg:check` | check upstream for a newer release |
| `task singbox:bump` / `task awg:bump` | controlled image-digest bump (validates against live config first) |
| `task egressor:rotations` | last-fire + next-fire date for each rotation tier |

### Rotation tiers

Four credential/parameter rotations on a tiered cadence:

| Tier | Task | Cadence | Continuity |
|---|---|---|---|
| Reality short_id | `task singbox:rotate-shortids` | monthly | **zero-downtime** — server keeps old IDs live for a 7-day grace window via `.pending-rotations.yaml`; clients pick up new IDs on next poll |
| Reality keypair | `task singbox:rotate-realitykey` | quarterly | with a second endpoint (`server_b` + `INCOMING_IP_2`): no flag day, the new key starts on the other endpoint and the previous key stays live for 7 days (`--retire` afterwards). Single endpoint: flag day, clients fail Reality until they apply the new profile |
| Hysteria2 cert | `task singbox:rotate-hy2` | yearly | no flag day — clients pin the current and the next public key; the rotation promotes the pre-generated next pair (`--bootstrap` once to create it, `--fresh` for an emergency flag-day replacement) |
| AWG params | `task awg:rotate-params` | manual | flag day — every device must MANUALLY re-import its `.conf`; the Amnezia VPN app does NOT auto-refresh imported configs |

The flag-day tasks have built-in `prompt:` confirmations so a typo'd
tab-completion doesn't trigger a stack-wide reconnect; bypass with
`task -y <task>` for non-interactive runs. Cron is unaffected (it
invokes the scripts directly, not through `task`).

Set `NOTIFY=/path/to/notify.sh` in the rotation script env (or wire
through a Discord helper like the household one in
[`singbox-server/check-config-drift.sh`](singbox-server/check-config-drift.sh))
to get rich rotation notifications: scheme, cadence, continuity model,
device count, next-fire date.

## Documentation

- [`docs/quickstart.md`](docs/quickstart.md) — fresh-VPS deployment, step-
  by-step. Start here if you want to run it.
- [`docs/architecture.md`](docs/architecture.md) — the renderer's
  composition model, the manifest trio (`profiles.yaml` /
  `.secrets.yaml` / `home_wg/`), 7-day rotation grace, SS-2022 multi-
  user EIH, server template substitution, the `🔗 Tailnet` selector, the
  embedded tsnet endpoint (inbound-only, with an add-a-device procedure),
  and why the relay is still the default for reaching tailnet peers. Read
  before changing `render.py` or adding a protocol.
- [`docs/hazards.md`](docs/hazards.md) — the silent-failure modes we've
  hit in production. Read once even if everything looks fine — most of
  these took more than a weekend to root-cause and the workarounds are
  baked into the renderer.
- [`docs/hardening.md`](docs/hardening.md) — pre-deploy security checklist
  for the host the stack runs on (SSH, cloud firewall, backups, image
  bumps). Read before pointing real users at a public IP.
- [`singbox-profiles/home_wg/README.md`](singbox-profiles/home_wg/README.md)
  — `.conf` format for the optional home-egress feature.

## Tests

The renderer has a stdlib-only golden-file test harness. Three fixture
users exercise every render branch (full traveller with home_wg,
single-country resident, multi-country traveller without home_wg).
Run on every change to `render.py` or the server template:

```sh
cd singbox-profiles
python3 tests/test_render.py            # assert against goldens
python3 tests/test_render.py --update   # regenerate after intentional changes
```

Goldens are committed; CI runs the same harness on every push (Stage 5).

## Configuration via env vars

| Var                  | What                                                  | Default                       |
| -------------------- | ----------------------------------------------------- | ----------------------------- |
| `PROFILE_HOST`       | Public hostname clients fetch profiles from           | `profile.example.com`         |
| `INCOMING_IP_1`  | IP that hy2/Reality bind on (multi-VNIC: matters)     | (required)                    |
| `INCOMING_IP_2` | Second Reality endpoint's local IP (alternating keypair rotation) | (unset: flag-day rotation) |
| `REALITY_B_PUBLIC_IP` | Its public IP, for `server_b: __REALITY_B_PUBLIC_IP__` | (unset)                       |
| `SINGBOX_SERVER_DIR` | Path to the singbox-server dir (compose bind mounts)  | `<repo>/singbox-server`       |
| `PUID` / `PGID`      | UID:GID owning config.json + hy2.{crt,key}            | (required)                    |
| `NOTIFY`             | Optional path to a notification script for cron jobs  | (unset — prints to stderr)    |
| `HY2_SNI`            | Cover hostname baked into the hy2 cert by rotate-hy2  | `cloud.example.com`           |

Set in a repo-level `.env` (gitignored — see `.gitignore`).

## Why these five protocols (DPI signature families)

The protocol mix isn't an arbitrary "more is better" stack — each
protocol covers a *different* DPI signature family. A national firewall
that classifies and blocks one family typically can't apply the same
classifier to the others without breaking unrelated traffic, so the user
manually switches lanes in the dashboard when one shape gets flagged.

| Family                          | Protocol                | What the wire looks like                                                      |
| ------------------------------- | ----------------------- | ----------------------------------------------------------------------------- |
| TLS-mimic-no-tunnel             | VLESS+Reality           | Real TLS handshake stolen from a public site; no SNI faking                   |
| CDN-fronted WebSocket           | VLESS-over-WS via CF    | Browser-fingerprint TLS to Cloudflare's edge, WS upgrade, VLESS inside        |
| Handshake-with-passthrough      | ShadowTLS+SS-2022       | Real TLS handshake to a cover SNI, then encrypted payload over TCP            |
| Obfuscated QUIC                 | Hysteria2 (salamander)  | Random-looking UDP payload, no parseable QUIC Initial                         |
| Obfuscated WG handshake         | **AmneziaWG**           | UDP that looks like nothing — junk packets pre-handshake (Jc/Jmin/Jmax),      |
|                                 |                         | padded init/response (S1/S2), custom magic headers (H1-H4) replacing WG's     |

### How each protocol evades DPI

**VLESS+Reality (TCP/443).** The server completes a real TLS handshake
against a real third-party site (e.g. `cloud.example.com`) — the client's
ClientHello carries a Reality public-key probe in its extensions, and if
it matches, the server takes over and proxies VLESS underneath; if it
doesn't match (random scanner, national-firewall prober), the server transparently
forwards the connection to the real cover site, which completes the
handshake and serves its actual content. So an active prober sees a
genuine, valid TLS session to a legitimate site every time. *Trade-off:*
the chosen cover SNI must be reachable from the VPS and plausible-looking
("a person at this IP browsing this site"). *Known weakness:* the `ru` region firewall's
TCP-freeze / IP-reputation attacks degrade Reality regardless of how
clean the handshake is — once the VPS IP is flagged, packets get
throttled or RST'd at the border. This is why AWG exists in parallel.

**VLESS-over-WebSocket via Cloudflare (TCP/443).** Client dials
Cloudflare's edge, not your VPS. TLS terminates at CF with a uTLS
browser fingerprint, so DPI sees an ordinary browser session to a
Cloudflare-hosted site. CF upgrades to WebSocket and forwards to your
origin; VLESS rides inside the WS. (ECH would additionally hide the
SNI, but sing-box cannot combine ECH with a uTLS fingerprint — the
dial fails outright — and the ECH extension is itself a censor tell;
see `hazards.md` #21.) *Trade-off:* an extra hop's latency, and
you inherit Cloudflare's reachability. *Known weakness:* some national
firewalls have periodically throttled CF's CIDR ranges wholesale (collateral
damage for them, but it has happened, for example in the `ru` region). Also smux on this outbound interacts
badly with CF's WS buffering and is disabled — see `hazards.md` #3.
*Survival role:* this is the only inbound that survives "your VPS IP
is blackholed," because clients aren't dialling your VPS.

**ShadowTLS v3 + Shadowsocks-2022 (TCP/8443).** ShadowTLS performs a
real TLS handshake to a cover SNI (e.g. `cloud.oracle.com`) to grab a
legitimate cert chain on the wire, then bridges the TCP stream to a
Shadowsocks-2022 server underneath. To DPI: a complete TLS handshake
followed by encrypted payload that's indistinguishable from random.
SS-2022's multi-user EIH lets one port serve many users with per-user
PSKs. *Trade-off vs Reality:* the cover handshake is just to grab a
cert; there's no "if probe fails, transparently proxy to the real
site." So an active prober who connects without the right PSK gets
junk back, which is itself a fingerprint. Mitigated with per-user SNI
pinning. *Known weakness:* mobile sing-box clients break ShadowTLS
after one probe when the SNI comes from a pool, so every mobile user
needs a pinned `shadowtls_sni` override (`hazards.md` #2). The override
is keyed on the user, not the device: it also takes that user's desktops
off the pool.

**Hysteria2 with salamander obfuscation (UDP/443).** Hy2 is QUIC-based,
but the salamander obfuscator XORs every UDP datagram with a shared
key. Result: no parseable QUIC Initial frame, no version field, no
SNI on the wire — just random-looking UDP to a foreign IP. To
protocol-aware DPI it's "high-throughput unidentified UDP," which
no signature classifier flags. *Trade-off:* "unidentified UDP to a
foreign IP" is itself a coarse signal censors can act on at the
IP/transport layer rather than the protocol layer. *Known weakness:*
the RU and IR national firewalls have demonstrated blanket UDP throttling — when
they do that, hy2 dies even though no classifier touched it. Also
sing-box has no per-user bandwidth caps for hy2 (`hazards.md` #7).
*When it works:* it screams — BBR-style congestion control, no HoL
blocking, the fastest lane in the mix.

**AmneziaWG (UDP/51820, separate Amnezia VPN app).** Vanilla
WireGuard's handshake is short, distinctive, and trivially
fingerprinted (well-known magic bytes, fixed packet sizes, no padding).
AWG modifies it: junk packets before the handshake (`Jc`/`Jmin`/
`Jmax`), padded init/response (`S1`/`S2`), and custom magic headers
(`H1`–`H4`) replacing WG's. The result is UDP that doesn't match any
known protocol fingerprint. *Trade-off:* official sing-box doesn't
speak AWG (the only AWG-capable fork is CLI-only, and the iOS App
Store rejects it), so AWG runs in the separate Amnezia VPN app, not
in the in-app selector. Two apps to install, not one. *Known
weakness:* same blanket-UDP-throttling risk as hy2 — both die together
under IP-level UDP marking. *When to enable it:* RU users where the national firewall
has degraded Reality, IR users where the national firewall pressures
TLS-shaped traffic. Off by default for CN (that firewall handles
protocol-aware classifiers but doesn't broadly mark UDP).

**Shared UDP-class risk worth flagging:** AmneziaWG and Hysteria2 both
die under blanket UDP marking. The protocol-specific classifiers that
censors actually deploy are uncorrelated, but the IP-level UDP throttling
some national firewalls (for example in RU and IR) have demonstrated isn't — when both UDP
protocols go dark together, fall back to one of the three TCP shapes.

AmneziaWG's role is specifically the threat model RU users actually face:
the national firewall's TCP-freeze attack on suspicious foreign IPs has degraded Reality
through late 2025; CF CIDR whitelisting has degraded VLESS-over-WS in
parallel. AWG is the protocol actually being deployed in that region — Amnezia's
Banzaev confirms the operates-stably-with-periodic-signature-blocks
model in the Jan 2026 TechRadar interview. AWG runs in a *separate*
[Amnezia VPN](https://amnezia.org/) app rather than the sing-box profile;
the two-app split is documented in [architecture.md](docs/architecture.md).

Adding a sixth protocol that falls into one of these families (e.g.
TUIC v5 — also obfuscated QUIC, same family as hy2) doesn't add real
resilience — a classifier that flags one will flag the other. We've
deliberately *not* added several otherwise-popular protocols on this
basis. As of early 2026 the only candidate in upstream-stable sing-box
that opens a genuinely new family is **AnyTLS** (real TLS session +
random padding + N:1 multiplex, available since sing-box v1.12.0), but
field reports flag fingerprintable structural quirks; it's a watchlist
item, not a default. Re-evaluate ~every 6 months.

## Threat model + design assumptions

**In scope:**

- DPI on the path between clients and the proxy server (for example
  the national firewalls in the CN, RU and IR regions) — addressed via four protocol shapes with
  different DPI signatures, per-user fingerprint decorrelation, and
  Cloudflare-fronted fallback.
- Server-side passive cred capture — every credential is per-user,
  per-device where the protocol allows; rotation is routine.
- Client-side stale config — auto-update + 7-day server-side rotation grace
  means you can rotate creds without coordinating with users.

**Out of scope:**

- Active DPI that physically blocks the destination IP. ws-cf through
  Cloudflare is the only inbound that survives "the proxy IP is
  blackholed" — keep your Cloudflare zone working and make sure
  `defaults['ws-cf'].host` is reachable.
- Endpoint compromise. If a user's device is rooted or has malware, none
  of this protects them.
- Anonymity. This routes traffic through your VPS — the VPS sees every
  destination. Use Tor over Egressor if you also want anonymity.
- Per-user bandwidth caps at the sing-box layer
  ([hazards.md #7](docs/hazards.md#7-sing-box-has-no-per-user-hy2-bandwidth-caps)).

## Contributing

Bug reports especially welcome — if you hit a silent-failure mode that
isn't in [hazards.md](docs/hazards.md), file an issue with the symptom,
the smallest reproducible config (with credentials redacted), and the
relevant log lines from `docker logs singbox-server`. The hazards doc is
the single biggest piece of operational knowledge in this repo; growing
it is more valuable than most code changes.

For code changes:

1. Run `python3 singbox-profiles/tests/test_render.py` first.
2. If the change intentionally affects rendered output, regenerate
   goldens with `--update` and include the diff in the PR.
3. Anything user-visible should be reflected in the per-user README
   that `render.py` generates.

## Formerly Clearway

This project was named **Clearway** until 2026-08-27.

Served profile filenames changed from `clearway-<user>-<type>…` to
`egressor-<user>-<type>…` at the same time. If you run a pre-rename
deploy, set `EMIT_CLEARWAY_ALIASES = True` in `render.py` before your
first render: it writes byte-identical `clearway-*` copies so
already-imported subscription URLs keep working until every device is
re-imported. The `CLEARWAY_*` environment variables are still honoured
as fallbacks.

The older shim for the pre-2026-07-26 names (`singbox-<device>.json`,
`singbox-<device>-<proto>.json`, `awg-<device>.conf`; `EMIT_LEGACY_ALIASES`
in `render.py`) was switched off on 2026-09-14. The constant is still there
for a one-line rollback, but a render with a shim off sweeps that
generation's copies out of `srv/`, so flip it back on before the render
that would prune them, not after.

## License

[AGPL-3.0](LICENSE). Derivatives must remain open. If you deploy a
modified version as a service, the modified source must be available
to the service's users.

## Acknowledgments

Stands on the shoulders of:

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — the protocol
  multiplexer this all runs on.
- [WireGuard](https://www.wireguard.com/) (Jason A. Donenfeld) — the base
  tunnel protocol AmneziaWG extends.
- [Amnezia VPN](https://amnezia.org/) (the [amnezia-vpn](https://github.com/amnezia-vpn)
  org) — three components egressor depends on directly:
  [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) (the userspace
  daemon awg-server runs),
  [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) (the
  `awg` CLI used to load the obfuscation parameters), and the
  [Amnezia VPN client apps](https://github.com/amnezia-vpn/amnezia-client)
  on Android / iOS / desktop that import the per-user `.conf` files. The
  protocol design — junk packets pre-handshake (Jc/Jmin/Jmax), padded
  init/response (S1/S2), custom magic headers (H1-H4) — is what makes
  AmneziaWG usable in CN/RU/IR where vanilla WireGuard is fingerprinted
  and blocked.
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) —
  the CN geosite/geoip rule-sets and the blocked-sites geosite list used for split
  routing in the CN profile.
- [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) —
  the RU geosite/geoip rule-sets, including the `ru-blocked` and
  `ru-available-only-inside` subsets that drive the 🚨 Restricted route
  for users in the RU region.
- [chocolate4u/Iran-sing-box-rules](https://github.com/chocolate4u/Iran-sing-box-rules) —
  the IR geosite/geoip rule-sets plus the malware/phishing/ads lists
  layered into the default DNS reject rule when IR is enabled.
- [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip) — the
  per-country geoip rule-sets the renderer pulls in for the optional
  home-egress feature (one `geoip-<iso>.srs` per `home_egress_countries`
  entry).
- [Hagezi](https://github.com/hagezi/dns-blocklists) — the DNS
  threat-intelligence (TIF) and pro-adblock lists wired into the default
  DNS reject rule, served as sing-box rule-sets via
  [razaxq/dns-blocklists-sing-box](https://github.com/razaxq/dns-blocklists-sing-box).
- [MetaCubeX/metacubexd](https://github.com/MetaCubeX/metacubexd) — the
  clash-api dashboard the Windows and Linux installers wire up.
- [NSSM](https://nssm.cc/), [WireGuard / wintun](https://www.wintun.net/) —
  the Windows install path. On Linux the installer uses the distro's
  sing-box package where one exists (Arch `extra/sing-box`) and upstream's
  own systemd unit; no third-party service wrapper is needed.
