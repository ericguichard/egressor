# Architecture

How the pieces fit together. Read this before changing the renderer or
adding a new protocol — most of the design choices are load-bearing in
non-obvious ways.

## The two halves

```
        ┌────────────────────────────────────┐
        │  singbox-profiles/                 │
        │  ─────────────────                 │
        │  profiles.yaml      (manifest)     │
        │  .secrets.yaml      (credentials)  │
        │  home_wg/*.conf     (WG identities)│
        │  render.py          (the renderer) │
        │  templates/         (PS1+SH+JSONC) │
        └─────────────┬──────────────────────┘
                      │  ./render.py
                      ▼
        ┌────────────────────────────────────┐
        │  Two independent outputs           │
        ├────────────────────────────────────┤
        │  1. Per-device client configs      │
        │     srv/p/<secret>/                │
        │       egressor-<u>-mobile.json     │
        │       egressor-<u>-windows.json    │
        │       egressor-<u>-linux.json      │
        │       install-singbox.{ps1,sh}     │
        │       README.md                    │
        │     ↓ served over HTTPS at         │
        │     https://<PROFILE_HOST>/p/...   │
        │                                    │
        │  2. singbox-server config          │
        │     ../singbox-server/config.json  │
        │     ↓ docker compose up -d         │
        │     sing-box server container      │
        └────────────────────────────────────┘
```

A single `./render.py` invocation produces both halves. They share the same
manifest (one source of truth — every credential, every user, every device
state) so the server's `users[]` arrays and the clients' outbound configs
can never drift out of sync.

The two halves are also physically independent: the renderer runs on
whichever machine you maintain config from (the docker host is a natural
choice, but it doesn't have to be); the server runs wherever your VPS is.
You can run the renderer on a laptop, push the rendered config to the VPS,
and never run Python on the VPS itself if you don't want to.

## The manifest trio

The renderer reads three files. Each owns a different category of state.

### `profiles.yaml` — the desired state, written by hand

Only contains things a human edits: user list, per-user country/protocol
choices, device list, home-egress preferences. No secrets, no derived
state. Schema-validated at load time (`PROFILES_SCHEMA` in `render.py`)
with JSONPath-precise error messages — typos fail loudly with a precise
location instead of cascading into a cryptic `sing-box check` error after
full render.

What lives here:

- `defaults.{reality, ws-cf, shadowtls, hy2}` — server endpoints,
  ports, SNIs, the default uTLS fingerprint, optional `proxy_server_ips`
  for multi-host deployments.
- `defaults.sip_hub` (optional): the SIP PBX host(s) and port ranges that
  must bypass the tunnel when the PBX shares the proxy host, plus the
  Android package ids of the softphone. See
  [hazard #25](hazards.md#25-softphone-on-a-tunnel-that-ends-on-the-pbx-host-gets-one-way-or-no-audio).
- `users.<name>.countries / protocols / devices` — what each user gets.
- `users.<name>.home` — optional WG-tunnelled home-egress block.
- `users.<name>.shadowtls_sni`: optional SNI override, keyed on the user
  and therefore applied to every device that user owns (see
  [hazard #2](hazards.md)).

What doesn't:

- Any UUID, password, key, or secret. The renderer auto-generates and
  stores them in `.secrets.yaml`.

### `.secrets.yaml` — the credentials, auto-managed

On every render, the renderer fills in any missing credentials and writes
them back. Mode is clamped to 0600 on every write. The "auto-fill missing"
loop is what makes onboarding a new user trivial — add `users.alice` to
`profiles.yaml`, run `./render.py`, and `.secrets.yaml` gets a freshly-generated
`secret`, `ws_cf_uuid`, `hy2_password`, `shadowtls_password`,
`shadowsocks_password`, and per-device `reality.{uuid, short_id}` and
`clash_secret`.

Per-user fields (`secret`, `ws_cf_uuid`, `hy2_password`,
`shadowtls_password`, `shadowsocks_password`) are auto-generated.
Per-device fields (`reality.uuid`, `reality.short_id`, `clash_secret`)
are auto-generated. The optional per-user `installer_webhook_public` is
**operator-supplied, never auto-generated — and PUBLIC by construction**:
it is baked verbatim into the generated `install-singbox.ps1`, which is
served behind the same path-secret as the profile, so anyone holding a
profile link can read it. Use a dedicated throwaway webhook on a
low-value channel, never an ops one. (Renamed from `notify_webhook`
2026-08-06 because that name carried no hint of the exposure; the legacy
key is now ignored with a render-time warning rather than silently
reused.) **Reality keypair** (`shared.reality_*`)
and **hy2 obfs password** (`shared.hy2_obfs_salamander_password`) are
NOT auto-generated — they require a paired server-side change (Reality
keypair) or shared-symmetric-secret coordination, so rotating them is a
deliberate operator action. Use `rotate-realitykey.sh` rather than editing
by hand.

### `home_wg/<user>-<device>.conf` — externally-generated WireGuard identities

Standard `wg-quick(8)` `.conf` files for any device that has a `home:` block
in `profiles.yaml`. The interface section becomes the device's `home_wg`
block in the rendered config; the peer section overwrites the user-level
`home` peer fields (endpoint, public key, AllowedIPs, etc.). `profiles.yaml`'s
`home:` block is structural-only (country / TLD lists); the peer details
always come from the `.conf`.

If a user has `home:` but the `.conf` is missing, render aborts with the
exact path it expected. Drop it in and re-run.

See `singbox-profiles/home_wg/README.md` for the file naming convention
and an example.

## Renderer composition — the dict-merge model

The renderer doesn't template strings. Each fragment is a function that
returns a Python `dict` describing a piece of the final sing-box JSON; the
composer merges them into a single dict and `json.dumps` serializes the
result. Comments live in fragment-function source for humans reading the
code; rendered JSON is pure JSON (no comments, no JSONC).

The fragment list, in `compose()` order:

```python
def compose(user, device, defaults):
    cfg = {}
    cfg.update(frag_log())                         # log.level / timestamp
    cfg.update(frag_ntp(device))                   # mobile-only NTP
    cfg.update(frag_dns(...))                      # DNS servers + rules
    if has_home and device.get('home_wg'):
        cfg.update(frag_home_endpoint(...))        # 🏢 Home WG endpoint
    cfg.update(frag_inbound(device))               # TUN inbound
    cfg.update(frag_outbounds(user, device, ...))  # Direct + per-protocol
                                                   # outbounds + selectors
    cfg.update(frag_route(user, device, defaults)) # rule_set + rules
    cfg.update(frag_experimental(device))          # cache_file + clash_api
    return cfg
```

Each fragment has a single, narrow responsibility and reads only from the
manifest dict it receives. There's no module-level state mutation between
fragments, which makes them trivially testable in isolation (see
`tests/test_render.py`).

Adding a new protocol means adding `frag_outbound_<name>` (returns the
outbound dict), wiring it into `frag_outbounds` (canonical-order append),
and extending `protocol_outbound_tags()`. Roughly 30 lines for a Reality
or hy2-style outbound; more if it has its own server template.

## The server template

`singbox-profiles/templates/singbox-server.template.jsonc` is a JSONC
file (JSON with `// line comments`) shaped like the final
`singbox-server/config.json`. The renderer:

1. Reads the template.
2. Strips JSONC comments (`_strip_jsonc`).
3. Substitutes `__PLACEHOLDER__` tokens — `__INCOMING_IP_1__`,
   `__USERS_SHADOWTLS__`, `__SHORT_IDS_REALITY__`,
   `__REALITY_PRIVATE_KEY__`, etc. — with values from the manifest.
4. Writes the result to `<server-dir>/config.json` (mode 0600).
5. Triggers `safe-restart.sh` on the server.

Why a template instead of building the dict like clients do: the server
config is mostly static — five inbound definitions plus a clash_api block.
Only the user arrays and a few SNI/key strings change per render. A
template + token substitution is shorter, more legible, and easier to
hand-audit than the equivalent dict-builder Python.

The substitution is strict: any `__PLACEHOLDER__` token in the template
that the renderer doesn't supply causes a `sys.exit(...)` at render time,
so a typo in the template fails fast.

## Rotation and the grace window (7 days)

Removing a user's credentials from `.secrets.yaml` and re-rendering must
not break a client that hasn't polled the new config yet. The pattern:

1. Operator removes user / rotates a credential.
2. `./render.py` computes the new server config, but before writing it,
   diffs against the live server config to find credentials that *were*
   live but are no longer in the manifest.
3. Each newly-orphaned credential gets added to `.pending-rotations.yaml`
   with an `expires_at` `ROTATION_TTL_HOURS` in the future (default 168 = 7 days,
   overridable by environment for a deliberate fast retirement).
4. The rendered server config = manifest credentials + still-valid pending
   credentials. So the orphaned creds stay live on the server for the grace window.
5. On the next render after expiry, `compute_rotation_plan` drops the
   expired entries permanently.

Identity for "is this the same credential" is the *authentication* field,
not `name`. Renaming `alice-mobile` → `alice-phone` keeps the same UUID
and is recognized as a rename (no rotation, no grace). Changing the UUID
*is* a rotation (grace applies). The `_item_key()` function in `render.py`
encodes this.

This means routine cred rotation (`rotate-shortids.sh`) is a flag-day-free
operation: any client that applies a fresh profile within the grace window
picks up the new short_id while the old one is still valid; any client that
polls *after* the rotation gets the new short_id from the start.

Why 7 days and not the original 2h: polling is not applying. The Windows and
Linux updaters restart the service when the config changes, so they switch
within one poll. Mobile apps (SFA/SFI 1.14 with `auto_update_interval: 60min`)
fetch hourly but apply a downloaded profile only when the tunnel reconnects,
which can be days later. With a 2h window such a phone still ran the old
credential after it expired and lost the tunnel; it then tried to fetch the
fix through the dead tunnel. 7 days covers ordinary reconnect cadence.

Trade-off: a removed user's credentials also stay live for the window. To
retire a user quickly, set a short TTL on the render that REMOVES them (the
expiry is stamped when the entry is added), then run the follow-up
`./render.py --server-apply -y` once it has passed:
`ROTATION_TTL_HOURS=2 ./render.py -y`.

What this *doesn't* cover:

- **Reality keypair rotation**: a Reality inbound holds a single private
  key, so the per-credential grace above cannot apply. With one endpoint,
  `rotate-realitykey.sh` is a flag day: clients that have not applied the
  new profile fail Reality, and a user whose 🔀 Proxy is set to reality has
  to switch protocol or re-apply the profile (see *Selector default and
  manual fallback* below). With a second endpoint (`defaults.reality.server_b`
  plus `INCOMING_IP_2`), rotation alternates instead: the new key
  starts on the other endpoint as `reality-in`, clients are re-rendered to
  dial it, and the previous key keeps running on the old endpoint as
  `reality-retiring-in` until `shared.reality_retiring_expires_at`
  (`REALITY_OVERLAP_DAYS`, default 7). A client still on the previous
  profile keeps working until it applies the new one, which is what mobile
  apps need: they apply a fetched profile only when the tunnel reconnects.
  `rotate-realitykey.sh --retire` removes the previous key after the
  window; the next rotation moves back the other way. Only Reality
  alternates; ShadowTLS and hy2 stay on `server`.
- **hy2 cert rotation** — no flag day. Clients pin the cert's public key
  by hash (`tls.certificate_public_key_sha256`, sing-box 1.13+), and the
  field is a list: every config carries the key the server presents now
  and the one the next rotation will present (`hy2-next.crt`, generated
  one cycle ahead). `rotate-hy2-cert.sh` promotes that pair, restarts the
  server, checks a handshake against the promoted key before any client
  file changes (rolling back if it fails), then generates the following
  next pair. Only a client that fetched nothing for a whole cycle loses
  hy2 until it does. `--bootstrap` creates the first next pair; `--fresh`
  replaces both keys at once after a suspected leak, which is a flag day.

## Selector default and manual fallback

The 🔀 Proxy selector emits `type: selector` (not `urltest`) with a
country-derived default. There is no automatic on-error switch between
protocols; the user manually flips in the dashboard if their default
breaks. This is a deliberate change from the pre-AWG design (which used
`urltest` to auto-pick the fastest protocol every few minutes).

### Why no automatic fallback

The pre-AWG renderer emitted a `⚡ Fastest` urltest outbound that probed
every enabled protocol on a 5-10 minute cadence. That probing pattern is
itself a fingerprint — regular small requests to multiple foreign IPs at
fixed intervals, observable behaviorally even when individual protocols
pass DPI. Removing it tightens the threat model materially.

Two on-error fallback approaches were considered as replacements:

1. **Route rules matching outbound errors and re-routing**. sing-box's
   route-rule schema (evaluated on 1.13.x) doesn't include an "outbound returned an error"
   matcher; this isn't expressible in vanilla sing-box.
2. **A thin watcher (sidecar) updating the selector default via the
   clash_api**. Adds a runtime component that has to be deployed on every
   client device — not viable for the iOS app, doesn't fit the renderer-
   only deployment model.

Neither produces a zero-runtime-component solution that sing-box (1.13.x
at the time of the evaluation) supports natively. We chose pure selector + documented manual fallback:
the 🔀 Proxy selector lists every enabled protocol; the user taps to
switch when the default fails. Per-user README spells out the procedure.

### Country defaults

Single-country residents get the protocol most likely to survive in their
region as the selector default:

| Country | Default | Why |
|---|---|---|
| `cn` | `reality` | Fastest when the proxy IP isn't IP-blocked; ws-cf is the survival fallback. |
| `ru` | `shadowtls` | Most resilient to the national firewall's TCP-freeze attack on suspicious foreign IPs. |
| `ir` | `shadowtls` | The most consistently surviving sing-box-native path post-2025 IR shutdown. |
| traveller / multi-country | `hy2` | Speed-first default when no specific region is targeted. |

Each country's `data/countries/<iso>.yaml` carries a `protocols.default`
field; `proxy_selector_default()` in render.py reads it. Override per-user
with `users.<name>.preferred_protocol: <tag>` in `profiles.yaml`.

### The `🔗 Tailnet` selector

Users carrying `tailnet: true` get a route rule sending Tailscale's CGNAT
range `100.64.0.0/10` to a `🔗 Tailnet` selector. Members, in order:

- **`🧵 Tailscale`** — present only on devices that also carry
  `tailscale: true`: the device's *own* embedded tailnet node (next
  section). Inbound reach and node presence only — never the default.
- **`🔀 Proxy`** — relay the range through the egressor host. The host is
  already a tailnet node, and the proxy server is a userspace proxy that
  `dial()`s each destination from the host; when that destination is a
  tailnet IP the kernel routes the socket out `tailscale0` sourced as the
  host's own tailnet address. So the host needs **zero** extra config: no
  `ip_forward`, no MASQUERADE, no route advertisement.
- **`➡️ Direct`** — hand the range to the device's *own* native Tailscale
  client.

Per-device default: **mobile → `🔀 Proxy`**, **desktop → `➡️ Direct`** — the
embedded endpoint is deliberately never the default (why below). The
rule must be emitted *before* the `ip_is_private` rule (which can otherwise
swallow the CGNAT range) and, for `admin` users, before the `port: 22` rule.

**On mobile, `🔀 Proxy` is the only member that reaches peers.** Android and
iOS allow one VPN slot; sing-box holds it, so the native Tailscale app cannot
run and `➡️ Direct` has nothing to hand off to. See
[hazards.md](hazards.md) entries 14 and 19. Without the embedded endpoint the
consequences on mobile are: reach is **outbound-only** (the host dials peers
as itself, so peers cannot initiate back), and the device reports `offline`
in `tailscale status` — expected, since it is a relay client rather than a
tailnet node. Enabling the embedded endpoint fixes exactly and only that:
the device becomes a registered, inbound-reachable node while its peer-bound
traffic keeps riding the relay.

#### The embedded `🧵 Tailscale` endpoint (`tailscale: true`)

sing-box 1.12+ can embed Tailscale (tsnet) as an `endpoints` entry, making
sing-box *itself* a tailnet node — crucial on Android, where nothing else
can hold a second VPN slot. Devices with `tailscale: true` (gated on the
user's `tailnet: true`) get one, with hostname `<user>-<type>`: a hardware
swap under the same user+type keeps the tailnet hostname, matching the
served-filename identity scheme.

**Scope doctrine: inbound + node presence ONLY.** Outbound-to-peers through
the endpoint is broken upstream
([#3755](https://github.com/SagerNet/sing-box/issues/3755), closed
unresolved; confirmed live — every peer-bound TCP connect is refused while
inbound works). So `🧵 Tailscale` is a selector *member* for completeness,
but the defaults stay relay (mobile) / native client (desktop), and the only
rules referencing the endpoint are inbound:

- tailnet → `tcp/22` is overridden to the device's local sshd
  (`127.0.0.1:8022` on mobile — Termux — and `:22` on desktop);
- **all other tailnet-inbound traffic is rejected.** The node is an ssh
  jump target, not a general exit.

Two hard-won operational facts:

1. **The endpoint's own control/DERP dials MUST be detoured.** Left raw,
   they are unprotected from the VpnService TUN on Android: they loop back
   into sing-box and the loop kills **all device egress** (empirically,
   2026-08-15 — browser, terminal, everything; the same mechanism shows up
   as registration flakiness on Windows). The renderer therefore always
   sets `detour` on the endpoint — `➡️ Direct` by default. Dial fields on a
   Tailscale endpoint affect only its own control-plane connections, never
   peer traffic.
2. **`tailscale_detour: proxy` (per-device) is the break-glass variant:**
   control/DERP rides the outbound `🔀 Proxy` defaults to for that user (a
   concrete outbound, not the selector, which sing-box 1.14 refuses as an
   endpoint detour), so the node stays registered and
   inbound-reachable on networks that block Tailscale outright — where a
   native client and a direct-detoured endpoint both die — for as long as
   the tunnel is up. It also registers much faster on hostile networks
   (~40 s observed, vs ~10 min on a flaky direct path).

Timing: after a profile switch or restart, allow the node **up to ~10
minutes** to re-register on the direct path before diagnosing anything.

#### Adding a tsnet device

1. Mint an auth key at
   `https://login.tailscale.com/admin/settings/keys` — **single-use, NOT
   ephemeral** (the node must survive being offline).
2. Add it in `.secrets.yaml` under the device as `tailscale_auth_key`.
3. In `profiles.yaml`, set `tailscale: true` on the device (the user must
   already carry `tailnet: true`); add `tailscale_detour: proxy` if this
   node needs the break-glass inbound path.
4. Render and deploy; have the client pull or re-import its profile.
5. Wait for enrollment (timing above). The key is consumed at first
   enrollment; node identity then persists in the endpoint's
   `state_directory`, so later re-renders and re-imports need no new key.
6. Optionally rename the node in the admin console — names are cosmetic;
   automation should target the tailnet IP.
7. Verify both directions: ssh to the node's tailnet IP (inbound), and
   confirm ordinary device egress still works (the failure mode of
   operational fact 1).

#### Why the relay is still the default

This section originally rejected the embedded endpoint outright. Its
reasons have aged — one empirically, one into a requirement — so here is
the current form of the argument:

1. **The fingerprint argument stands, but only for the data plane.** tsnet
   peer traffic speaks plain WireGuard/DERP and *cannot* be wrapped — dial
   fields cover only the endpoint's own connections — so reaching *other*
   peers covertly still means the relay. The control plane, by contrast,
   detours cleanly: the old claim that `detour` on the endpoint panics at
   startup ([#2588](https://github.com/SagerNet/sing-box/issues/2588)) no
   longer holds on 1.13.x or 1.14.x, where the detour is now load-bearing
   (with one 1.14 rule: the detour must name a concrete outbound, since
   1.14 refuses a selector there at runtime and `sing-box check` does not
   catch it).
2. **Inbound reach to mobile devices became a requirement** — the exact
   revisit condition this section used to name — and the endpoint ships in
   precisely that narrow role: inbound + presence, nothing else. Mobile
   immaturity is handled by scoping around it: the known peer-reach bug
   ([#3755](https://github.com/SagerNet/sing-box/issues/3755)) is outside
   the endpoint's job description.
3. **The auth key rides the rendered profile** (served over the secret
   URL) — a class of secret the manifest does not otherwise carry.
   Accepted: the key is single-use and consumed at first enrollment, so
   the exposure window closes as soon as the node registers.

### AWG as a parallel resilience tunnel

AWG never shows up as a sing-box selector option — it's served by a
separate Amnezia VPN app on the user's device. When all four sing-box-
native protocols fail (e.g. a coordinated TCP-freeze + UDP/443 throttle),
the user starts the AWG tunnel from the Amnezia app as the second-leg
fallback. The two-app split is documented in the per-user README and
[hazards.md](hazards.md#amnezia-vpn-app-on-ios-conflicts-with-active-sing-box-vpn-profile).
On desktops (Windows/macOS/Linux) the two are operated as **mutually exclusive**,
like Android/iOS enforce by design: stop sing-box before connecting Amnezia,
quit Amnezia before starting sing-box. The sing-box profile still carries a
bypass for the AWG endpoint (route rule + TUN `route_exclude_address`) so a
stray overlap does not silently starve the Amnezia tunnel, but the overlap
itself crash-loops sing-box on Windows — see hazards.md #23.

### Per-protocol single-outbound profiles (alternate-client fallback)

The renderer emits, alongside the unified `egressor-<user>-<type>.json`, a
stripped `egressor-<user>-<type>-<proto>.json` for every protocol the user
has — but only
for mobile devices with ≥2 protocols. Each per-protocol file contains
exactly one proxy outbound; the 🔀 Proxy selector still exists but lists
only that one protocol.

**Why.** [Hazard #15](hazards.md#15-user-imports-profile-into-hiddify-next-instead-of-official-sing-box)
specifically identifies Hiddify-Next as a client that wraps imported
profiles in its own urltest "Auto" group, defeating the manual-selector
design. The risk generalises: any iOS client that does the same wrap-on-
import — current or future — breaks the design the same way. The
discriminating question for any candidate client ("does it wrap user-
imported selectors in its own urltest?") can change per release and
isn't testable from the renderer side.

The per-protocol file defangs the wrapper concern *generically*: with
exactly one outbound, there is nothing for an auto-switcher to switch
between. The wrapper layer becomes a no-op regardless of what the host
client does internally. The user manually switches *profiles* in their
client (instead of switching protocols inside the unified profile's
selector) to flip protocol — same conceptual load, different surface.

**When this matters.** Users on a Mainland-CN or RU Apple ID storefront
can't install SFI directly (see *CN/RU iOS storefront wall* below). If
they get onto an alternate sing-box-JSON-consuming client instead
(Karing, V2Box, Shadowrocket — list will shift over time), the per-
protocol files give them a wrapper-tolerant path regardless of whether
that client wraps imported selectors.

**Why mobile-only and ≥2-protocols-only.** Windows and Linux desktops run
the native sing-box binary directly (`install-singbox.ps1`,
`install-singbox.sh`): no App Store gating, the wrapper concern doesn't
apply. Single-protocol
users would emit per-protocol files byte-identical to their unified file,
so the renderer skips that case.

**Why not recommend a specific alternate client by name.** App Store
availability for proxy clients in restricted regions shifts often.
Naming a specific app would either freeze a stale recommendation in the
README or force flag-day refreshes when stores remove it. The README
points at "any client that consumes a sing-box JSON profile" and tells
the user to ask the operator what's currently working before installing.

### CN/RU iOS storefront wall

Two regions matter operationally (for example, today: CN and RU), and both
have removed essentially every sing-box-JSON-consuming client from their
local Apple App Store:

- **SFI (sing-box for iOS)**: pulled from CN under the 2017 VPN ban; from
  RU intermittently under Roskomnadzor pressure 2024-25.
- **Karing**: not on CN (the project's own FAQ tells CN users to switch
  to a non-Mainland Apple ID); pulled from RU under Roskomnadzor.
- **V2Box, Shadowrocket, Streisand, Quantumult X**: variously pulled from
  CN and/or RU at different points; the set has been monotonically
  shrinking, not growing.

The per-protocol single-outbound work above was originally framed as "a
way to serve users in CN/RU who can't install SFI." That framing partly
collapses on availability: the users who can't install SFI from their
Mainland-CN or RU Apple ID storefront mostly can't install the alternates
either, because the same storefront removed them too.

What an actual CN/RU iOS user has to do — verified 2026-05-08 — is leave
the storefront before any config-shape decision matters:

1. **Region-switch their Apple ID** to a US/HK/JP/etc. account (the same
   workaround Karing's own FAQ documents for CN). This is the path most
   users take. Once on a non-restricted store they install SFI as
   recommended and the unified profile works as designed.
2. **Sideload via TestFlight, AltStore, or SideStore.** Slot-limited
   (TestFlight) or 7-day re-sign required (AltStore/SideStore with a
   free Apple Developer account); a Mac/PC tether is needed for the
   latter. For committed users only.

**Update 2026-07-29 — the storefront wall went global.** SFI's successor
listing "sing-box VT" has been delisted from every storefront (verified:
the App Store URLs 404 from any region), the second delisting after SFI
itself in 2024. Region-switching an Apple ID no longer yields an official
sing-box install at all; the remaining iOS paths are the TestFlight beta
(sponsor-gated) or an alternate client consuming a per-protocol
single-outbound file. This strengthens the case for emitting those files
for every mobile user rather than treating them as a CN/RU nicety.

The egressor side is ready for whichever client the user lands on after
clearing the storefront wall: SFI gets the unified profile, any wrap-on-
import client gets the per-protocol single-outbound files. **The
storefront itself is the wall the project cannot move.** This is recorded
explicitly so the alt-client vetting work below is not misread as a CN/RU-
availability solution — it solves the *behaviour* problem (which client's
internals are compatible with the no-urltest design), not the
*availability* problem (which client a Mainland-storefront user can
install at all).

### Vetting procedure for naming a candidate alt-client

If an operator wants to add a name-by-name recommendation for a specific
client (Karing, V2Box, Shadowrocket, etc.), the discriminating test is
whether the client wraps the imported selector. Run on a real device
with a real profile:

1. Install the candidate client.
2. Import the unified `egressor-<user>-<type>.json` (not a per-protocol file —
   the test is *whether the wrapper exists*, which only shows when there
   are multiple outbounds for an "Auto" group to claim).
3. Open the dashboard / proxy view. Confirm 🔀 Proxy's selected default
   matches the country-derived default the renderer emitted (visible in
   the per-user README under *Selectors*). If the client shows an "Auto"
   / "urltest" / "Smart" group above or alongside 🔀 Proxy that the
   profile didn't declare — **fail**.
4. Manually switch 🔀 Proxy to a different protocol. Confirm traffic
   actually flows through that protocol (e.g. `curl ifconfig.me` and
   match the IP, or compare latency). If the client silently re-picks a
   different protocol — **fail**.
5. Block the default protocol's path (firewall, drop the server IP, etc.).
   Confirm traffic stops on that profile — i.e. the client does **not**
   auto-switch to a working protocol. The whole no-probe design depends
   on this. If the client auto-recovers — **fail**.

If all four pass, the client is safe to recommend alongside the unified
profile. If any fail, the client is still useable, but only with the
per-protocol single-outbound files — it must not be recommended for the
unified profile, since the wrapper would silently override the design.

This test result is per-release; clients can change wrap-on-import
behaviour between versions. Re-test on major version bumps before
keeping the recommendation.

### Test results

| Client | Date | Verdict | Notes |
|---|---|---|---|
| **Karing** (v1.2.18.2102) | 2026-05-08 | **Fails step 3** — wraps imported selectors | Maintainer closed [issue #1097](https://github.com/KaringX/karing/issues/1097) requesting user-defined `select`/`urltest` group support with "无计划" ("no plan"). [Issue #1460](https://github.com/KaringX/karing/issues/1460) traces the wrap to a closed `vpn_service` Dart sibling package (declared via path dependency in `pubspec.yaml:154`; companion repo URL 404s — not auditable) which regenerates `service_core.json` and silently nulls outbound `detour` fields. Public Dart code corroborates: `lib/app/modules/server_manager.dart:345-349` rewrites `Selector`-typed entries to `Urltest`; `lib/screens/home_screen.dart:1156` defaults newly-imported profiles to `ServerManager.getUrltest()`. No setting disables it. Karing's own docs treat "Auto Select" as a first-class app-level concept independent of the imported profile. **Use Karing only with per-protocol single-outbound files** (one outbound, nothing for the wrap to engage with). Re-test gate: a future release shipping the issue #1097 capability would invalidate this verdict. Karing is also not on the CN App Store (FAQ tells CN users to use a non-Mainland Apple ID) and was pulled from the RU storefront under Roskomnadzor pressure — the population this verification was meant to serve likely can't install Karing without the same region-switch they'd do for SFI. |

## awg-server: separate container, separate failure domain

AmneziaWG runs in `amneziavpn/amneziawg-go` (the official Amnezia upstream
image) as a sidecar to `singbox-server`. Two services in `compose.yaml`,
opt-in via `--profile awg-server`. sing-box stays unmodified at upstream
HEAD — egressor's stack pays no version-lag tax for using AWG. Failure
isolation is a free bonus: a wedged AWG container doesn't touch the four
sing-box-native protocols, and a wedged sing-box doesn't touch AWG.

The alternative (replace upstream sing-box with a hoaxisr/amnezia-box
fork that carries the AWG outbound type) would have made every existing
protocol pay the fork tax — single-maintainer dependency, version lag
(1.12.x vs upstream 1.13.x), no upstream docker images, schema validators
lag the fork. The 95% of egressor functionality that's not AWG inherits
this tax to enable a feature used by some users on one protocol. The
sidecar architecture skips that math entirely.

amneziawg-go runs userspace WireGuard and needs `NET_ADMIN` to manage the
TUN device + iptables NAT rules. This is unavoidable for any WG userspace
implementation. Compensate with read-only rootfs, image digest pin, narrow
port exposure (UDP/51820 only via INCOMING_IP_1), no-new-privileges.
See [hardening.md](hardening.md).

## AWG subnet allocation

Per-device IPv4 addresses inside `awg.subnet` are allocated deterministically
by `_allocate_awg_addresses()` in render.py. AWG identities are per-device
(each device of an AWG-enabled user gets its own keypair, /32 address, and
[Peer] block on the server). The mechanics:

1. The first host address (e.g. `10.66.66.1` for the default `/24`) is
   reserved for the awg-server's own [Interface] block. Never assigned to
   any device, even via explicit pin.

2. Pinned `awg_address` values from `profiles.yaml` (set per device under
   `users.<n>.devices[].awg_address`) are processed first. Operator-set
   pins are validated (must parse as a CIDR, must lie inside `awg.subnet`,
   must not collide with the server address or another pin). Errors here
   exit before any rendering happens, so a bad pin surfaces with a precise
   message rather than as a downstream "subnet full" red herring.

3. Hash-allocated for the rest. `int(sha256("<uname>/<dev_name>").hexdigest(), 16) % N`
   picks a starting offset; linear-probe forward (modulo `N`, sorted by
   `(uname, dev_name)` for determinism) until a free slot. Fail loud if
   the subnet is full.

Hashing on `<uname>/<dev_name>` means **adding a user or device mid-life
doesn't reshuffle existing peers** — each is found at the same hash
position on every run, which keeps `.conf` distributions stable across
renders. Linear probe handles incidental collisions without resetting
the whole allocation.

`awg.subnet` defaults to `10.66.66.0/24` (254 host addrs, comfortable
upper bound for the household scale egressor targets — a 5-user household
with 3 devices each fills 15 of the 254 slots). The default is chosen
unconventional-enough to rarely collide with home networks; deployments
where it *does* collide change it in `.secrets.yaml` and re-render.
Subnet change is a flag-day for AWG devices (every `.conf` becomes
invalid; redistribute) — see [hazards.md #17](hazards.md#17-awg-subnet-collision-with-home_wg-ranges).

## SS-2022 multi-user EIH

ShadowTLS's inner Shadowsocks-2022 inbound runs in **multi-user EIH** mode:

- The inbound carries a server-level `password` (32-byte base64 PSK),
  shared across all users.
- Each user has their own per-user `password`, a separate 32-byte PSK.
- Clients send the colon-joined form `<server_psk>:<user_psk>` as their
  outbound password. sing-box splits on `:`, encrypts under the server PSK,
  embeds an Encrypted Identity Header (EIH) carrying the user PSK's
  identity, and routes the session.

This gets you per-user revocation on a single inbound (rotate one user's
PSK without touching others) and per-user audit identity in server logs,
without running N separate inbounds.

`render.py`'s `frag_outbound_shadowtls` builds the colon-joined password
on the client side (`f"{d['shadowsocks_password']}:{user_ss_pw}"`); the
server template emits a `users[]` array with per-user `password` entries.
Both halves come from `.secrets.yaml`: `shared.shadowsocks_password` (the
server-level PSK) and per-user `users.<name>.shadowsocks_password`.

## File serving and `PROFILE_HOST`

The renderer writes per-user output to `singbox-profiles/srv/p/<secret>/`.
This directory is meant to be served behind a reverse proxy (Traefik,
Caddy, nginx, whatever) at `https://<PROFILE_HOST>/p/<secret>/`. The path
secret is the credential — knowing the URL grants access to that user's
config, install script, and credentials README. Treat it like a token:
generate fresh ones with `secrets.token_hex(16)` (the renderer does this),
rotate by removing the user from `.secrets.yaml.users.<name>.secret` and
re-rendering.

`PROFILE_HOST` is read from the env var of the same name (or repo
`.env`). The renderer bakes it into:
- per-user README URLs (the user-facing onboarding doc)
- the Windows and Linux installer one-liners inside that README
- `secrets.txt` header (operator-side mapping)
- the rendered Windows `install-singbox.ps1` — every URL that fetches
  config / version / NSSM / wintun goes through `PROFILE_HOST`
- the rendered Linux `install-singbox.sh` and the updater it installs:
  the config and version fetches go through `PROFILE_HOST` (only the
  release tarball, on distros without a sing-box package, comes from
  GitHub)

There's no fallback domain in clients — if `PROFILE_HOST` is unreachable
from a Windows or Linux client, the hourly update (scheduled task on
Windows, `egressor-update.timer` on Linux) silently fails (and
notifies via `WEBHOOK_URL` if set on that user). Initial install needs
`PROFILE_HOST` reachable, but once installed, the client keeps running on
its last good config until either the host comes back or the user
manually fetches a new config.

Every render also prunes `srv/p/<secret>/`: the current `egressor-*`
names, both legacy generations (`clearway-*`, `singbox-*`, `awg-*`) and
the short AWG aliases are globbed, and anything the plan did not emit is
deleted. A legacy name is only emitted while its migration shim in
`render.py` is on, so switching a shim off makes the next render delete
that generation's copies. Since 2026-09-14 the delete step tolerates a
path the plan lists twice (`unlink(missing_ok=True)`): the first such
duplicate aborted an apply half-way and left the tree half-written, and
`rotate-shortids.sh` runs the same apply unattended every month.

## When to update the schema

The `PROFILES_SCHEMA` dict in `render.py` is the contract between
`profiles.yaml` and the renderer. Update it when:

- Adding a new manifest field (new `defaults.*` block, new per-user knob).
  The schema is `additionalProperties: default-allow` for unknown keys, so
  forgetting to add a field doesn't break loading — but a typo in an
  *existing* field name will silently no-op instead of erroring.
- Adding a new enum value (a new country code, a new protocol, a new
  device type). Add it to the `enum:` list so typos fail at load time.
- Adding a new username pattern restriction. The current pattern enforces
  lowercase `[a-z][a-z0-9_-]{1,23}` because uppercase usernames render
  into served directory paths with case inconsistency, which has bitten
  us before.

## Testing

`tests/test_render.py` is a stdlib-only golden-file harness. It imports
`render.py` as a module, monkey-patches the path globals to point at
`tests/fixtures/`, runs the full pipeline, and byte-compares each
rendered config against `tests/goldens/<user>-<device>.json`.

The fixtures cover the combinations the renderer actually branches on:

- `test_alice` — full traveller (every protocol, home_wg, multi-country, admin)
- `test_bob` — single-country resident (subset of protocols, no home)
- `test_dave` — multi-country traveller without home_wg
  (also the only fixture with a `linux` device, `workstation`, so the
  desktop-shaped Linux config and its systemd installer have goldens of
  their own)

Mobile devices with ≥2 protocols also emit one solo-outbound golden per
protocol (`<user>-<device>-<proto>.json`), mirroring the per-protocol
files described in [Per-protocol single-outbound profiles](#per-protocol-single-outbound-profiles-alternate-client-fallback) — so the goldens directory has more files than the
fixture count suggests.

Run as `python3 tests/test_render.py` (assert) or `--update` (regenerate
goldens). When you intentionally change rendered output, regenerate and
eyeball the diff in `git diff tests/goldens/` before committing.

CI runs the same harness on every push (see [`.github/workflows/`](https://github.com/) once added at Stage 5).
