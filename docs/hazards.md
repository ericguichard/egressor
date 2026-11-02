# Hazards

A field guide to the silent-failure modes we've hit running this stack in
production. Most of these have a fix already baked into the renderer or the
keep-scripts; they're documented here so a future you (or a contributor)
doesn't spend a weekend re-deriving them.

If you hit something not listed, file an issue with the symptom + the smallest
reproducible config. The point of this doc is to make hazards cumulative.

---

## 1. hy2 self-signed cert must have `subjectAltName`, not just CN

**Symptom.** Hysteria2 outbound shows "no speed" / never picks up latency in
the client's urltest panel. Reality / ShadowTLS / WS-CDN on the same client
work normally. Server logs nothing (the *client* aborts the handshake after
receiving the cert). Mobile clients (iOS SFI, Android SFA) hit this most
often, but the failure is universal — desktop sing-box on Go ≥ 1.15 fails
the same way.

**Why.** Go 1.15 removed the CN hostname fallback (`GODEBUG=x509ignoreCN`
disappeared in 1.17). sing-box runs on a recent Go. The client does two
separate TLS checks: cert pinning via `tls.certificate` (passes — bytes
match) and hostname validation against `tls.server_name`. Hostname validation
reads `subjectAltName` *exclusively*; a cert with only `CN` returns "no DNS
names listed" and the handshake aborts. Pinning bypasses CA trust, **not**
hostname validation.

**Fix.** Always generate hy2.crt with both CN and a matching SAN. The
`singbox-server/rotate-hy2-cert.sh` script does this correctly — use it
rather than hand-rolled `openssl`. Manual equivalent (replace the SNI):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout hy2.key -out hy2.crt -days 730 -nodes \
  -subj "/CN=cloud.example.com" \
  -addext "subjectAltName=DNS:cloud.example.com"
```

After regen, run `./render.py -y` from `singbox-profiles/` to republish the
pin, then `docker restart singbox-server` (see hazard #5 below — `up -d`
alone is not sufficient).

**Since the public-key pin.** Clients on sing-box 1.13+ pin the cert's
public key (`tls.certificate_public_key_sha256`); with that field sing-box
checks neither the chain nor the hostname, so a SAN-less cert would connect.
The requirement above still holds for a client rendered with the PEM
fallback (`core_min` below 1.13), and the rotation script keeps emitting the
SAN.

---

## 2. ShadowTLS on mobile sing-box breaks when SNI ≠ the server's handshake target

**Symptom.** Mobile sing-box (Android SFA, iOS SFI) shows a brief latency on
the `ShadowTLS` outbound on the first probe, then it goes dark — subsequent
probes time out, app stays at 0 b/s. Other outbounds on the same client are
fine. Desktop sing-box (Windows, Linux) on the *same* config doesn't hit it.
Server intermittently logs `client hello verify failed: unexpected session
id length` and `hmac mismatch` on the ShadowTLS port.

**Why (theory).** TLS 1.3 session resumption on the mobile sing-box TLS
stack reuses a session ticket whose original handshake was against the
virtual-hosted cover cert (e.g. `docs.cover.com` served via the configured
handshake target on :443). On the resumed ClientHello the `session_id`
field shape changes, breaking ShadowTLS v3's HMAC-in-`session_id` contract
(the server expects exactly 32 bytes with HMAC in the last 8). Root cause
not fully proven (capture the resumed ClientHello with tcpdump if you want
to confirm), but the workaround is trivial.

**Fix.** For every mobile user that uses ShadowTLS, set
`shadowtls_sni: <handshake-host>` under their `users.<name>:` block in
`profiles.yaml` so they use the canonical cover SNI rather than a
pool-rotated one. Users whose devices are all Windows or Linux desktops
can stay on `defaults.shadowtls.sni_pool` (per-user JA3/JA4 decorrelation
still works for them). The override is keyed on the user, not the
device: a user who owns a mobile and a desktop pulls the desktop off the
pool as well, and the renderer's hard check demands the override for any
ShadowTLS user with a `mobile` or `mac` device (only `windows` and `linux`
are exempt, same CLI core). Don't disable
`wildcard_sni: "authed"` server-side — the issue is client-side
session-cache × SNI-mismatch, not server policy. The renderer already
honours `users.<name>.shadowtls_sni` as an override; profiles.example.yaml's
`dave` archetype demonstrates the pattern, mixed-device cost included.

---

## 3. smux on VLESS-over-WebSocket through Cloudflare is broken

**Symptom.** WS-CDN outbound completes the TLS handshake to Cloudflare,
upgrades to WebSocket cleanly, then dies on the first VLESS request. Server
logs `inbound/vless[vless-ws-in]: process multiplex stream: read multiplex
stream request: EOF` — the client closed the connection before a complete
multiplex stream request landed. Other outbounds (Reality, hy2, ShadowTLS)
work fine on the same client.

**Why.** Cloudflare's WebSocket proxy has tightened binary-frame buffering
and streaming, which interacts poorly with smux's framing. The same config
on direct WS-to-origin (bypassing Cloudflare) sometimes also reproduces, so
it may also be a sing-box-side smux regression that only surfaces under
CF-added latency. We didn't dig further because removal is the cheap fix.

**Fix.** Don't enable `multiplex` on a VLESS-over-WS outbound that goes
through Cloudflare. The renderer disables it in `frag_outbound_ws_cf` by
default with a block comment explaining why. The per-request handshake
overhead without multiplex is negligible on modern CF edges (a few ms per
new VLESS stream for the WS round-trip). Server-side `multiplex.enabled:
true` stays on harmlessly — it's an accept-all gate, not a mandate.

If you want to re-enable on the client side, render a single test user,
have them try, and tail `vless-ws-in` for `read multiplex stream request:
EOF` before rolling it out.

---

## 4. sing-box 1.12+ rejects `detour` to a bare direct outbound

**Symptom.** Client crashes at init with:

```
ERROR ntp: initialize time: detour to an empty direct outbound makes no sense
```

DNS never comes up, no outbound ever connects. Hits NTP first because that's
typically the first feature with a `detour:` field; the same trap applies to
any DNS server / service with `detour:`.

**Why.** sing-box 1.12+ validates that `detour` references do meaningful
routing. A detour pointing to a `{type: "direct"}` outbound with no other
fields is treated as a no-op and rejected.

**Fix.** Either omit `detour` entirely (the feature runs on the default
direct path, identical behaviour) or point it at an outbound that does
something. The renderer's "➡️ Direct" outbound carries `udp_fragment: false`
specifically so it's non-empty and can legally serve as a detour for
`bootstrap_dns` (which needs to dial UDP/53 outside the tunnel).

---

## 5. Single-file bind mounts pin the inode — `up -d` alone won't pick up edits

**Symptom.** You edit a bind-mounted single file (`config.json`, `hy2.crt`,
or similar), restart with `docker compose up -d`, and the container keeps
serving the old content. SIGHUP / config-reload doesn't help either. Symptom
on hy2: clients still pinned to the *new* cert can't handshake the server
that's still presenting the *old* cert; the failure mode is silent (TLS
abort at QUIC layer, no log line, zero packets visible).

**Why.** Docker resolves a single-file bind mount to an *inode* at container
start, not a path. Atomic-rename writers (`Edit`, `sed -i`, `mv`) replace
the path with a *new* inode; the container keeps the old inode mapped.
`docker compose up -d` is a no-op when compose.yaml/env haven't changed,
so it doesn't re-resolve the mount. SIGHUP only helps if the file was
modified in-place (same inode), which most edit tools don't do.

**Fix.**
- After editing a bind-mounted single file, run `docker restart
  <container>` to re-resolve the mount inode.
- Prefer bind-mounting a *directory* over a single file when the contents
  may change at runtime — directory mounts resolve paths inside on each
  access, so rename-replacements work transparently.
- The supplied `singbox-server/safe-restart.sh` already covers this: if
  `up -d` is a no-op (container ID unchanged), it follows up with `docker
  restart`.

To test whether the container sees your edit: `docker exec <ctr> cat
/path/inside` and compare to the host file.

---

## 6. TUN `auto_route + strict_route` captures hy2's own QUIC egress

**Symptom.** On a mobile client running TUN with `auto_route: true` and
`strict_route: true` (the renderer's default), Hysteria2 fails to establish.
Outer QUIC packets to the proxy server's UDP/443 never make it out — they
get pulled back into `route.rules`. If a `{network: udp, port: 443, action:
reject}` rule is present (to kill browser HTTP/3 and force TCP fallback),
hy2 hits it and dies.

**Why.** `strict_route` unconditionally routes every egress packet through
the TUN's `route.rules`, including packets sourced by sing-box's own
outbounds. First-match-wins, so a blanket UDP/443 reject can swallow hy2's
own outer transport before it reaches the link.

**Fix.** Order matters in `route.rules`. The proxy-server bypass — `{ip_cidr:
[<server-IPs>], outbound: "➡️ Direct"}` — must come **before** any UDP/443
reject. The renderer's `frag_route` does this when `defaults.proxy_server_ips`
is set; for single-host deployments where the proxy hostname only resolves
to one IP that's already excluded by another route rule, the list can be
empty. Same trap exists for any other port/network reject that could overlap
a proxy-server outbound's outer transport (TCP/853 DoT reject, etc. —
sequence them after the bypass).

---

## 7. sing-box has no per-user hy2 bandwidth caps

**Symptom.** You want "one stolen credential can't saturate the uplink" as
a defensive measure. sing-box's hy2 inbound `users[]` schema is exactly
`{name, password}` — `up_mbps` / `down_mbps` per user is rejected by
`sing-box check`. The inbound-level `up_mbps` / `down_mbps` exist but are
*advertisements for Hysteria2's brutal congestion control* (client trusts
the value and paces accordingly), not enforced rate limits.

**Fix.** Don't try to put per-user caps in the sing-box layer — it's an
upstream feature gap, not a config issue. If per-user rate limiting matters,
implement at the Linux layer: `tc` qdiscs keyed on source IP, or iptables
`--hashlimit` per source. Mapping source-IP → user is non-trivial since
QUIC uses one 5-tuple per session, so this is more involved than it sounds.

A cheaper mitigation: ban source IPs that show ≥10 auth failures in a short
window — a 30-line shell script reading `docker logs singbox-server | grep
'authentication failed'` is enough to start with.

---

## 8. Android Private DNS leaks DoT through the TUN

**Symptom.** On Android with "Private DNS" enabled (system setting →
"Automatic" or a custom hostname), sing-box logs flood with `connection
to 172.16.0.2:853 timed out` at startup. Every DNS lookup the OS attempts
goes to the system's DoT target, gets pulled back into the TUN by
`auto_route + strict_route`, hits the TUN peer at port 853, and times out
after 5s before any proxy comes up.

**Why.** Android's resolver emits DoT (TCP/853) when Private DNS is on.
Under strict_route the TUN captures every egress packet — DoT included —
and the loop has no exit.

**Fix.** Add `{network: tcp, port: 853, action: reject}` to `route.rules`,
*after* the proxy-server bypass and *before* the catch-all. The renderer
does this in `frag_route`. Combined with the existing `port: 53,
action: hijack-dns` (which catches the resulting Do53 fallback queries),
DoT-speaking apps drop transparently to sing-box's own DNS stack with no
capability loss. Side benefit: the same rule shuts the door on apps that
sidestep the port-53 hijack by speaking DoT directly.

---

## 9. sing-box ANSI colors in logs are not suppressible at the source

**Symptom.** Logs from sing-box always carry ANSI color escapes
(`\x1b[31m...\x1b[0m`, etc.) regardless of TTY status. This clutters
`docker logs`, grep, and any log-aggregator ingest. Setting `tty: false`
in compose.yaml doesn't help; neither does `NO_COLOR=1` in the
environment.

**Why.** sing-box's log formatter doesn't honor `NO_COLOR` and there's no
config field to disable colors. `log.disable_color: true` returns
`json: unknown field "disable_color"` from `sing-box check`.

**Fix.** Strip downstream, not at the source.
- Promtail / Vector / Loki ingest pipeline: `replace` stage with regex
  `\x1b\[[0-9;]*m` → empty.
- Ad-hoc CLI: `docker logs singbox-server | sed 's/\x1b\[[0-9;]*m//g'`.

Don't try to wrap the container command with `sh -c '... | sed'` — that
breaks pid-1 signal semantics (sing-box no longer receives SIGTERM
cleanly), so `docker stop` waits the full grace period before SIGKILL.

## 10. GFW marks IPs sending sustained UDP/443 volume — drops *all* incoming UDP for ~1h

**Symptom.** Hysteria2 from CN works fine for a while, then a single
client (or many clients sharing the same overseas server IP) suddenly
loses *all* UDP connectivity to that server for tens of minutes to an
hour. TCP to the same server (Reality on TCP/443, ShadowTLS on TCP/8443)
keeps working. urltest demotes hy2; user notices nothing if they have
TCP fallbacks enabled.

**Why.** GFW maintains a per-IP heuristic that flags overseas hosts
generating sustained high-volume UDP/443 flows from inside CN. Once
flagged, all UDP from that host is dropped at the border for the
rest of an hourly window (apernet/hysteria#1157, Telegram-sourced
community report — not peer-reviewed but consistent enough that
Hysteria upstream ships port-hopping for exactly this case). Salamander
obfuscation does *not* help here; the heuristic is volume-based and
shape-agnostic. The SNI-classifier vector documented in USENIX Sec '25
(Zohaib et al.) is a separate mechanism that salamander *does* defeat.

**Fix.** Hysteria2 port-hopping. Server keeps listening on a single
port (e.g. UDP/443); a host iptables NAT redirect collapses a wide
port range (e.g. UDP/20000-30000) onto that single listen port. Clients
get `server_ports: ["20000:30000"]` instead of `server_port: 443` and
dial random ports from the range — packets spread across thousands of
5-tuples so no single flow accumulates enough volume to trip the
heuristic.

Three coordinated parts:

1. **Manifest.** Add `server_ports: ["20000:30000"]` to
   `defaults.hy2` in `profiles.yaml`. The renderer emits
   `server_ports` *instead of* `server_port` when this is set
   (sing-box's hy2 outbound dials `server_port` first if both are
   present, defeating the spread).

2. **Host iptables.** Run
   `singbox-server/setup-hy2-port-hop.sh` on the docker host. It adds:
   ```
   iptables -t nat -A PREROUTING -d <hy2_listen_ip> -p udp \
       --dport 20000:30000 -j REDIRECT --to-ports 443
   ```
   and persists via `netfilter-persistent save`. Idempotent — safe to
   re-run.

3. **Cloud firewall.** Open UDP `20000-30000` ingress on the VNIC
   that hy2 binds to (the one matching `defaults.reality.server` in
   `profiles.yaml`). On Oracle Cloud, this is one ingress rule on the
   VCN security list. Once port-hopping is rolled out and clients have
   updated, *remove* the UDP/443 rule — no client should hit it
   anymore, and removing it shrinks the attack surface.

The TCP/443 rule (Reality) stays — different protocol, different rule.

---

## 11. AWG obfuscation params silently mismatch on rotation

**Symptom.** After running `awg-server/rotate-params.sh`, AWG clients
who haven't re-imported their `.conf` get a hung "connecting" state in
the Amnezia VPN app — no error, no log line on either side, just a dead
handshake.

**Why.** AWG's Jc/Jmin/Jmax/S1/S2/H1-H4 obfuscation params have to match
EXACTLY between server and every client. Mismatch produces a packet
shape the *other* side parses as random noise, by deliberate design (the
whole point of these params is to defeat active probing — failed
handshakes look identical to passive scanner traffic). There's no error
to surface; the params just don't validate.

**Fix.** After every rotation, every AWG client must refetch its
`.conf`. The per-device `<user>-<type>.conf` URLs in the user's
`srv/p/<secret>/` directory get re-rendered atomically with the server
config; clients can curl / re-import. **Unlike sing-box's hourly
remote-profile poll, the Amnezia VPN app does NOT auto-refresh `.conf`
files** — re-import is a manual user action, once per device. Send a
notification on rotation if you have one wired.

If a single device is broken post-rotation, eyeball-diff its
`egressor-<user>-<type>-awg.conf` against the matching `[Peer]` block in the server's
`awg-server/config/awg0.conf` (peer comments carry `# uname/dev_name`
for fast lookup); the divergent line is the first place to look.

---

## 12. amneziawg-go requires NET_ADMIN — incompatible with `cap_drop: [ALL]`

**Symptom.** `cap_drop: [ALL]` on the awg-server container produces
`operation not permitted` errors in the daemon log on TUN device
creation, immediately after start.

**Why.** Userspace WireGuard (every implementation, including
amneziawg-go and wireguard-go) needs `NET_ADMIN` to create + configure
the TUN device and to manage iptables NAT rules in PostUp/PostDown.
There's no way to drop that and still have a functional daemon.

**Fix.** awg-server's compose has `cap_add: [NET_ADMIN]` and *no*
`cap_drop` — the cap is unavoidable. Compensate with read-only rootfs,
image digest pin, narrow port exposure (UDP/51820 only via
`${INCOMING_IP_1}`), `no-new-privileges`, mem/cpu ceilings. See
[hardening.md § awg-server](hardening.md#awg-server-only-if-awg-enabled)
for the full bundle. The residual risk surface is comparable to
singbox-server's even though `cap_drop: [ALL]` isn't viable here.

---

## 13. WireGuard keepalive storm bug (sing-box #3981) — affects amneziawg-go too

**Symptom.** Idle mobile clients drain battery faster than expected after
connecting to AWG. `tcpdump` on the server shows the awg-server sending
keepalive packets every 2-3 seconds to every connected peer.

**Why.** sing-box and amneziawg-go share the same wireguard-go base. A
known bug in wireguard-go (sing-box issue #3981 in tracker) makes the
*server* side send keepalives whenever a peer is configured with any
non-zero `PersistentKeepalive`. The intent of `PersistentKeepalive` is
client-side NAT traversal; server-initiated keepalive is the bug.

**Fix.** awg-server's [Peer] blocks emit `PersistentKeepalive = 0`
server-side (render.py defaults this in `_render_awg_server_config`).
Clients still drive keepalive themselves (the client-side
AWG client template emits `PersistentKeepalive = 25`) — that's
what's actually needed for NAT traversal. The server-side zero just
disables the buggy server-initiated stream.

---

## 14. Amnezia VPN app on iOS conflicts with active sing-box VPN profile

**Symptom.** iOS user has both sing-box (for the four sing-box-native
protocols) and Amnezia VPN (for AWG) installed. Connecting in one app
silently disconnects the other; the user sees the previously-connected
app's tunnel stop without warning.

**Why.** iOS allows *exactly one* VPN profile to be active at a time —
this is an OS-level constraint, not an app bug. Starting a second VPN
implicitly deactivates the first. The apps don't surface this clearly;
a user toggling between protocols may think both are running when only
one ever is.

**Fix.** Document the "tap to switch" flow in the per-user README (the
AWG section appears only when the user has AWG enabled, and explicitly
calls out the one-VPN-at-a-time constraint).

**CORRECTION — this applies to Android too (verified 2026-07-19).** This
entry previously claimed "on Android both VPNs can coexist on different
network namespaces — no manual switching needed there." That is wrong.
Android's `VpnService` is single-slot in exactly the same way: whichever
app holds it excludes the other. Verified by watching the AWG server while
an Android handset switched apps — the device's peer sat at
`latest handshake = 0`, `rx = 0`, `tx = 0` for as long as sing-box held the
slot, then completed a handshake within ~3s of the AWG app being connected.
So "tap to switch" is required on **both** platforms, and any docs or
tooling assuming Android coexistence are wrong. See also hazard 19.

---

## 15. User imports profile into Hiddify-Next instead of official sing-box

**Symptom.** A user sets up egressor following someone else's tutorial
that recommended Hiddify-Next; everything appears to work but
country-derived selector defaults don't take effect, and traffic flows
through whatever Hiddify's own auto-switcher picks.

**Why.** Hiddify-Next wraps any imported profile in its own urltest
"Auto" group regardless of the profile's own selector configuration
(Hiddify GitHub issues #552 / #1188, both open). The whole no-probe
selector design egressor is built around — country-derived defaults +
manual fallback, no steady-state probing — is overridden silently. The
user thinks they're getting the design payoff (no probe fingerprint)
when they're not.

**Fix.** The per-user README explicitly directs users to the official
sing-box client by platform with all three install paths (Play Store /
App Store $3.99 / GitHub releases sideload + SHA256 verification) and
a "**Do not use Hiddify-Next**" callout. Also called out in this
repo's top-level README. If a user reports this symptom: confirm which
client they installed, and have them switch.

**Generalisation + escape hatch.** The wrap-on-import behaviour isn't
unique to Hiddify-Next; any current or future iOS client that does the
same thing breaks the design identically. For users who can't install
SFI (CN App Store has banned all VPN/proxy apps; RU App Store
availability is intermittent), the renderer also emits **per-protocol
single-outbound profiles** (`egressor-<user>-<type>-<proto>.json`, mobile devices
with ≥2 protocols only). With exactly one outbound, there is nothing
for an alt-client's auto-switcher to wrap. The user imports one file
per protocol and switches profiles in their client to switch protocol.
Design rationale + scope in
[architecture.md § Per-protocol single-outbound profiles](architecture.md#per-protocol-single-outbound-profiles-alternate-client-fallback);
user-facing instructions in the per-user README's *If you can't install
sing-box* section.

---

## 16. Selector default unreachable, no fall-through (manual escape hatch)

**Symptom.** User's country-derived default protocol stops working (e.g.
Reality IPs blocked overnight in CN) and they're stuck on the broken
default. Nothing on the device cycles through to a working alternative
on its own.

**Why.** This is the deliberate cost of dropping urltest. Pure selector
+ country default means "no auto-switch when default fails" — the user
manually flips in the dashboard. See
[architecture.md § Selector default and manual fallback](architecture.md#selector-default-and-manual-fallback)
for the design rationale (the steady-state probing was itself a
fingerprint).

**Fix.** It's by design, not a bug — but the operator should make sure
every user knows the manual-flip flow before this happens. The per-user
README has the procedure as the first item in the "Manual fallback"
section. If a user can't find it, screenshot the path: open the sing-box
app → tap **🔀 Proxy** → pick a different protocol from the dropdown.

If too many users hit this regularly, that's a signal to revisit the
spike (route-rule on-error matching, watcher sidecar) when sing-box
gains a primitive that supports it cleanly.

---

## 17. AWG subnet collision with home_wg ranges

**Symptom.** A user with both `home:` (home-egress WireGuard) and
`awg` enabled has overlapping IPs between their home WG range and the
AWG subnet. Routing rules send traffic to one tunnel that should have
gone to the other; pages time out unpredictably.

**Why.** WireGuard tunnels are identified by their subnet. `home_wg/`
ranges are operator-controlled per device (whatever the home router's
WG side issues); `awg.subnet` in `.secrets.yaml` defaults to
`10.66.66.0/24`. If the home network also uses `10.66.66.0/24`, both
tunnels claim the same address space.

**Fix.** Default `awg.subnet` to `10.66.66.0/24` (chosen because it's
unconventional enough to not conflict with most home_wg defaults) and
document the constraint. If you DO have a clash, change `awg.subnet`
to a different RFC-1918 chunk you don't use elsewhere (e.g.
`10.77.77.0/24`), re-render, redistribute every AWG client's `.conf`.

---

## 18. amneziavpn/amneziawg-go is amd64-only — ARM hosts can't pull

**Symptom.** Operator on Oracle Cloud Ampere (ARM64) runs
`docker compose --profile awg-server up -d awg-server` and gets
`no matching manifest for linux/arm64/v8 in the manifest list entries`.

**Why.** As of 2026-04, the upstream `amneziavpn/amneziawg-go` Docker
Hub image ships an amd64 manifest only. There's no arm64 build in the
multi-arch index.

**Fix.** Two options:

1. Build the daemon from source for ARM. The upstream repo at
   `github.com/amnezia-vpn/amneziawg-go` has a Dockerfile that builds
   on ARM. Push to your own registry, swap the `image:` line in
   `awg-server/compose.yaml` to your fork's pinned digest. **Pin by
   digest just like the upstream image** — `:latest` from your own
   registry is a worse supply-chain story than the upstream digest pin.

2. Skip AWG entirely until upstream ships arm64. The four sing-box-
   native protocols still run on ARM hosts — singbox-server is
   multi-arch.

Don't swap in a random community-maintained ARM image without source-
auditing it first. The whole point of the digest pin is supply-chain
discipline; throwing that away to get AWG running is a worse posture
than not having AWG.

---

## 19. `🔗 Tailnet` → `➡️ Direct` is a silent no-op on mobile

**Symptom.** A mobile client with `tailnet: true` is flipped from `🔀 Proxy`
to `➡️ Direct` and loses all tailnet reach — connections to `100.64.0.0/10`
just hang. Separately, the device shows as `offline` in `tailscale status`
on other nodes even though its VPN is plainly working, which reads as a
broken Tailscale install and sends you debugging the wrong thing.

**Why.** The same single-slot constraint as hazard 14. `➡️ Direct` hands the
CGNAT range to *the device's own Tailscale* — on mobile that means the native
Tailscale app, which cannot run while sing-box holds the one VPN slot. Nothing
is listening for the range, so packets leave via the physical interface and are
dropped. The `offline` status has the same root cause and is **expected**: while
sing-box is up the device is a *relay client*, not a tailnet node. Desktop
platforms are unaffected — they hold multiple TUN adapters, so native Tailscale
and sing-box coexist and `➡️ Direct` genuinely works. Hence the per-device
defaults (mobile → `🔀 Proxy`, desktop → `➡️ Direct`).

**Fix.** Leave mobile clients on `🔀 Proxy` — it is the only working member
there, not merely the default. Note the relay is **outbound-only** (the host
dials peers as itself), so a peer cannot initiate a connection *to* the phone;
inbound reach needs a reverse tunnel or the embedded tsnet endpoint
(hazard 20) rather than the phone's tailnet IP. If you
are hardening this, consider omitting the `➡️ Direct` member entirely for
`type: mobile` devices so the broken option is not offered.

---

## 20. Embedded tsnet endpoint without a detour kills ALL Android egress

**Symptom.** A mobile device with `tailscale: true` enrolls fine — tailnet
ping works, inbound ssh over the tailnet works — but every outbound TCP
connection from the device is refused instantly: browser, terminal,
everything, including flows whose route rules predate the change.
`sing-box check` passes, and the identical core version runs clean on the
server, so it reads as a route-rule bug. It is not.

**Why.** The endpoint's own control/DERP dials are plain sockets, not
protected from the VpnService TUN the way sing-box's own dialers are: they
loop back into the TUN, re-enter routing, and the feedback loop starves
all device egress. This is Android-runtime behaviour, invisible to config
validation and absent on the server. Windows survives (multiple TUN
adapters coexist) but shows the same mechanism as slow, flaky
registration. Dial fields on a `tailscale` endpoint govern only the
endpoint's own connections — peer data-plane traffic is untouched (and
unwrappable, see architecture.md).

**Fix.** Always emit the endpoint with a `detour`: `➡️ Direct` by default
(sing-box's protected-socket dialer breaks the loop), or `🔀 Proxy` when
the device carries `tailscale_detour: proxy` (break-glass: the node stays
registered on networks that block Tailscale outright, and registers much
faster on hostile networks). The renderer does this unconditionally —
never add a tsnet endpoint without one. Related timing gotcha: after a
profile switch or restart, allow up to ~10 minutes for re-registration on
the direct path before diagnosing anything else.

---

## 21. ECH + uTLS on the same outbound never connects — and fails silently

**Symptom.** An outbound with both `tls.utls` (any fingerprint) and
`tls.ech.enabled: true` fails every dial with
`connection: ... tls: malformed outer client hello` — locally, before a
single packet reaches the server. From the server side the outbound just
goes quiet: zero connection attempts, nothing to correlate. Because the
selector is manual and the other protocols keep working, nobody notices
until someone actually flips to that lane.

**Why.** sing-box builds the ECH outer ClientHello through the uTLS
mimicry layer, and the two do not compose — the resulting outer hello is
rejected as malformed. Verified broken on 1.13.18 and 1.14.0-beta.3;
either knob alone works fine. `sing-box check` passes (it's a runtime
dial failure), so config validation never catches it.

**Fix.** Pick one per outbound. The renderer keeps uTLS on the WS-CDN
path and drops ECH: this family's cover story is "ordinary browser HTTPS
to a Cloudflare site," which the browser fingerprint provides and which
ECH actively undermines (the ECH extension is RST-blocked toward
Cloudflare in some countries). If you re-introduce ECH anywhere, drop
uTLS on that outbound and verify with a real dial through the built
config — not just `sing-box check`.

---

## 22. Outbound server lookups bypass dns.rules — a domain-addressed proxy deadlocks when selected

**Symptom.** Flipping 🔀 Proxy to the WS-CDN outbound kills everything with
`lookup vpnws.…: DNS query loopback in transport[cloudflare_doh]` (then
`context deadline exceeded` on every query). The other lanes work; the DNS
rule routing that exact hostname to `bootstrap_dns` sits right there in the
config, first in the list — and never fires.

**Why.** In the 1.12+ DNS model there are two resolution paths. Client
queries (hijacked from the TUN) go through the DNS *router* and honor
`dns.rules` — that's the path the bootstrap rule protects, and why the
🏢 Home WG peer's DDNS bootstrap works. But an *outbound's own server
lookup* goes through `route.default_domain_resolver` (or the outbound's
`domain_resolver`) and never consults `dns.rules`. Our default resolver is
`cloudflare_doh`, which detours via 🔀 Proxy — so when 🔀 Proxy *is* the
domain-addressed outbound, resolving its server requires dialing it:
deadlock. The trap is that this only fires when that outbound is selected,
which for a fallback lane is precisely the emergency it exists for.

**Fix.** Any domain-addressed outbound must carry its own
`domain_resolver: bootstrap_dns` (plaintext UDP:53 via Direct — same
pre-tunnel exposure trade-off as the WG DDNS bootstrap). The renderer pins
it on ws-cf, the only domain-addressed outbound. If you ever add another,
pin it the same way — and test it *selected as* 🔀 Proxy, not just as an
idle member.

---

## 23. A running sing-box TUN silently kills the Amnezia (AWG) tunnel on desktops

**Symptom.** Amnezia shows "connected", the AWG server even logs a
handshake from the device, but nothing goes through: no reply from the AWG
gateway, and after ~2 minutes the server-side `latest handshake` just stops
advancing. No error on either side. Seen 2026-08-28 on Windows right after
sing-box was (re)started while Amnezia was up.

**Why.** AWG is a separate app, not a sing-box outbound, so its endpoint is
deliberately *not* in `proxy_server_ips`. On Windows/macOS both apps can run
at once and sing-box's `auto_route` + `strict_route` TUN owns the default
route, so the Amnezia app's UDP to the AWG server is captured and re-enters
`route.rules`. This deployment binds AWG on **UDP/443** for QUIC cover — the
exact port the blanket QUIC reject rule drops. First-match-wins: AWG never
reaches `final`. (Android/iOS never hit this: the OS allows one VPN at a time.)

**Fix.** The renderer now emits, for every AWG-enabled user, a rule sending
exactly the AWG endpoint (`ip_cidr <host>/32` or `domain <host>`, `network:
udp`, `port: <awg port>`) to ➡️ Direct, placed right after the proxy-server
bypass and *before* the UDP/443 reject. The two apps then coexist: sing-box
keeps the default route, AWG carries only what the user points at it. This
is a bypass for the AWG control/data path, **not** a way to "use both" — the
default route still belongs to sing-box.

**Part 2 (same day).** The route rule alone is not enough for true coexistence: a packet the
TUN captures is re-emitted by the *sing-box process*, and Amnezia's kill switch whitelists only
its own traffic (with the kill switch on it also blocks sing-box's proxies and Tailscale — total
loss of connectivity). The renderer additionally lists the AWG endpoint in the TUN's
`route_exclude_address` (literal IP only) so Amnezia's own packets never enter the TUN.

**Operating rule (household decision):** on Windows/macOS run ONE of the two at a time, as
Android/iOS enforce by design — stop sing-box before connecting Amnezia, quit Amnezia before
starting sing-box; kill switch off regardless. Note: the sing-box crash-loop first blamed on
this overlap turned out to be an unrelated upstream bug — see #24.

---

## 24. sing-box ≥ 1.13.15 on Windows crash-loops with `fatal error: thread exhaustion` (upstream #4446)

**Symptom.** A Windows client's VPN "randomly" dies; the NSSM service restarts sing-box every
~20 s for hours; `logs\service.err.log` rotates dozens of times (each crash writes a ~10 MB Go
goroutine dump — 46 GB / 8,700 files accumulated on one laptop in a month). Header:
`runtime: program exceeds 10000-thread limit` / `fatal error: thread exhaustion`. In the dump
~9,940 goroutines sit in `[syscall]` inside `syscall.Closesocket`, created by
`route.(*ConnectionManager).NewPacketConnection` / `udpnat2.(*Service).NewPacket`. Crash cadence
is UDP-churn dependent (30-90 min on a quiet desktop, seconds under load).

**Why.** Upstream regression: SagerNet/sing-box **#4446** (open, 2026-08-25) — goroutine/thread
leak per UDP NAT session on Windows, `closesocket()` never returns, one OS thread pinned per
leaked session. Our timeline matches exactly: 1.13.14 (installed 06-28) ran clean; 1.13.15
landed 07-30 11:49 UTC via the hourly self-upgrade and the first burst started that hour; .16,
.18, .19 all crash. It is not config- or Amnezia-related (first suspected, see #23).

**Fix.** Pin the Windows fleet to the last good release until upstream ships a fix:
`publish-version.sh` honours a pin file next to the mirror
(`singbox-profiles/.sing-box-version.pin`, one semver line) and publishes THAT instead of the
container's version; the updater compares `-ne`, so every PC downgrades on its next hourly poll
(the mirror logic fetches the pinned zip from GitHub as usual). Remove the pin after the
upstream fix is confirmed on one PC. Clean the accumulated dumps (`service.err-*.log`) by hand;
the updater now prunes rotated logs older than 7 days.

**Scope.** Windows only — the leak is in the Windows socket-close path (`syscall.Closesocket`).
Linux clients are unaffected: a `type: linux` device on Arch runs the distro package (which
tracks upstream within a day) untouched by the pin, and the release-mode Linux installer follows the
published version like Windows does, so a pin meant for Windows also downgrades release-mode
Linux clients. Prefer the package path on distros that have one. The server is not covered by
the pin file either: its image is pinned by digest in `singbox-server/compose.yaml`, on
sing-box 1.14.1 since 2026-09-15 (1.14.0 from 2026-08-31), and each bump commit names the
version behind the digest.

---

## 25. Softphone on a tunnel that ends on the PBX host gets one-way or no audio

**Symptom.** A SIP PBX (Asterisk or similar) runs on the same host as the
sing-box server. A tunnelled phone registers and calls connect, but every
call to the phone has one-way audio or none at all, on every line.

**Why.** SIP signalling is TCP and hairpins through the proxy without
trouble. Media is UDP, and a proxy does not relay UDP whose destination is
its own host: the phone's RTP toward the PBX never comes out of the
server-side relay, while the PBX's RTP toward the phone only lands by
accident, on the relay socket the phone discovered via STUN through the
tunnel (measured with a NIC capture on the host, 2026-09-05). Android adds
a second layer: a `package_name` route rule only decides where a packet
the TUN has already captured is re-emitted, so the softphone still sees
the TUN as its interface, binds media to the TUN address and STUNs through
the tunnel. With push notifications on, the app's SIP rides the vendor's
push proxy and its reflexive address comes from the vendor's STUN servers,
so host/port rules never see the flows that matter and no RTP reaches the
host at all.

**Fix.** The optional `defaults.sip_hub` block in `profiles.yaml`:

```yaml
defaults:
  sip_hub:
    hosts: [sip.example.com, 192.0.2.25]        # registrar NAME and literal IP
    port_ranges: ["5061:5061", "10000:10100"]   # SIP + RTP, "start:end", ORed
    android_packages: [com.example.softphone]   # mobile only: the whole app bypasses
```

The renderer emits one `➡️ Direct` route rule per `hosts` entry, carrying
`port_range`, placed after the AWG endpoint bypass and before the UDP/443
reject. Both host forms are needed because the two SIP flows look
different to the router: signalling is dialled by the registrar name,
which becomes a fake IP under the client DNS, so only a `domain` rule
matches it; media goes to the literal IP from the SDP, so only an
`ip_cidr` rule matches that. One field per rule: `domain` and `ip_cidr`
in the same rule are ANDed and match nothing. Only those ports leave the
tunnel; SSH and everything else to that host keep riding the proxy. On
`type: mobile` devices the renderer also emits a `package_name` rule for
`android_packages` and, the part that actually fixes media, lists the
same packages in the TUN inbound's `exclude_package` (the OS-level
VpnService bypass: the app never sees the VPN, so its local address, STUN
and RTP all use the real network; the sing-box app's per-app screen
overrides this same field). Both are Android fields and are inert on
iOS. Anything that binds media or STUNs belongs in `android_packages`,
not in route rules.

---

## Adding to this doc

If you hit a silent-failure mode that took >2h to debug, write it up here.
Format per entry:

- **What you saw** (the symptom — exact log line if you have one)
- **Why it happens** (the underlying mechanism, not the proximate cause)
- **The fix** (what to change in the renderer / scripts / config)

Keep it brief. The point is "future-you can grep this in 10s when the same
thing comes back," not a thorough write-up.
