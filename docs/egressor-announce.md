# Egressor — announcement drafts

Three variants below — pick by venue, not by length. URL is
`https://github.com/ericguichard/egressor` everywhere.

Refreshed 2026-08-27 for the project rename (Clearway → Egressor; the
name is the pitch — it's the household's *egress* path out of a hostile
network) and for the current feature state. Two correctness notes vs the
original drafts: the protocol selector is **manual by design**
(urltest was removed to eliminate the steady-state probing fingerprint —
do not resurrect "urltest picks the fastest" phrasing), and the platform
list now includes macOS.

## Tiny — Twitter / Bluesky (≤280 / ≤300 chars)

> Open-sourced Egressor: one YAML manifest → a household's whole egress
> path out of CN/RU/IR. sing-box configs per device, 4 DPI-distinct
> protocols (Reality / Hysteria2 / ShadowTLS / VLESS-WS), credential
> rotation, WG home egress, Tailscale-behind-DPI relay. AGPL-3.0.
>
> https://github.com/ericguichard/egressor

(~250 chars + URL: ~273 effective on Twitter (t.co = 23), ~291 on Bluesky
(full URL counts, 300 cap). Re-count before posting if you edit.)

## Short — Mastodon (≤500 chars)

> Open-sourced Egressor: the egress path for a household stuck behind a
> national firewall, as a multi-user sing-box config generator + server
> stack. One YAML manifest in;
> per-device configs (Android / iOS / Windows / macOS) + a hardened
> docker compose server out. Four DPI-distinct protocols (Reality /
> Hysteria2 / ShadowTLS / VLESS-WS), per-country routing for CN/RU/IR,
> credential rotation with a 2h grace window, self-updating clients, a
> relay that keeps Tailscale reachable behind DPI. AGPL-3.0.
>
> https://github.com/ericguichard/egressor

(~480 chars + URL-as-23: ~500 effective — right at the cap; trim a clause
if your instance counts differently. Mastodon counts every link as 23.)

## Longer — Reddit, Hacker News, forums (~260 words)

Suggested HN title (hyphen, not a dash):
`Show HN: Egressor - one YAML manifest to get a household out through the GFW`

(Fallback if that reads too cute for HN: `Show HN: Egressor - sing-box
config generator for households in restrictive networks`.)

> **Egressor: a sing-box config generator for households and small teams
> in restrictive networks.** The name is literal — it builds and runs the
> egress path for everyone in the house. Open-sourced after running it
> for a small household network for a while.
>
> The basic idea: write a YAML manifest describing your users, their
> devices, and which countries they live in or visit (CN/RU/IR
> supported). `./render.py` produces per-device sing-box configs
> (Android, iOS, Windows, macOS) plus a hardened docker compose stack
> for the server side. The default mix is VLESS+Reality on TCP/443,
> Hysteria2 on UDP/443, ShadowTLS+Shadowsocks-2022 on TCP/8443, and
> VLESS-over-WebSocket fronted by Cloudflare: four orthogonal DPI
> signature families, so a classifier built for one family does not
> transfer to the others. Protocol switching is a manual in-app selector
> on purpose; there is no steady-state urltest probing for a firewall to
> fingerprint.
>
> What's there:
>
> - Per-user PSKs / UUIDs, per-user uTLS fingerprint, per-user ShadowTLS
>   SNI override.
> - Credential rotation as routine, not a fire drill: monthly and
>   quarterly rotation scripts with a 2h server-side grace window so
>   live clients don't drop.
> - Optional WireGuard "home egress" so a traveller's home-country
>   traffic exits from a WG peer back home.
> - A relay that keeps Tailscale usable behind DPI (routes the CGNAT
>   range through the proxy host), plus an optional embedded tsnet node
>   for inbound ssh to devices.
> - A one-line PowerShell installer for Windows that sets up an
>   NSSM-managed service with hourly auto-update.
> - AmneziaWG served from the same manifest as a parallel second-leg
>   tunnel.
> - Stdlib-only golden-file test suite running on every push.
> - A docs/hazards.md collecting the 20 silent-failure modes I've spent
>   real time root-causing: the hy2 cert SAN requirement, the ShadowTLS
>   mobile pooled-SNI break, smux-over-WS-through-Cloudflare EOFs, the
>   embedded Tailscale endpoint killing all Android egress without a
>   detour, and so on.
>
> AGPL-3.0. Quickstart + architecture + hardening guide in `docs/`.
>
> https://github.com/ericguichard/egressor

## Notes for posting

- Pick the venue carefully. The natural audiences:
  - **Mastodon (infosec.exchange, fosstodon.org)** — receptive to
    privacy / circumvention tooling. Use the short version.
  - **Hacker News** — use the longer version with the title above. Best
    window is weekday mornings US time.
  - **r/selfhosted** on Reddit — broad "self-hosted services" audience,
    likely a friendly first take. Mention the docker compose + the
    one-command Windows installer specifically; that audience cares.
  - **r/sing_box** if it exists / a sing-box GitHub Discussions thread
    — narrower but the right audience for the protocol-mix design
    choices.
- Don't post to the same audience twice in close succession; pick one
  high-traffic venue (HN or r/selfhosted) for first wave, others later.
- Be ready to answer "why not just use [X]?" in comments. The answer is
  in the README's "What's in the box" + threat-model sections — link
  back rather than retyping.
- Don't promise support beyond "issues welcome". This is small-team
  software; setting expectations early is worth it.
- The project was called **Clearway** until 2026-08-27. It was never
  announced under that name, so don't mention it in posts — the only
  place it belongs is the README's "Formerly Clearway" note for anyone
  who cloned the repo before the rename (GitHub redirects the old URL).

## Things NOT to include in the announcement

- Anything implying it's been audited. It hasn't.
- Specific user numbers. "small household network" is honest; "scaling
  to N users" is not.
- The production hostname. Public egressor should look generic;
  pointing at a specific live deployment invites probing.
