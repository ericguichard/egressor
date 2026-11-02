# Egressor: announcement drafts

Three variants below: pick by venue, not by length. The link is
`https://egressor.org` everywhere (the docs site; the code is one click
away at github.com/ericguichard/egressor).

Refreshed 2026-11-03 for the public repo under its own domain and the
current feature state. Correctness notes: the protocol selector is
**manual by design** (urltest was removed to eliminate the steady-state
probing fingerprint, so never write "urltest picks the fastest"); the
rotation grace window is **7 days**, not 2h; platforms are Android, iOS,
Windows, macOS and Linux. Posts describe the target as "restrictive
networks" and name no country.

## Tiny: Twitter / Bluesky (≤280 / ≤300 chars)

> Open-sourced Egressor: one YAML manifest → a household's whole egress
> path out of restrictive networks. Per-device sing-box configs, 4
> DPI-distinct protocols, credential rotation, WireGuard home exits,
> Tailscale behind DPI. AGPL-3.0.
>
> https://egressor.org

(About 257 characters, link counted as 23. Re-count before posting if you
edit: Twitter counts any link as 23, Bluesky counts it in full.)

## Short: Mastodon (≤500 chars)

> Open-sourced Egressor: the egress path for a household behind a
> restrictive network, as a multi-user sing-box config generator plus
> server stack. One YAML manifest in; per-device configs (Android, iOS,
> Windows, macOS, Linux) and a hardened docker compose server out. Four
> DPI-distinct protocols (Reality, Hysteria2, ShadowTLS, VLESS-WS),
> per-region routing, credential rotation with a 7-day grace window,
> WireGuard home exits, Tailscale behind DPI. AGPL-3.0.
>
> https://egressor.org

(About 482 characters with the link counted as 23. Re-count if you edit.)

## Longer: Reddit, Hacker News, forums (~280 words)

Suggested HN title (plain hyphen):
`Show HN: Egressor - one YAML manifest to get a household out of a restrictive network`

(Fallback if that reads too cute for HN: `Show HN: Egressor - sing-box
config generator for households in restrictive networks`.)

> **Egressor: a sing-box config generator for households and small teams
> in restrictive networks.** The name is literal: it builds and runs the
> egress path for everyone in the house. Open-sourced after running it
> for a small household network for a while.
>
> The basic idea: write a YAML manifest describing your users, their
> devices and the regions they live in or visit. `./render.py` produces
> per-device sing-box configs (Android, iOS, Windows, macOS, Linux) plus
> a hardened docker compose stack for the server side. The default mix
> is VLESS+Reality on TCP/443, Hysteria2 on UDP/443,
> ShadowTLS+Shadowsocks-2022 on TCP/8443, and VLESS over WebSocket
> fronted by Cloudflare: four orthogonal DPI signature families, so a
> classifier built for one family does not transfer to the others.
> Protocol switching is a manual in-app selector on purpose; there is no
> steady-state probing for a firewall to fingerprint.
>
> What's there:
>
> - Per-user PSKs / UUIDs, per-user uTLS fingerprint, per-user ShadowTLS
>   SNI override.
> - Credential rotation as routine, not a fire drill: scheduled rotation
>   scripts with a 7-day server-side grace window, and Reality key
>   rotation that alternates between two endpoints, so live clients never
>   drop.
> - WireGuard exits: a traveller's home-country traffic leaves through a
>   peer back home, and extra exits (a second home, an office) can be
>   picked per user, with their LANs reachable.
> - A relay that keeps Tailscale usable behind DPI, plus an optional
>   embedded tsnet node for inbound ssh to devices.
> - One-line installers for Windows (service with hourly auto-update)
>   and Linux (systemd service and timer).
> - AmneziaWG served from the same manifest as a parallel second tunnel.
> - Per-user traffic accounting on the server.
> - A stdlib-only golden-file test suite running on every push.
> - docs/hazards.md: 25 silent-failure modes I spent real time
>   root-causing, such as the hy2 cert SAN requirement, the ShadowTLS
>   mobile pooled-SNI break, and smux over WebSocket through Cloudflare.
>
> AGPL-3.0. Quickstart, architecture and hardening guides on the site.
>
> https://egressor.org

## Notes for posting

- Pick the venue carefully. The natural audiences:
  - **Mastodon (infosec.exchange, fosstodon.org)**: receptive to privacy
    and circumvention tooling. Use the short version.
  - **Hacker News**: use the longer version with the title above. Best
    window is weekday mornings, US time.
  - **r/selfhosted** on Reddit: broad self-hosting audience, likely a
    friendly first take. Mention the docker compose stack and the
    one-line installers; that audience cares.
  - **sing-box community** (GitHub Discussions or a sing-box subreddit
    if active): narrower, but the right audience for the protocol-mix
    design choices.
- Don't post to the same audience twice in close succession: one
  high-traffic venue (HN or r/selfhosted) first, others later.
- Be ready for "why not just use X?". The answer is in the README's
  "What's in the box" and threat-model sections: link back rather than
  retyping.
- Don't promise support beyond "issues welcome". This is small-team
  software; setting expectations early is worth it.
- The project was called **Clearway** until 2026-08-27. It was never
  announced under that name, so don't mention it in posts.

## Things NOT to include in the announcement

- Anything implying it has been audited. It hasn't.
- Specific user numbers. "small household network" is honest; "scaling
  to N users" is not.
- The production hostname. Public egressor should look generic;
  pointing at a specific live deployment invites probing.
- Country names. Say "restrictive networks".
