# `home_wg/` — WireGuard identities for home-egress devices

Drop one standard WireGuard config file per (user, device) that has a `home:`
block in `profiles.yaml`, named `<user>-<device>.conf`. The renderer parses
each `.conf`, lifts the `[Interface]` keys into the device's `home_wg` block
and the `[Peer]` keys into the user's `home` block, and emits a sing-box
WireGuard endpoint pointing back at your home network.

## File naming

```
home_wg/alice-pixel.conf
home_wg/alice-laptop.conf
```

The stem before the first `-` is the username (must match a user in
`profiles.yaml`); the rest is the device name (must match a device under that
user). One file per (user, device) pair — there's no fan-out from a single
file to multiple devices.

## File format

Standard WireGuard `.conf` (the same shape `wg-quick(8)` reads). Generate one
on your home router or `wg`-running peer for each client device, then copy it
here. Example:

```ini
[Interface]
PrivateKey = <client device private key>
Address = 10.10.0.2/24
MTU = 1280

[Peer]
PublicKey = <home router public key>
Endpoint = home.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

`MTU` defaults to 1280 if omitted (the IPv6 minimum — safe for any nested
path; the home WG endpoint rides inside whichever proxy protocol the user
selected, so its MTU has to leave headroom for the outer tunnel's overhead).

`PreSharedKey` (interface side) and `Reserved` (peer side) are optional and
only emitted into the rendered config if set in the `.conf` — the renderer
intentionally omits empty fields rather than emitting empty strings that
sing-box rejects at load time.

## Permissions

These files contain the device's WireGuard private key. Keep this directory
owned by the rendering user, mode 0700, and the individual files mode 0600.
The whole directory is gitignored at the repo root so a `git add .` accident
can't leak them — verify with `git check-ignore home_wg/*.conf`.

## What the renderer does with these

For each user with a `home:` block in `profiles.yaml`:

1. For each device in that user, look up `home_wg/<user>-<device>.conf`. If
   missing, the renderer aborts with the path of the expected file — drop it
   in and re-run.
2. The interface section becomes `device.home_wg` (private_key, address,
   listen_port).
3. The peer section overwrites the user-level `home` block's peer fields
   (endpoint, endpoint_port, peer_public_key, allowed_ips, etc.) — the
   `home:` block in `profiles.yaml` is structural-only (country / TLD lists);
   peer details always come from the `.conf`.
4. The composed sing-box config gets a `🏢 Home` WireGuard endpoint and a
   `🏠 Home Sites` selector that routes the user's home-country geoips and
   TLDs through it.

If a user has no `home:` block, drop no `.conf` — they just don't get a home
egress endpoint.

## Rotation

Re-deriving WireGuard keys (e.g. after a compromised device) is a routine
WireGuard rotation: regenerate the keypair on the device, update the home
peer's `AllowedIPs` if you also re-IP, write the new `.conf` here, re-run
`./render.py`. The renderer doesn't track WG rotations in `.pending-rotations`
— sing-box brings the new endpoint up the next time the client fetches its
config, and the old session dies naturally when the client stops sending the
old key. There's no grace window, so plan rotations during a moment the user
can briefly re-fetch their profile.
