# Quickstart

Set up Egressor on a fresh VPS in about 30 minutes. Targets Oracle Cloud
ARM Ampere (free tier — 4 OCPU / 24 GiB RAM is plenty), but anything with
a public IP and Docker works.

This walkthrough deploys the full default stack: ShadowTLS + Hysteria2 +
VLESS+Reality + VLESS-over-WS-via-Cloudflare. Skip steps for inbounds you
don't want.

> **Before pointing real users at this**, work through
> [docs/hardening.md](hardening.md). The container hardening shipped in
> compose.yaml handles container-side security; the host the stack runs
> on is your responsibility (SSH, cloud firewall, backups, image bumps).

## Prerequisites

- A VPS with a public IP, Docker + Docker Compose v2, openssl, git.
- A domain you control with at least two A records:
  - **`vpnws.<your-domain>`** — pointed at Cloudflare (proxy on / orange
    cloud) for the WS-CDN front. Cloudflare needs an Origin server
    config that points back to your VPS — this guide assumes Traefik or
    Caddy fronting the VPS does the TLS termination.
  - **`profile.<your-domain>`** — A record direct to your VPS public IP
    (no Cloudflare proxy), TLS terminated by your reverse proxy. This is
    the URL clients fetch their config from.
- A handshake-cover hostname for Reality. Pick a real, busy, allowed-
  everywhere site that's TLS-1.3-capable and plausibly reachable from
  your VPS. For an Oracle Cloud VM, an Oracle Cloud console hostname
  works (`console.<region>.oraclecloud.com`); for AWS / GCP / DO, pick a
  matching cloud-provider hostname. Verify TLS 1.3 before pinning:
  ```
  openssl s_client -tls1_3 -connect <host>:443 -servername <host>
  ```
  If the handshake aborts, the host doesn't speak TLS 1.3 — pick another.
- A reverse proxy in front of the VPS handling Let's Encrypt for
  `profile.<your-domain>` and `vpnws.<your-domain>`. Traefik, Caddy, or
  nginx — anything that routes `Host:` matches works. The repo doesn't
  ship a reverse-proxy config (out of scope; pick what you already run).

## 1. Clone and create the env file

```sh
git clone https://github.com/<your-fork>/egressor.git /opt/egressor
cd /opt/egressor
```

Create a repo-level `.env` (gitignored) with the host-wide config:

```sh
cat > .env <<'EOF'
# Public hostname clients fetch their config from. Must match the cert on
# your reverse proxy.
PROFILE_HOST=profile.example.com

# Repo paths — used by docker compose for bind mounts. Absolute paths.
SINGBOX_SERVER_DIR=/opt/egressor/singbox-server

# UID / GID that own config.json + hy2.{crt,key}. Should match the user
# who runs ./render.py and `docker compose up`. `id -u` / `id -g`.
PUID=1000
PGID=1000

# Hysteria2 binds explicitly to this IP. On a single-VNIC host, set to
# your primary public IP or 127.0.0.1 (compose runs host-network so
# 127.0.0.1 binds the loopback only — useful for testing). On multi-VNIC
# hosts (Oracle Cloud's two-VNIC layout, AWS multi-ENI), set this to the
# VNIC that owns the public IP you want hy2 reachable on. See
# docs/hazards.md #6 for why explicit binding matters with multi-VNIC.
INCOMING_IP_1=10.0.0.10
EOF
chmod 600 .env
```

Add a host-level sysctl so the singbox-server container (running as
non-root) can bind to ports 443/8443:

```sh
sudo tee /etc/sysctl.d/99-singbox-unpriv-port.conf <<'EOF'
net.ipv4.ip_unprivileged_port_start=443
EOF
sudo sysctl --system
```

## 2. Generate the hy2 cert

```sh
cd singbox-server
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout hy2.key -out hy2.crt -days 730 -nodes \
  -subj "/CN=cloud.example.com" \
  -addext "subjectAltName=DNS:cloud.example.com"
chmod 600 hy2.key
chmod 644 hy2.crt
chown $(id -u):$(id -g) hy2.{crt,key}
cd ..
```

`cloud.example.com` here matches what you'll set as `defaults.hy2.sni`
in `profiles.yaml` next. Clients pin the cert's public key by hash, so the
hostname is cover traffic, not a trust check; keep the SAN anyway (see
[hazard #1](hazards.md#1-hy2-self-signed-cert-must-have-subjectaltname-not-just-cn)).

Once the manifest renders (step 4), run
`singbox-server/rotate-hy2-cert.sh --bootstrap` once. It generates
`hy2-next.crt`/`.key`, the pair the first rotation will switch to, and
re-renders so clients learn that key ahead of time. Without it the first
rotation refuses to run (it would be a flag day).

## 3. Edit the manifest

```sh
cd singbox-profiles
cp profiles.example.yaml profiles.yaml
```

Open `profiles.yaml` and edit:

- `defaults.reality.server` — your VPS public IP.
- `defaults.reality.handshake_sni` — your verified TLS-1.3 cover host.
- `defaults['ws-cf'].host` — `vpnws.<your-domain>`.
- `defaults.shadowtls.sni` — your ShadowTLS cover host (typically same as
  `defaults.hy2.sni`; both should match the hy2 cert SAN if you want to
  share one cover identity).
- `defaults.hy2.sni` — must match the hy2 cert CN/SAN above.
- (Optional) `defaults.proxy_server_ips` — only set if you have multiple
  public IPs / multiple servers. Single-VPS deployments leave it empty.
- (Optional) `defaults.sip_hub`: set it only if a SIP PBX runs on the same
  host as the proxy; without it a tunnelled softphone gets one-way audio.
  See [hazard #25](hazards.md#25-softphone-on-a-tunnel-that-ends-on-the-pbx-host-gets-one-way-or-no-audio).
- `users.*` — replace `alice`/`bob`/`dave` with your actual users. See
  the inline comments for what each archetype demonstrates. Each device
  carries a `type` of `mobile`, `windows`, `mac` or `linux`, at most one
  device per type per user (the served filename is keyed on user + type).

For users with `home:` blocks, drop a `home_wg/<user>-<device>.conf`
file alongside (standard `wg-quick` format). See
`singbox-profiles/home_wg/README.md`.

## 4. First render

The first render auto-generates every secret it needs (UUIDs, passwords,
Reality keypair, etc.) into `.secrets.yaml`:

```sh
PROFILE_HOST=$(grep ^PROFILE_HOST ../.env | cut -d= -f2) ./render.py
```

Or set `PROFILE_HOST` and `INCOMING_IP_1` in your shell env / source
`../.env` first; `render.py` reads from process env, falling back to the
repo `.env`.

You'll be prompted to confirm the auto-generated changes. Say `y`. Output
files land in `singbox-profiles/srv/p/<secret>/`.

The first render also writes `singbox-server/config.json` and runs
`safe-restart.sh`, which `sing-box check`s the new config inside a
throwaway container before reconciling the real one. If `check` fails,
the live server stays untouched.

## 5. Wire up your reverse proxy

You need two routes:

- **`profile.<your-domain>`** → static file serving from
  `singbox-profiles/srv/`. The path inside is `/p/<secret>/...`. Any
  static-file backend works (Traefik `file` provider with
  `Directory: srv`, Caddy `file_server`, nginx `location /p/`).
- **`vpnws.<your-domain>`** → reverse-proxy WebSocket traffic to
  `http://172.17.0.1:10001/` (the singbox-server container's WS-in
  inbound, bound to docker0). TLS terminated by your reverse proxy;
  inside the docker host the connection is plaintext.

The repo doesn't ship reverse-proxy config because everyone runs a
different one. The only requirements: HTTPS termination on both
hostnames, and WebSocket upgrade support on `vpnws`.

## 6. Verify

After the first render + restart:

```sh
docker compose --profile singbox-server up -d singbox-server
docker logs singbox-server --tail 20
docker ps --filter name=singbox-server  # should show "healthy" after ~1m
```

Healthy means: ShadowTLS (TCP 8443), WS-in (TCP 172.17.0.1:10001),
Hysteria2 (UDP 443 on `${INCOMING_IP_1}`), and clash_api (TCP
127.0.0.1:9095) all answer. Reality on TCP 443 isn't probed (would log
spurious "invalid connection" lines on every healthcheck — see
`compose.yaml` comment).

Sanity-check the served URLs:

```sh
curl -s -o /dev/null -w "%{http_code}\n" \
  https://profile.<your-domain>/p/$(awk -v u=alice '$1==u{print $2}' singbox-profiles/secrets.txt)/egressor-alice-mobile.json
# → 200
```

## 7. Onboard a user

The renderer wrote a per-user README to `srv/p/<secret>/README.md` with
copy-paste setup instructions for each device, the install URLs, and the
credentials block. Send the user the URL:

```
https://profile.<your-domain>/p/<their-secret>/
```

They can read the README in a browser and follow the per-platform sections.
For mobile (sing-box app on Android/iOS), the URL of the JSON is the
remote-profile URL — paste it into the app's "Remote profile" field, set
auto-update to 60 minutes, save. For Windows, the README contains a
PowerShell one-liner that pulls the install script + sets up an NSSM
service + scheduled hourly config refresh. For Linux (`type: linux`), the
README contains a `curl ... | sudo bash`-style one-liner that installs
sing-box (from the distro package on Arch Linux, from the GitHub release
tarball elsewhere), writes `/etc/sing-box/config.json`, enables the
upstream `sing-box.service` and an `egressor-update.timer` that refreshes
the config hourly.

## 8. Rotation cron

Two periodic tasks for routine hygiene:

```cron
# Monthly Reality short_id rotation. Zero-downtime via the 2h grace
# window (see docs/architecture.md). 03:30 UTC on the 1st.
30 3 1 * *  cd /opt/egressor/singbox-profiles && ./rotate-shortids.sh

# Yearly hy2 cert rotation. No flag day once `--bootstrap` has run:
# clients already pin the key it switches to (docs/architecture.md).
0 5 1 4 *  HY2_SNI=cloud.example.com /opt/egressor/singbox-server/rotate-hy2-cert.sh
```

For Reality keypair rotation (a bigger flag day — see
[architecture.md § rotation](architecture.md#rotation-and-the-2-hour-grace-window)):
run `singbox-profiles/rotate-realitykey.sh` manually when you need to,
during a window where a brief Reality outage is acceptable.

For monthly image bumps:

```cron
# Monthly sing-box image bump (digest pin update). 04:00 UTC on the 5th.
0 4 5 * *  /opt/egressor/singbox-server/bump-image.sh
```

Each bump lands as its own commit on `singbox-server/compose.yaml` naming
the sing-box version behind the new digest (1.14.1 as of 2026-09-15), so
`git log --oneline -- singbox-server/compose.yaml` is the version history.

If you want notifications for any of these (success / failure pings to
Slack / Discord / your own webhook), set `NOTIFY=/path/to/notify.sh` in
the cron line. The script gets one argument: a one-line summary string.

## 9. (Optional) Enable AWG for RU/IR users

Skip this section if no user has `awg` in their `protocols:` list.
AmneziaWG (AWG) gives RU/IR users a fifth-protocol parallel tunnel that
runs in the **separate Amnezia VPN app** on the user's device — never in
the sing-box profile. Operator setup adds a sidecar container.

### Generate the AWG keypair + obfuscation params

Server keypair (one shared keypair for the awg-server side):

```sh
# Server private key (raw 32-byte X25519, base64-encoded — wg-quick format).
wg genkey | tee /tmp/awg-server.priv | wg pubkey > /tmp/awg-server.pub
cat /tmp/awg-server.priv  # paste under `awg.server_private_key`
cat /tmp/awg-server.pub   # paste under `awg.server_public_key`
shred -u /tmp/awg-server.priv /tmp/awg-server.pub
```

Per-device private keys are **auto-generated** by `render.py` on first run
— one keypair per device under each AWG-enabled user. No manual `wg genkey`
needed; the matching public key is computed at render time. Keys land at
`.secrets.yaml.users.<name>.devices.<dev>.awg_private_key` and stay stable
across runs.

Obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4 — they MUST match exactly
between server and every client; one mismatched octet silently times out
the handshake by AWG design):

```sh
python3 - <<'PY'
import secrets
# Full documented-safe AWG 1.0 ranges (same generator as awg-server/rotate-params.sh).
print(f'  Jc: {secrets.randbelow(125)+4}')       # 4..128
jmin = secrets.randbelow(661) + 40               # 40..700
print(f'  Jmin: {jmin}')
print(f'  Jmax: {jmin + 1 + secrets.randbelow(1280 - jmin)}')  # Jmin+1..1280
s1 = secrets.randbelow(1118) + 15                # 15..1132
print(f'  S1: {s1}')
while True:
    s2 = secrets.randbelow(1174) + 15            # 15..1188, and S1+56 != S2
    if s2 != s1 + 56:
        break
print(f'  S2: {s2}')
hs = []
while len(hs) < 4:
    h = secrets.randbelow(2**32 - 5) + 5         # 5..2^32-1; 1..4 are WG's own types
    if h not in hs:
        hs.append(h)
for i, h in enumerate(hs, 1):
    print(f'  H{i}: {h}')
PY
```

### Add the awg block to .secrets.yaml

```yaml
awg:
  endpoint_host: vpn.<your-domain>     # public DNS / IP for client <user>-<type>.conf
  port: 51820                          # standard WG default
  subnet: 10.66.66.0/24                # avoid collision with home_wg ranges
  server_private_key: <from wg genkey above>
  server_public_key:  <from wg pubkey above>
  Jc: <generated>                      # paste output of the python snippet
  Jmin: <generated>
  Jmax: <generated>
  S1: <generated>
  S2: <generated>
  H1: <generated>
  H2: <generated>
  H3: <generated>
  H4: <generated>
```

Then add `awg` to the user's `protocols:` list in `profiles.yaml` and
re-render:

```sh
./render.py -y
```

The renderer auto-generates a fresh keypair per device, allocates each
device a /32 inside `awg.subnet` (hash-of-`<uname>/<dev_name>` so adding
a device doesn't reshuffle the others), and emits one `egressor-<user>-<type>-awg.conf`
per device into `srv/p/<secret>/`, plus a short `<user>-<type>.conf` copy —
the one the README advertises, because the Amnezia apps name the tunnel
after the file and reject names over 15 characters. The server-side `awg-server/config/awg0.conf`
gets a matching `[Peer]` block per device.

### Open UDP/51820 in the cloud + host firewall

See [hardening.md § Cloud-provider firewall](hardening.md#network).

### Start the awg-server container

awg-server lives behind the `awg-server` compose profile. Add the profile
to your normal compose-up command:

```sh
cd /opt/egressor/awg-server
docker compose --profile awg-server --env-file ../.env up -d awg-server
docker logs awg-server --tail 20
```

Or, if you're starting the whole stack at once:

```sh
cd /opt/egressor
docker compose --profile vpn up -d
# `--profile vpn` enables singbox-server + awg-server + (whatever else
# you've grouped under that profile). Same final state, single command.
```

`amneziavpn/amneziawg-go` is **amd64-only** as of 2026-04. ARM hosts must
build the daemon from source (see
[hardening.md § awg-server](hardening.md#awg-server-only-if-awg-enabled))
or skip AWG.

### Validate end-to-end

You can't validate AWG fully without a client device. The minimum signal
on the server side:

- [ ] `docker ps --filter name=awg-server` shows running, no recent restarts.
- [ ] `docker logs awg-server` is clean (no NET_ADMIN denials, no key-format
      errors, no "address in use" on UDP/51820).
- [ ] On the host: `ss -ulnp | grep 51820` shows the listener bound to
      `${INCOMING_IP_1}:51820`, owned by the docker-userland process.
- [ ] An AWG-enabled user can fetch a device's `.conf`:
      `curl -sk https://${PROFILE_HOST}/p/<secret>/<user>-<type>.conf | head` returns
      a valid wg-quick config.

Then on a test device:

- [ ] Install Amnezia VPN (Android: github.com/amnezia-vpn/amnezia-client
      releases; iOS: App Store, app id 1600529900).
- [ ] Import the device's `<user>-<type>.conf` URL (each device imports its own).
- [ ] Connect — the Amnezia app should show "connected" within ~2s. If it
      sits on "connecting" beyond ~5s, the handshake is failing — check
      that obfuscation params on the server match the per-user .conf
      (re-run `./render.py -y` if you've edited `.secrets.yaml` since
      the .conf was generated).
- [ ] Browse `https://ifconfig.me` — must show the awg-server's egress IP
      (the VPS public IP), not the device's ISP IP.
- [ ] On Android (which permits two simultaneous VPN tunnels), verify
      sing-box and Amnezia VPN can both be active. On iOS, verify the
      "tap to switch" flow works (only one VPN profile active at a time).

If validation fails, `docker logs awg-server` is the first stop. The
[hazards.md](hazards.md) AWG section covers the most common silent
failure modes.

### Rotate AWG obfuscation params periodically

Quarterly cron is the suggested cadence (sooner if a regional throughput
drop on AWG users suggests the national firewall has fingerprinted your specific param
tuple). Cost: every AWG client must re-import their `.conf`.

```cron
# Quarterly AWG obfuscation rotation. Schedule for a low-traffic window —
# every AWG client will need to re-import their .conf after this fires.
0 6 1 */3 *  /opt/egressor/awg-server/rotate-params.sh
```

### Bump the awg-server image

```cron
# Monthly awg-server image bump (digest pin update).
0 4 6 * *  /opt/egressor/awg-server/bump-image.sh
```

## 10. Adding more users

Edit `profiles.yaml` → add a `users.<name>:` block → run `./render.py`.
The renderer auto-fills all credentials, writes their per-device configs
+ README, regenerates the Windows / Linux installers, and re-applies the server
config (with 2h rotation grace for any creds that changed). Send the new
user their URL.

Removing a user is the same in reverse: delete the block from
`profiles.yaml`, re-render. Their credentials sit in
`.pending-rotations.yaml` for 2h (so any in-flight session can complete),
then drop on the next render.

## Troubleshooting

- **`./render.py` aborts with "env vars missing"** — `PROFILE_HOST` and
  `INCOMING_IP_1` aren't in process env or repo `.env`. Fix the
  `.env` or export them in your shell.
- **`sing-box check` fails on first render** — read the error; usually
  a typo in `profiles.yaml`. Schema validation runs first and gives a
  precise JSONPath.
- **Container starts but healthcheck never goes green** — `docker logs
  singbox-server` shows what's wrong. Common: hy2 cert path readability
  (chown to `${PUID}:${PGID}`), VNIC bind IP wrong (kernel chooses egress
  source IP via default route — see
  [hazard #6](hazards.md#6-tun-auto_route--strict_route-captures-hy2s-own-quic-egress)).
- **Mobile client connects but everything times out** — try flipping
  `🔀 Proxy` from `⚡ Fastest` to a specific protocol via the in-app
  selector. If only one protocol works, the others have an issue
  (cert mismatch, DNS leak, or a hazard listed in
  [hazards.md](hazards.md)).
- **Windows installer fails on `Invoke-WebRequest`** — `PROFILE_HOST` not
  reachable from the Windows machine (DNS, firewall, or the user's
  current network). The installer retries 3× with backoff before failing;
  if all fail, run the install script with `-Verbose` to see the URL
  it's trying.
- **Linux installer: `pacman could not install sing-box`** — the local
  package index is stale (the installer deliberately avoids `pacman -Sy`,
  a partial-upgrade hazard on Arch). Run `sudo pacman -Syu`, then re-run
  the one-liner.
- **Linux: service active but the updater never changes anything** — check
  `journalctl -u egressor-update`. "pre-flight: profile host unreachable"
  every hour means the tunnel itself is down (the updater fetches THROUGH
  sing-box, on the ordinary `🔀 Proxy` path); stop the service once
  (`sudo systemctl stop sing-box`), re-run the installer (its initial fetch
  then goes direct), and it self-heals — same catch-22 as on Windows.

For deeper debugging, the [hazards](hazards.md) doc covers every silent-
failure mode we've hit in production. Read it once even if everything
looks fine — it's faster than re-discovering them.
