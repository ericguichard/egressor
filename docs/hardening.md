# Hardening checklist

The compose stack ships with reasonable container hardening (cap_drop ALL,
read-only rootfs, no-new-privileges, digest-pinned image, mem/cpu limits,
healthcheck). That handles container-side security. The host the stack runs
on is your responsibility.

This is a checklist, not a tutorial — each item links out to a canonical
reference. The point is "did you actually do these" before you point a
public IP at this stack and start serving real users.

## Pre-deploy

- [ ] **SSH hardening.** Disable password auth + root login in
  `/etc/ssh/sshd_config`:
  - `PermitRootLogin no`
  - `PasswordAuthentication no`
  - `KbdInteractiveAuthentication no`
  - `PermitEmptyPasswords no`
  - And restart `ssh`. References:
  [Mozilla SSH guide](https://infosec.mozilla.org/guidelines/openssh.html),
  [DigitalOcean's hardening doc](https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-22-04).
  Confirm with `sudo ssh -G localhost | grep -E '(passwordauth|permitroot)'`.
- [ ] **`fail2ban` or equivalent for SSH.** Even with key-only auth,
  bots will hit port 22 forever. `apt install fail2ban` ships sensible
  defaults; the `sshd` jail is on by default. Verify:
  `sudo fail2ban-client status sshd`.
- [ ] **Cloud-provider firewall.** The container hardening doesn't help
  if you accidentally leave random ports open at the cloud-network layer.
  The port set depends on which optional features you've enabled —
  baseline is the four sing-box-native protocols, additions stack on top:

  | Port | Proto | What | When it's needed |
  |---|---|---|---|
  | `22` | tcp | SSH | always (lock to admin IPs) |
  | `443` | tcp | Reality | always |
  | `443` | udp | hy2 (single-port mode) | always (also keep open in port-hopping mode as fallback for older clients) |
  | `8443` | tcp | ShadowTLS | always |
  | `<low>:<high>` | udp | hy2 port-hopping range | if `defaults.hy2.server_ports` is set in `profiles.yaml` (see [hazards.md #10](hazards.md#10-gfw-marks-ips-sending-sustained-udp443-volume--drops-all-incoming-udp-for-1h)) |
  | `51820` | udp | AmneziaWG | if any user has `awg` in protocols (see quickstart §9) |

  ws-cf doesn't appear here directly — it lives behind your reverse
  proxy on `443/tcp` (Cloudflare → reverse proxy → docker0:10001
  internally). Port `10001` is bound to the docker0 bridge IP only and
  must not be reachable on the public IP.

  Multi-VNIC deployments: hy2 + Reality + AWG bind to `${INCOMING_IP_1}`,
  so those rules go in the secondary VNIC's NSG (or its subnet's
  security list). SSH + ShadowTLS + the reverse proxy bind on the
  primary VNIC.

  - **Oracle Cloud:** edit the VCN's security list / NSG attached to
    each VNIC. Lock SSH to your home IP if practical.
  - **AWS:** same, via the VPC Security Group attached to the instance.
  - **GCP:** same, via firewall rules attached to the VPC.
  - **Hetzner / Scaleway / DO / etc.:** equivalent firewall panel in the
    web console.
- [ ] **Host firewall** as defense-in-depth (separate from cloud-side).
  `ufw` on Debian/Ubuntu — uncomment the lines that match the features
  you've enabled (baseline + opt-ins; mirrors the cloud-firewall table):
  ```
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow 22/tcp
  sudo ufw allow 443/tcp
  sudo ufw allow 443/udp
  sudo ufw allow 8443/tcp
  # If hy2 port-hopping is enabled (defaults.hy2.server_ports set):
  sudo ufw allow 20000:30000/udp
  # If AWG is enabled (any user has 'awg' in profiles.yaml protocols):
  sudo ufw allow 51820/udp
  sudo ufw enable
  ```
  Verify: `sudo ufw status verbose`. Cloud firewall + host firewall
  is belt-and-braces; if you can only do one, do the cloud firewall (it
  blocks earlier in the path).
- [ ] **Unattended security updates.** `unattended-upgrades` on Debian/
  Ubuntu auto-installs security patches without human intervention:
  ```
  sudo apt install unattended-upgrades
  sudo dpkg-reconfigure -plow unattended-upgrades
  ```
  Verify the timer is active: `systemctl status apt-daily-upgrade.timer`.
  Reference: [Debian wiki](https://wiki.debian.org/UnattendedUpgrades).

## Sysctls

- [ ] **`net.ipv4.ip_unprivileged_port_start=443`** — required so the
  singbox-server container's non-root UID can bind 443/8443. The
  quickstart already has this; it goes in
  `/etc/sysctl.d/99-singbox-unpriv-port.conf`.
- [ ] **`net.core.{rmem,wmem}_max=16777216`** — UDP socket buffer ceiling
  for Hysteria2 (QUIC). Without this, the kernel's default ~208 KiB
  caps `setsockopt(SO_RCVBUF/SNDBUF)` and throttles QUIC throughput on
  long-RTT / lossy paths; Hysteria2 upstream recommends 16 MiB so
  per-socket buffers can grow enough to absorb reorder windows without
  drops. TCP flows (ShadowTLS, Reality, ws-cf) auto-scale via
  `net.ipv4.tcp_{r,w}mem` and aren't affected. Goes in
  `/etc/sysctl.d/99-singbox-quic.conf`:
  ```
  net.core.rmem_max = 16777216
  net.core.wmem_max = 16777216
  ```
  Verify after `sysctl --system`: `sysctl net.core.{r,w}mem_max`.

## Host-system

- [ ] **Backup `.secrets.yaml`.** The renderer auto-generates UUIDs,
  passwords, and the Reality keypair into this file. Losing it means
  re-rotating every credential and re-onboarding every user. Encrypted
  off-host backup is mandatory; rotate the encryption key separately.
  The egressor repo intentionally doesn't ship a backup script — pick
  one that fits your stack (`borg`, `restic`, `rclone` to a cloud
  destination with `--password-command`, etc.).
- [ ] **Backup `home_wg/*.conf`.** Each device's WireGuard private
  key — losing one means re-deriving that device's WG identity and
  pushing a new config to the user. Same backup target as
  `.secrets.yaml`.
- [ ] **Mount the secrets dir at 0700, files at 0600.** The renderer
  clamps `.secrets.yaml` to 0600 on every write, but the parent
  `singbox-profiles/` dir defaults to 0755. Tighten:
  ```
  chmod 0700 singbox-profiles/home_wg
  ```
- [ ] **Image bumps cadence.** sing-box releases regularly with
  bug/security fixes. `singbox-server/bump-image.sh` validates
  the new image with `sing-box check` before swapping the digest pin.
  Run it monthly via cron (the quickstart has the line). Skipping bumps
  for >6 months means missing real CVEs. Each bump is its own commit on
  `singbox-server/compose.yaml` naming the sing-box version behind the
  digest (1.14.1 as of 2026-09-15). If you have AWG enabled, run
  `awg-server/bump-image.sh` on the same cadence — fewer releases but
  the same supply-chain risk.

## awg-server (only if AWG enabled)

awg-server runs `amneziavpn/amneziawg-go`, the official Amnezia upstream
image. Userspace WireGuard fundamentally needs `NET_ADMIN` to manage the
TUN device + iptables NAT rules — there's no way to drop that capability
without breaking the daemon. This is the only container in egressor with
`NET_ADMIN`.

Compensating hardenings (already enforced in `awg-server/compose.yaml`):

- **Image digest pin.** `amneziavpn/amneziawg-go:latest@sha256:<index-digest>`.
  A Docker Hub credential compromise can't silently push a backdoor; bumps
  go through `awg-server/bump-image.sh` (resolves via
  `docker buildx imagetools inspect`, validates pull, then `safe-restart`).
- **Read-only root filesystem.** Daemon writes only to `/run` (tmpfs).
- **Narrow port exposure.** UDP/51820 only, bound to `${INCOMING_IP_1}`
  (not `0.0.0.0`). Single-VNIC deployments can set this to the host's
  primary IP if separation isn't available.
- **`no-new-privileges`** + **`mem_limit: 256m`** + **`cpus: 0.5`**.
- **Opt-in compose profile.** awg-server is only started when the
  operator passes `--profile awg-server` (or `--profile vpn` / `--profile
  all`); it stays off on deployments without AWG users.

The compensating-controls bundle plus the digest pin makes the residual
risk roughly equivalent to the singbox-server container's risk surface,
even though `cap_drop: [ALL]` isn't viable here.

**Architecture caveat — amneziavpn/amneziawg-go is amd64-only as of
2026-04.** ARM hosts (Oracle Ampere, Raspberry Pi) currently can't pull
the upstream image. Either build the daemon from source (the upstream
repo at github.com/amnezia-vpn/amneziawg-go has a Dockerfile that builds
on ARM) and pin the resulting image's digest in `awg-server/compose.yaml`,
or skip AWG until upstream ships a multi-arch image. **Do not** swap in a
random community-maintained ARM image — it defeats the digest-pin
discipline. See [hazards.md](hazards.md).

## Things specifically NOT in scope

These are out of scope for egressor. If you need them, build them
alongside.

- **Per-user bandwidth caps** at the sing-box layer (sing-box doesn't
  support it — see [hazards.md #7](hazards.md#7-sing-box-has-no-per-user-hy2-bandwidth-caps)).
- **Audit logging** of which user opened which connection (sing-box logs
  user names per connection; if you want a SIEM-style audit trail, point
  the container's stderr at a log shipper — promtail/Vector/Fluentbit
  to Loki/Splunk/CloudWatch — and strip the ANSI colors per
  [hazards.md #9](hazards.md#9-sing-box-ansi-colors-in-logs-are-not-suppressible-at-the-source)).
- **DDoS protection.** Cloudflare in front of WS-CDN gets you some
  layer-7 protection there. Reality / hy2 / ShadowTLS go direct to
  the VPS — protection at that layer is the cloud provider's job
  (Oracle Cloud, AWS Shield Standard, etc. — none of them are free
  beyond a baseline level).
- **Compliance certifications.** This is a household / small-team
  tool. If you're handling regulated data over the tunnel, the
  responsibility for whatever certification regime applies is on the
  operator.

## After deploy

- [ ] **Verify the cloud firewall is what you expected.** From an
  outside host:
  ```
  for port in 22 80 443 2222 3000 8080 8443 9090 9091; do
    nc -zv -w 2 <your-vps-ip> $port 2>&1 | grep -E 'succeeded|refused|timed'
  done
  ```
  Only 22, 443, 8443 should report "succeeded". (Add 80 if you serve
  Let's Encrypt HTTP-01; otherwise it should be closed too.)
- [ ] **Verify the singbox-server container is running with the
  expected cap set.** Caps should be empty:
  ```
  docker inspect singbox-server --format '{{json .HostConfig.CapDrop}}'
  # → ["ALL"]
  docker inspect singbox-server --format '{{json .HostConfig.CapAdd}}'
  # → null
  ```
  If `CapAdd` is non-null, something added a capability — review
  before continuing.
- [ ] **Verify pinned-by-digest, not by tag.** `docker inspect
  singbox-server --format '{{.Config.Image}}'` should end in
  `@sha256:<hex>`, not `:latest`. A `:latest` tag means the image can
  be replaced under you between deploys.

## Periodic

These run as cron in production (the quickstart's cron block). Check
quarterly that they're still firing:

- `safe-restart.sh` — invoked by `render.py --server-apply` on every
  cred rotation; should run cleanly, no error notifications.
- `rotate-shortids.sh` — monthly; cred rotation with 7-day grace.
- `rotate-hy2-cert.sh` — yearly; no flag day (clients pin the next key a cycle ahead).
- `rotate-realitykey.sh` — quarterly; flag-day for Reality.
- `bump-image.sh` — monthly; controlled image-digest upgrade.

A silent cron is a dead cron. Wire a `NOTIFY=` script (Discord, Slack,
or your own webhook) into each so a failure pings someone. The
suppliedscripts all support `NOTIFY` as an env-var hook.
