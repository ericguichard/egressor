#!/usr/bin/env python3
"""
singbox-exporter — tiny Prometheus exporter for sing-box's clash_api.

Why: sing-box's clash_api exposes live connection + global byte totals, but
the data only lives there until somebody asks for it. Prometheus + Grafana
want a pull endpoint. This process proxies one call to clash_api per scrape
and returns a text-format metrics payload. No background state — every
scrape is independent — so restarts never drop counters (clash_api holds
the cumulative values for the life of the sing-box process).

Why on-demand and not a long-running poller:
  - simpler (no state, no race on shutdown)
  - clash_api's uploadTotal/downloadTotal ARE the cumulative source of
    truth; we just forward them as Prometheus counters
  - per-inbound live connection counts come from the same /connections
    response, so one HTTP call per scrape covers everything we expose

Per-user metrics: clash_api connection metadata carries the inbound tag but
not the authenticated user. The server config therefore routes each user
through a direct outbound of their own, tagged "user:<name>" (render.py,
_server_user_accounting): the tag shows up in the connection's `chains` and
the credential name in its `rule` ("auth_user=<name> => route(...)"). From
those we accrue singbox_cumulative_*_bytes_by_user, labelled with user,
credential, source IP and inbound. A connection with no such tag (a server
config rendered before that change) is accrued under user="".
Per-source-IP metrics stay exposed as well (singbox_live_connections_by_ip,
singbox_live_bytes_by_ip, singbox_cumulative_*_bytes_by_ip).

Deployment: host networking (so 127.0.0.1:9095 and 172.17.0.1:9097 are
both reachable from the same namespace). Secret is read from the
CLASH_SECRET env var at startup.
"""
import concurrent.futures
import heapq
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

CLASH_URL = os.environ.get("CLASH_URL", "http://127.0.0.1:9095/connections")
CLASH_SECRET = os.environ.get("CLASH_SECRET", "")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "172.17.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9097"))
TIMEOUT_S = float(os.environ.get("CLASH_TIMEOUT", "3.0"))

# Optional bearer-token auth on /metrics. When set, callers must send
# `Authorization: Bearer <token>` exactly matching EXPORTER_SECRET. When
# empty/unset, /metrics is served without auth (backwards-compat with the
# original deployment). Why: the exporter listens on 172.17.0.1:9097, which
# is reachable from ANY container on ANY docker bridge (aio_network
# included) via host routing — a compromised container could read per-IP
# metrics with rDNS labels that reveal household users' residential/
# carrier IPs. Prometheus is the only legitimate scraper; a shared-secret
# gate is the minimum-blast-radius fix. /healthz stays unauthenticated so
# the docker healthcheck doesn't need the token.
EXPORTER_SECRET = os.environ.get("EXPORTER_SECRET", "")

# --- PTR (reverse-DNS) enrichment for the per-IP metrics ---
# Grafana's top-10-by-IP panels show raw numeric IPs by default, which gives
# no signal about whether an IP is a household user's residential/mobile
# carrier, a known scanner, a cloud VM, etc. Resolving the PTR once and
# emitting it as an extra label lets the dashboard render "92.184.117.188
# 92-184-117-188.mobile.fr.orangecustomers.net" — same UX as the Discord
# ban-notification rDNS added 2026-04-23.
#
# Design:
#   - Each scrape looks up PTRs only for the top-50 IPs we already emit.
#   - Results are cached in-process for PTR_TTL_S (1h default) — PTRs
#     for household + scanner IPs are very stable, and a stale PTR is
#     far less harmful than stalling the scrape.
#   - Lookups run in a bounded ThreadPoolExecutor (blocking gethostbyaddr
#     can take multi-second on timeout). We wait for at most PTR_WAIT_S
#     total per scrape; any lookup that hasn't returned by then emits
#     an empty PTR for this scrape and is retried next tick.
#   - RFC1918 + loopback source IPs (docker0 bridge, Traefik-fronted
#     connections) are skipped — they have no meaningful public PTR,
#     and reverse lookups on private IPs are slow timeouts waiting to
#     happen against resolvers that refuse them.
#   - Cache is soft-capped at 500 entries so a cardinality spike from
#     a scanner wave can't bloat the process indefinitely.
PTR_TTL_S = float(os.environ.get("PTR_TTL", "3600"))
PTR_WAIT_S = float(os.environ.get("PTR_WAIT", "2.0"))
PTR_WORKERS = int(os.environ.get("PTR_WORKERS", "8"))
PTR_CACHE_MAX = int(os.environ.get("PTR_CACHE_MAX", "500"))

# Cumulative-bytes tracking: how long an IP can be silent before we forget
# its accrued totals. Bounds the per-IP series cardinality so a one-time
# scanner doesn't sit forever in Prometheus storage. 6h default —
# household traffic patterns mean a real user reappears well within that
# window; pure-scanner IPs go away after 6h of silence.
CUMULATIVE_TTL_S = float(os.environ.get("CUMULATIVE_TTL", "21600"))

if not CLASH_SECRET:
    # Fail loudly at startup rather than silently serving singbox_up=0
    # forever — a missing secret is almost certainly a deployment bug,
    # not a transient condition.
    print("FATAL: CLASH_SECRET env is empty", file=sys.stderr)
    sys.exit(1)


# Cumulative-by-IP state. _CONN_LAST_BYTES tracks per-connection (upload,
# download) at last scrape so we can compute deltas and accrue them into
# _CUMULATIVE_BY_IP without double-counting. _CUMULATIVE_BY_IP is what
# we export — real Counter semantics (monotonically increasing per IP
# until exporter restart). Module-level state, single-thread access via
# the BaseHTTPServer worker, so no lock needed (the metrics handler
# serializes scrapes).
_CONN_LAST_BYTES = {}      # connection_id -> (up_bytes, down_bytes)
_CUMULATIVE_BY_IP = {}     # ip -> [up_total, down_total, last_seen_epoch]
# Same accrual, keyed by (user, credential, ip, inbound) — see the module
# docstring for where the user comes from.
_CUMULATIVE_BY_USER = {}   # (user, auth, ip, inbound) -> [up, down, last_seen]
USER_TAG_PREFIX = "user:"
_AUTH_USER_RE = re.compile(r"auth_user=(\S+)")

_PTR_CACHE = {}            # ip -> (ptr_str, expires_at_epoch)
_PTR_CACHE_LOCK = threading.Lock()
_PTR_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=PTR_WORKERS, thread_name_prefix="ptr"
)


def _escape(v):
    # Prometheus exposition-format label-value escaping. Hoisted to module
    # scope so every emission block can reuse it without a local re-def.
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _is_private_ip(ip):
    """Skip reverse-DNS on RFC1918/loopback/link-local — no useful PTR and
    resolvers often block/slow-timeout these. Parsing failures (unknown IP
    strings like 'unknown') are treated as private → skipped."""
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


def _ptr_lookup(ip):
    """Blocking reverse lookup. Returns the PTR without trailing dot, or ''
    on any failure. Intended to run in a ThreadPoolExecutor."""
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return (name or "").rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _prune_cache(now):
    """Drop expired + oldest entries if the cache has grown past PTR_CACHE_MAX.
    Caller holds _PTR_CACHE_LOCK."""
    if len(_PTR_CACHE) <= PTR_CACHE_MAX:
        # Still prune expired entries cheaply if we happen to be iterating.
        expired = [k for k, (_, exp) in _PTR_CACHE.items() if exp <= now]
        for k in expired:
            _PTR_CACHE.pop(k, None)
        return
    # Over-capacity: drop the 20% with the nearest-expiry (LRU approximation
    # via TTL). Keeps long-stable household IPs; evicts short-lived scanner
    # bursts first since they have the oldest entries.
    victims = sorted(_PTR_CACHE.items(), key=lambda kv: kv[1][1])[: len(_PTR_CACHE) // 5]
    for k, _ in victims:
        _PTR_CACHE.pop(k, None)


def resolve_ptrs(ips):
    """Return {ip: ptr_or_empty} for all IPs, honouring the TTL cache and
    the PTR_WAIT_S global deadline. IPs that didn't resolve in time get ""
    (and are NOT cached, so they retry on the next scrape)."""
    now = time.time()
    out = {}
    to_resolve = []

    with _PTR_CACHE_LOCK:
        for ip in ips:
            if _is_private_ip(ip):
                out[ip] = ""
                continue
            entry = _PTR_CACHE.get(ip)
            if entry and entry[1] > now:
                out[ip] = entry[0]
            else:
                to_resolve.append(ip)

    if not to_resolve:
        return out

    futs = {_PTR_POOL.submit(_ptr_lookup, ip): ip for ip in to_resolve}
    done, _not_done = concurrent.futures.wait(futs, timeout=PTR_WAIT_S)

    with _PTR_CACHE_LOCK:
        for f in done:
            ip = futs[f]
            try:
                ptr = f.result(timeout=0)
            except Exception:
                ptr = ""
            _PTR_CACHE[ip] = (ptr, now + PTR_TTL_S)
            out[ip] = ptr
        _prune_cache(now)

    # Unfinished lookups: serve empty for this scrape; the background
    # thread will finish eventually and its result is discarded (we only
    # cache via the `done` path above to avoid a race where a lookup
    # races with a newer cache write).
    for ip in to_resolve:
        if ip not in out:
            out[ip] = ""
    return out


def _conn_user(conn):
    """(user, credential) of a connection, "" for whichever is unknown."""
    user = next((t[len(USER_TAG_PREFIX):] for t in conn.get("chains") or []
                 if t.startswith(USER_TAG_PREFIX)), "")
    m = _AUTH_USER_RE.search(conn.get("rule") or "")
    return user, (m.group(1) if m else "")


def fetch_clash():
    """Return the parsed JSON from /connections, or None on any failure."""
    req = urllib.request.Request(
        CLASH_URL, headers={"Authorization": f"Bearer {CLASH_SECRET}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        # Log and return None — the metrics handler will emit singbox_up=0
        # instead of 500-ing, so Prometheus scrape stays successful and
        # grafana/alerts can react to the gauge flipping.
        print(f"clash_api fetch failed: {e}", file=sys.stderr)
        return None


def render_metrics(data):
    """Build the Prometheus text-format payload from one clash_api snapshot."""
    lines = []

    if data is None:
        lines.append("# HELP singbox_up 1 if the last clash_api poll succeeded, else 0")
        lines.append("# TYPE singbox_up gauge")
        lines.append("singbox_up 0")
        return "\n".join(lines) + "\n"

    lines.append("# HELP singbox_up 1 if the last clash_api poll succeeded, else 0")
    lines.append("# TYPE singbox_up gauge")
    lines.append("singbox_up 1")

    # Global byte totals come from clash_api's cumulative counters — these
    # reset only when the sing-box process restarts, so exposing them as
    # Prometheus counters (not gauges) is correct: Prometheus handles the
    # reset via rate()'s counter-reset detection.
    lines.append("# HELP singbox_upload_bytes_total cumulative bytes uploaded (client→internet) since sing-box start")
    lines.append("# TYPE singbox_upload_bytes_total counter")
    lines.append(f"singbox_upload_bytes_total {int(data.get('uploadTotal', 0))}")

    lines.append("# HELP singbox_download_bytes_total cumulative bytes downloaded (internet→client) since sing-box start")
    lines.append("# TYPE singbox_download_bytes_total counter")
    lines.append(f"singbox_download_bytes_total {int(data.get('downloadTotal', 0))}")

    # Sing-box process RSS (bytes) as reported via clash_api. Cheap co-located
    # gauge; saves a separate cadvisor query for dashboards focused on VPN.
    if "memory" in data:
        lines.append("# HELP singbox_memory_bytes sing-box process resident memory in bytes")
        lines.append("# TYPE singbox_memory_bytes gauge")
        lines.append(f"singbox_memory_bytes {int(data.get('memory', 0))}")

    # Per-inbound live connection count + per-source-IP connection count
    # and per-source-IP cumulative bytes. Walk the /connections list once
    # and build both aggregations in lockstep to keep this O(conn).
    #
    # clash_api connection shape (relevant keys):
    #   metadata.type        -> inbound tag (e.g. "shadowtls/shadowtls-in")
    #   metadata.sourceIP    -> source IP on the wire-side (real client IP
    #                            for Reality/hy2/ShadowTLS inbounds; for
    #                            vless-ws-in this is the docker0 bridge IP
    #                            since Traefik fronts, which we surface as-is
    #                            — CF edge is already forwarded in X-F-F that
    #                            we don't parse here).
    #   upload/download      -> per-connection cumulative bytes so far.
    counts_by_inbound = Counter()
    counts_by_ip = Counter()
    upload_by_ip = Counter()
    download_by_ip = Counter()
    now = time.time()
    seen_conn_ids = set()
    for c in data.get("connections") or []:
        meta = c.get("metadata") or {}
        counts_by_inbound[meta.get("type", "unknown")] += 1
        src = meta.get("sourceIP") or "unknown"
        counts_by_ip[src] += 1
        # `upload`/`download` on a clash_api connection are cumulative
        # bytes for the lifetime of THIS connection. Summing them per-IP
        # across all live connections gives "bytes in-flight or transferred
        # so far by this IP's current connections" — a gauge, not a
        # counter. It resets whenever connections close, so don't use
        # rate() on it; graph as instant-value / max_over_time instead.
        cur_up = int(c.get("upload") or 0)
        cur_down = int(c.get("download") or 0)
        upload_by_ip[src] += cur_up
        download_by_ip[src] += cur_down

        # Cumulative-by-IP delta accrual. Compute the increase since the
        # last scrape for THIS connection (keyed by clash_api's UUID id)
        # and add it to the per-IP cumulative. New connections accrue
        # from 0; closed connections are pruned below (their final bytes
        # are already baked in). max(0, ...) is system-boundary defense
        # against clash_api occasionally returning a smaller value than
        # before — never want to double-decrement a Counter.
        conn_id = c["id"]
        seen_conn_ids.add(conn_id)
        prev_up, prev_down = _CONN_LAST_BYTES.get(conn_id, (0, 0))
        up_delta = max(0, cur_up - prev_up)
        down_delta = max(0, cur_down - prev_down)
        entry = _CUMULATIVE_BY_IP.setdefault(src, [0, 0, now])
        entry[0] += up_delta
        entry[1] += down_delta
        entry[2] = now
        user, auth = _conn_user(c)
        entry = _CUMULATIVE_BY_USER.setdefault(
            (user, auth, src, meta.get("type", "unknown")), [0, 0, now])
        entry[0] += up_delta
        entry[1] += down_delta
        entry[2] = now
        _CONN_LAST_BYTES[conn_id] = (cur_up, cur_down)

    # Drop tracking rows for connections that closed since last scrape
    # (their final bytes are already accrued). Set-difference is C-level
    # and reads cleaner than a listcomp+`in`.
    for k in _CONN_LAST_BYTES.keys() - seen_conn_ids:
        del _CONN_LAST_BYTES[k]
    # Age out IPs silent past CUMULATIVE_TTL_S so one-time scanners
    # don't sit in Prometheus storage forever.
    for ip in [ip for ip, (_, _, ts) in _CUMULATIVE_BY_IP.items()
               if now - ts > CUMULATIVE_TTL_S]:
        del _CUMULATIVE_BY_IP[ip]
    for key in [key for key, (_, _, ts) in _CUMULATIVE_BY_USER.items()
                if now - ts > CUMULATIVE_TTL_S]:
        del _CUMULATIVE_BY_USER[key]

    lines.append("# HELP singbox_live_connections current number of live connections per inbound")
    lines.append("# TYPE singbox_live_connections gauge")
    total = 0
    for inbound, n in sorted(counts_by_inbound.items()):
        # _escape is belt-and-braces here — inbound tags are ASCII identifiers,
        # but future tags could include special characters that need escaping.
        lines.append(f'singbox_live_connections{{inbound="{_escape(inbound)}"}} {n}')
        total += n
    lines.append("# HELP singbox_live_connections_total current total number of live connections")
    lines.append("# TYPE singbox_live_connections_total gauge")
    lines.append(f"singbox_live_connections_total {total}")

    # Per-source-IP series. High-cardinality risk: a scan burst could spray
    # Prometheus with thousands of transient IPs. Cap at the top 50 by
    # connection count (live) and cumulative download bytes (counters)
    # so Prometheus can't OOM on a cardinality spike. Residual IPs still
    # count toward the total inbound gauge. heapq.nlargest is O(n log 50)
    # — matters once _CUMULATIVE_BY_IP grows past a few hundred entries
    # under sustained scanner pressure.
    top_ips = counts_by_ip.most_common(50)
    cum_top_ips = heapq.nlargest(
        50, _CUMULATIVE_BY_IP.items(), key=lambda kv: kv[1][1]
    )

    # Reverse-DNS each top IP once per PTR_TTL_S. The `ptr` label lets
    # Grafana show "IP (hostname)" instead of raw numeric IPs. Empty ptr
    # is a valid value — Prometheus treats {ptr=""} and an absent ptr
    # label as distinct, so always emit the label with the same set on
    # every series for a given metric. Resolve the union of both top-50
    # IP sets in a single call so we only pay one PTR_WAIT_S deadline
    # per scrape.
    ptrs = resolve_ptrs(list({ip for ip, _ in top_ips}
                             | {ip for ip, _ in cum_top_ips}))

    def _emit_by_ip(name, mtype, help_text, items, value_fn):
        # Emit a singbox_*_by_ip series for each (ip, _) in `items`. value_fn
        # returns the numeric value for an item. Consolidates four nearly
        # identical loops into one helper to prevent label-set drift.
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        for item in items:
            ip = item[0]
            lines.append(
                f'{name}{{src_ip="{_escape(ip)}",ptr="{_escape(ptrs.get(ip, ""))}"}} {value_fn(item)}'
            )

    _emit_by_ip(
        "singbox_live_connections_by_ip", "gauge",
        "current live connections grouped by source IP (top 50)",
        top_ips, lambda kv: kv[1],
    )
    _emit_by_ip(
        "singbox_live_upload_bytes_by_ip", "gauge",
        "cumulative upload bytes of currently-live connections by source IP (resets as connections close; treat as gauge)",
        top_ips, lambda kv: upload_by_ip[kv[0]],
    )
    _emit_by_ip(
        "singbox_live_download_bytes_by_ip", "gauge",
        "cumulative download bytes of currently-live connections by source IP (resets as connections close; treat as gauge)",
        top_ips, lambda kv: download_by_ip[kv[0]],
    )
    # Cumulative-by-IP counters. Real Counter semantics — monotonically
    # increasing per IP, accrued from per-connection deltas above. Use
    # increase() / rate() / sum_over_time() in Grafana for "bytes
    # transferred in window". Series age out after CUMULATIVE_TTL_S of
    # silence to bound cardinality.
    _emit_by_ip(
        "singbox_cumulative_upload_bytes_by_ip", "counter",
        "total bytes uploaded by source IP since the exporter started seeing it (resets only on exporter restart or after CUMULATIVE_TTL of silence)",
        cum_top_ips, lambda kv: kv[1][0],
    )
    _emit_by_ip(
        "singbox_cumulative_download_bytes_by_ip", "counter",
        "total bytes downloaded by source IP since the exporter started seeing it (resets only on exporter restart or after CUMULATIVE_TTL of silence)",
        cum_top_ips, lambda kv: kv[1][1],
    )

    # Cumulative-by-user counters, same semantics as the by-IP pair above.
    # Capped like them: authenticated traffic is a handful of series, the
    # cap only matters for the user="" bucket under scanner pressure.
    cum_top_users = heapq.nlargest(
        200, _CUMULATIVE_BY_USER.items(), key=lambda kv: kv[1][0] + kv[1][1]
    )
    for name, idx, word in (("singbox_cumulative_upload_bytes_by_user", 0, "uploaded"),
                            ("singbox_cumulative_download_bytes_by_user", 1, "downloaded")):
        lines.append(f"# HELP {name} total bytes {word} per user, credential, source IP and inbound (resets only on exporter restart or after CUMULATIVE_TTL of silence)")
        lines.append(f"# TYPE {name} counter")
        for (user, auth, ip, inbound), totals in cum_top_users:
            lines.append(
                f'{name}{{user="{_escape(user)}",auth="{_escape(auth)}",'
                f'src_ip="{_escape(ip)}",inbound="{_escape(inbound)}"}} {totals[idx]}'
            )

    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    # Shorten the default BaseHTTPRequestHandler access log — it's every
    # Prometheus scrape otherwise, which floods docker logs pointlessly.
    def log_message(self, fmt, *args):  # noqa: N802 (stdlib name)
        return

    def do_GET(self):  # noqa: N802 (stdlib name)
        # /healthz — unauthenticated liveness probe for the docker healthcheck.
        # Body is tiny + stable; doesn't leak metrics. Used in compose.yaml.
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        # Bearer-token check. Constant-time compare so a timing-oracle
        # attacker can't sniff the secret one byte at a time over the
        # network. If EXPORTER_SECRET is empty, auth is disabled and any
        # caller can scrape (backward-compat default).
        if EXPORTER_SECRET:
            auth = self.headers.get("Authorization", "")
            expected = f"Bearer {EXPORTER_SECRET}"
            import hmac
            if not hmac.compare_digest(auth, expected):
                # 401 with WWW-Authenticate to be well-behaved; the realm
                # is cosmetic (Prom scrapers send the header unconditionally).
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="singbox-exporter"')
                self.end_headers()
                return

        body = render_metrics(fetch_clash()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"singbox-exporter listening on {LISTEN_HOST}:{LISTEN_PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
