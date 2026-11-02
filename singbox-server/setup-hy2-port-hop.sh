#!/usr/bin/env bash
# Add the iptables NAT redirect that backs Hysteria2 port-hopping.
# Clients with `server_ports: ["20000:30000"]` dial random ports from
# that range; this rule collapses them back to the single port that
# sing-box's hy2 inbound actually listens on. Without it, clients would
# hit closed ports.
#
# Why we do this: a national firewall marks IPs that send sustained high-volume
# UDP traffic on a fixed port and drops *all* incoming UDP from the
# overseas side for ~hour windows (apernet/hysteria#1157). Spreading
# packets across thousands of ports keeps any single 5-tuple flow under
# the volume threshold while the aggregate gets through. See
# docs/hazards.md.
#
# Idempotent. Saves the resulting ruleset via netfilter-persistent so
# it survives reboot.
#
# Env (with defaults matching the production manifest):
#   HY2_LISTEN_IP    IP that sing-box's hy2 inbound binds to
#                    (must match defaults.reality.server in profiles.yaml)
#   HY2_LISTEN_PORT  port sing-box listens on
#   HY2_PORT_RANGE   range to redirect from (must match the value of
#                    defaults.hysteria2.server_ports[0] in profiles.yaml)

set -euo pipefail

# Default to ${INCOMING_IP_1} from the .env (matches singbox-server's
# compose.yaml binding). Fail fast if neither is set so the user gets a
# pointer to the right knob instead of a cryptic iptables error later.
HY2_LISTEN_IP="${HY2_LISTEN_IP:-${INCOMING_IP_1:?HY2_LISTEN_IP and INCOMING_IP_1 both unset; export one}}"
HY2_LISTEN_PORT="${HY2_LISTEN_PORT:-443}"
HY2_PORT_RANGE="${HY2_PORT_RANGE:-20000:30000}"

# Validate the range up-front: iptables would also reject malformed input,
# but its error messages are cryptic and a typo here (e.g. swapped delimiter
# or missing upper bound) would otherwise only surface mid-rule. Both ports
# must be 1..65535 and low <= high.
if ! [[ ${HY2_PORT_RANGE} =~ ^([0-9]+):([0-9]+)$ ]] \
   || (( BASH_REMATCH[1] < 1 || BASH_REMATCH[1] > 65535 )) \
   || (( BASH_REMATCH[2] < 1 || BASH_REMATCH[2] > 65535 )) \
   || (( BASH_REMATCH[1] > BASH_REMATCH[2] )); then
    echo "invalid HY2_PORT_RANGE='${HY2_PORT_RANGE}' (expected low:high, both 1..65535, low<=high)" >&2
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found" >&2
    exit 1
fi

# Use explicit DNAT instead of REDIRECT --to-ports. REDIRECT rewrites the
# destination IP to the *primary* address of the incoming interface, which
# on a multi-VNIC host is the wrong VNIC: hy2 binds the secondary
# (${INCOMING_IP_1}) but the NIC's primary is ${VNIC_PRIMARY_IP} — and
# ${VNIC_PRIMARY_IP}:udp/443 is DNAT'd by Docker to the awg-server container.
# Result: hy2 port-hop traffic gets silently delivered to AmneziaWG, which
# drops it. DNAT with
# an explicit --to-destination keeps both IP and port pinned to where
# sing-box actually listens. Insert at top of PREROUTING so it precedes
# the DOCKER chain jump.
# Drop any legacy REDIRECT rule from older versions of this script.
while iptables -t nat -C PREROUTING \
        -d "$HY2_LISTEN_IP" -p udp --dport "$HY2_PORT_RANGE" \
        -j REDIRECT --to-ports "$HY2_LISTEN_PORT" 2>/dev/null; do
    iptables -t nat -D PREROUTING \
        -d "$HY2_LISTEN_IP" -p udp --dport "$HY2_PORT_RANGE" \
        -j REDIRECT --to-ports "$HY2_LISTEN_PORT"
    echo "Removed legacy REDIRECT rule."
done

if ! iptables -t nat -C PREROUTING \
        -d "$HY2_LISTEN_IP" -p udp --dport "$HY2_PORT_RANGE" \
        -j DNAT --to-destination "$HY2_LISTEN_IP:$HY2_LISTEN_PORT" 2>/dev/null; then
    iptables -t nat -I PREROUTING 1 \
        -d "$HY2_LISTEN_IP" -p udp --dport "$HY2_PORT_RANGE" \
        -j DNAT --to-destination "$HY2_LISTEN_IP:$HY2_LISTEN_PORT"
    echo "Added: UDP $HY2_LISTEN_IP:$HY2_PORT_RANGE -> $HY2_LISTEN_IP:$HY2_LISTEN_PORT"
else
    echo "Already present: UDP $HY2_LISTEN_IP:$HY2_PORT_RANGE -> $HY2_LISTEN_IP:$HY2_LISTEN_PORT"
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null
    echo "Persisted via netfilter-persistent."
else
    echo "WARNING: netfilter-persistent not installed — rule will not survive reboot." >&2
fi
