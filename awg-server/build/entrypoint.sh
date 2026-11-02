#!/bin/bash
set -e

IFACE=wg0
CONF=/etc/amneziawg/wg0.conf

cleanup() {
    echo "Shutting down $IFACE..."
    iptables -t nat -D POSTROUTING -s 10.9.0.0/24 -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i $IFACE -j ACCEPT 2>/dev/null || true
    ip link del $IFACE 2>/dev/null || true
}
trap cleanup EXIT SIGTERM SIGINT

# Create TUN node if the host didn't bind-mount /dev/net/tun
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# amneziawg-go creates the WireGuard interface and then exits, handing it
# off to the kernel (oracle 6.17 has native AmneziaWG support in the
# wireguard interface type with extended UAPI for jc/jmin/jmax/h1-h4).
# WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD is set to suppress the
# "kernel has support" banner that would otherwise prevent it from starting.
WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 amneziawg-go $IFACE
# (exits here — interface is now kernel-owned)

# Load the AmneziaWG config: private key, listen port, Jc/Jmin/Jmax,
# S1/S2, H1-H4, and peer block.
awg setconf $IFACE $CONF

# Assign tunnel address and bring interface up
ip addr add 10.9.0.1/24 dev $IFACE
ip link set mtu 1420 up dev $IFACE

# NAT so tunnel clients can reach the internet through this host
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -j MASQUERADE
iptables -A FORWARD -i $IFACE -j ACCEPT

PORT=$(awk '/^ListenPort/{print $3}' $CONF)
echo "AmneziaWG listening on UDP :${PORT} (interface $IFACE)"

# SOCKS5 proxy for sing-box integration — binds to the VPN gateway address
# so only clients connected through the AmneziaWG tunnel can reach it.
# sing-box uses this as the ericamneziawg outbound (detoured via client-wg0).
microsocks -i 10.9.0.1 -p 1080 &

echo "SOCKS5 proxy listening on 10.9.0.1:1080"

# Kernel owns the interface now — just keep the container alive
sleep infinity &
wait $!
