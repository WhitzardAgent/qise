#!/bin/bash
# Restrict sandbox network: only allow outbound to api.siliconflow.cn:443
# Run with: sudo bash restrict_network.sh
set -e

BRIDGE="qise-sandbox"  # Docker compose network bridge name

echo "Applying network restrictions for $BRIDGE..."

# Get the bridge interface name
IFACE=$(docker network inspect "${BRIDGE}" -f '{{.Options}}' 2>/dev/null | grep -o 'br-[a-f0-9]*' || echo "br-$(docker network inspect "${BRIDGE}" -f '{{.Id}}' 2>/dev/null | head -c 12)")

if [ -z "$IFACE" ]; then
    echo "ERROR: Cannot find bridge interface for network '$BRIDGE'"
    echo "Make sure 'docker compose up' has been run first."
    exit 1
fi

echo "Bridge interface: $IFACE"

# Allow container-to-container communication
iptables -I FORWARD -i "$IFACE" -o "$IFACE" -j ACCEPT

# Allow DNS (UDP/TCP port 53)
iptables -I FORWARD -i "$IFACE" -p udp --dport 53 -j ACCEPT
iptables -I FORWARD -i "$IFACE" -p tcp --dport 53 -j ACCEPT

# Allow HTTPS to SiliconFlow (resolve IP dynamically)
# Note: DNS resolution happens before iptables, so we allow HTTPS generally
# and restrict at the application level via Qise proxy
iptables -I FORWARD -i "$IFACE" -p tcp --dport 443 -j ACCEPT

# Drop all other outbound traffic
iptables -A FORWARD -i "$IFACE" -j DROP

echo "Network restrictions applied:"
echo "  - Container-to-container: ALLOWED"
echo "  - DNS (port 53): ALLOWED"
echo "  - HTTPS (port 443): ALLOWED"
echo "  - All other outbound: BLOCKED"
echo ""
echo "To remove restrictions:"
echo "  sudo iptables -D FORWARD -i $IFACE -j DROP"
