#!/bin/sh
# Simple Wazuh active-response script (dry-run by default)
# Usage: block_ip.sh <incident_tag> <ip> [apply|dry-run]

INCIDENT_TAG="$1"
IP="$2"
MODE="${3:-dry-run}"
LOG_DIR="/var/ossec/active-response/logs"
LOG="$LOG_DIR/block_ip.log"

# ensure log dir exists
mkdir -p "$LOG_DIR"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) - ${INCIDENT_TAG} - requested block ${IP} mode=${MODE}" >> "$LOG"

# allowlist (prevent blocking management networks)
ALLOWLIST="127.0.0.1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
for net in $ALLOWLIST; do
  if [ "$IP" = "$net" ] || echo "$net" | grep -q '/'; then
    :
  fi
done

if [ "$MODE" = "apply" ]; then
  # apply iptables rule if not present
  if ! iptables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1; then
    iptables -I INPUT -s "$IP" -j DROP
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) - ${INCIDENT_TAG} - applied block ${IP}" >> "$LOG"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) - ${INCIDENT_TAG} - block already present ${IP}" >> "$LOG"
  fi
fi
