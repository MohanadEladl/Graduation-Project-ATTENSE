#!/usr/bin/env bash
# setup_auditd.sh — Install auditd and configure EXECVE monitoring for the Watcher Agent.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash setup_auditd.sh"
  exit 1
fi

echo "[1/4] Installing auditd..."
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins

echo "[2/4] Writing audit rules..."
RULES_FILE="/etc/audit/rules.d/watcher.rules"
cat > "$RULES_FILE" <<'EOF'
-a exit,always -F arch=b64 -S execve -k cmd_monitor
-a exit,always -F arch=b32 -S execve -k cmd_monitor
EOF
echo "Rules written to $RULES_FILE"

echo "[3/4] Loading rules and restarting auditd..."
augenrules --load
systemctl restart auditd

echo "[4/4] Done. Verification:"
echo "  Check active rules : auditctl -l | grep cmd_monitor"
echo "  Tail the log live  : tail -f /var/log/audit/audit.log"
echo "  Trigger a test     : ls /tmp && ausearch -k cmd_monitor --start recent"
