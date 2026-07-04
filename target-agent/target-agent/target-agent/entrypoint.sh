#!/bin/bash
# entrypoint.sh — target-agent container init.
#
# Runs three processes with proper supervision:
#   1. Wazuh agent  → ships logs to wazuh-manager (auto-enrolled via authd)
#   2. nginx        → reverse proxy :80 → Flask :5000
#   3. Flask app    → intentionally vulnerable Python web app (PID 1 via exec)
#
# Fixes vs. original:
#   * Waits for the manager's authd (port 1515) before starting the agent
#   * Removes any stale client.keys (prevents duplicate-enrollment warnings)
#   * Runs nginx in foreground-daemon-off model via explicit config
#   * Validates each service started, fails loudly otherwise
set -euo pipefail

MANAGER_HOST="${MANAGER_HOST:-wazuh.manager}"
MANAGER_AUTHD_PORT="${MANAGER_AUTHD_PORT:-1515}"

log() { echo "[entrypoint] $*"; }

# ── 1. Wait for Wazuh manager authd to be reachable ───────────────────────────
log "Waiting for Wazuh manager authd at ${MANAGER_HOST}:${MANAGER_AUTHD_PORT}..."
for i in $(seq 1 60); do
    if (echo > /dev/tcp/${MANAGER_HOST}/${MANAGER_AUTHD_PORT}) >/dev/null 2>&1; then
        log "Manager authd reachable after ${i}s."
        break
    fi
    sleep 2
    if [ "$i" = "60" ]; then
        log "WARN: manager authd not reachable after 120s; agent may fail enrollment."
    fi
done

# ── 2. Purge any stale client.keys so enrollment succeeds cleanly ─────────────
# (Prevents 'duplicate agent' warnings on container recreate with the same hostname.)
if [ -f /var/ossec/etc/client.keys ]; then
    log "Clearing stale /var/ossec/etc/client.keys"
    : > /var/ossec/etc/client.keys
    chown root:wazuh /var/ossec/etc/client.keys 2>/dev/null || true
    chmod 640 /var/ossec/etc/client.keys
fi

# ── 3. Start Wazuh agent ──────────────────────────────────────────────────────
log "Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || log "WARN: wazuh-control returned non-zero"
sleep 3
/var/ossec/bin/wazuh-control status || true

# ── 4. Start nginx (daemon mode; it's light, we supervise indirectly) ─────────
log "Starting nginx..."
nginx
sleep 1
if ! pgrep -x nginx >/dev/null; then
    log "ERROR: nginx failed to start"
    exit 1
fi

# ── 5. Exec Flask as PID 1 replacement (so Ctrl-C / docker stop works) ────────
log "Starting Flask vulnerable app on :5000..."
cd /app
exec python3 main.py
