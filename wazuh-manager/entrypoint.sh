#!/bin/bash
# 99-attense-setup.sh — runs from /entrypoint-scripts/ (loaded by 2-manager AFTER
# 0-wazuh-init has populated /var/ossec/etc from the image's permanent-data).
#
# Installs custom rules and enables authd password-less auto-enrollment for
# the lab.
set -euo pipefail

log() { echo "[attense-setup] $*"; }

# ── 1. Install custom rules ───────────────────────────────────────────────────
CUSTOM_RULES_SRC="/custom/local_rules.xml"
CUSTOM_RULES_DST="/var/ossec/etc/rules/local_rules.xml"
if [ -f "$CUSTOM_RULES_SRC" ]; then
    log "Installing custom rules → $CUSTOM_RULES_DST"
    mkdir -p "$(dirname "$CUSTOM_RULES_DST")"
    cp "$CUSTOM_RULES_SRC" "$CUSTOM_RULES_DST"
    chown root:wazuh "$CUSTOM_RULES_DST" 2>/dev/null || true
    chmod 660 "$CUSTOM_RULES_DST"
fi

# ── 2. Enable password-less auto-enrollment on authd ──────────────────────────
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    if grep -q "<use_password>yes</use_password>" "$OSSEC_CONF"; then
        log "Disabling authd password (lab mode)"
        sed -i 's|<use_password>yes</use_password>|<use_password>no</use_password>|g' "$OSSEC_CONF"
    fi
    if grep -q "<auth>" "$OSSEC_CONF" && grep -q "<disabled>yes</disabled>" "$OSSEC_CONF"; then
        log "Ensuring authd is enabled"
        awk '
            /<auth>/ {in_auth=1}
            /<\/auth>/ {in_auth=0}
            { if (in_auth) sub("<disabled>yes</disabled>", "<disabled>no</disabled>"); print }
        ' "$OSSEC_CONF" > "${OSSEC_CONF}.new" && mv "${OSSEC_CONF}.new" "$OSSEC_CONF"
    fi
else
    log "WARN: ossec.conf still missing after mount_permanent_data — authd tweaks skipped."
fi

# ── 3. Pre-create log directories analysisd needs ────────────────────────────
YEAR=$(date +%Y)
mkdir -p \
    "/var/ossec/logs/archives/$YEAR" \
    "/var/ossec/logs/alerts/$YEAR" \
    "/var/ossec/logs/firewall/$YEAR"
chown -R wazuh:wazuh /var/ossec/logs/ 2>/dev/null || true
log "Log directories ensured for $YEAR"
