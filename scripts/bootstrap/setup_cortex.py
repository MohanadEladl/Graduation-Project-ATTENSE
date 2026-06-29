#!/usr/bin/env python3
"""
setup_cortex.py ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Cortex First-Boot Automator
===============================================
Automates the entire Cortex ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ TheHive API key wiring in one shot.

What it does
------------
1. Waits for the Cortex container to become healthy.
2. Creates the first admin user + organisation via the Cortex bootstrap API.
3. Generates an API key for that organisation.
4. Enables the Wazuh-backed and target-app containment responders, with the
   backend configuration required to work without manual Cortex UI setup.
5. Writes the API key into secrets/{ORG_NAME}.env as CORTEX_API_KEY (gitignored).
   TheHive reads it via `key = ${?CORTEX_API_KEY}` in thehive/application.conf,
   so the live key is NEVER written into tracked config.
6. Recreates TheHive (docker compose up -d thehive) so it loads the new key.

Usage (from project root)
--------------------------
    python scripts/setup_cortex.py

Or inside the container network:
    docker compose run --rm attense-app python /scripts/setup_cortex.py

Requirements
------------
- Docker stack must be running (`docker compose up -d`)
- Cortex port 9001 must be reachable on localhost
- Run ONCE after first `docker compose up`; safe to re-run (idempotent checks included)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Load secrets/{ORG_NAME}.env automatically ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬
# The secrets file is named after the organisation (e.g. ATTENSE.env). It is
# EPHEMERAL: scripts/close_lab.py timestamp-backs-up and deletes it when the lab
# is closed, and this script auto-restores it from the newest backup on open
# (see _restore_secrets_if_missing above). It holds org bootstrap/runtime
# secrets only ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â externally-issued keys (VirusTotal/AbuseIPDB) live in the
# PERSISTENT secrets/enrichment.env instead.
#
# Load order: env vars already set in the shell always win over the file.

_SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"


def _resolve_secrets_path(org_name: str) -> Path:
    """Return the path to secrets/{org_name}.env."""
    return _SECRETS_DIR / f"{org_name}.env"


def _restore_secrets_if_missing(org_name: str) -> None:
    """
    Re-open support: if secrets/{org_name}.env is gone (deleted by close_lab.py
    when the lab was last closed), restore it from the newest timestamped backup
    under secrets/backups/. Backup names end in a UTC stamp (ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦Z), which sorts
    lexically, so the last entry is the most recent. No-op if the file exists or
    there are no backups.
    """
    path = _resolve_secrets_path(org_name)
    if path.exists():
        return
    backups = sorted((_SECRETS_DIR / "backups").glob(f"{path.name}.*"))
    if not backups:
        return
    latest = backups[-1]
    try:
        shutil.copy2(latest, path)
        print(f"ÃƒÂ¢Ã¢â€žÂ¢Ã‚Â»ÃƒÂ¯Ã‚Â¸Ã‚Â  Restored {path.name} from latest backup: {latest.name}")
    except Exception as exc:
        print(f"ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Could not restore {path.name} from {latest.name}: {exc}")


def _load_secrets_file(org_name: str = "ATTENSE") -> Path | None:
    """
    Load secrets/{org_name}.env into os.environ.
    Returns the resolved Path so main() can delete it later, or None if not found.
    """
    path = _resolve_secrets_path(org_name)
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key and key not in os.environ:   # real env var always wins
            os.environ[key] = value
    return path


# Bootstrap: restore the ephemeral org secrets file from backup if a prior
# close deleted it, then load it. We default to 'ATTENSE' for the first pass,
# then re-resolve after ORG_NAME is set below.
_restore_secrets_if_missing(os.getenv("CORTEX_ORG_NAME", "ATTENSE"))
_load_secrets_file(os.getenv("CORTEX_ORG_NAME", "ATTENSE"))


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Configuration ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

CORTEX_URL        = os.getenv("CORTEX_URL",        "http://localhost:9001")

# Project root + compose service used to recreate TheHive after the key rotates.
PROJECT_ROOT    = Path(__file__).resolve().parent.parent
THEHIVE_SERVICE = os.getenv("THEHIVE_SERVICE", "thehive")

# Admin credentials that will be created on first boot
ADMIN_LOGIN    = os.getenv("CORTEX_ADMIN_LOGIN",    "admin")
ADMIN_PASSWORD = os.getenv("CORTEX_ADMIN_PASSWORD", "attense-Admin1!")  # ÃƒÂ¢Ã¢â‚¬Â°Ã‚Â¥8 chars, 1 upper, 1 digit
ADMIN_NAME     = os.getenv("CORTEX_ADMIN_NAME",     "ATTENSE Admin")

# Organisation that owns the Wazuh-backed responders
ORG_NAME       = os.getenv("CORTEX_ORG_NAME",       "ATTENSE")
ORG_ADMIN_LOGIN = os.getenv("CORTEX_ORG_ADMIN",     "attense-analyst")
ORG_ADMIN_PASS  = os.getenv("CORTEX_ORG_PASS",      "attense-Analyst1!")

# Responders to enable, grouped by backend configuration.
WAZUH_RESPONDERS = {"WazuhBlockIP", "WazuhIsolateHost", "WazuhDisableAccount"}
TARGET_RESPONDERS = {
    "TargetSanitizeInput",
    "TargetKillProcess",
    "TargetBlockPath",
    "TargetRemoveFile",
    "TargetEnableCsrfProtection",
}
RESPONDERS = sorted(WAZUH_RESPONDERS | TARGET_RESPONDERS)
RESPONDER_DISPLAY_NAMES = {
    "WazuhBlockIP": "IPLocker",
    "WazuhIsolateHost": "IsolateHost",
    "WazuhDisableAccount": "DisableAccount",
    "TargetSanitizeInput": "SanitizeInput",
    "TargetKillProcess": "KillProcess",
    "TargetBlockPath": "BlockPath",
    "TargetRemoveFile": "RemoveFile",
    "TargetEnableCsrfProtection": "EnableCSRFProtection",
}

# Wazuh connection details passed into each responder's configuration so
# they work immediately after setup, without manual Cortex UI configuration.
# Reuses the same WAZUH_API_URL / WAZUH_USER / WAZUH_PASS keys already
# defined in secrets/{ORG_NAME}.env for the responders themselves.
WAZUH_API_URL      = os.getenv("WAZUH_API_URL",      "https://wazuh-manager:55000")
WAZUH_USER         = os.getenv("WAZUH_USER",         "wazuh")
WAZUH_PASS         = os.getenv("WAZUH_PASS",         "wazuh")
WAZUH_AGENT_NAME   = os.getenv("WAZUH_AGENT_NAME",   "target-agent")
TARGET_URL         = os.getenv("TARGET_URL",         "http://target-agent:80")
CONTAINMENT_TOKEN  = os.getenv("CONTAINMENT_API_TOKEN", "attense-containment-token")

# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Helpers ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def _req(
    method: str,
    path: str,
    body: dict | None = None,
    token: tuple[str, str] | None = None,
    login_pass: tuple[str, str] | None = None,
) -> dict | list | str:
    """Make an HTTP request to Cortex. Returns parsed JSON, or a bare string for text/plain responses."""
    url = f"{CORTEX_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        # Only set this when there's an actual body ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Cortex's JSON body
        # parser otherwise treats "Content-Type: application/json" plus an
        # empty body as a parse error (e.g. on bodyless GET requests).
        req.add_header("Content-Type", "application/json")

    if token:
        # Cortex's local/admin auth is cookie-based (see _get_session_token),
        # not a Bearer token ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â `token` is (session_cookie, xsrf_token). Once a
        # session cookie is present, Play's CSRF filter requires the
        # CORTEX-XSRF-TOKEN cookie value to also be echoed back as the
        # X-CORTEX-XSRF-TOKEN header (double-submit cookie pattern; header
        # name confirmed from Cortex's own frontend bundle).
        session_cookie, xsrf_token = token
        cookie_value = f"CORTEX_SESSION={session_cookie}"
        if xsrf_token:
            cookie_value += f"; CORTEX-XSRF-TOKEN={xsrf_token}"
            req.add_header("X-CORTEX-XSRF-TOKEN", xsrf_token)
        req.add_header("Cookie", cookie_value)
    elif login_pass:
        import base64
        cred = base64.b64encode(f"{login_pass[0]}:{login_pass[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            if not raw.strip():
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Some endpoints (e.g. key/renew) respond with a bare
                # text/plain value rather than JSON.
                return raw.strip()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} from {method} {path}: {err_body}") from e


def _api_key_authenticates(api_key: str) -> bool:
    """Return True when an existing Cortex API key can authenticate."""
    if not api_key:
        return False
    req = urllib.request.Request(f"{CORTEX_URL}/api/user/current", method="GET")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return False
        raise RuntimeError(f"HTTP {exc.code} while validating existing Cortex API key") from exc
    except urllib.error.URLError:
        return False


def _wait_for_cortex(max_wait: int = 120) -> None:
    """Poll until Cortex responds on /api/status."""
    print(f"ÃƒÂ¢Ã‚ÂÃ‚Â³ Waiting for Cortex at {CORTEX_URL} ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            _req("GET", "/api/status")
            print(" ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Cortex is up!")
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(3)
    print()
    sys.exit("ÃƒÂ¢Ã‚ÂÃ…â€™ Cortex did not become ready in time. Is `docker compose up -d` running?")


def _fetch_xsrf_token() -> str:
    """
    GET a public endpoint to obtain the CORTEX-XSRF-TOKEN cookie Play issues
    on any request (auth not required ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â confirmed it's set even on an
    unauthenticated request). Returns "" if not present for any reason;
    callers degrade gracefully (no XSRF header sent) rather than failing.
    """
    req = urllib.request.Request(f"{CORTEX_URL}/api/status", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            cookie_header = resp.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError:
        return ""
    match = re.search(r"CORTEX-XSRF-TOKEN=([^;]+)", cookie_header)
    return match.group(1) if match else ""


def _get_session_token(
    login: str,
    password: str,
    *,
    retry_transient: bool = False,
    max_wait: int = 120,
) -> tuple[str, str]:
    """
    Log in and return (session_cookie, xsrf_token).

    Cortex's local auth is cookie-based (Set-Cookie: CORTEX_SESSION=<jwt>) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â
    the login response body carries no token, so this talks to urllib
    directly to read the response headers instead of going through _req().
    The XSRF cookie isn't set on the login response itself, so a follow-up
    request fetches it (see _fetch_xsrf_token).
    """
    url = f"{CORTEX_URL}/api/login"
    deadline = time.time() + max_wait

    while True:
        data = json.dumps({"user": login, "password": password}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                cookie_header = resp.headers.get("Set-Cookie", "")
            break
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            message = f"HTTP {e.code} from POST /api/login: {err_body}"
            transient = e.code >= 500 and (
                "NoNodeAvailable" in err_body
                or "ElasticSearch cluster is unreachable" in err_body
                or "ServiceUnavailable" in err_body
            )
            if not retry_transient or not transient or time.time() >= deadline:
                raise RuntimeError(message) from e
            print("   Cortex API is up but Elasticsearch is not ready; retrying ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦", flush=True)
            time.sleep(5)
        except urllib.error.URLError as e:
            if not retry_transient or time.time() >= deadline:
                raise RuntimeError(f"POST /api/login failed: {e}") from e
            print("   Cortex login endpoint is temporarily unreachable; retrying ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦", flush=True)
            time.sleep(5)

    match = re.search(r"CORTEX_SESSION=([^;]+)", cookie_header)
    if not match:
        raise RuntimeError(f"Login succeeded but no session cookie returned: {cookie_header!r}")
    return match.group(1), _fetch_xsrf_token()


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 1: Bootstrap admin ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_bootstrap_admin() -> tuple[str, str]:
    """Create the first admin user if Cortex is in maintenance mode. Returns session token."""
    print("\nÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â§ Step 1: Bootstrap Cortex admin user ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")

    # Check if already bootstrapped
    try:
        token = _get_session_token(
            ADMIN_LOGIN,
            ADMIN_PASSWORD,
            retry_transient=True,
        )
        print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Admin '{ADMIN_LOGIN}' already exists ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping creation.")
        return token
    except RuntimeError as e:
        if "HTTP 520" not in str(e) and "HTTP 401" not in str(e):
            # 520 = maintenance mode (first boot), 401 = wrong creds
            # Any other error is unexpected
            raise

    # Cortex is in maintenance mode. The first superadmin user must belong to
    # the special 'cortex' platform organisation ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â it is not auto-created by
    # Cortex and is distinct from the 'ATTENSE' org created later ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â so ensure
    # it exists before creating the admin user.
    orgs = _req("GET", "/api/organization")
    existing_orgs = [o.get("name") for o in (orgs if isinstance(orgs, list) else [])]
    if "cortex" not in existing_orgs:
        print(f"   Creating bootstrap organisation 'cortex' ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
        _req("POST", "/api/organization", {
            "name":        "cortex",
            "description": "Cortex platform organisation",
            "status":      "Active",
        })

    print(f"   Creating admin user '{ADMIN_LOGIN}' ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
    _req("POST", "/api/user", {
        "login":    ADMIN_LOGIN,
        "name":     ADMIN_NAME,
        "password": ADMIN_PASSWORD,
        "roles":    ["superadmin"],
    })
    token = _get_session_token(ADMIN_LOGIN, ADMIN_PASSWORD)
    print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Admin created and logged in.")
    return token


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 2: Create organisation ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_create_org(admin_token: tuple[str, str]) -> str:
    """Create the ATTENSE organisation. Returns org name."""
    print(f"\nÃƒÂ°Ã…Â¸Ã‚ÂÃ‚Â¢ Step 2: Create organisation '{ORG_NAME}' ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")

    # List existing orgs
    orgs = _req("GET", "/api/organization", token=admin_token)
    existing = [o.get("name") for o in (orgs if isinstance(orgs, list) else [])]
    if ORG_NAME in existing:
        print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Organisation '{ORG_NAME}' already exists ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping.")
        return ORG_NAME

    _req("POST", "/api/organization", {
        "name":        ORG_NAME,
        "description": "ATTENSE Cyber Range Organisation",
        "status":      "Active",
    }, token=admin_token)
    print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Organisation '{ORG_NAME}' created.")
    return ORG_NAME


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 3: Create org-level user + API key ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_create_api_key(admin_token: tuple[str, str]) -> str:
    """Create an org analyst user and generate an API key. Returns the API key."""
    print(f"\nÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ¢â‚¬Ëœ Step 3: Create analyst user and generate API key ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")

    # Check if user exists already. Cortex's /api/user list responses key
    # the login under "id" (and "_id"), not "login".
    users: list = _req("GET", "/api/user", token=admin_token)
    existing_logins = [u.get("id") for u in (users if isinstance(users, list) else [])]

    if ORG_ADMIN_LOGIN not in existing_logins:
        print(f"   Creating user '{ORG_ADMIN_LOGIN}' in org '{ORG_NAME}' ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
        _req("POST", "/api/user", {
            "login":        ORG_ADMIN_LOGIN,
            "name":         "ATTENSE Analyst",
            "password":     ORG_ADMIN_PASS,
            "organization": ORG_NAME,
            "roles":        ["read", "analyze", "orgadmin"],
        }, token=admin_token)
        print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ User '{ORG_ADMIN_LOGIN}' created.")
    else:
        print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ User '{ORG_ADMIN_LOGIN}' already exists ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping creation.")

    existing_api_key = os.getenv("CORTEX_API_KEY", "").strip()
    if _api_key_authenticates(existing_api_key):
        print(f"   Existing CORTEX_API_KEY for '{ORG_ADMIN_LOGIN}' is valid -- reusing it.")
        return existing_api_key

    # Generate (or renew) API key for that user
    print(f"   Generating API key for '{ORG_ADMIN_LOGIN}' ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
    resp = _req("POST", f"/api/user/{ORG_ADMIN_LOGIN}/key/renew", token=admin_token)
    # This endpoint responds with a bare text/plain key, not JSON ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â but
    # handle a dict shape too in case that ever changes.
    api_key = resp.get("key", "") if isinstance(resp, dict) else resp
    if not api_key:
        raise RuntimeError(f"Could not extract API key from response: {resp}")

    print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ API key generated: {api_key[:8]}ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦{api_key[-4:]} (truncated for display)")
    return str(api_key)


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 4: Enable containment responders ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_enable_responders(org_token: tuple[str, str]) -> None:
    """Enable Wazuh and target-app responders in the ATTENSE organisation."""
    print(f"\nÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â« Step 4: Enable containment responders ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")

    # List available responder definitions. This needs an org-scoped session
    # (read/analyze/orgadmin) ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the platform superadmin alone gets a 403
    # "Insufficient rights" against /api/responderdefinition.
    try:
        definitions = _req("GET", "/api/responderdefinition", token=org_token)
    except RuntimeError as e:
        print(f"   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Could not list responders: {e}")
        print("       Responders will need to be enabled manually in the Cortex UI.")
        return

    if not isinstance(definitions, list):
        print("   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Unexpected responder list format ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping auto-enable.")
        return

    # Already-enabled responders for this org ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â needed for idempotency,
    # since re-enabling one that's already active is a version conflict.
    enabled = _req("GET", "/api/organization/responder?range=all", token=org_token)
    enabled_items = enabled if isinstance(enabled, list) else []
    enabled_by_definition = {
        e.get("workerDefinitionId"): e for e in enabled_items if e.get("workerDefinitionId")
    }

    wazuh_configuration = {
        "wazuh_url":      WAZUH_API_URL,
        "wazuh_username": WAZUH_USER,
        "wazuh_password": WAZUH_PASS,
        "agent_name":     WAZUH_AGENT_NAME,
    }
    target_configuration = {
        "target_url": TARGET_URL,
        "containment_api_token": CONTAINMENT_TOKEN,
    }

    for responder_name in RESPONDERS:
        configuration = (
            wazuh_configuration
            if responder_name in WAZUH_RESPONDERS
            else target_configuration
        )
        target = next((d for d in definitions if d.get("name") == responder_name), None)
        if not target:
            print(f"   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Responder '{responder_name}' not found yet.")
            print("       Cortex may still be scanning the responders directory.")
            print("       Wait 30s and re-run, or enable it manually in the Cortex UI.")
            continue

        worker_definition_id = target.get("id")
        if not worker_definition_id:
            print(f"   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Found responder '{responder_name}' but missing ID ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â skipping.")
            continue

        display_name = RESPONDER_DISPLAY_NAMES[responder_name]
        existing = enabled_by_definition.get(worker_definition_id)
        if existing:
            # Always refresh configuration (not just rename on mismatch): Cortex
            # does not pick up env var changes for an already-enabled responder
            # on its own, so re-running this script after rotating WAZUH_PASS /
            # CONTAINMENT_API_TOKEN must re-PATCH it here or the rotation never
            # reaches the responder that actually sends the credential.
            patch_body = {"configuration": configuration}
            if existing.get("name") != display_name:
                patch_body["name"] = display_name
            _req(
                "PATCH",
                f"/api/responder/{existing['id']}",
                patch_body,
                token=org_token,
            )
            print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ '{display_name}' enabled for org '{ORG_NAME}' ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â configuration refreshed.")
            continue

        # Note: the org is implied by the caller's own session/org
        # membership, not a path segment ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Cortex's own UI calls this same
        # "/api/organization/responder/{id}" path with no org name in it.
        # "name" is what TheHive shows in the responder picker. Keep it
        # independent from Cortex's required versioned worker definition ID.
        _req("POST", f"/api/organization/responder/{worker_definition_id}", {
            "name":          display_name,
            "configuration": configuration,
            "jobCache":      10,
        }, token=org_token)
        print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ '{display_name}' responder enabled for org '{ORG_NAME}'.")

    # Remove older enabled versions after the current definitions are ready.
    current_definition_ids = {
        d.get("id") for d in definitions if d.get("name") in RESPONDERS
    }
    for old in enabled_items:
        definition_id = old.get("workerDefinitionId", "")
        base_name = definition_id.rsplit("_", 2)[0]
        if base_name in RESPONDERS and definition_id not in current_definition_ids:
            _req("DELETE", f"/api/responder/{old['id']}", token=org_token)
            print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Removed obsolete responder instance '{definition_id}'.")


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 5: Write CORTEX_API_KEY into secrets/{ORG_NAME}.env ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_write_cortex_key_env(api_key: str) -> None:
    """Upsert CORTEX_API_KEY=<key> into secrets/{ORG_NAME}.env.

    The renewed key is delivered to TheHive purely through the environment: the
    thehive service loads this file via `env_file` in docker-compose, and
    thehive/application.conf reads it with `key = ${?CORTEX_API_KEY}`. We must
    NEVER write the live key into the tracked thehive/application.conf ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â doing so
    is exactly what previously leaked the Cortex key into git history. This file
    is gitignored, so rotating the key here can never end up in a commit.
    """
    print(f"\nÃƒÂ°Ã…Â¸Ã¢â‚¬Å“Ã‚Â Step 5: Writing CORTEX_API_KEY to secrets/{ORG_NAME}.env ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
    path = _resolve_secrets_path(ORG_NAME)
    path.parent.mkdir(parents=True, exist_ok=True)

    new_line = f"CORTEX_API_KEY={api_key}"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    replaced = False
    out: list[str] = []
    for line in existing:
        # Replace the active CORTEX_API_KEY= line (ignore commented-out ones).
        if line.lstrip().startswith("CORTEX_API_KEY=") and not line.lstrip().startswith("#"):
            out.append(new_line)
            replaced = True
        else:
            out.append(line)

    if not replaced:
        if out and out[-1].strip():
            out.append("")  # keep a blank line before the appended key
        out.append("# Cortex API key generated by scripts/setup_cortex.py;")
        out.append("# read by thehive/application.conf via ${?CORTEX_API_KEY}.")
        out.append(new_line)

    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Key {'updated in' if replaced else 'appended to'} {path}")
    print("   ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ¢â‚¬â„¢ Tracked thehive/application.conf left untouched ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no key in git.")


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Step 7: Recreate TheHive so it loads the new CORTEX_API_KEY ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_reload_thehive() -> None:
    """
    Recreate the TheHive container so it picks up the CORTEX_API_KEY we just
    wrote into secrets/{ORG_NAME}.env.

    Why recreate, not restart: docker-compose resolves `env_file` values into a
    container's environment at CREATE time, so a plain `docker restart` keeps the
    OLD key. The container must be recreated with `docker compose up -d thehive`
    (the same recreate pattern setup_thehive.py uses for attense-app after
    rotating HIVE_API_KEY).

    Runs `docker compose up -d thehive` from the project root, and falls back to
    printing the command if the docker CLI isn't available here (e.g. when this
    script runs inside a container without the CLI).
    """
    if not THEHIVE_SERVICE:
        print("\nStep 7: TheHive recreate skipped; compose starts TheHive after cortex-init.")
        return
    print(f"\nÃƒÂ¢Ã¢â€žÂ¢Ã‚Â»ÃƒÂ¯Ã‚Â¸Ã‚Â  Step 7: Recreating TheHive so it loads the new Cortex key ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦")
    cmd = ["docker", "compose", "up", "-d", THEHIVE_SERVICE]
    try:
        result = subprocess.run(
            cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=180
        )
    except FileNotFoundError:
        print("   ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¹ÃƒÂ¯Ã‚Â¸Ã‚Â  docker CLI not available here ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â recreate it yourself:")
        print(f"       docker compose up -d {THEHIVE_SERVICE}")
        return
    except Exception as exc:
        print(f"   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  Could not recreate TheHive automatically ({exc}). Run:")
        print(f"       docker compose up -d {THEHIVE_SERVICE}")
        return

    if result.returncode == 0:
        print("   ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ TheHive recreated ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ready in ~30s at http://localhost:9000")
    else:
        print(f"   ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  `docker compose up -d {THEHIVE_SERVICE}` failed:")
        print(f"      {(result.stderr or result.stdout).strip()[:200]}")
        print(f"      Run it manually from {PROJECT_ROOT}.")


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Main ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def step_note_secrets_kept() -> None:
    """
    Setup keeps secrets/{ORG_NAME}.env in place ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â it is NOT backed up or deleted
    here. The timestamped backup + deletion happen when you CLOSE the lab via
    scripts/close_lab.py; the next open auto-restores it from that backup.
    """
    print(f"\nÃƒÂ°Ã…Â¸Ã¢â‚¬â€Ã¢â‚¬Å¾ÃƒÂ¯Ã‚Â¸Ã‚Â  Step 6: Secrets file kept in place (not deleted).")
    secrets_path = _resolve_secrets_path(ORG_NAME)
    print(f"   ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¹ÃƒÂ¯Ã‚Â¸Ã‚Â  {secrets_path}")
    print("      Closing the lab (scripts/close_lab.py) timestamp-backs-up and removes")
    print("      this file; the next open restores it. VirusTotal/AbuseIPDB keys live")
    print("      in secrets/enrichment.env and are kept permanently.")


# ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ Main ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬

def main() -> None:
    print("=" * 60)
    print(f"  ATTENSE ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Cortex First-Boot Setup  [{ORG_NAME}]")
    print("=" * 60)
    print(f"  Secrets file: secrets/{ORG_NAME}.env  (kept; backed up on success)")
    print("=" * 60)

    _wait_for_cortex()

    admin_token = step_bootstrap_admin()
    step_create_org(admin_token)
    api_key = step_create_api_key(admin_token)
    org_token = _get_session_token(ORG_ADMIN_LOGIN, ORG_ADMIN_PASS)
    step_enable_responders(org_token)
    step_write_cortex_key_env(api_key)  # writes CORTEX_API_KEY to secrets/ATTENSE.env (never the tracked conf)
    step_note_secrets_kept()            # keeps ATTENSE.env in place (close_lab.py backs up + deletes)
    step_reload_thehive()               # recreates TheHive so it loads the new key from env_file

    print("\n" + "=" * 60)
    print("Cortex setup complete ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â fully automated!")
    print()
    print("What just happened:")
    print("  - Cortex admin user + ATTENSE org created")
    print("  - API key generated and written to secrets/ATTENSE.env as CORTEX_API_KEY")
    print(f"  - {len(RESPONDERS)} Wazuh and target-app responders enabled")
    print("  - Secrets file kept in place (close_lab.py backs it up + removes it on close)")
    print("  - TheHive recreated to load the new key from the environment")
    print()
    print("You can now:")
    print("  - Open TheHive at http://localhost:9000")
    print("  - On an alert, the analyst chooses the matching containment responder")
    print("  - ATTENSE records CONTAINING/CONTAINED only after that chosen action runs")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        with open("/secrets/cortex_init_error.txt", "w") as f:
            traceback.print_exc(file=f)
        raise
