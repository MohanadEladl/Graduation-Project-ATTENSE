#!/usr/bin/env python3
"""
setup_thehive.py — TheHive First-Boot Automator
=================================================
Automates the blue-team org / notification-webhook wiring for TheHive 4.1.24.

What it does
------------
1. Waits for TheHive to be ready.
2. Creates the 'blue-team' organisation (idempotent).
3. Creates 'blueteam-admin@lab.local' in blue-team with correct roles (idempotent).
4. Calls PUT /api/config/organisation/notification so AnyEvent → webhook → blueteam.

Why this exists
---------------
TheHive 4.1.24 CE requires TWO things for webhooks to fire:
  a) notification.webhook.endpoints in application.conf  (static — already there)
  b) PUT /api/config/organisation/notification per org   (dynamic, stored in JanusGraph)

Without (b) the triggerMap stays empty and no webhook is ever sent.
This script performs (b) idempotently on every fresh stack start.

Usage (from project root)
--------------------------
    python scripts/setup_thehive.py          # host, connecting to localhost:9000
    # or inside docker-compose network:
    # python /scripts/setup_thehive.py       (run by thehive-init container)
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request


# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL   = os.getenv("THEHIVE_URL",   "http://localhost:9000")
ADMIN_LOGIN   = os.getenv("THEHIVE_ADMIN_LOGIN", "admin@thehive.local")
ADMIN_PASS    = os.getenv("THEHIVE_ADMIN_PASS",  "secret")
ORG_NAME      = os.getenv("THEHIVE_ORG_NAME",    "blue-team")

# Org-admin user created inside blue-team (needs manageConfig permission)
ORG_ADMIN_LOGIN = os.getenv("THEHIVE_ORG_ADMIN_LOGIN", "blueteam-admin@lab.local")
ORG_ADMIN_PASS  = os.getenv("THEHIVE_ORG_ADMIN_PASS",  "Password1!")
ORG_ADMIN_NAME  = os.getenv("THEHIVE_ORG_ADMIN_NAME",  "BlueTeam Admin")

# Name of the webhook endpoint defined in notification.webhook.endpoints (application.conf)
WEBHOOK_ENDPOINT = os.getenv("THEHIVE_WEBHOOK_ENDPOINT", "blueteam")

# Notification trigger payload — "any event in this org → webhook → blueteam endpoint"
NOTIFICATION_CONFIG = [
    {
        "trigger":  {"name": "AnyEvent"},
        "notifier": {"name": "webhook", "endpoint": WEBHOOK_ENDPOINT},
        "delegate": False,
    }
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _req(
    method: str,
    path: str,
    body: dict | None = None,
    login: str | None = None,
    password: str | None = None,
) -> dict | list:
    """Make an HTTP request to TheHive. Returns parsed JSON."""
    url = f"{THEHIVE_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if login and password:
        cred = base64.b64encode(f"{login}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode().strip()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} from {method} {path}: {e.read().decode()}") from e


def _wait_for_thehive(max_wait: int = 180) -> None:
    print(f"⏳ Waiting for TheHive at {THEHIVE_URL} …", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            status = _req("GET", "/api/status")
            if status.get("versions"):
                print(" ✅ TheHive is up!")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    sys.exit("\n❌ TheHive did not become ready. Is docker compose up -d running?")


# ── Step 1: Create organisation ───────────────────────────────────────────────

def step_create_org() -> None:
    print(f"\n🏢 Step 1: Ensure organisation '{ORG_NAME}' exists …")
    try:
        orgs = _req("GET", "/api/organisation",
                    login=ADMIN_LOGIN, password=ADMIN_PASS)
        existing = [o.get("name") for o in (orgs if isinstance(orgs, list) else [])]
    except RuntimeError as e:
        # Admin account might not be set up yet — defer
        print(f"   ⚠️  Could not list organisations: {e}")
        return

    if ORG_NAME in existing:
        print(f"   ✅ Organisation '{ORG_NAME}' already exists — skipping.")
        return

    _req("POST", "/api/organisation", {
        "name":        ORG_NAME,
        "description": "Blue Team — SOC analysts",
        "taskRule":    "AllAssignee",
    }, login=ADMIN_LOGIN, password=ADMIN_PASS)
    print(f"   ✅ Organisation '{ORG_NAME}' created.")


# ── Step 2: Create org-admin user ─────────────────────────────────────────────

def step_create_user() -> None:
    print(f"\n👤 Step 2: Ensure user '{ORG_ADMIN_LOGIN}' exists in '{ORG_NAME}' …")

    # Direct GET is more reliable than listing all users, because the admin's
    # GET /api/user scope only returns users in the admin org.
    user_exists = False
    try:
        u = _req("GET", f"/api/user/{ORG_ADMIN_LOGIN}",
                 login=ADMIN_LOGIN, password=ADMIN_PASS)
        user_exists = u.get("login") == ORG_ADMIN_LOGIN
    except RuntimeError:
        user_exists = False

    if not user_exists:
        print(f"   Creating user '{ORG_ADMIN_LOGIN}' …")
        _req("POST", "/api/user", {
            "login":        ORG_ADMIN_LOGIN,
            "name":         ORG_ADMIN_NAME,
            "password":     ORG_ADMIN_PASS,
            "organisation": ORG_NAME,
            "profile":      "org-admin",
        }, login=ADMIN_LOGIN, password=ADMIN_PASS)
    else:
        print(f"   ✅ User '{ORG_ADMIN_LOGIN}' already exists — skipping creation.")

    # TheHive 4 bug: POST /api/user ignores `profile` and defaults to read-only.
    # We must PATCH roles explicitly to grant manageConfig (needed for step 3).
    print(f"   Patching roles for '{ORG_ADMIN_LOGIN}' …")
    try:
        _req("PATCH", f"/api/user/{ORG_ADMIN_LOGIN}", {
            "roles": ["admin", "write", "read", "alert"],
        }, login=ADMIN_LOGIN, password=ADMIN_PASS)
        print(f"   ✅ User '{ORG_ADMIN_LOGIN}' ready with admin/write/read/alert roles.")
    except RuntimeError as e:
        print(f"   ⚠️  Could not patch roles: {e}")


# ── Step 3: Set org notification config ──────────────────────────────────────

def step_set_notification_config(retries: int = 5, delay: int = 10) -> None:
    print(f"\n🔔 Step 3: Configure webhook notification for '{ORG_NAME}' …")

    for attempt in range(1, retries + 1):
        try:
            _req("PUT", "/api/config/organisation/notification",
                 body={"value": NOTIFICATION_CONFIG},
                 login=ORG_ADMIN_LOGIN, password=ORG_ADMIN_PASS)
            print(f"   ✅ Notification config saved — webhook 'AnyEvent → {WEBHOOK_ENDPOINT}' active.")
            return
        except RuntimeError as e:
            msg = str(e)
            if "403" in msg or "AuthorizationError" in msg:
                print(f"   ⚠️  403 Forbidden on attempt {attempt}/{retries} — roles patch may not have taken effect yet.")
            elif "401" in msg or "AuthenticationError" in msg:
                print(f"   ⚠️  401 on attempt {attempt}/{retries} — TheHive may still be restarting.")
            else:
                print(f"   ⚠️  Attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                print(f"       Retrying in {delay}s …")
                time.sleep(delay)

    print(f"   ❌ Could not set notification config after {retries} attempts.")
    print(f"      Run manually after stack is up:")
    print(f'      curl -u "{ORG_ADMIN_LOGIN}:{ORG_ADMIN_PASS}" \\')
    print(f'           -X PUT http://localhost:9000/api/config/organisation/notification \\')
    print(f"           -H 'Content-Type: application/json' \\")
    print(f"           -d '{{\"value\":{json.dumps(NOTIFICATION_CONFIG)}}}'")


# ── Step 4: Verify ────────────────────────────────────────────────────────────

def step_verify() -> None:
    print(f"\n🔍 Step 4: Verify notification config …")
    try:
        result = _req("GET", "/api/config/organisation/notification",
                      login=ORG_ADMIN_LOGIN, password=ORG_ADMIN_PASS)
        value = result.get("value", [])
        if value:
            print(f"   ✅ Notification config confirmed: {len(value)} trigger(s) registered.")
            for entry in value:
                trigger   = entry.get("trigger", {}).get("name", "?")
                notifier  = entry.get("notifier", {}).get("name", "?")
                endpoint  = entry.get("notifier", {}).get("endpoint", "?")
                print(f"      - trigger={trigger} notifier={notifier} endpoint={endpoint}")
        else:
            print("   ⚠️  Notification config appears empty.")
    except RuntimeError as e:
        print(f"   ⚠️  Could not verify config: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(f"  ATTENSE — TheHive First-Boot Setup  [{ORG_NAME}]")
    print("=" * 60)

    _wait_for_thehive()

    step_create_org()
    step_create_user()
    step_set_notification_config()
    step_verify()

    print("\n" + "=" * 60)
    print("TheHive setup complete!")
    print()
    print(f"  - Org '{ORG_NAME}' exists with webhook notification configured")
    print(f"  - User '{ORG_ADMIN_LOGIN}' ready (roles: admin/write/read/alert)")
    print(f"  - Webhook: AnyEvent → '{WEBHOOK_ENDPOINT}' endpoint")
    print()
    print("Events in blue-team will now POST to attense-app /internal/webhook/hive")
    print("=" * 60)


if __name__ == "__main__":
    main()
