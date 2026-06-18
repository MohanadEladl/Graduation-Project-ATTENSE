#!/usr/bin/env python3
"""
setup_thehive.py — TheHive First-Boot Automator (blueteam auth)
================================================================
Automates wiring blueteam → TheHive authentication in one shot.

This is the TheHive counterpart to scripts/setup_cortex.py. Where setup_cortex
wires TheHive → Cortex (and writes thehive/application.conf), this script wires
the ATTENSE Blue Team backend → TheHive by generating an org-scoped API key and
delivering it to the attense-app container.

What it does
------------
1. Waits for TheHive to answer /api/status.
2. Logs in as the TheHive super-admin (admin@thehive.local by default).
3. Creates the ATTENSE organisation (idempotent).
4. Creates an org-admin analyst user inside that org (idempotent).
5. Generates / renews that user's API key.
6. Writes HIVE_API_KEY=<key> into secrets/blueteam.env, which is bind-mounted
   into attense-app at /run/secrets/blueteam.env and read by blueteam's settings.
7. Restarts the attense-app container via the Docker socket so blueteam
   re-reads the freshly fetched key.

"With every organisation created the key is fetched automatically": set
THEHIVE_ORG_NAME (comma-separated for several). The FIRST org's key is the one
written to blueteam.env (blueteam authenticates as one org); every listed org is
still created + keyed so the keys exist in TheHive.

Usage (inside the container network, as wired in docker-compose `thehive-init`)
-------------------------------------------------------------------------------
    docker compose run --rm thehive-init
or simply `docker compose up` — thehive-init runs once after TheHive starts.

Safe to re-run: every run refreshes the org key and re-injects it into blueteam.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000").rstrip("/")

# Where the generated key is written. Bind-mounted into attense-app and read by
# blueteam's pydantic settings (env_file) as HIVE_API_KEY.
BLUETEAM_ENV_PATH = os.getenv("BLUETEAM_ENV_PATH", str(
    Path(__file__).resolve().parent.parent / "secrets" / "blueteam.env"
))

# Super-admin created by TheHive on first boot.
ADMIN_LOGIN    = os.getenv("THEHIVE_ADMIN_LOGIN",    "admin@thehive.local")
ADMIN_PASSWORD = os.getenv("THEHIVE_ADMIN_PASSWORD", "secret")

# Organisation(s) to create. Comma-separated; the first is the one blueteam uses.
ORG_NAMES = [
    o.strip() for o in os.getenv("THEHIVE_ORG_NAME", "ATTENSE").split(",") if o.strip()
]

# Profile granted to the per-org service user (org-admin has full org perms,
# including createAlert/createCase used by blueteam).
ORG_USER_PROFILE = os.getenv("THEHIVE_ORG_PROFILE", "org-admin")

# Container restarted so blueteam re-reads the key. Empty string = skip restart.
ATTENSE_APP_CONTAINER = os.getenv("ATTENSE_APP_CONTAINER", "attense_app")


# ── Cookie-aware HTTP client ──────────────────────────────────────────────────
# TheHive uses a session cookie (THEHIVE-SESSION) after /api/login, so we drive
# the whole flow through one opener that persists cookies between requests.

_cookie_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cookie_jar))


def _req(method: str, path: str, body: dict | None = None, raw: bool = False):
    """
    Make an HTTP request to TheHive over the shared (cookie-bearing) opener.

    Returns parsed JSON by default; with raw=True returns the response body as a
    stripped string (used by the key/renew endpoint, which returns plain text).
    """
    url = f"{THEHIVE_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _opener.open(req, timeout=15) as resp:
            payload = resp.read().decode().strip()
            if raw:
                return payload
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} from {method} {path}: {err_body}") from e


# ── Step 0: Wait for TheHive ──────────────────────────────────────────────────

def wait_for_thehive(max_wait: int = 300) -> None:
    """Poll /api/status until TheHive answers (DB migration can take a while)."""
    print(f"⏳ Waiting for TheHive at {THEHIVE_URL} …", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            _req("GET", "/api/status")
            print(" ✅ TheHive is up!")
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(4)
    print()
    sys.exit("❌ TheHive did not become ready in time. Is the thehive container running?")


# ── Step 1: Login ─────────────────────────────────────────────────────────────

def login() -> None:
    """Log in as super-admin; the session cookie is stored in the shared jar."""
    print(f"\n🔐 Step 1: Logging in as '{ADMIN_LOGIN}' …")
    _req("POST", "/api/login", {"user": ADMIN_LOGIN, "password": ADMIN_PASSWORD})
    print("   ✅ Authenticated (session cookie stored).")


# ── Step 2: Create organisation (idempotent) ──────────────────────────────────

def ensure_org(org_name: str) -> None:
    print(f"\n🏢 Step 2: Ensuring organisation '{org_name}' …")
    # NOTE: GET /api/v1/organisation 404s on TheHive 4.1.x — the v0 list endpoint
    # is the reliable one. Checking first is essential: the v1 create endpoint will
    # happily make a DUPLICATE org with the same name if we don't.
    try:
        orgs = _req("GET", "/api/organisation")
        existing = {o.get("name") for o in (orgs if isinstance(orgs, list) else [])}
    except Exception:
        existing = set()

    if org_name in existing:
        print(f"   ✅ Organisation '{org_name}' already exists — skipping.")
        return

    try:
        _req("POST", "/api/v1/organisation", {
            "name":        org_name,
            "description": f"{org_name} Cyber Range Organisation",
        })
        print(f"   ✅ Organisation '{org_name}' created.")
    except RuntimeError as e:
        # Tolerate races / 'already exists' style conflicts.
        if "already exists" in str(e).lower() or "HTTP 400" in str(e) or "HTTP 409" in str(e):
            print(f"   ✅ Organisation '{org_name}' already present — continuing.")
        else:
            raise


# ── Step 3: Create the per-org service user (idempotent) ──────────────────────

def _user_login_for(org_name: str) -> str:
    """Deterministic service-account login for an org (e.g. attense → blueteam@attense.thehive)."""
    slug = org_name.strip().lower().replace(" ", "-")
    return f"blueteam@{slug}.thehive"


def ensure_user(org_name: str) -> str:
    user_login = _user_login_for(org_name)
    print(f"\n👤 Step 3: Ensuring service user '{user_login}' in '{org_name}' …")

    # Does the user already exist? (v0 user endpoint is the reliable one here.)
    try:
        _req("GET", f"/api/user/{user_login}")
        print(f"   ✅ User '{user_login}' already exists — skipping creation.")
        return user_login
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            # Unexpected — surface it.
            raise

    _req("POST", "/api/v1/user", {
        "login":        user_login,
        "name":         f"{org_name} Blue Team Service",
        "organisation": org_name,
        "profile":      ORG_USER_PROFILE,
    })
    print(f"   ✅ User '{user_login}' created with profile '{ORG_USER_PROFILE}'.")
    return user_login


# ── Step 4: Generate / renew the API key ──────────────────────────────────────

def fetch_api_key(user_login: str) -> str:
    print(f"\n🔑 Step 4: Generating API key for '{user_login}' …")
    # key/renew returns the key as plain text. TheHive 4.1.x exposes this on the
    # v0 route (the v1 route 404s with "User not found").
    key = _req("POST", f"/api/user/{user_login}/key/renew", raw=True)
    # Some builds wrap it in JSON — handle both.
    if key.startswith("{"):
        try:
            key = json.loads(key).get("key", key)
        except Exception:
            pass
    key = key.strip().strip('"')
    if not key:
        raise RuntimeError("TheHive returned an empty API key.")
    print(f"   ✅ API key generated: {key[:8]}…{key[-4:]} (truncated for display)")
    return key


# ── Step 4b: Register the CaseCreated → webhook notification rule ─────────────
# The webhook ENDPOINT ('local') is declared in thehive/application.conf
# (notification.webhook.endpoints). That only REGISTERS it — TheHive 4.1.x will
# not call it until a per-organisation RULE says to. This step adds that rule so
# promoting an alert to a case fires the webhook into blueteam, which then
# attaches the attacker activity log. Without it, no case ever calls back.
NOTIFICATION_RULE = [{
    "delegate": False,
    "trigger":  {"name": "CaseCreated"},
    "notifier": {"name": "webhook", "endpoint": "local"},
}]


def ensure_notification_rule(org_name: str, api_key: str) -> None:
    """Set the org's notification config to fire the 'local' webhook on CaseCreated.

    Uses the org service-user key (org-admin), since notification config is
    organisation-scoped — the super-admin session is in the 'admin' org and
    cannot set it for another org directly.
    """
    print(f"\n🔔 Step 4b: Registering CaseCreated→webhook rule for '{org_name}' …")
    url = f"{THEHIVE_URL}/api/config/organisation/notification"
    data = json.dumps({"value": NOTIFICATION_RULE}).encode()
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 201, 204):
                print("   ✅ Rule registered: CaseCreated → webhook 'local'.")
            else:
                print(f"   ⚠️  TheHive returned {resp.status} setting the notification rule.")
    except urllib.error.HTTPError as e:
        print(f"   ⚠️  Could not set notification rule: HTTP {e.code}: {e.read().decode()[:160]}")
    except Exception as exc:
        print(f"   ⚠️  Could not set notification rule: {exc}")


# ── Step 5: Write the key into secrets/blueteam.env ───────────────────────────

def write_blueteam_env(api_key: str) -> None:
    print(f"\n📝 Step 5: Writing HIVE_API_KEY to {BLUETEAM_ENV_PATH} …")
    path = Path(BLUETEAM_ENV_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Generated by scripts/setup_thehive.py — do not edit by hand.\n"
        "# Bind-mounted into attense-app at /run/secrets/blueteam.env and read by\n"
        "# blueteam's pydantic settings as HIVE_API_KEY.\n"
        f"HIVE_API_KEY={api_key}\n",
        encoding="utf-8",
    )
    print(f"   ✅ Key written to {path}")


# ── Step 6: Restart attense-app via the Docker socket ─────────────────────────

def restart_attense_app() -> None:
    """Restart the attense-app container so blueteam re-reads the new key."""
    import http.client as _http
    import socket as _sock

    if not ATTENSE_APP_CONTAINER:
        print("\n⏭️  Step 6: ATTENSE_APP_CONTAINER empty — skipping restart.")
        return

    DOCKER_SOCKET = "/var/run/docker.sock"
    print(f"\n♻️  Step 6: Restarting '{ATTENSE_APP_CONTAINER}' to load the new key …")

    if not Path(DOCKER_SOCKET).exists():
        print(f"   Docker socket not found at {DOCKER_SOCKET} — skipping auto-restart.")
        print(f"   Run manually: docker compose restart attense-app")
        return

    class _UnixHTTPConnection(_http.HTTPConnection):
        def connect(self) -> None:
            self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect(DOCKER_SOCKET)

    try:
        conn = _UnixHTTPConnection("localhost")
        conn.request("POST", f"/containers/{ATTENSE_APP_CONTAINER}/restart")
        resp = conn.getresponse()
        if resp.status in (200, 204):
            print(f"   ✅ '{ATTENSE_APP_CONTAINER}' is restarting (Docker status {resp.status}).")
        else:
            body = resp.read().decode()
            print(f"   ⚠️  Docker returned {resp.status}: {body}")
            print(f"   Run manually: docker compose restart attense-app")
    except Exception as exc:
        print(f"   ⚠️  Could not restart via socket: {exc}")
        print(f"   Run manually: docker compose restart attense-app")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(f"  ATTENSE — TheHive First-Boot Setup  {ORG_NAMES}")
    print("=" * 60)

    wait_for_thehive()
    login()

    blueteam_key: str | None = None
    for org_name in ORG_NAMES:
        ensure_org(org_name)
        user_login = ensure_user(org_name)
        key = fetch_api_key(user_login)
        ensure_notification_rule(org_name, key)
        if blueteam_key is None:        # first org owns the blueteam identity
            blueteam_key = key

    if not blueteam_key:
        sys.exit("❌ No organisation processed — nothing to write.")

    write_blueteam_env(blueteam_key)
    restart_attense_app()

    print("\n" + "=" * 60)
    print("TheHive setup complete — fully automated!")
    print()
    print("What just happened:")
    print(f"  - Organisation(s) ensured in TheHive: {', '.join(ORG_NAMES)}")
    print("  - A blue-team service user + API key created per org")
    print("  - CaseCreated → webhook notification rule registered per org")
    print(f"  - First org's key written to {BLUETEAM_ENV_PATH} as HIVE_API_KEY")
    print(f"  - {ATTENSE_APP_CONTAINER or 'attense-app'} restarted to load the key")
    print("=" * 60)


if __name__ == "__main__":
    main()
