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
6. Writes HIVE_API_KEY=<key> into the project-root .env file, which docker-compose
   injects into attense-app as the HIVE_API_KEY environment variable
   (`${HIVE_API_KEY}`). (A future version persists the key in the Attense App DB.)
7. Tells you to recreate attense-app so it picks up the new key.

"With every organisation created the key is fetched automatically": set
THEHIVE_ORG_NAME (comma-separated for several). The FIRST org's key is the one
written to the root .env (blueteam authenticates as one org); every listed org is
still created + keyed so the keys exist in TheHive.

Usage (run on the host, after TheHive is up)
--------------------------------------------
    python scripts/setup_thehive.py
    docker compose up -d attense-app      # recreate so it reads the new key

Safe to re-run: every run refreshes the org key and rewrites it into the root .env.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# This script prints status with emoji. On a Windows host the default console
# codec (cp1252) can't encode them and would crash mid-run, so force UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass


# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000").rstrip("/")

# Where the org-scoped API key (created in TheHive, pulled via key/renew) is
# written: the project-root .env file. docker-compose injects it into attense-app
# as the HIVE_API_KEY env var (`${HIVE_API_KEY}`). The key is NEVER generated
# locally — it is always fetched from TheHive.
ENV_FILE_PATH = os.getenv("ENV_FILE_PATH", str(
    Path(__file__).resolve().parent.parent / ".env"
))

# TheHive's HOCON config. We patch its webhook `includedTheHiveOrganisations`
# allow-list to exactly the org(s) we create, so a different THEHIVE_ORG_NAME
# works with no hand-editing (TheHive rejects webhooks for orgs not on this
# case-sensitive list with "organisation <x> is not authorised to use the webhook").
THEHIVE_CONF_PATH = os.getenv("THEHIVE_CONF_PATH", str(
    Path(__file__).resolve().parent.parent / "thehive" / "application.conf"
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


def _req(method: str, path: str, body: dict | None = None, raw: bool = False,
         org: str | None = None):
    """
    Make an HTTP request to TheHive over the shared (cookie-bearing) opener.

    Returns parsed JSON by default; with raw=True returns the response body as a
    stripped string (used by the key/renew endpoint, which returns plain text).

    `org` sets the `X-Organisation` header. TheHive 4.x resolves org-scoped
    routes (e.g. /api/user/<login>, key/renew) in the *current* organisation, and
    the admin session lives in the 'admin' org — so reaching a user that lives in
    another org (ATTENSE) requires naming that org here, else TheHive 404s with
    "User not found".
    """
    url = f"{THEHIVE_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if org:
        req.add_header("X-Organisation", org)
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
    # Must look in the org the user belongs to, not the admin session's org.
    try:
        _req("GET", f"/api/user/{user_login}", org=org_name)
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

def fetch_api_key(user_login: str, org_name: str) -> str:
    print(f"\n🔑 Step 4: Generating API key for '{user_login}' …")
    # key/renew returns the key as plain text. TheHive 4.1.x exposes this on the
    # v0 route (the v1 route 404s with "User not found"). The X-Organisation
    # header is required so TheHive resolves the user in their own org, not the
    # admin session's 'admin' org.
    key = _req("POST", f"/api/user/{user_login}/key/renew", raw=True, org=org_name)
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


# ── Step 4c: Authorise the org(s) on the webhook in application.conf ──────────

def patch_webhook_orgs(org_names: list[str]) -> None:
    """Set webhook `includedTheHiveOrganisations` to exactly *org_names*.

    TheHive's webhook authorisation is case-sensitive and per-org (and "all" is
    NOT a wildcard), so the org must appear here verbatim or TheHive raises
    "organisation <x> is not authorised to use the webhook". We rewrite the list
    from THEHIVE_ORG_NAME so switching orgs needs no hand-editing. Takes effect
    after TheHive is restarted (it reads application.conf at startup).
    """
    print(f"\n🔐 Step 4c: Authorising org(s) on the webhook in application.conf …")
    conf_path = Path(THEHIVE_CONF_PATH)
    if not conf_path.exists():
        print(f"   ⚠️  {conf_path} not found — skipping (set THEHIVE_CONF_PATH).")
        print(f"      Manually set: includedTheHiveOrganisations = {json.dumps(org_names)}")
        return

    content = conf_path.read_text(encoding="utf-8")
    # JSON happens to render a HOCON string array correctly: ["A", "B"]
    new_list = json.dumps(org_names)
    pattern = re.compile(r'includedTheHiveOrganisations\s*=\s*\[[^\]]*\]')
    if not pattern.search(content):
        print("   ⚠️  Could not find `includedTheHiveOrganisations = [...]`.")
        print(f"      Manually set it to: {new_list}")
        return

    new_content = pattern.sub(f"includedTheHiveOrganisations = {new_list}", content)
    if new_content == content:
        print(f"   ✅ Webhook already authorised for {new_list} — no change.")
        return
    conf_path.write_text(new_content, encoding="utf-8")
    print(f"   ✅ Webhook authorised for {new_list} in {conf_path}")
    print(f"      (restart TheHive to load it: docker compose restart thehive)")


# ── Step 5: Write the key into the project-root .env ──────────────────────────

def write_env_file(api_key: str) -> None:
    """Insert/update HIVE_API_KEY=<key> in the root .env, preserving other lines."""
    print(f"\n📝 Step 5: Writing HIVE_API_KEY to {ENV_FILE_PATH} …")
    path = Path(ENV_FILE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    new_line = f"HIVE_API_KEY={api_key}"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    replaced = False
    out: list[str] = []
    for line in existing:
        # Replace the active HIVE_API_KEY= line (ignore commented-out ones).
        if line.lstrip().startswith("HIVE_API_KEY=") and not line.lstrip().startswith("#"):
            out.append(new_line)
            replaced = True
        else:
            out.append(line)

    if not replaced:
        if out and out[-1].strip():
            out.append("")  # keep a blank line before the appended key
        out.append("# TheHive API key generated by scripts/setup_thehive.py.")
        out.append(new_line)

    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"   ✅ Key {'updated in' if replaced else 'appended to'} {path}")


# ── Step 6: Tell the operator how to load the new key + webhook authorisation ─

def print_recreate_instructions() -> None:
    """
    Two things must be loaded into the running stack:
      1. attense-app — docker-compose substitutes ${HIVE_API_KEY} from the root
         .env only at `up`/recreate time, so a plain restart keeps the OLD key;
         the container must be RECREATED.
      2. TheHive — reads application.conf (the webhook org allow-list we just
         patched) only at startup, so it must be RESTARTED.
    """
    print("\n♻️  Step 6: Load the changes into the running stack:")
    print("   # recreate attense-app to pick up the new HIVE_API_KEY from .env")
    print(f"       docker compose up -d {ATTENSE_APP_CONTAINER or 'attense-app'}")
    print("   # restart TheHive to load the patched webhook org allow-list")
    print("       docker compose restart thehive\n")


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
        key = fetch_api_key(user_login, org_name)
        ensure_notification_rule(org_name, key)
        if blueteam_key is None:        # first org owns the blueteam identity
            blueteam_key = key

    if not blueteam_key:
        sys.exit("❌ No organisation processed — nothing to write.")

    patch_webhook_orgs(ORG_NAMES)
    write_env_file(blueteam_key)
    print_recreate_instructions()

    print("\n" + "=" * 60)
    print("TheHive setup complete!")
    print()
    print("What just happened:")
    print(f"  - Organisation(s) ensured in TheHive: {', '.join(ORG_NAMES)}")
    print("  - A blue-team service user created per org; its API key PULLED from TheHive")
    print("  - CaseCreated → webhook notification rule registered per org")
    print(f"  - Webhook org allow-list patched in application.conf to {json.dumps(ORG_NAMES)}")
    print(f"  - First org's key written to {ENV_FILE_PATH} as HIVE_API_KEY")
    print(f"  - Next: recreate {ATTENSE_APP_CONTAINER or 'attense-app'} (key) + restart thehive (allow-list)")
    print("=" * 60)


if __name__ == "__main__":
    main()
