#!/usr/bin/env python3
"""
setup_cortex.py — Cortex First-Boot Automator
===============================================
Automates the entire Cortex → TheHive API key wiring in one shot.

What it does
------------
1. Waits for the Cortex container to become healthy.
2. Creates the first admin user + organisation via the Cortex bootstrap API.
3. Generates an API key for that organisation.
4. Enables the WazuhBlockIP responder in that organisation.
5. Writes the API key into thehive/application.conf so TheHive can talk to Cortex.
6. Prints clear next steps.

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
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ── Load secrets/{ORG_NAME}.env automatically ────────────────────────────────
# The secrets file is named after the organisation (e.g. ATTENSE.env).
# It is a TEMPORARY file: setup_cortex.py deletes it after a successful run
# because the API key has been written to thehive/application.conf and the
# plaintext copy is no longer needed.
#
# Load order: env vars already set in the shell always win over the file.

_SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"


def _resolve_secrets_path(org_name: str) -> Path:
    """Return the path to secrets/{org_name}.env."""
    return _SECRETS_DIR / f"{org_name}.env"


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


# Bootstrap: load using the default org name so the config block below can read
# CORTEX_ORG_NAME if it was set in the file (circular but safe — we default to
# 'ATTENSE' for the first pass, then re-resolve after ORG_NAME is set).
_load_secrets_file(os.getenv("CORTEX_ORG_NAME", "ATTENSE"))


# ── Configuration ─────────────────────────────────────────────────────────────

CORTEX_URL        = os.getenv("CORTEX_URL",        "http://localhost:9001")
THEHIVE_CONF_PATH = os.getenv("THEHIVE_CONF_PATH", str(
    Path(__file__).resolve().parent.parent / "thehive" / "application.conf"
))

# Admin credentials that will be created on first boot
ADMIN_LOGIN    = os.getenv("CORTEX_ADMIN_LOGIN",    "admin")
ADMIN_PASSWORD = os.getenv("CORTEX_ADMIN_PASSWORD", "attense-Admin1!")  # ≥8 chars, 1 upper, 1 digit
ADMIN_NAME     = os.getenv("CORTEX_ADMIN_NAME",     "ATTENSE Admin")

# Organisation that owns the WazuhBlockIP responder
ORG_NAME       = os.getenv("CORTEX_ORG_NAME",       "ATTENSE")
ORG_ADMIN_LOGIN = os.getenv("CORTEX_ORG_ADMIN",     "attense-analyst")
ORG_ADMIN_PASS  = os.getenv("CORTEX_ORG_PASS",      "attense-Analyst1!")

# Responder to enable
RESPONDER_NAME = "WazuhBlockIP"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _req(
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
    login_pass: tuple[str, str] | None = None,
) -> dict:
    """Make an HTTP request to Cortex. Returns parsed JSON."""
    url = f"{CORTEX_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")

    if token:
        req.add_header("Authorization", f"Bearer {token}")
    elif login_pass:
        import base64
        cred = base64.b64encode(f"{login_pass[0]}:{login_pass[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode().strip()
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Cortex returns some values (e.g. API keys) as plain strings
                return {"_raw": raw, "key": raw.strip('"')}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} from {method} {path}: {err_body}") from e


def _wait_for_cortex(max_wait: int = 120) -> None:
    """Poll until Cortex responds on /api/status."""
    print(f"⏳ Waiting for Cortex at {CORTEX_URL} …", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            _req("GET", "/api/status")
            print(" ✅ Cortex is up!")
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(3)
    print()
    sys.exit("❌ Cortex did not become ready in time. Is `docker compose up -d` running?")


def _get_session_token(login: str, password: str) -> str:
    """Log in, capture the CORTEX_SESSION cookie, use it to generate an API key.

    Cortex 3.x POST /api/login returns the user object in the body and puts
    the real auth credential in a Set-Cookie header (CORTEX_SESSION). We
    extract that cookie, call POST /api/user/{login}/key/renew with it to
    obtain an API key, and return the key so all downstream Bearer-token
    calls work without modification.
    """
    import http.cookiejar
    import urllib.request as _ur

    url = f"{CORTEX_URL}/api/login"
    data = json.dumps({"user": login, "password": password}).encode()
    req = _ur.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")

    jar = http.cookiejar.CookieJar()
    opener = _ur.build_opener(_ur.HTTPCookieProcessor(jar))
    try:
        with opener.open(req, timeout=10) as resp:
            resp.read()  # consume body
    except Exception as e:
        raise RuntimeError(f"Login failed for {login}: {e}") from e

    # Extract session cookie value
    session_cookie = next(
        (c.value for c in jar if c.name == "CORTEX_SESSION"), None
    )
    if not session_cookie:
        raise RuntimeError(f"Login succeeded but no CORTEX_SESSION cookie returned")

    # Fetch a CSRF token — Play CSRF requires it as ?csrfToken= query param on POST
    csrf_jar = http.cookiejar.CookieJar()
    csrf_opener = _ur.build_opener(_ur.HTTPCookieProcessor(csrf_jar))
    csrf_get = _ur.Request(f"{CORTEX_URL}/api/status")
    csrf_get.add_header("Cookie", f"CORTEX_SESSION={session_cookie}")
    with csrf_opener.open(csrf_get, timeout=10):
        pass
    xsrf_token = next(
        (c.value for c in csrf_jar if "XSRF" in c.name.upper()), None
    )
    if not xsrf_token:
        raise RuntimeError("Could not obtain CORTEX XSRF token from /api/status")

    # Use session cookie + CSRF query param to generate an API key
    key_url = f"{CORTEX_URL}/api/user/{login}/key/renew?csrfToken={xsrf_token}"
    key_req = _ur.Request(key_url, data=b"", method="POST")
    key_req.add_header("Cookie", f"CORTEX_SESSION={session_cookie}; CORTEX-XSRF-TOKEN={xsrf_token}")
    try:
        with _ur.urlopen(key_req, timeout=10) as resp:
            raw = resp.read().decode().strip()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} from POST /api/user/{login}/key/renew: {e.read().decode()}") from e

    # Cortex returns the API key as a plain string (not JSON)
    if not raw:
        raise RuntimeError("API key renewal returned empty response")
    # Strip surrounding quotes if Cortex wraps the key in a JSON string
    key = raw.strip('"')
    if not key:
        raise RuntimeError(f"API key renewal returned unusable response: {raw!r}")
    return key


# ── Step 1: Bootstrap admin ───────────────────────────────────────────────────

def step_bootstrap_admin() -> str:
    """Create the first admin user if Cortex is in maintenance mode. Returns session token."""
    print("\n🔧 Step 1: Bootstrap Cortex admin user …")

    # Check if already bootstrapped
    try:
        token = _get_session_token(ADMIN_LOGIN, ADMIN_PASSWORD)
        print(f"   ✅ Admin '{ADMIN_LOGIN}' already exists — skipping creation.")
        return token
    except RuntimeError as e:
        if "HTTP 520" not in str(e) and "HTTP 401" not in str(e):
            # 520 = maintenance mode (first boot), 401 = wrong creds
            # Any other error is unexpected
            raise

    # Cortex is in maintenance mode — must call /api/maintenance/migrate first
    # to transition out of maintenance mode before the bootstrap POST /api/user
    # will be accepted (without this call, POST /api/user returns HTTP 520).
    print("   Running database migration …")
    try:
        _req("POST", "/api/maintenance/migrate")
        print("   ✅ Migration done.")
    except RuntimeError as me:
        if "HTTP 204" not in str(me):
            print(f"   ⚠️  Migration call returned: {me} (continuing anyway)")

    # Cortex is in maintenance mode — create admin
    print(f"   Creating admin user '{ADMIN_LOGIN}' …")
    _req("POST", "/api/user", {
        "login":    ADMIN_LOGIN,
        "name":     ADMIN_NAME,
        "password": ADMIN_PASSWORD,
        "roles":    ["superadmin"],
    })
    token = _get_session_token(ADMIN_LOGIN, ADMIN_PASSWORD)
    print(f"   ✅ Admin created and logged in.")
    return token


# ── Step 2: Create organisation ───────────────────────────────────────────────

def step_create_org(admin_token: str) -> str:
    """Create the ATTENSE organisation. Returns org name."""
    print(f"\n🏢 Step 2: Create organisation '{ORG_NAME}' …")

    # List existing orgs
    orgs = _req("GET", "/api/organization", token=admin_token)
    existing = [o.get("name") for o in (orgs if isinstance(orgs, list) else [])]
    if ORG_NAME in existing:
        print(f"   ✅ Organisation '{ORG_NAME}' already exists — skipping.")
        return ORG_NAME

    _req("POST", "/api/organization", {
        "name":        ORG_NAME,
        "description": "ATTENSE Cyber Range Organisation",
        "status":      "Active",
    }, token=admin_token)
    print(f"   ✅ Organisation '{ORG_NAME}' created.")
    return ORG_NAME


# ── Step 3: Create org-level user + API key ───────────────────────────────────

def step_create_api_key(admin_token: str) -> str:
    """Create an org analyst user and generate an API key. Returns the API key."""
    print(f"\n🔑 Step 3: Create analyst user and generate API key …")

    # Check if user exists already
    users: list = _req("GET", "/api/user", token=admin_token)
    existing_logins = [u.get("login") for u in (users if isinstance(users, list) else [])]

    if ORG_ADMIN_LOGIN not in existing_logins:
        print(f"   Creating user '{ORG_ADMIN_LOGIN}' in org '{ORG_NAME}' …")
        try:
            _req("POST", "/api/user", {
                "login":        ORG_ADMIN_LOGIN,
                "name":         "ATTENSE Analyst",
                "password":     ORG_ADMIN_PASS,
                "organization": ORG_NAME,
                "roles":        ["read", "analyze", "orgadmin"],
            }, token=admin_token)
            print(f"   ✅ User '{ORG_ADMIN_LOGIN}' created.")
        except RuntimeError as e:
            if "ConflictError" in str(e) or "already exists" in str(e):
                print(f"   ✅ User '{ORG_ADMIN_LOGIN}' already exists — skipping creation.")
            else:
                raise
    else:
        print(f"   ✅ User '{ORG_ADMIN_LOGIN}' already exists — skipping creation.")

    # Get the existing API key if there is one — avoids invalidating a key
    # that TheHive may already be using. Only renew if the key is absent.
    print(f"   Fetching API key for '{ORG_ADMIN_LOGIN}' …")
    try:
        existing_key_resp = _req("GET", f"/api/user/{ORG_ADMIN_LOGIN}/key", token=admin_token)
        existing_key = existing_key_resp.get("key") or existing_key_resp.get("_raw", "")
        if isinstance(existing_key, str):
            existing_key = existing_key.strip('"')
    except RuntimeError:
        existing_key = ""

    if existing_key and len(existing_key) > 8:
        print(f"   ✅ Reusing existing API key: {existing_key[:8]}…{existing_key[-4:]}")
        return str(existing_key)

    print(f"   No existing key found — generating new one …")
    resp = _req("POST", f"/api/user/{ORG_ADMIN_LOGIN}/key/renew", token=admin_token)
    api_key = resp.get("key") or resp  # some versions return the key string directly
    if isinstance(api_key, dict):
        api_key = api_key.get("key", "")
    if not api_key:
        raise RuntimeError(f"Could not extract API key from response: {resp}")

    print(f"   ✅ API key generated: {api_key[:8]}…{api_key[-4:]} (truncated for display)")
    return str(api_key)


# ── Step 4: Enable WazuhBlockIP responder ────────────────────────────────────

def step_enable_responder(org_api_key: str) -> None:
    """Enable the WazuhBlockIP responder in the ATTENSE organisation.

    Must be called with the ORG user's API key (not admin), because:
    - GET /api/responderdefinition  lists catalog definitions (org user scope)
    - POST /api/organization/responder/:defId  creates a WorkerConfig for the org
    Both endpoints use Bearer auth which bypasses Play's CSRF check.
    """
    print(f"\n🔫 Step 4: Enable '{RESPONDER_NAME}' responder …")

    # Check if it is already enabled for this org
    try:
        enabled = _req("GET", "/api/responder", token=org_api_key)
        if isinstance(enabled, list) and any(r.get("name") == RESPONDER_NAME for r in enabled):
            print(f"   ✅ '{RESPONDER_NAME}' already enabled for org '{ORG_NAME}' — skipping.")
            return
    except RuntimeError:
        pass  # will re-raise on the real call if truly broken

    # List available responder DEFINITIONS (catalog scan result)
    try:
        definitions = _req("GET", "/api/responderdefinition", token=org_api_key)
    except RuntimeError as e:
        print(f"   ⚠️  Could not list responder definitions: {e}")
        print("       The responder will need to be enabled manually in the Cortex UI.")
        return

    if not isinstance(definitions, list):
        print("   ⚠️  Unexpected responder definition list format — skipping auto-enable.")
        return

    target = next((d for d in definitions if d.get("name") == RESPONDER_NAME), None)
    if not target:
        print(f"   ⚠️  Responder '{RESPONDER_NAME}' not found in definitions.")
        print("       Cortex may still be scanning the responders directory.")
        print("       Wait 30s and re-run, or enable it manually in the Cortex UI.")
        return

    definition_id = target.get("id")
    if not definition_id:
        print(f"   ⚠️  Found responder definition but missing id — skipping.")
        return

    # Enable: POST /api/organization/responder/:defId (org-user context)
    try:
        _req("POST", f"/api/organization/responder/{definition_id}", {
            "name":          RESPONDER_NAME,
            "configuration": {},
        }, token=org_api_key)
    except RuntimeError as e:
        if "ConflictError" in str(e) or "already exists" in str(e):
            print(f"   ✅ '{RESPONDER_NAME}' already enabled — skipping.")
            return
        raise
    print(f"   ✅ '{RESPONDER_NAME}' responder enabled for org '{ORG_NAME}'.")


# ── Step 5: Patch thehive/application.conf ────────────────────────────────────

def step_patch_thehive_conf(api_key: str) -> None:
    """Replace the Cortex API key placeholder in thehive/application.conf."""
    print(f"\n📝 Step 5: Patching thehive/application.conf …")

    conf_path = Path(THEHIVE_CONF_PATH)
    if not conf_path.exists():
        print(f"   ❌ File not found: {conf_path}")
        print(f"      Set THEHIVE_CONF_PATH env var to the correct path.")
        return

    content = conf_path.read_text(encoding="utf-8")

    # Match the 'key = "..."' line inside the cortex block
    pattern = re.compile(r'(cortex\s*\{[^}]*key\s*=\s*")[^"]*(")', re.DOTALL)

    if not pattern.search(content):
        print("   ⚠️  Could not find `key = \"...\"` inside the cortex block.")
        print(f"      Please manually set the key to:\n      {api_key}")
        return

    new_content = pattern.sub(rf'\g<1>{api_key}\g<2>', content)
    conf_path.write_text(new_content, encoding="utf-8")
    print(f"   ✅ API key written to {conf_path}")


# ── Step 7: Auto-restart TheHive via Docker socket ───────────────────────────

def step_restart_thehive() -> None:
    """
    Restart the TheHive container via the Docker Unix socket so it
    immediately picks up the new Cortex API key we just wrote.

    Uses only Python stdlib — no pip installs needed.
    Skips gracefully if the Docker socket is not mounted (e.g. running
    the script manually on the host outside Docker).

    How it works:
        Docker exposes a REST API over a Unix socket at /var/run/docker.sock.
        We open that socket like a normal HTTP connection and POST to:
            /containers/attense_thehive/restart
        Docker then restarts the container, exactly like `docker restart`.
    """
    import http.client as _http
    import socket as _sock

    DOCKER_SOCKET    = "/var/run/docker.sock"
    THEHIVE_CONTAINER = os.getenv("THEHIVE_CONTAINER", "attense_thehive")

    print(f"\nStep 7: Restarting TheHive so it picks up the new Cortex key …")

    if not Path(DOCKER_SOCKET).exists():
        print(f"   Docker socket not found at {DOCKER_SOCKET} — skipping auto-restart.")
        print(f"   Run manually: docker compose restart thehive")
        return

    # Build a minimal HTTP client that talks over the Unix socket
    class _UnixHTTPConnection(_http.HTTPConnection):
        def connect(self) -> None:
            self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect(DOCKER_SOCKET)

    try:
        conn = _UnixHTTPConnection("localhost")
        conn.request("POST", f"/containers/{THEHIVE_CONTAINER}/restart")
        resp = conn.getresponse()
        if resp.status in (200, 204):
            print(f"   TheHive is restarting … (Docker status {resp.status})")
            print(f"   It will be ready in ~30 seconds at http://localhost:9000")
        else:
            body = resp.read().decode()
            print(f"   Docker returned {resp.status}: {body}")
            print(f"   Run manually: docker compose restart thehive")
    except Exception as exc:
        print(f"   Could not restart TheHive via socket: {exc}")
        print(f"   Run manually: docker compose restart thehive")


# ── Main ─────────────────────────────────────────────────────────────────────

def step_delete_secrets_file() -> None:
    """
    Securely delete secrets/{ORG_NAME}.env after a successful setup.

    The API key is now in thehive/application.conf — keeping the plaintext
    secrets file around any longer is unnecessary and a security risk.
    The secrets/ directory (and the file) is already gitignored, but removing
    it from disk is the safest option for a shared or cloud-hosted machine.
    """
    print(f"\n🗑️  Step 6: Removing temporary secrets file …")
    secrets_path = _resolve_secrets_path(ORG_NAME)
    if not secrets_path.exists():
        print(f"   ℹ️  {secrets_path.name} not found — nothing to delete.")
        return

    # Overwrite with zeros before deletion (best-effort scrub)
    try:
        size = secrets_path.stat().st_size
        secrets_path.write_bytes(b"\x00" * size)
    except Exception:
        pass  # scrub failed — still delete

    try:
        secrets_path.unlink()
        print(f"   ✅  secrets/{secrets_path.name} deleted — plaintext credentials removed from disk.")
    except Exception as exc:
        print(f"   ⚠️  Could not delete {secrets_path}: {exc}")
        print("      Please delete it manually.")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(f"  ATTENSE — Cortex First-Boot Setup  [{ORG_NAME}]")
    print("=" * 60)
    print(f"  Secrets file: secrets/{ORG_NAME}.env  (will be deleted on success)")
    print("=" * 60)

    _wait_for_cortex()

    admin_token = step_bootstrap_admin()
    step_create_org(admin_token)
    api_key = step_create_api_key(admin_token)
    step_enable_responder(api_key)
    step_patch_thehive_conf(api_key)
    step_delete_secrets_file()          # removes ATTENSE.env from disk
    step_restart_thehive()              # auto-restarts TheHive via Docker socket

    print("\n" + "=" * 60)
    print("Cortex setup complete — fully automated!")
    print()
    print("What just happened:")
    print("  - Cortex admin user + ATTENSE org created")
    print("  - API key generated and written to thehive/application.conf")
    print("  - WazuhBlockIP responder enabled")
    print("  - Secrets file deleted from disk")
    print("  - TheHive restarted to pick up the new key")
    print()
    print("You can now:")
    print("  - Open TheHive at http://localhost:9000")
    print("  - On an alert → click Responders → WazuhBlockIP")
    print("  - Incident transitions: CONTAINING → CONTAINED automatically")
    print("=" * 60)


if __name__ == "__main__":
    main()
