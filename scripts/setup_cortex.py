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

import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Cortex 3.x authenticates the admin session with a Set-Cookie session, NOT a
# bearer token in the login response body. We keep a process-wide cookie jar so
# that once we POST /api/login, every subsequent request is authenticated by the
# session cookie automatically. `_get_session_token` returns this sentinel
# instead of a real token; `_req` treats it as "use the session cookie".
_COOKIE_JAR = http.cookiejar.CookieJar()
_OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_COOKIE_JAR))
SESSION_SENTINEL = "__cortex_session_cookie__"


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
    # Only advertise a JSON body when we actually send one. Cortex rejects a
    # GET (or any bodyless request) that carries Content-Type: application/json
    # with HTTP 400 "Invalid Json: No content to map".
    if data is not None:
        req.add_header("Content-Type", "application/json")

    if token and token != SESSION_SENTINEL:
        # A real API-key bearer token (not the admin session sentinel).
        req.add_header("Authorization", f"Bearer {token}")
    elif login_pass:
        import base64
        cred = base64.b64encode(f"{login_pass[0]}:{login_pass[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    # When token == SESSION_SENTINEL we send no auth header — the session cookie
    # carried by _OPENER authenticates the request.

    # Cortex (Play framework) enforces CSRF on cookie-authenticated mutating
    # requests. After a GET it sets a CORTEX-XSRF-TOKEN cookie; that value must
    # be echoed in the X-CORTEX-XSRF-TOKEN header on POST/PUT/DELETE/PATCH or the
    # request is rejected with 403 "No CSRF token found". API-key (bearer) auth
    # is exempt, so only add it for session-based mutations.
    if method.upper() in ("POST", "PUT", "DELETE", "PATCH") and (not token or token == SESSION_SENTINEL):
        xsrf = next((c.value for c in _COOKIE_JAR if "xsrf" in c.name.lower()), None)
        if xsrf:
            req.add_header("X-CORTEX-XSRF-TOKEN", xsrf)

    try:
        with _OPENER.open(req, timeout=10) as resp:
            raw = resp.read().decode()
            if not raw.strip():
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Some endpoints (e.g. /api/user/<login>/key/renew) return the
                # raw value as plain text, not JSON. Hand it back as a string.
                return raw.strip()
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
    """Log in to Cortex. Cortex 3.x sets a session cookie (captured by _OPENER's
    cookie jar) and returns the user object — there is no token in the body. We
    return a sentinel that tells _req to authenticate via that session cookie.
    A bearer token in the response (older builds) is honoured if present."""
    resp = _req("POST", "/api/login", {"user": login, "password": password})
    token = resp.get("token") or resp.get("access_token")
    if token:
        return token
    # Prime the CSRF token: Cortex only sets the CORTEX-XSRF-TOKEN cookie in
    # response to a GET, so make one harmless GET now. After this, _req can
    # attach the X-CORTEX-XSRF-TOKEN header to subsequent session-auth POSTs.
    try:
        _req("GET", "/api/user/current", token=SESSION_SENTINEL)
    except RuntimeError:
        pass
    # Cookie-based session: succeeds as long as a session cookie was set.
    if any(c.name.lower() in ("play_session", "cortex-session", "session")
           for c in _COOKIE_JAR):
        return SESSION_SENTINEL
    # Fall back to the sentinel anyway — the cookie jar will carry whatever
    # Cortex set; if nothing was set, the next authenticated call will fail
    # clearly rather than here.
    return SESSION_SENTINEL


# ── Step 1: Bootstrap admin ───────────────────────────────────────────────────

def step_bootstrap_admin(max_wait: int = 180) -> str:
    """Create the first admin user once Cortex finishes its first-boot DB
    migration. Returns session token.

    Cortex answers /api/status with 200 while its Elasticsearch indexes are
    still migrating, but every other endpoint (including POST /api/user) returns
    HTTP 520 'maintenance mode' until migration completes. The compose
    healthcheck therefore passes too early. We retry the bootstrap, tolerating
    520, until the migration window closes.
    """
    print("\n🔧 Step 1: Bootstrap Cortex admin user …")
    deadline = time.time() + max_wait
    attempt = 0
    while True:
        attempt += 1
        # Cortex answers /api/status with 200 but returns 520 for every other
        # endpoint until its Elasticsearch indexes are migrated. The migration
        # is NOT automatic — it must be triggered once via this endpoint. It is
        # idempotent (returns 204 whether or not it was already run), so it is
        # safe to call on every attempt.
        try:
            _req("POST", "/api/maintenance/migrate")
            print("   🗄️  Cortex database migration triggered (or already done).")
        except RuntimeError as e:
            # 520 here just means Cortex isn't ready to migrate yet — keep going.
            if "HTTP 520" not in str(e):
                raise

        # Check if already bootstrapped.
        #   200 → admin exists, we're done.
        #   401 → no admin yet (fresh, migrated Cortex) OR wrong password —
        #         fall through and try to create it. If it already exists with a
        #         different password, the create call below fails loudly.
        #   520 → still migrating — fall through, the create call will 520 too
        #         and we retry.
        try:
            token = _get_session_token(ADMIN_LOGIN, ADMIN_PASSWORD)
            print(f"   ✅ Admin '{ADMIN_LOGIN}' already exists — skipping creation.")
            return token
        except RuntimeError as e:
            if "HTTP 401" not in str(e) and "HTTP 520" not in str(e):
                # Unexpected error — surface it.
                raise

        # Try to create the admin user.
        try:
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
        except RuntimeError as e:
            if "HTTP 520" not in str(e):
                raise
            if time.time() >= deadline:
                raise RuntimeError(
                    f"Cortex still in maintenance mode (HTTP 520) after "
                    f"{max_wait}s — DB migration did not finish in time."
                ) from e
            print(f"   ⏳ Cortex still migrating (attempt {attempt}); retrying in 5s …")
            time.sleep(5)


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

    # NOTE: GET /api/user is scoped to the superadmin's current org, so a user
    # that lives in the ATTENSE org may be absent from this list even though it
    # exists. We therefore also tolerate a ConflictError on creation.
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

    # Ensure the analyst has a password set (needed if it was created on a prior
    # partial run before this step completed). Idempotent on Cortex.
    try:
        _req("POST", f"/api/user/{ORG_ADMIN_LOGIN}/password/set",
             {"password": ORG_ADMIN_PASS}, token=admin_token)
    except RuntimeError:
        pass

    # Generate (or renew) API key for that user
    print(f"   Generating API key for '{ORG_ADMIN_LOGIN}' …")
    resp = _req("POST", f"/api/user/{ORG_ADMIN_LOGIN}/key/renew", token=admin_token)
    # /key/renew returns the key as a plain string on Cortex 3.x; older builds
    # wrap it in {"key": ...}. _req hands back a str or a dict accordingly.
    if isinstance(resp, str):
        api_key = resp
    elif isinstance(resp, dict):
        api_key = resp.get("key", "")
    else:
        api_key = ""
    if not api_key:
        raise RuntimeError(f"Could not extract API key from response: {resp!r}")

    print(f"   ✅ API key generated: {api_key[:8]}…{api_key[-4:]} (truncated for display)")
    return str(api_key)


# ── Step 4: Enable WazuhBlockIP responder ────────────────────────────────────

def step_enable_responder(org_key: str) -> None:
    """Enable the WazuhBlockIP responder in the ATTENSE organisation.

    Responder management is an ORG-level action: the Cortex superadmin gets 403
    'Insufficient rights' on /api/responder. We authenticate with the ATTENSE
    org analyst's API key (orgAdmin role), which is also exempt from CSRF.
    """
    print(f"\n🔫 Step 4: Enable '{RESPONDER_NAME}' responder …")

    # List available responder definitions (as the org analyst, via API key)
    try:
        definitions = _req("GET", "/api/responder", token=org_key)
    except RuntimeError as e:
        print(f"   ⚠️  Could not list responders: {e}")
        print("       The responder will need to be enabled manually in the Cortex UI.")
        return

    if not isinstance(definitions, list):
        print("   ⚠️  Unexpected responder list format — skipping auto-enable.")
        return

    target = next((d for d in definitions if d.get("name") == RESPONDER_NAME), None)
    if not target:
        print(f"   ⚠️  Responder '{RESPONDER_NAME}' not found yet.")
        print("       Cortex may still be scanning the responders directory.")
        print("       Wait 30s and re-run, or enable it manually in the Cortex UI.")
        return

    worker_definition_id = target.get("id")
    if not worker_definition_id:
        print(f"   ⚠️  Found responder but missing ID — skipping.")
        return

    # Enable it in the ATTENSE org (org analyst / API key)
    try:
        _req("POST", f"/api/organization/{ORG_NAME}/responder/{worker_definition_id}", {
            "configuration": {},
            "jobCache":      10,
        }, token=org_key)
        print(f"   ✅ '{RESPONDER_NAME}' responder enabled for org '{ORG_NAME}'.")
    except RuntimeError as e:
        if "already" in str(e).lower() or "conflict" in str(e).lower():
            print(f"   ✅ '{RESPONDER_NAME}' responder already enabled — skipping.")
        else:
            raise


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
    step_enable_responder(admin_token)
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
