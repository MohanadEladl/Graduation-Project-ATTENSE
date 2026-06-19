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
4. Enables the Wazuh-backed and target-app containment responders, with the
   backend configuration required to work without manual Cortex UI setup.
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
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ── Load secrets/{ORG_NAME}.env automatically ────────────────────────────────
# The secrets file is named after the organisation (e.g. ATTENSE.env). It is
# EPHEMERAL: scripts/close_lab.py timestamp-backs-up and deletes it when the lab
# is closed, and this script auto-restores it from the newest backup on open
# (see _restore_secrets_if_missing above). It holds org bootstrap/runtime
# secrets only — externally-issued keys (VirusTotal/AbuseIPDB) live in the
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
    under secrets/backups/. Backup names end in a UTC stamp (…Z), which sorts
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
        print(f"♻️  Restored {path.name} from latest backup: {latest.name}")
    except Exception as exc:
        print(f"⚠️  Could not restore {path.name} from {latest.name}: {exc}")


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


# ── Configuration ─────────────────────────────────────────────────────────────

CORTEX_URL        = os.getenv("CORTEX_URL",        "http://localhost:9001")
THEHIVE_CONF_PATH = os.getenv("THEHIVE_CONF_PATH", str(
    Path(__file__).resolve().parent.parent / "thehive" / "application.conf"
))

# Admin credentials that will be created on first boot
ADMIN_LOGIN    = os.getenv("CORTEX_ADMIN_LOGIN",    "admin")
ADMIN_PASSWORD = os.getenv("CORTEX_ADMIN_PASSWORD", "attense-Admin1!")  # ≥8 chars, 1 upper, 1 digit
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

# ── Helpers ───────────────────────────────────────────────────────────────────

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
        # Only set this when there's an actual body — Cortex's JSON body
        # parser otherwise treats "Content-Type: application/json" plus an
        # empty body as a parse error (e.g. on bodyless GET requests).
        req.add_header("Content-Type", "application/json")

    if token:
        # Cortex's local/admin auth is cookie-based (see _get_session_token),
        # not a Bearer token — `token` is (session_cookie, xsrf_token). Once a
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


def _fetch_xsrf_token() -> str:
    """
    GET a public endpoint to obtain the CORTEX-XSRF-TOKEN cookie Play issues
    on any request (auth not required — confirmed it's set even on an
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

    Cortex's local auth is cookie-based (Set-Cookie: CORTEX_SESSION=<jwt>) —
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
            print("   Cortex API is up but Elasticsearch is not ready; retrying …", flush=True)
            time.sleep(5)
        except urllib.error.URLError as e:
            if not retry_transient or time.time() >= deadline:
                raise RuntimeError(f"POST /api/login failed: {e}") from e
            print("   Cortex login endpoint is temporarily unreachable; retrying …", flush=True)
            time.sleep(5)

    match = re.search(r"CORTEX_SESSION=([^;]+)", cookie_header)
    if not match:
        raise RuntimeError(f"Login succeeded but no session cookie returned: {cookie_header!r}")
    return match.group(1), _fetch_xsrf_token()


# ── Step 1: Bootstrap admin ───────────────────────────────────────────────────

def step_bootstrap_admin() -> tuple[str, str]:
    """Create the first admin user if Cortex is in maintenance mode. Returns session token."""
    print("\n🔧 Step 1: Bootstrap Cortex admin user …")

    # Check if already bootstrapped
    try:
        token = _get_session_token(
            ADMIN_LOGIN,
            ADMIN_PASSWORD,
            retry_transient=True,
        )
        print(f"   ✅ Admin '{ADMIN_LOGIN}' already exists — skipping creation.")
        return token
    except RuntimeError as e:
        if "HTTP 520" not in str(e) and "HTTP 401" not in str(e):
            # 520 = maintenance mode (first boot), 401 = wrong creds
            # Any other error is unexpected
            raise

    # Cortex is in maintenance mode. The first superadmin user must belong to
    # the special 'cortex' platform organisation — it is not auto-created by
    # Cortex and is distinct from the 'ATTENSE' org created later — so ensure
    # it exists before creating the admin user.
    orgs = _req("GET", "/api/organization")
    existing_orgs = [o.get("name") for o in (orgs if isinstance(orgs, list) else [])]
    if "cortex" not in existing_orgs:
        print(f"   Creating bootstrap organisation 'cortex' …")
        _req("POST", "/api/organization", {
            "name":        "cortex",
            "description": "Cortex platform organisation",
            "status":      "Active",
        })

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

def step_create_org(admin_token: tuple[str, str]) -> str:
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

def step_create_api_key(admin_token: tuple[str, str]) -> str:
    """Create an org analyst user and generate an API key. Returns the API key."""
    print(f"\n🔑 Step 3: Create analyst user and generate API key …")

    # Check if user exists already. Cortex's /api/user list responses key
    # the login under "id" (and "_id"), not "login".
    users: list = _req("GET", "/api/user", token=admin_token)
    existing_logins = [u.get("id") for u in (users if isinstance(users, list) else [])]

    if ORG_ADMIN_LOGIN not in existing_logins:
        print(f"   Creating user '{ORG_ADMIN_LOGIN}' in org '{ORG_NAME}' …")
        _req("POST", "/api/user", {
            "login":        ORG_ADMIN_LOGIN,
            "name":         "ATTENSE Analyst",
            "password":     ORG_ADMIN_PASS,
            "organization": ORG_NAME,
            "roles":        ["read", "analyze", "orgadmin"],
        }, token=admin_token)
        print(f"   ✅ User '{ORG_ADMIN_LOGIN}' created.")
    else:
        print(f"   ✅ User '{ORG_ADMIN_LOGIN}' already exists — skipping creation.")

    # Generate (or renew) API key for that user
    print(f"   Generating API key for '{ORG_ADMIN_LOGIN}' …")
    resp = _req("POST", f"/api/user/{ORG_ADMIN_LOGIN}/key/renew", token=admin_token)
    # This endpoint responds with a bare text/plain key, not JSON — but
    # handle a dict shape too in case that ever changes.
    api_key = resp.get("key", "") if isinstance(resp, dict) else resp
    if not api_key:
        raise RuntimeError(f"Could not extract API key from response: {resp}")

    print(f"   ✅ API key generated: {api_key[:8]}…{api_key[-4:]} (truncated for display)")
    return str(api_key)


# ── Step 4: Enable containment responders ────────────────────────────────────

def step_enable_responders(org_token: tuple[str, str]) -> None:
    """Enable Wazuh and target-app responders in the ATTENSE organisation."""
    print(f"\n🔫 Step 4: Enable containment responders …")

    # List available responder definitions. This needs an org-scoped session
    # (read/analyze/orgadmin) — the platform superadmin alone gets a 403
    # "Insufficient rights" against /api/responderdefinition.
    try:
        definitions = _req("GET", "/api/responderdefinition", token=org_token)
    except RuntimeError as e:
        print(f"   ⚠️  Could not list responders: {e}")
        print("       Responders will need to be enabled manually in the Cortex UI.")
        return

    if not isinstance(definitions, list):
        print("   ⚠️  Unexpected responder list format — skipping auto-enable.")
        return

    # Already-enabled responders for this org — needed for idempotency,
    # since re-enabling one that's already active is a version conflict.
    enabled = _req("GET", "/api/organization/responder?range=all", token=org_token)
    enabled_ids = {
        e.get("workerDefinitionId") for e in (enabled if isinstance(enabled, list) else [])
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
            print(f"   ⚠️  Responder '{responder_name}' not found yet.")
            print("       Cortex may still be scanning the responders directory.")
            print("       Wait 30s and re-run, or enable it manually in the Cortex UI.")
            continue

        worker_definition_id = target.get("id")
        if not worker_definition_id:
            print(f"   ⚠️  Found responder '{responder_name}' but missing ID — skipping.")
            continue

        if worker_definition_id in enabled_ids:
            print(f"   ✅ '{responder_name}' already enabled for org '{ORG_NAME}' — skipping.")
            continue

        # Note: the org is implied by the caller's own session/org
        # membership, not a path segment — Cortex's own UI calls this same
        # "/api/organization/responder/{id}" path with no org name in it.
        _req("POST", f"/api/organization/responder/{worker_definition_id}", {
            "name":          worker_definition_id,
            "configuration": configuration,
            "jobCache":      10,
        }, token=org_token)
        print(f"   ✅ '{responder_name}' responder enabled for org '{ORG_NAME}'.")


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

    # Match the bearer auth 'key = "..."' line inside the cortex block
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

def step_note_secrets_kept() -> None:
    """
    Setup keeps secrets/{ORG_NAME}.env in place — it is NOT backed up or deleted
    here. The timestamped backup + deletion happen when you CLOSE the lab via
    scripts/close_lab.py; the next open auto-restores it from that backup.
    """
    print(f"\n🗄️  Step 6: Secrets file kept in place (not deleted).")
    secrets_path = _resolve_secrets_path(ORG_NAME)
    print(f"   ℹ️  {secrets_path}")
    print("      Closing the lab (scripts/close_lab.py) timestamp-backs-up and removes")
    print("      this file; the next open restores it. VirusTotal/AbuseIPDB keys live")
    print("      in secrets/enrichment.env and are kept permanently.")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(f"  ATTENSE — Cortex First-Boot Setup  [{ORG_NAME}]")
    print("=" * 60)
    print(f"  Secrets file: secrets/{ORG_NAME}.env  (kept; backed up on success)")
    print("=" * 60)

    _wait_for_cortex()

    admin_token = step_bootstrap_admin()
    step_create_org(admin_token)
    api_key = step_create_api_key(admin_token)
    org_token = _get_session_token(ORG_ADMIN_LOGIN, ORG_ADMIN_PASS)
    step_enable_responders(org_token)
    step_patch_thehive_conf(api_key)
    step_note_secrets_kept()            # keeps ATTENSE.env in place (close_lab.py backs up + deletes)
    step_restart_thehive()              # auto-restarts TheHive via Docker socket

    print("\n" + "=" * 60)
    print("Cortex setup complete — fully automated!")
    print()
    print("What just happened:")
    print("  - Cortex admin user + ATTENSE org created")
    print("  - API key generated and written to thehive/application.conf")
    print(f"  - {len(RESPONDERS)} Wazuh and target-app responders enabled")
    print("  - Secrets file kept in place (close_lab.py backs it up + removes it on close)")
    print("  - TheHive restarted to pick up the new key")
    print()
    print("You can now:")
    print("  - Open TheHive at http://localhost:9000")
    print("  - On an alert, the analyst chooses the matching containment responder")
    print("  - ATTENSE records CONTAINING/CONTAINED only after that chosen action runs")
    print("=" * 60)


if __name__ == "__main__":
    main()
