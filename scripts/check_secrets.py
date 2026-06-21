#!/usr/bin/env python3
"""
check_secrets.py — Env/secrets pre-flight checker
=====================================================
Validates the env files that back docker-compose.yml before you bring the
stack up:

1. Every required key is present and non-empty.
2. THEHIVE_ADMIN_PASSWORD is not still TheHive's stock "secret" default —
   that superadmin account can see every company's org/cases, so leaving it
   default is a real cross-tenant leak the moment more than one person has
   access to this deployment. This is the only default-value check that
   fails the run.
3. Every OTHER credential still at its shipped default (Cortex/Wazuh admin
   passwords, webhook/play secrets, ZAP's key, the containment token) is
   reported as a warning, not a failure — those are single shared infra
   pieces with no per-company data to leak, so leaving them default in a
   solo local lab is a reasonable, deliberate choice.
4. HIVE_API_KEY actually authenticates against a running TheHive instance.
   Tries the host URL first; if TheHive's port isn't published (e.g. after
   public-exposure hardening), falls back to checking from inside the
   attense-app container, which is on the same Docker network.

Usage (from project root)
--------------------------
    python scripts/check_secrets.py

Exits non-zero only if a required key is missing/empty, THEHIVE_ADMIN_PASSWORD
is still default, or HIVE_API_KEY fails to authenticate. Other unrotated
defaults print as warnings but don't fail the run.
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ENV_FILES = [
    ROOT / ".env",
    ROOT / "attense-app" / ".env",
    ROOT / "secrets" / "ATTENSE.env",
    ROOT / "secrets" / "enrichment.env",
]

# Must be present and non-empty.
REQUIRED_KEYS = [
    "HIVE_API_KEY",
    "THEHIVE_ADMIN_LOGIN",
    "THEHIVE_ADMIN_PASSWORD",
    "THEHIVE_SECRET",
    "CORTEX_ADMIN_KEY",
    "CORTEX_ADMIN_LOGIN",
    "CORTEX_ADMIN_PASSWORD",
    "CORTEX_PLAY_SECRET",
    "CORTEX_ORG_ADMIN",
    "CORTEX_ORG_PASS",
    "WEBHOOK_SECRET",
    "WAZUH_USER",
    "WAZUH_PASS",
    "ZAP_API_KEY",
    "CONTAINMENT_API_TOKEN",
]

# Left empty on purpose to disable that enrichment source gracefully.
OPTIONAL_KEYS = ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]

# Fails the run: this account can see every company's org/cases, so an
# unrotated default here is a real cross-tenant leak, not just hygiene.
CRITICAL_DEFAULTS = {
    "THEHIVE_ADMIN_PASSWORD": "secret",
}

# Warns but doesn't fail: single shared infra credentials with no
# per-company data behind them, so a solo local lab can reasonably leave
# these default until more than one person gets access to the deployment.
WARN_DEFAULTS = {
    "THEHIVE_ADMIN_LOGIN": "admin@thehive.local",
    "CORTEX_ADMIN_PASSWORD": "attense-Admin1!",
    "CORTEX_ORG_PASS": "attense-Analyst1!",
    "WAZUH_PASS": "wazuh",
    "WEBHOOK_SECRET": "changeme-webhook",
    "ZAP_API_KEY": "attense-lab-key",
    "THEHIVE_SECRET": (
        "attense-super-secret-key-that-is-at-least-64-bytes-long-for-thehive-so-it-starts"
    ),
    "CORTEX_PLAY_SECRET": (
        "5f6e69909a9ca4768d36c3f418a9a6e0857a0eac393d18071291f0971abc7e80f3dd02112b7f4505ae8f17eb8500aa61"
    ),
    "CONTAINMENT_API_TOKEN": "attense-containment-token",
}


def load_env_files() -> dict[str, tuple[str, Path]]:
    """Merge all env files; first file to define a key wins (matches the
    scripts/setup_*.py convention where real env vars take precedence)."""
    env: dict[str, tuple[str, Path]] = {}
    for path in ENV_FILES:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in env:
                env[key] = (value.strip(), path)
    return env


def check_required(env: dict[str, tuple[str, Path]]) -> list[str]:
    problems = []
    for key in REQUIRED_KEYS:
        if key not in env or not env[key][0]:
            problems.append(f"missing or empty: {key}")
    return problems


def _default_hits(env: dict[str, tuple[str, Path]], defaults: dict[str, str]) -> list[str]:
    hits = []
    for key, default_value in defaults.items():
        if key in env and env[key][0] == default_value:
            value, path = env[key]
            hits.append(
                f"{key} in {path.relative_to(ROOT)} is still the shipped default "
                f"({value!r})"
            )
    return hits


def check_critical_defaults(env: dict[str, tuple[str, Path]]) -> list[str]:
    return [
        f"{hit} -- this account can see every company's data; rotate it before "
        f"this stack is reachable by more than one trusted user"
        for hit in _default_hits(env, CRITICAL_DEFAULTS)
    ]


def check_warn_defaults(env: dict[str, tuple[str, Path]]) -> list[str]:
    return _default_hits(env, WARN_DEFAULTS)


def _try_hive_key_http(hive_url: str, key: str) -> list[str] | None:
    """[] on success, a problem list on a definite auth rejection, or None if
    this URL couldn't be reached at all (caller should try a fallback)."""
    request = urllib.request.Request(
        f"{hive_url}/api/user/current",
        headers={"Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return [] if response.status == 200 else [
                f"HIVE_API_KEY rejected by TheHive (HTTP {response.status})"
            ]
    except urllib.error.HTTPError as exc:
        return [f"HIVE_API_KEY rejected by TheHive (HTTP {exc.code})"]
    except urllib.error.URLError:
        return None


def _try_hive_key_via_container(key: str) -> list[str] | None:
    """Run the same check from inside attense-app instead of the host. TheHive's
    port is not published (public-exposure hardening), so the host can no
    longer reach it directly — attense-app is on attense_net and can."""
    container = os.getenv("ATTENSE_APP_CONTAINER", "attense_app")
    probe = (
        "import sys, urllib.request, urllib.error\n"
        "req = urllib.request.Request('http://thehive:9000/api/user/current', "
        "headers={'Authorization': 'Bearer ' + sys.argv[1]})\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=5) as r:\n"
        "        print(f'HTTP_STATUS={r.status}')\n"
        "        sys.exit(0 if r.status == 200 else 2)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(f'HTTP_STATUS={e.code}')\n"
        "    sys.exit(2)\n"
        "except Exception:\n"
        "    sys.exit(99)\n"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container, "python", "-c", probe, key],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return None  # docker itself unavailable here; let caller report generic failure
    if result.returncode == 0:
        return []
    if result.returncode == 99:
        return None  # couldn't reach TheHive even internally; not a key problem
    if result.returncode == 2:
        status_line = next(
            (line for line in result.stdout.splitlines() if line.startswith("HTTP_STATUS=")),
            "",
        )
        status = status_line.partition("=")[2]
        if status.isdigit():
            return [
                f"HIVE_API_KEY rejected by TheHive (HTTP {status}, checked from "
                f"inside {container} since TheHive's port isn't published)"
            ]

    # A docker/exec failure is not an HTTP response and must not be presented
    # as an authentication rejection (for example, docker exits 1 when its
    # daemon is stopped or the caller cannot access the engine pipe).
    return None


def check_hive_key_live(env: dict[str, tuple[str, Path]]) -> list[str]:
    key = env.get("HIVE_API_KEY", ("", None))[0]
    if not key:
        return []  # already reported by check_required

    host_url = os.getenv("HIVE_URL", "http://localhost:9000").rstrip("/")
    result = _try_hive_key_http(host_url, key)
    if result is not None:
        return result

    result = _try_hive_key_via_container(key)
    if result is not None:
        return result

    return [
        f"Could not reach TheHive at {host_url} from the host, and the "
        f"attense-app container fallback also failed -- is the stack running?"
    ]


def main() -> int:
    env = load_env_files()

    problems = check_required(env)
    problems += check_critical_defaults(env)
    problems += check_hive_key_live(env)
    warnings = check_warn_defaults(env)

    if warnings:
        print("Secrets check warnings (not fatal):\n")
        for warning in warnings:
            print(f"  - {warning}")
        print()

    if problems:
        print("Secrets check FAILED:\n")
        for problem in problems:
            print(f"  - {problem}")
        print(
            f"\n{len(problems)} problem(s) found across "
            f"{', '.join(str(p.relative_to(ROOT)) for p in ENV_FILES if p.exists())}."
        )
        return 1

    print("Secrets check passed: all required keys present, THEHIVE_ADMIN_PASSWORD rotated, HIVE_API_KEY is valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
