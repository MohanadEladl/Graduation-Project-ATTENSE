"""
backend/identity.py — Resolve a red-team operator's real identity.

The frontend forwards whatever session token it captured at login (see
frontends/red-team/src/routes/Login.jsx) as X-Session-Token. We validate it
against attense-app's own session store -- the same one every other ATTENSE
service trusts (core/session_store.py) -- rather than inventing a second
identity system.

validate_session() is intentionally soft (never raises, returns None on any
failure) -- main.py's require_operator_session is what turns a None into a
401 for routes that must have a real operator behind them.
"""
from __future__ import annotations

import os

import requests

ATTENSE_APP_URL = os.environ.get("ATTENSE_APP_URL", "http://attense-app:8020")
_ME_ENDPOINT = f"{ATTENSE_APP_URL}/api/auth/me"
_TIMEOUT = float(os.environ.get("ATTENSE_AUTH_TIMEOUT", "3"))


def login(username: str, password: str) -> tuple[int, dict]:
    """Proxy a login attempt to attense-app. Returns (status_code, body).

    Server-to-server on purpose: the browser never needs CORS access to
    attense-app directly, and attense-app's URL never has to appear in
    frontend code.
    """
    try:
        resp = requests.post(
            f"{ATTENSE_APP_URL}/api/auth/login",
            json={"username": username, "password": password},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as exc:
        return 502, {"detail": f"attense-app unreachable: {exc}"}
    try:
        body = resp.json()
    except ValueError:
        body = {"detail": "invalid response from attense-app"}
    return resp.status_code, body


def validate_session(token: str | None) -> dict | None:
    """Validate *token* against attense-app.

    Returns {"username", "role", "type"} (whatever GET /api/auth/me returns)
    on success, or None if the token is missing, invalid, or attense-app is
    unreachable.
    """
    if not token:
        return None
    try:
        resp = requests.get(
            _ME_ENDPOINT,
            headers={"X-Session-Token": token},
            timeout=_TIMEOUT,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None
