import os

from fastapi import Header, HTTPException

from attense_core.security.bearer_auth import verify_bearer_token
from core import session_store


def require_session(x_session_token: str = Header(default=None)):
    if not x_session_token:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    session = session_store.validate_session(x_session_token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session


def require_events_secret(authorization: str = Header(default="")):
    """
    Service-to-service auth for internal event-ingestion callers (e.g. the
    red-team engine posting malicious_action_executed). Port 8020 is
    published to the host, so this endpoint needs its own gate rather than
    relying on Docker-network trust alone. Mirrors the Bearer +
    constant-time-compare pattern already used for TheHive's webhook
    (blueteam/api/webhook_router.py), with a separate secret because
    these are different trust relationships.
    """
    secret = os.environ.get("RED_TEAM_EVENTS_SECRET", "")
    if not verify_bearer_token(authorization, secret):
        raise HTTPException(status_code=401, detail="invalid_events_token")

