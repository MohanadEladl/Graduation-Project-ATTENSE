import hmac
import os

from fastapi import Header, HTTPException

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
    (ATTENSE_app/blueteam/api/webhook_router.py) — a separate secret because
    these are different trust relationships.
    """
    secret = os.environ.get("RED_TEAM_EVENTS_SECRET", "")
    scheme, _, token = authorization.partition(" ")
    if not secret or scheme.lower() != "bearer" or not hmac.compare_digest(
        token.encode("utf-8"), secret.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="invalid_events_token")
