"""Shared Bearer-token verification for internal/webhook auth gates.

Used by control-api's require_events_secret (red-team engine -> control-api
event ingestion) and blue-team-api's Hive webhook receiver - both need the
same "Authorization: Bearer <secret>" check with a constant-time compare so
the secret can't leak via timing, just against different secrets/callers.
"""
from __future__ import annotations

import hmac


def verify_bearer_token(authorization_header: str, expected_secret: str) -> bool:
    """
    Check an `Authorization` header value against an expected bearer secret.

    Returns False (rather than raising) on a missing/empty secret or a
    non-Bearer scheme, so callers can turn that into their own framework's
    401 response with their own error detail string.
    """
    if not expected_secret:
        return False
    scheme, _, token = authorization_header.partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(
        token.encode("utf-8"), expected_secret.encode("utf-8")
    )
