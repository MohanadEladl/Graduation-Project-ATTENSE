from fastapi import Header, HTTPException

from core import session_store


def require_session(x_session_token: str = Header(default=None)):
    if not x_session_token:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    session = session_store.validate_session(x_session_token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session
