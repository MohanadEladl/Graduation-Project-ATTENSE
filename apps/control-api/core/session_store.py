import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
SESSIONS_DIR = Path(TEMP_PATH) / "sessions"


def _session_path(token: str) -> Path:
    return SESSIONS_DIR / f"{token}.json"


def generate_session(username: str, role: str, company_id: Optional[str] = None) -> str:
    token = str(uuid.uuid4())
    session = {
        "token": token,
        "username": username,
        "role": role,
        "company_id": company_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_session_path(token), "w") as f:
        json.dump(session, f, indent=2)
    return token


def validate_session(token: str) -> Optional[dict]:
    path = _session_path(token)
    if not path.exists():
        return None
    with open(path, "r") as f:
        return json.load(f)


def delete_session(token: str) -> None:
    path = _session_path(token)
    if path.exists():
        path.unlink()
