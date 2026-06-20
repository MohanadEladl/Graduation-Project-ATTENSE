import json
import os
import uuid
from pathlib import Path
from typing import Optional

import bcrypt

VALID_ROLES = {
    "ciso",
    "soc_manager",
    "soc_l2",
    "soc_l1",
    "professional",
    "intermediate",
}

HIVE_KEY_ROLES = {"soc_manager", "soc_l1", "soc_l2"}

TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
USERS_FILE = Path(TEMP_PATH) / "users.json"


def _load_users() -> list[dict]:
    if not USERS_FILE.exists():
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users: list[dict]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def create_user(
    username: str,
    email: str,
    password: str,
    role: str,
    company_id: Optional[str] = None,
    hive_key: Optional[str] = None,
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")

    if role == "ciso":
        company_id = None
    elif not company_id:
        raise ValueError("company_id is required for this role")

    if role not in HIVE_KEY_ROLES:
        hive_key = None

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "role": role,
        "company_id": company_id,
        "hive_key": hive_key,
    }

    users = _load_users()
    users.append(user)
    _save_users(users)
    return user


def register_user(
    username: str,
    email: str,
    password: str,
    role: str,
    company_id: Optional[str] = None,
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")

    if role != "ciso" and company_id is None:
        raise ValueError("company_id is required for this role")

    users = _load_users()
    if any(u["username"] == username for u in users):
        raise ValueError(f"Username already exists: {username}")

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "role": role,
        "company_id": company_id if role != "ciso" else None,
        "hive_key": None,
    }

    users.append(user)
    _save_users(users)
    return {k: v for k, v in user.items() if k != "hashed_password"}


def login_user(username: str, password: str) -> Optional[dict]:
    users = _load_users()
    for user in users:
        if user["username"] == username:
            if bcrypt.checkpw(password.encode("utf-8"), user["hashed_password"].encode("utf-8")):
                return {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"],
                    "company_id": user["company_id"],
                }
            return None
    return None


def set_hive_key(user_id: str, hive_key: str) -> dict:
    users = _load_users()
    for user in users:
        if user["id"] == user_id:
            user["hive_key"] = hive_key
            _save_users(users)
            return user
    raise ValueError(f"User not found: {user_id}")


def get_users_by_company(company_id: str) -> list[dict]:
    users = _load_users()
    return [
        {k: v for k, v in user.items() if k != "hashed_password"}
        for user in users
        if user["company_id"] == company_id
    ]
