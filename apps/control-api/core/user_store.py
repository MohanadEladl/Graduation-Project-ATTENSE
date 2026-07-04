import os
from typing import Optional

import bcrypt
import psycopg

from core import company_store
from core.db import connection, encryption_key, int_id

VALID_ROLES = {
    "ciso",
    "soc_manager",
    "soc_l2",
    "soc_l1",
    "red_team",
}

RED_TEAM_TYPES = {"expert", "intermediate"}

HIVE_KEY_ROLES = {"soc_manager", "soc_l1", "soc_l2"}

USER_SELECT = '''
    SELECT u.user_id, u.username, u.email, u.role, u.company_id, u.user_type,
           CASE
               WHEN bt.thehive_api_key IS NULL THEN NULL
               ELSE pgp_sym_decrypt(bt.thehive_api_key, %s)
           END AS hive_key,
           u.active_room_id
    FROM "User" u
    LEFT JOIN "BlueTeam" bt ON bt.user_id = u.user_id
'''

USER_SELECT_WITH_HASH = '''
    SELECT u.user_id, u.username, u.email, u.hashed_password, u.role, u.company_id, u.user_type,
           CASE
               WHEN bt.thehive_api_key IS NULL THEN NULL
               ELSE pgp_sym_decrypt(bt.thehive_api_key, %s)
           END AS hive_key,
           u.active_room_id
    FROM "User" u
    LEFT JOIN "BlueTeam" bt ON bt.user_id = u.user_id
'''

USER_RETURNING = '''
    RETURNING user_id, username, email, role, company_id, user_type,
              NULL::text AS hive_key,
              active_room_id
'''


def _user_from_row(row: dict | None, *, include_hash: bool = False) -> Optional[dict]:
    if row is None:
        return None
    user = {
        "id": str(row["user_id"]),
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "type": row.get("user_type"),
        "company_id": str(row["company_id"]) if row.get("company_id") is not None else None,
        "hive_key": row.get("hive_key"),
        "active_room_id": row.get("active_room_id"),
    }
    if include_hash:
        user["hashed_password"] = row["hashed_password"]
    return user


def _public(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != "hashed_password"}


def _runtime_secret(name: str) -> Optional[str]:
    return os.getenv(name) or None


def _store_blue_team_profile(cur, user_id: int, role: str, hive_key: Optional[str], key_secret: str) -> None:
    cortex_key = _runtime_secret("CORTEX_API_KEY")
    cur.execute(
        '''
        INSERT INTO "BlueTeam" (
            user_id, team_role, thehive_api_key, cortex_api_key
        )
        VALUES (
            %s, %s,
            CASE WHEN %s::text IS NULL THEN NULL ELSE pgp_sym_encrypt(%s::text, %s) END,
            CASE WHEN %s::text IS NULL THEN NULL ELSE pgp_sym_encrypt(%s::text, %s) END
        )
        ON CONFLICT (user_id) DO UPDATE SET
            team_role = EXCLUDED.team_role,
            thehive_api_key = COALESCE(
                EXCLUDED.thehive_api_key,
                "BlueTeam".thehive_api_key
            ),
            cortex_api_key = COALESCE(
                EXCLUDED.cortex_api_key,
                "BlueTeam".cortex_api_key
            )
        ''',
        (
            user_id,
            role,
            hive_key,
            hive_key,
            key_secret,
            cortex_key,
            cortex_key,
            key_secret,
        ),
    )


def _store_red_team_profile(cur, user_id: int, key_secret: str) -> None:
    zap_key = _runtime_secret("ZAP_API_KEY")
    cur.execute(
        '''
        INSERT INTO "RedTeam" (user_id, zap_api_key)
        VALUES (
            %s,
            CASE WHEN %s::text IS NULL THEN NULL ELSE pgp_sym_encrypt(%s::text, %s) END
        )
        ON CONFLICT (user_id) DO UPDATE SET
            zap_api_key = COALESCE(
                EXCLUDED.zap_api_key,
                "RedTeam".zap_api_key
            )
        ''',
        (user_id, zap_key, zap_key, key_secret),
    )


def username_exists(username: str) -> bool:
    with connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT 1 FROM "User" WHERE username = %s', (username,))
        return cur.fetchone() is not None


def ciso_exists() -> bool:
    with connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT 1 FROM "User" WHERE role = %s LIMIT 1', ("ciso",))
        return cur.fetchone() is not None


def create_user(
    username: str,
    email: str,
    password: str,
    role: str,
    company_id: Optional[str] = None,
    hive_key: Optional[str] = None,
) -> dict:
    return register_user(username, email, password, role, company_id=company_id, hive_key=hive_key)


def register_user(
    username: str,
    email: str,
    password: str,
    role: str,
    company_id: Optional[str] = None,
    hive_key: Optional[str] = None,
    type: Optional[str] = None,
) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")

    if role == "red_team":
        if type not in RED_TEAM_TYPES:
            raise ValueError(
                f"type is required for red_team and must be one of: "
                f"{', '.join(sorted(RED_TEAM_TYPES))}"
            )
    elif type is not None:
        raise ValueError("type must be None for non-red-team roles")

    db_company_id = None
    if role != "ciso":
        db_company_id = int_id(company_id, "company_id")
        if company_store.get_company(str(db_company_id)) is None:
            raise ValueError("Company does not exist")

    if username_exists(username):
        raise ValueError(f"Username already exists: {username}")

    if role not in HIVE_KEY_ROLES:
        hive_key = None

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    key_secret = encryption_key()

    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                '''
                INSERT INTO "User" (
                    username, email, hashed_password, role, company_id,
                    user_type, active_room_id, admin_name
                )
                VALUES (%s, %s, %s, %s, %s, %s, NULL, 'Admin')
                ''' + USER_RETURNING,
                (username, email, hashed_password, role, db_company_id, type),
            )
            row = cur.fetchone()
            if role in HIVE_KEY_ROLES:
                _store_blue_team_profile(cur, row["user_id"], role, hive_key, key_secret)
                row["hive_key"] = hive_key
            elif role == "red_team":
                _store_red_team_profile(cur, row["user_id"], key_secret)
            return _public(_user_from_row(row))
    except psycopg.errors.UniqueViolation as exc:
        raise ValueError(f"Username or email already exists: {username}") from exc


def login_user(username: str, password: str) -> Optional[dict]:
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(USER_SELECT_WITH_HASH + ' WHERE u.username = %s', (key_secret, username))
        user = _user_from_row(cur.fetchone(), include_hash=True)
    if user is None:
        return None
    if not bcrypt.checkpw(password.encode("utf-8"), user["hashed_password"].encode("utf-8")):
        return None
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "type": user.get("type"),
        "company_id": user["company_id"],
    }


def set_hive_key(user_id: str, hive_key: str) -> dict:
    db_user_id = int_id(user_id, "user_id")
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            SELECT user_id, username, email, role, company_id, user_type,
                   NULL::text AS hive_key,
                   active_room_id
            FROM "User"
            WHERE user_id = %s
            ''',
            (db_user_id,),
        )
        user = _user_from_row(cur.fetchone())
        if user is not None and user["role"] in HIVE_KEY_ROLES:
            _store_blue_team_profile(cur, db_user_id, user["role"], hive_key, key_secret)
            user["hive_key"] = hive_key
    if user is None:
        raise ValueError(f"User not found: {user_id}")
    if user["role"] not in HIVE_KEY_ROLES:
        raise ValueError("Hive keys belong to Blue Team users only")
    return user


def set_active_room(user_id: str, room_id: str) -> dict:
    """Record the most recently joined room for a red_team user."""
    key_secret = encryption_key()
    db_user_id = int_id(user_id, "user_id")
    with connection() as conn, conn.cursor() as cur:
        cur.execute('UPDATE "User" SET active_room_id = %s WHERE user_id = %s', (room_id, db_user_id))
        cur.execute(USER_SELECT + ' WHERE u.user_id = %s', (key_secret, db_user_id))
        user = _user_from_row(cur.fetchone())
    if user is None:
        raise ValueError(f"User not found: {user_id}")
    return user


def get_blue_team_runtime_keys(user_id: str) -> dict:
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            SELECT
                CASE
                    WHEN thehive_api_key IS NULL THEN NULL
                    ELSE pgp_sym_decrypt(thehive_api_key, %s)
                END AS hive_api_key,
                CASE
                    WHEN cortex_api_key IS NULL THEN NULL
                    ELSE pgp_sym_decrypt(cortex_api_key, %s)
                END AS cortex_api_key
            FROM "BlueTeam"
            WHERE user_id = %s
            ''',
            (key_secret, key_secret, int_id(user_id, "user_id")),
        )
        row = cur.fetchone()
    if row is None:
        return {"hive_api_key": None, "cortex_api_key": None}
    return {"hive_api_key": row["hive_api_key"], "cortex_api_key": row["cortex_api_key"]}


def get_red_team_runtime_keys(user_id: str) -> dict:
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            SELECT
                CASE
                    WHEN zap_api_key IS NULL THEN NULL
                    ELSE pgp_sym_decrypt(zap_api_key, %s)
                END AS zap_api_key
            FROM "RedTeam"
            WHERE user_id = %s
            ''',
            (key_secret, int_id(user_id, "user_id")),
        )
        row = cur.fetchone()
    if row is None:
        return {"zap_api_key": None}
    return {"zap_api_key": row["zap_api_key"]}


def get_users_by_company(company_id: str) -> list[dict]:
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            USER_SELECT + ' WHERE u.company_id = %s ORDER BY u.user_id',
            (key_secret, int_id(company_id, "company_id")),
        )
        return [_public(_user_from_row(row)) for row in cur.fetchall()]


def get_user_by_username(username: str) -> Optional[dict]:
    key_secret = encryption_key()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(USER_SELECT + ' WHERE u.username = %s', (key_secret, username))
        user = _user_from_row(cur.fetchone())
    return _public(user) if user is not None else None