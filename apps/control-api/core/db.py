"""PostgreSQL connection helpers for ATTENSE control API stores."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://attense:attense-dev-password@postgres:5432/attense",
)
POSTGRES_SCHEMA = os.getenv("POSTGRES_SCHEMA", "attense")


def encryption_key() -> str:
    """Key used by Postgres pgcrypto for per-user API key storage."""
    return (
        os.getenv("ATTENSE_KEY_ENCRYPTION_SECRET")
        or os.getenv("THEHIVE_SECRET")
        or os.getenv("WEBHOOK_SECRET")
        or "attense-local-dev-key-change-me"
    )


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(POSTGRES_SCHEMA)))
        yield conn


def int_id(value: str | int | None, name: str) -> int:
    if value is None:
        raise ValueError(f"{name} is required")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a numeric database id") from exc