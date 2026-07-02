"""Tests for Control API PostgreSQL wiring."""
from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))


class FakeCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[object, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None) -> None:
        self.executed.append((query, params))


class FakeConnection:
    def __init__(self) -> None:
        self.cursors: list[FakeCursor] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        cursor = FakeCursor()
        self.cursors.append(cursor)
        return cursor


class DatabaseWiringTests(unittest.TestCase):
    def test_connection_uses_configured_postgres_url_and_schema(self):
        import core.db as db

        original_env = os.environ.copy()
        fake_conn = FakeConnection()
        try:
            with patch.dict(
                os.environ,
                {
                    "DATABASE_URL": "postgresql://attense-test:secret@db.example:5432/attense_test",
                    "POSTGRES_SCHEMA": "attense_test_schema",
                },
                clear=False,
            ):
                db = importlib.reload(db)
                with patch.object(db.psycopg, "connect", return_value=fake_conn) as connect:
                    with db.connection() as conn:
                        self.assertIs(conn, fake_conn)

                connect.assert_called_once_with(
                    "postgresql://attense-test:secret@db.example:5432/attense_test",
                    row_factory=db.dict_row,
                )
                self.assertEqual(len(fake_conn.cursors), 1)
                self.assertEqual(len(fake_conn.cursors[0].executed), 1)
                query, params = fake_conn.cursors[0].executed[0]
                self.assertIsNone(params)
                self.assertEqual(
                    repr(query),
                    "Composed([SQL('SET search_path TO '), Identifier('attense_test_schema')])",
                )
        finally:
            os.environ.clear()
            os.environ.update(original_env)
            importlib.reload(db)

    def test_control_api_stores_use_shared_db_connection_helper(self):
        from core import company_store, mission_store, room_manager, user_store

        for module in (company_store, mission_store, room_manager, user_store):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.connection.__module__, "core.db")


if __name__ == "__main__":
    unittest.main()
