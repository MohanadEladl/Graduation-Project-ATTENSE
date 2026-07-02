"""Unit coverage for database-backed company persistence."""
from __future__ import annotations

from contextlib import contextmanager
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from core import company_store  # noqa: E402


class FakeCursor:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query: str, params=()) -> None:
        normalized = " ".join(query.split()).upper()
        if normalized.startswith('INSERT INTO "COMPANY"'):
            name, created_by = params
            existing = next((row for row in self.rows if row["name"] == name), None)
            if existing is None:
                existing = {
                    "company_id": len(self.rows) + 1,
                    "name": name,
                    "status": "pending",
                    "created_by": created_by,
                }
                self.rows.append(existing)
            self.result = dict(existing)
            return
        if normalized.startswith('UPDATE "COMPANY" SET STATUS'):
            company_id = params[0]
            row = next((item for item in self.rows if item["company_id"] == company_id), None)
            if row is not None:
                row["status"] = "active"
                self.result = dict(row)
            else:
                self.result = None
            return
        if 'WHERE STATUS = %S' in normalized:
            status = params[0]
            self.result = [dict(row) for row in self.rows if row["status"] == status]
            return
        raise AssertionError(f"Unexpected query: {query}")

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class FakeConnection:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows

    def cursor(self):
        return FakeCursor(self.rows)


class CompanyStoreTests(unittest.TestCase):
    def test_create_confirm_and_filter_company(self):
        rows: list[dict] = []

        @contextmanager
        def fake_connection():
            yield FakeConnection(rows)

        with patch.object(company_store, "connection", fake_connection):
            company = company_store.create_company("Example Co", "manager")
            self.assertEqual(company["status"], "pending")
            company_store.confirm_company(company["id"])
            self.assertEqual(company_store.list_companies("active"), [
                {**company, "status": "active"}
            ])
