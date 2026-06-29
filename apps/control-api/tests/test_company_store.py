"""Unit coverage for JSON-backed company persistence."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from core import company_store  # noqa: E402


class CompanyStoreTests(unittest.TestCase):
    def test_create_confirm_and_filter_company(self):
        with tempfile.TemporaryDirectory() as temp:
            store_path = Path(temp) / "companies.json"
            with patch.object(company_store, "COMPANIES_FILE", store_path):
                company = company_store.create_company("Example Co", "manager")
                self.assertEqual(company["status"], "pending")
                company_store.confirm_company(company["id"])
                self.assertEqual(company_store.list_companies("active"), [
                    {**company, "status": "active"}
                ])
