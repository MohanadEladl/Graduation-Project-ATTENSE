import json
import os
import uuid
from pathlib import Path
from typing import Optional

TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
COMPANIES_FILE = Path(TEMP_PATH) / "companies" / "companies.json"


def _load_companies() -> list[dict]:
    if not COMPANIES_FILE.exists():
        return []
    with open(COMPANIES_FILE, "r") as f:
        return json.load(f)


def _save_companies(companies: list[dict]) -> None:
    COMPANIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(COMPANIES_FILE, "w") as f:
        json.dump(companies, f, indent=2)


def create_company(name: str, created_by: str) -> dict:
    companies = _load_companies()
    company = {
        "id": str(uuid.uuid4()),
        "name": name,
        "status": "pending",
        "created_by": created_by,
    }
    companies.append(company)
    _save_companies(companies)
    return company


def get_company(company_id: str) -> Optional[dict]:
    companies = _load_companies()
    for company in companies:
        if company["id"] == company_id:
            return company
    return None


def confirm_company(company_id: str) -> Optional[dict]:
    companies = _load_companies()
    for company in companies:
        if company["id"] == company_id:
            company["status"] = "active"
            _save_companies(companies)
            return company
    return None


def delete_company(company_id: str) -> None:
    companies = [c for c in _load_companies() if c["id"] != company_id]
    _save_companies(companies)


def list_companies(status: Optional[str] = None) -> list[dict]:
    companies = _load_companies()
    if status is not None:
        return [c for c in companies if c.get("status") == status]
    return companies
