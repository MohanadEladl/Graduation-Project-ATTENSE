import os

import httpx

HIVE_URL = os.getenv("HIVE_URL", "http://thehive:9000")
HIVE_ADMIN_KEY = os.getenv("HIVE_ADMIN_KEY", "")


def create_org(company_name: str) -> str:
    headers = {"Authorization": f"Bearer {HIVE_ADMIN_KEY}"}
    try:
        response = httpx.post(
            f"{HIVE_URL}/api/organisation",
            json={"name": company_name},
            headers=headers,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to create Hive organisation '{company_name}': {exc}") from exc
    return company_name


def create_user_in_org(org_name: str, username: str) -> str:
    headers = {"Authorization": f"Bearer {HIVE_ADMIN_KEY}"}
    try:
        response = httpx.post(
            f"{HIVE_URL}/api/user",
            json={"login": username, "organisation": org_name, "roles": ["analyst"]},
            headers=headers,
        )
        response.raise_for_status()

        key_response = httpx.post(
            f"{HIVE_URL}/api/user/{username}/key/renew",
            headers=headers,
        )
        key_response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Failed to create Hive user '{username}' in org '{org_name}': {exc}"
        ) from exc
    return key_response.text.strip()
