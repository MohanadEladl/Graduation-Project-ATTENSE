import os
import time

import httpx

HIVE_URL = os.getenv("HIVE_URL", "http://thehive:9000").rstrip("/")
ADMIN_LOGIN = os.getenv("THEHIVE_ADMIN_LOGIN", "admin@thehive.local")
ADMIN_PASSWORD = os.getenv("THEHIVE_ADMIN_PASSWORD", "secret")


def _admin_client() -> httpx.Client:
    client = httpx.Client(base_url=HIVE_URL, timeout=20)
    try:
        response = client.post(
            "/api/login", json={"user": ADMIN_LOGIN, "password": ADMIN_PASSWORD}
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        client.close()
        raise RuntimeError(f"Failed to authenticate to TheHive: {exc}") from exc
    return client


def create_org(company_name: str) -> str:
    """Create a TheHive 4 organisation, returning its name. Safe to retry."""
    client = None
    try:
        client = _admin_client()
        response = client.get("/api/organisation")
        response.raise_for_status()
        if any(org.get("name") == company_name for org in response.json()):
            return company_name
        response = client.post(
            "/api/v1/organisation",
            json={
                "name": company_name,
                "description": f"{company_name} ATTENSE organisation",
            },
        )
        response.raise_for_status()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(
            f"Failed to create TheHive organisation '{company_name}': {exc}"
        ) from exc
    finally:
        if client is not None:
            client.close()
    return company_name


def create_user_in_org(org_name: str, username: str) -> str:
    """Create an org-scoped analyst and return a newly generated API key."""
    client = None
    try:
        client = _admin_client()
        existing = client.get(f"/api/user/{username}", headers={"X-Organisation": org_name})
        if existing.status_code == 404:
            response = client.post(
                "/api/v1/user",
                json={
                    "login": username,
                    "name": username,
                    "organisation": org_name,
                    "profile": "org-admin",
                },
            )
            response.raise_for_status()
        else:
            existing.raise_for_status()

        key_response = None
        for attempt in range(3):
            key_response = client.post(
                f"/api/user/{username}/key/renew",
                headers={"X-Organisation": org_name},
            )
            if key_response.status_code != 404:
                break
            if attempt < 2:
                time.sleep(1)
        key_response.raise_for_status()
        try:
            key = key_response.json().get("key", "")
        except ValueError:
            key = key_response.text
        key = key.strip().strip('"')
        if not key:
            raise RuntimeError("TheHive returned an empty API key")
        return key
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Failed to create TheHive user '{username}' in '{org_name}': {exc}"
        ) from exc
    finally:
        if client is not None:
            client.close()
