import logging
import os

import httpx
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_result,
    stop_after_attempt,
    wait_fixed,
)

logger = logging.getLogger("attense.hive_provisioner")

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


def _return_last_response(retry_state):
    """When the retry budget is exhausted, return the final response instead of
    raising tenacity's RetryError — the caller then runs raise_for_status() on
    it, exactly as the original loop did: the HTTP error is raised AFTER the
    retry completes, never inside an attempt."""
    return retry_state.outcome.result()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(1),
    retry=retry_if_result(lambda r: r.status_code == 403),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    retry_error_callback=_return_last_response,
)
def _create_org_user(client: httpx.Client, payload: dict) -> httpx.Response:
    # TheHive can 403 the first user in a freshly-created org until the org is
    # visible; retry on 403 only, 3 attempts 1s apart.
    return client.post("/api/v1/user", json=payload)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(1),
    retry=retry_if_result(lambda r: r.status_code == 404),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    retry_error_callback=_return_last_response,
)
def _renew_user_key(client: httpx.Client, username: str, org_name: str) -> httpx.Response:
    # The just-created user can 404 on key/renew until visible; retry on 404 only.
    return client.post(
        f"/api/user/{username}/key/renew",
        headers={"X-Organisation": org_name},
    )


def create_user_in_org(org_name: str, username: str, attense_role: str) -> str:
    """Create an org-scoped user and return a newly generated API key."""
    profiles = {
        "soc_manager": "admin",
        "soc_l2": "analyst",
        "soc_l1": "analyst",
    }
    if attense_role not in profiles:
        raise ValueError(
            "attense_role must be one of: soc_l1, soc_l2, soc_manager"
        )
    profile = profiles[attense_role]

    client = None
    try:
        client = _admin_client()
        existing = client.get(f"/api/user/{username}", headers={"X-Organisation": org_name})
        if existing.status_code == 404:
            response = _create_org_user(
                client,
                {
                    "login": username,
                    "name": username,
                    "organisation": org_name,
                    "profile": profile,
                },
            )
            response.raise_for_status()
        else:
            existing.raise_for_status()

        key_response = _renew_user_key(client, username, org_name)
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
