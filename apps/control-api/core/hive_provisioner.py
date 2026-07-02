import base64
import hashlib
import hmac
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
# No baked-in default: "secret" is TheHive's stock admin password, so a fallback
# here would be a working credential in source. The check-secrets boot gate
# (scripts/bootstrap/check_secrets.py) already requires this to be set and
# rotated off the stock default; empty here fails loudly instead of silently
# authenticating with a known password if ever run outside that gate.
ADMIN_PASSWORD = os.getenv("THEHIVE_ADMIN_PASSWORD", "")


def derive_password(login: str) -> str:
    """Deterministically derive a TheHive web-login password for a user.

    Derived (not stored) so the same credential can be recomputed and shown to
    the analyst on every room entry without persisting a plaintext password.
    Keyed by a server secret; the fixed prefix guarantees TheHive's password
    complexity (upper, lower, digit, symbol).
    """
    secret = os.getenv("THEHIVE_USER_PASSWORD_SECRET") or ADMIN_PASSWORD or "attense-range"
    digest = hmac.new(secret.encode("utf-8"), login.lower().encode("utf-8"), hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:16]
    return f"At1!{token}"


_alert_org_cache: str | None = None


def alert_org() -> str:
    """The TheHive organisation the Blue Team alert pipeline writes into.

    The pipeline raises every alert with a single global API key
    (``HIVE_API_KEY``), so alerts land in that key's org. Room members must be
    provisioned into this same org or they'd log into an empty org and see zero
    alerts. Resolved once from the key (overridable via ``HIVE_ALERT_ORG``),
    falling back to ``blue-team``.
    """
    global _alert_org_cache
    if _alert_org_cache:
        return _alert_org_cache
    override = os.getenv("HIVE_ALERT_ORG")
    if override:
        _alert_org_cache = override
        return override
    gkey = os.getenv("HIVE_API_KEY", "")
    if gkey:
        try:
            response = httpx.get(
                f"{HIVE_URL}/api/v1/user/current",
                headers={"Authorization": f"Bearer {gkey}"},
                timeout=15,
            )
            response.raise_for_status()
            org = response.json().get("organisation")
            if org:
                _alert_org_cache = org
                return org
        except (httpx.HTTPError, ValueError):
            logger.warning(
                "Could not resolve alert org from HIVE_API_KEY; using fallback",
                exc_info=True,
            )
    _alert_org_cache = "blue-team"
    return _alert_org_cache


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
    raising tenacity's RetryError - the caller then runs raise_for_status() on
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


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(1),
    retry=retry_if_result(lambda r: r.status_code == 404),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    retry_error_callback=_return_last_response,
)
def _set_user_password(client: httpx.Client, username: str, org_name: str, password: str) -> httpx.Response:
    # As with key/renew, the freshly-created user can 404 until visible.
    return client.post(
        f"/api/user/{username}/password/set",
        json={"password": password},
        headers={"X-Organisation": org_name},
    )


def create_user_in_org(org_name: str, username: str, attense_role: str, renew_key: bool = True):
    """Ensure an org-scoped user exists with a web-login password.

    Idempotent: creates the user if missing, always (re)sets the derived
    web-login password. When ``renew_key`` is True a fresh API key is generated
    and returned; when False (a re-entry that only needs the human able to log
    in) key generation is skipped - avoiding needless key churn that would
    invalidate the key the Blue Team automation is already using - and None is
    returned.
    """
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

        key = None
        if renew_key:
            key_response = _renew_user_key(client, username, org_name)
            key_response.raise_for_status()
            try:
                key = key_response.json().get("key", "")
            except ValueError:
                key = key_response.text
            key = key.strip().strip('"')
            if not key:
                raise RuntimeError("TheHive returned an empty API key")

        # Give the account a web-login password so a human analyst can actually
        # sign in to TheHive (not just the automation via the API key).
        # Best-effort: the API key already works, so a password-set failure is
        # logged rather than aborting provisioning.
        try:
            pw_response = _set_user_password(client, username, org_name, derive_password(username))
            pw_response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(
                "Failed to set TheHive web password for '%s' in '%s': %s",
                username, org_name, exc,
            )
        return key
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Failed to create TheHive user '{username}' in '{org_name}': {exc}"
        ) from exc
    finally:
        if client is not None:
            client.close()
