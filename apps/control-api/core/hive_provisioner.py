import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

import docker
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


def api_key_is_valid(api_key: str) -> bool:
    """Whether *api_key* still authenticates against TheHive.

    A room's pipeline key is normally minted exactly once (see
    `room_manager._ensure_room_hive`) and assumed valid forever after -
    but if TheHive's own state is ever reset independently of ATTENSE's
    room store (its DB/volumes recreated, the service account manually
    removed, etc.), that assumption breaks: the room keeps a key TheHive
    no longer recognises, and every alert/notification-rule call for that
    room 401s forever with no way to recover (confirmed live: a service
    account that TheHive now 404s on `GET /api/user/{login}`, while the
    room's stored key still exists and gets rejected). Callers use this to
    detect that case and re-provision instead of trusting a stored key
    blindly.
    """
    if not api_key:
        return False
    try:
        response = httpx.get(
            f"{HIVE_URL}/api/v1/user/current",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        return response.status_code == 200
    except httpx.HTTPError:
        return False


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
    # TheHive's "admin" profile is instance/platform admin (manageOrganisation,
    # manageUser, manageConfig, ...) - it has NO manageCase/manageAlert and
    # cannot create a case (confirmed live: 403 "Operation not permitted").
    # "org-admin" is the org-scoped full-permissions profile (manageCase,
    # manageAlert, manageUser, ... within this org) - that's what a room's SOC
    # manager needs, since their key is what the alert-raising pipeline uses.
    profiles = {
        "soc_manager": "org-admin",
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
            # A user can be "Locked" if this org was previously wiped for reuse
            # (see wipe_org) or was otherwise locked/de-provisioned. TheHive has
            # no hard user delete, only lock - so re-provisioning the SAME
            # username (e.g. the same analyst re-entering, or a new room that
            # reused a pooled org and happens to share a username with the
            # pooled org's prior occupant) must self-heal by unlocking, or the
            # key-renew/password-set calls below would silently fail against a
            # locked account.
            if existing.json().get("status") == "Locked":
                unlock = client.patch(
                    f"/api/user/{username}",
                    json={"status": "Ok"},
                    headers={"X-Organisation": org_name},
                )
                unlock.raise_for_status()

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


# -- Per-org webhook authorisation (real room/company isolation) --------------
# TheHive gates its CaseCreated webhook in two independent places:
#   1. A per-organisation NOTIFICATION RULE ("fire the 'local' webhook on
#      CaseCreated") - live, org-scoped, no restart needed.
#   2. The webhook ENDPOINT's static `includedTheHiveOrganisations` allow-list
#      in application.conf - a hard gate TheHive enforces regardless of (1);
#      an org missing from this list gets "organisation X is not authorised
#      to use the webhook" even with a valid notification rule. Only this
#      part requires a config rewrite + TheHive restart, and only the FIRST
#      time a given org is created (see room_manager._ensure_room_hive).

NOTIFICATION_RULE = [{
    "delegate": False,
    "trigger": {"name": "CaseCreated"},
    "notifier": {"name": "webhook", "endpoint": "local"},
}]

THEHIVE_CONF_PATH = os.getenv("THEHIVE_CONF_PATH", "/thehive/application.conf")
THEHIVE_CONTAINER_NAME = os.getenv("THEHIVE_CONTAINER_NAME", "attense_thehive")


def ensure_notification_rule(org_name: str, org_api_key: str) -> None:
    """Set *org_name*'s notification config to fire the 'local' webhook on
    CaseCreated. Live API call, takes effect immediately - no restart.

    Uses the org's own service-user key (org-admin): notification config is
    organisation-scoped, so the super-admin session (in TheHive's 'admin'
    org) can't set it for another org directly. Retries on connection
    errors/5xx - the caller (authorize_org_for_webhook) already waits for
    TheHive to answer /api/status before calling this, but a retry here is
    cheap insurance against any residual timing flakiness (confirmed live:
    without it, calling this right after a bare `container.restart()` -
    which returns once the container PROCESS restarts, well before TheHive's
    Play server is actually listening again - silently fails and that org's
    cases never auto-attach). Best-effort: a failure here means that org's
    cases won't auto-attach attacker evidence, but must never block
    room/user provisioning.
    """
    try:
        response = _put_notification_rule(org_api_key)
        response.raise_for_status()
    except httpx.HTTPError:
        logger.exception(
            "Could not register CaseCreated->webhook notification rule for org '%s'",
            org_name,
        )


@retry(
    stop=stop_after_attempt(5),
    wait=wait_fixed(3),
    retry=retry_if_result(lambda r: r.status_code >= 500),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    retry_error_callback=_return_last_response,
)
def _put_notification_rule(org_api_key: str):
    return httpx.put(
        f"{HIVE_URL}/api/config/organisation/notification",
        json={"value": NOTIFICATION_RULE},
        headers={"Authorization": f"Bearer {org_api_key}"},
        timeout=20,
    )


def _wait_for_thehive_ready(timeout_seconds: float = 280) -> bool:
    """Poll /api/status until TheHive answers or *timeout_seconds* elapses.

    A restarted container's PROCESS comes back long before its Play/JVM
    server actually binds port 9000 (confirmed live: ~60-90s gap, but the
    container's own healthcheck allows a `start_period` of up to 240s on a
    cold boot) - so this must wait comfortably past that, not just past the
    common case. Callers that need to talk to TheHive right after a restart
    (e.g. ensure_notification_rule) must wait for this, not just for
    `container.restart()` to return. Runs off the request path (see
    `authorize_org_for_webhook`), so a generous timeout here no longer costs
    the calling HTTP request anything.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{HIVE_URL}/api/status", timeout=5)
            if resp.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(3)
    return False


# Guards the conf-file read-modify-write below (Race B: two entries for two
# different brand-new rooms landing on different threadpool threads - see
# room_manager.enter_room, dispatched via FastAPI's sync-route threadpool -
# could otherwise read the file before either writes and silently clobber
# each other's appended org). Held only briefly and synchronously on the
# calling thread; the file I/O + json parse it guards is sub-millisecond, so
# this never reintroduces the blocking problem below.
_conf_lock = threading.Lock()

# Guards the actual `container.restart()` (Race A: two near-simultaneous
# entries into two different brand-new rooms would otherwise each spawn
# their own restart thread, restarting the one shared TheHive container back
# to back). Only ever acquired from the background restart thread, never
# from a request thread.
_restart_lock = threading.Lock()
# Monotonic counter of conf-file writes, and the highest one already covered
# by a completed restart. Lets a later-queued restart notice that an
# earlier one (which restarted AFTER this org was already written to disk)
# already picked up its org, so it can skip its own redundant restart
# instead of unconditionally restarting again - this is what actually fixes
# "TheHive keeps restarting forever" when several new rooms are entered in
# a session, not just the double-restart case.
_conf_write_seq = 0
_restarted_through_seq = 0


def authorize_org_for_webhook(org_name: str) -> bool:
    """Add *org_name* to the webhook's `includedTheHiveOrganisations` allow-list
    in application.conf and schedule a TheHive restart in the BACKGROUND so
    the change takes effect - this returns as soon as the conf file is
    written, without waiting for the restart or for TheHive to come back up.

    Additive: other already-authorised orgs (other rooms/companies) are kept,
    so this never de-authorises anyone else's webhook. Returns False (no-op,
    nothing scheduled) if the org was already on the list. Returns True if
    the org was newly added and a restart has been queued - this does NOT
    mean TheHive has finished restarting, only that it will (eventually,
    possibly coalesced with another room's restart - see
    `_restart_thehive_in_background`). Raises RuntimeError only for the
    synchronous conf-parsing failure; a restart/readiness failure can no
    longer propagate from here (it happens on a background thread) and is
    instead logged there - callers should treat the whole thing as
    best-effort (a missing/delayed restart only degrades auto-attach, it
    doesn't break the room itself, and the next room entry retries it - see
    room_manager._ensure_room_hive).
    """
    with _conf_lock:
        conf_path = Path(THEHIVE_CONF_PATH)
        content = conf_path.read_text(encoding="utf-8")
        pattern = re.compile(r'includedTheHiveOrganisations\s*=\s*(\[[^\]]*\])')
        match = pattern.search(content)
        if not match:
            raise RuntimeError(
                f"Could not find includedTheHiveOrganisations in {conf_path}"
            )
        current: list[str] = json.loads(match.group(1))
        if org_name in current:
            return False

        current.append(org_name)
        new_content = content[: match.start(1)] + json.dumps(current) + content[match.end(1):]
        conf_path.write_text(new_content, encoding="utf-8")
        global _conf_write_seq
        _conf_write_seq += 1
        my_seq = _conf_write_seq

    logger.info(
        "Authorised org '%s' for the TheHive webhook; restart queued in the "
        "background (seq=%s)", org_name, my_seq,
    )
    threading.Thread(
        target=_restart_thehive_in_background,
        args=(org_name, my_seq),
        daemon=True,
        name=f"thehive-restart-{org_name}",
    ).start()
    return True


def _restart_thehive_in_background(org_name: str, my_seq: int) -> None:
    """Restart TheHive and wait for it to come back up, off the request path.

    Runs on its own daemon thread (spawned by `authorize_org_for_webhook`).
    Must never let an exception escape: a daemon thread's default excepthook
    just prints to stderr, so this is the ONLY place a docker/restart
    failure for *org_name* can be observed - every failure path here is
    caught and logged with the org name.
    """
    global _restarted_through_seq
    try:
        with _restart_lock:
            if _restarted_through_seq >= my_seq:
                # A restart that already ran (queued after this org was
                # written to disk - conf writes happen under _conf_lock
                # before their restart is queued, so ordering is guaranteed)
                # already picked up this org. Restarting again would just be
                # another multi-minute outage for no new authorization.
                logger.info(
                    "TheHive restart already covers org '%s' (seq %s); "
                    "skipping redundant restart", org_name, my_seq,
                )
                return

            logger.info("Restarting TheHive container for org '%s' ...", org_name)
            client = docker.from_env()
            try:
                container = client.containers.get(THEHIVE_CONTAINER_NAME)
                container.restart(timeout=30)
            finally:
                client.close()

            # container.restart() returns once the container PROCESS is
            # back, not once TheHive's own server is accepting requests -
            # wait here so the "restart done" bookkeeping below is accurate.
            if _wait_for_thehive_ready():
                logger.info("TheHive back up after restart for org '%s'.", org_name)
            else:
                logger.warning(
                    "TheHive did not answer /api/status within the timeout "
                    "after restarting for org '%s' - next room entry retries.",
                    org_name,
                )

            with _conf_lock:
                _restarted_through_seq = max(_restarted_through_seq, _conf_write_seq)
    except Exception:
        logger.exception("Background TheHive restart failed for org '%s'", org_name)


# -- Org reuse (TheHive has no organisation-delete API) ------------------------
# Confirmed live (DELETE/PATCH-status/lock all 404 or no-op on TheHive 4.1.24)
# and matches an unresolved upstream report (TheHive-Project/TheHive#1558,
# "How to delete Organization", never answered). A per-room org is therefore
# permanent - the only way to avoid unbounded org growth as ephemeral rooms
# come and go is to WIPE and REUSE a closed room's org for the next room
# instead of always minting a new one (see room_manager's org pool).

def wipe_org(org_name: str) -> None:
    """Delete every alert and case, and lock every non-admin user, in
    *org_name* - so a pooled org starts clean for its next occupant.

    Alerts and cases are distinct TheHive objects (promoting an alert to a
    case does not delete the alert), so a wipe that only cleared cases left
    every previous occupant's raw alerts behind for the next room to inherit
    - the same unbounded-accumulation problem as the shared "blue-team"
    fallback org, just recurring per recycled org instead of in one bucket.

    Best-effort per-item: one failure (e.g. an alert/case already gone) is
    logged and skipped rather than aborting the whole wipe - a partially-clean
    org is still safe to reuse, just not perfectly tidy. Never raises.
    """
    client = None
    try:
        client = _admin_client()

        alerts = client.post(
            "/api/alert/_search", json={"query": {}}, headers={"X-Organisation": org_name}
        )
        for alert in (alerts.json() if alerts.status_code == 200 else []):
            alert_id = alert.get("id") or alert.get("_id")
            if not alert_id:
                continue
            try:
                client.delete(f"/api/alert/{alert_id}", headers={"X-Organisation": org_name}).raise_for_status()
            except httpx.HTTPError:
                logger.warning("Could not delete alert %s while wiping org '%s'", alert_id, org_name)

        cases = client.post(
            "/api/case/_search", json={"query": {}}, headers={"X-Organisation": org_name}
        )
        for case in (cases.json() if cases.status_code == 200 else []):
            case_id = case.get("id") or case.get("_id")
            if not case_id:
                continue
            try:
                client.delete(f"/api/case/{case_id}", headers={"X-Organisation": org_name}).raise_for_status()
            except httpx.HTTPError:
                logger.warning("Could not delete case %s while wiping org '%s'", case_id, org_name)

        users = client.post(
            "/api/v1/query",
            json={"query": [{"_name": "listUser"}]},
            headers={"X-Organisation": org_name},
        )
        for user in (users.json() if users.status_code == 200 else []):
            login = user.get("login")
            # Never lock the platform super-admin, which TheHive's listUser
            # includes for every org's context.
            if not login or login == ADMIN_LOGIN:
                continue
            try:
                client.delete(f"/api/user/{login}", headers={"X-Organisation": org_name}).raise_for_status()
            except httpx.HTTPError:
                logger.warning("Could not lock user '%s' while wiping org '%s'", login, org_name)
    except Exception:
        logger.exception("Wipe failed for org '%s' (best-effort, org still usable)", org_name)
    finally:
        if client is not None:
            client.close()
