import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import docker
import httpx

from core import company_store, port_pool, user_store
from core.db import connection

logger = logging.getLogger(__name__)


TEMP_PATH = os.getenv("ATTENSE_TEMP_PATH", "/attense/temp")
ROOMS_DIR = Path(TEMP_PATH) / "rooms"
BLUETEAM_IMAGE = "attense-app-blueteam"
DOCKER_NETWORK = "attense_net"
SIGNAL_STORE_URL = os.getenv("SIGNAL_STORE_URL", "http://signal-store:8000")
SIGNAL_STORE_CONFIG_SECRET = os.getenv("SIGNAL_STORE_CONFIG_SECRET", "")


def _configure_signal_store_incident(incident_id: Optional[str], room_id: Optional[str] = None) -> None:
    """Tell the long-lived signal-store which active room/incident owns new alerts.

    Wazuh alerts do not contain ATTENSE room IDs. Without this handoff they keep
    using the static container INCIDENT_ID and cannot join the red-team event
    stream for a room created after compose startup. The room_id is forwarded so
    the signal-store can stamp X-Room-Id on raise-alert calls (which the Blue
    Team API requires), landing the alerts in the room's TheHive incident.
    """
    if not SIGNAL_STORE_CONFIG_SECRET:
        raise RuntimeError("SIGNAL_STORE_CONFIG_SECRET is not configured")
    try:
        response = httpx.put(
            f"{SIGNAL_STORE_URL.rstrip('/')}/configuration/active-incident",
            json={"incident_id": incident_id, "room_id": room_id},
            headers={"X-Signal-Store-Secret": SIGNAL_STORE_CONFIG_SECRET},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to configure signal-store incident: {exc}") from exc


def _replay_signal_store_alerts(room: dict, force: bool = False) -> dict:
    """Ask the signal-store to re-deliver this room's stored attack detections.

    In deferred exercises the detections fire before any analyst enters the
    room, so they never reached TheHive (roomless raise-alert calls are
    rejected). Replaying them on entry puts the case's alerts in TheHive right
    as the analyst opens it. Scoped to the room's attack window via `since`.

    `force` re-delivers even detections already replayed to this room, so a room
    that's re-opened (or whose earlier delivery silently failed) still gets its
    alerts. Returns the signal-store's {replayed, skipped, failed} counts.
    """
    if not SIGNAL_STORE_CONFIG_SECRET:
        raise RuntimeError("SIGNAL_STORE_CONFIG_SECRET is not configured")
    incident_id = (room.get("incidents") or [room.get("incident_id")])[0]
    if not incident_id:
        return {}
    payload = {"incident_id": incident_id, "room_id": room["room_id"], "force": force}
    since = room.get("attack_started_at") or room.get("created_at")
    if since:
        payload["since"] = since
    try:
        response = httpx.post(
            f"{SIGNAL_STORE_URL.rstrip('/')}/replay",
            json=payload,
            headers={"X-Signal-Store-Secret": SIGNAL_STORE_CONFIG_SECRET},
            timeout=60.0,
        )
        response.raise_for_status()
        result = response.json()
        logger.info(
            "Signal-store replay for room %s: %s", room["room_id"], result
        )
        return result
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to replay signal-store alerts: {exc}") from exc


def resync_room_alerts(room_id: str) -> dict:
    """Re-push a room's stored detections into TheHive, for any room status.

    Called when a Blue Team user (re-)opens a room in the UI - including a closed
    / past room that can't be re-entered - so its alerts appear in TheHive even
    if the original delivery never happened. Uses force=True so the signal-store
    re-delivers regardless of its in-process replay dedup; TheHive dedups by
    sourceRef, so re-opening the same room never creates duplicate alerts.
    """
    room = _load_room(room_id)
    # Point the signal-store at this room first, so live alerts (if any still
    # arrive) are also scoped here, mirroring enter_room's routing.
    try:
        _configure_signal_store_incident(
            (room.get("incidents") or [room["incident_id"]])[0], room_id
        )
    except Exception:
        logger.exception("Failed to route signal-store to room %s on resync", room_id)
    return _replay_signal_store_alerts(room, force=True)


def _room_path(room_id: str) -> Path:
    return ROOMS_DIR / f"{room_id}.json"


def _ensure_room_db_schema() -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute('ALTER TABLE "Room" ADD COLUMN IF NOT EXISTS room_key varchar(100)')
        cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_room_room_key ON "Room" (room_key)')
        cur.execute('ALTER TABLE "Room" ADD COLUMN IF NOT EXISTS company_key varchar(100)')
        cur.execute('ALTER TABLE "Room" ADD COLUMN IF NOT EXISTS scenario_key varchar(100)')
        cur.execute('ALTER TABLE "Room" ADD COLUMN IF NOT EXISTS incident_key varchar(100)')
        cur.execute('ALTER TABLE "Room" ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT \'{}\'::jsonb')


# -- TheHive org reuse pool ----------------------------------------------------
# TheHive has no organisation-delete API (confirmed live against 4.1.24: DELETE
# and PATCH-status both 404/no-op; matches the never-resolved upstream report
# TheHive-Project/TheHive#1558). A per-room org (see _ensure_room_hive) is
# therefore permanent, so closed rooms release their org here instead of
# leaving it orphaned forever, and a new room claims a wiped org from the pool
# before minting a brand-new one - capping total orgs at "max concurrent rooms
# ever simultaneously open" instead of "total rooms ever created".

# Grace period before a released org is eligible for reuse: matches
# AttackerLogAttacher.DEFAULT_PENDING_TIMEOUT_SECONDS (apps/blue-team-api) so
# any in-flight auto-attach retry against the org's about-to-be-wiped cases
# has already given up before a new room's wipe_org() can race it.
HIVE_ORG_POOL_GRACE_SECONDS = 30 * 60


def _ensure_hive_org_pool_schema() -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS "HiveOrgPool" (
                org_name varchar(200) PRIMARY KEY,
                released_at timestamptz NOT NULL DEFAULT now()
            )
            '''
        )


def _acquire_pooled_org() -> Optional[str]:
    """Claim and remove the oldest reuse-eligible org from the pool.

    Returns None if the pool is empty or every released org is still within
    its grace period - callers should mint a fresh org in that case.
    """
    _ensure_hive_org_pool_schema()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            DELETE FROM "HiveOrgPool"
            WHERE org_name = (
                SELECT org_name FROM "HiveOrgPool"
                WHERE released_at <= now() - (%s * interval '1 second')
                ORDER BY released_at ASC
                LIMIT 1
            )
            RETURNING org_name
            ''',
            (HIVE_ORG_POOL_GRACE_SECONDS,),
        )
        row = cur.fetchone()
        return row["org_name"] if row else None


def _release_org_to_pool(org_name: str) -> None:
    """Return a closed room's org to the pool for a future room to reuse."""
    _ensure_hive_org_pool_schema()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            '''
            INSERT INTO "HiveOrgPool" (org_name, released_at)
            VALUES (%s, now())
            ON CONFLICT (org_name) DO UPDATE SET released_at = now()
            ''',
            (org_name,),
        )


def _room_owner_id(username: str | None) -> int:
    with connection() as conn, conn.cursor() as cur:
        if username:
            cur.execute('SELECT user_id FROM "User" WHERE username = %s', (username,))
            row = cur.fetchone()
            if row is not None:
                return row["user_id"]
        # Unknown/absent creator (e.g. auto-created "system" rooms): fall back to
        # any existing user so the NOT NULL user_id constraint is satisfied.
        cur.execute('SELECT user_id FROM "User" ORDER BY user_id LIMIT 1')
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("No user exists to own room")
        return row["user_id"]


def _load_room_from_db(room_id: str) -> Optional[dict]:
    _ensure_room_db_schema()
    with connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT metadata FROM "Room" WHERE room_key = %s', (room_id,))
        row = cur.fetchone()
        return dict(row["metadata"]) if row is not None else None


def _load_room(room_id: str) -> dict:
    room = _load_room_from_db(room_id)
    if room is not None:
        return room

    path = _room_path(room_id)
    if not path.exists():
        raise ValueError(f"Room not found: {room_id}")

    with path.open("r", encoding="utf-8") as room_file:
        room = json.load(room_file)
        _save_room(room)
        return room


def _save_room_to_db(room: dict) -> None:
    _ensure_room_db_schema()
    owner_id = _room_owner_id(room.get("created_by") or room.get("blue_started_by") or room.get("prefired_by"))
    payload = json.dumps(room)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
        '''
        INSERT INTO "Room" (
        room_key, company_key, scenario_key, incident_key, status,
        user_id, start_time, end_time, metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s::timestamptz, %s::timestamptz, %s::jsonb)
        ON CONFLICT (room_key) DO UPDATE SET
        company_key = EXCLUDED.company_key,
        scenario_key = EXCLUDED.scenario_key,
        incident_key = EXCLUDED.incident_key,
        status = EXCLUDED.status,
        start_time = EXCLUDED.start_time,
        end_time = EXCLUDED.end_time,
        metadata = EXCLUDED.metadata
        ''',
        (
        room["room_id"],
        room.get("company_id"),
        room.get("scenario_id"),
        room.get("incident_id"),
        room.get("status"),
        owner_id,
        room.get("blue_started_at") or room.get("attack_started_at"),
        room.get("closed_at") if room.get("status") == "closed" else None,
        payload,
        ),
        )


def _save_room(room: dict) -> None:
    _save_room_to_db(room)
    ROOMS_DIR.mkdir(parents=True, exist_ok=True)
    with _room_path(room["room_id"]).open("w", encoding="utf-8") as room_file:
        json.dump(room, room_file, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()




def _record_participant(room: dict, username: str, team_role: str, *, completed_at: Optional[str] = None) -> None:
    try:
        from core import mission_store

        mission_store.record_room_participant(
        room["room_id"],
        username,
        team_role,
        joined_at=room.get("created_at") if team_role == "creator" else None,
        completed_at=completed_at,
        payload={
        "room_id": room.get("room_id"),
        "company_id": room.get("company_id"),
        "incident_id": room.get("incident_id"),
        "scenario_id": room.get("scenario_id"),
        "status": room.get("status"),
        "team_role": team_role,
        },
        )
    except Exception:
        logger.exception("Failed to dual-write room participant %s for room %s", username, room.get("room_id"))

def create_room(company_id: str, scenario_id: str, created_by: str, team_name: str | None = None, room_name: str | None = None) -> dict:
    company = company_store.get_company(company_id)
    if company is None:
        raise ValueError(f"Company not found: {company_id}")
    if company["status"] != "active":
        raise RuntimeError("Company must be confirmed before creating rooms")
    room_id = str(uuid.uuid4())
    incident_id = str(uuid.uuid4())

    room = {
        "room_id": room_id,
        "company_id": company_id,
        "incident_id": incident_id,
        "incidents": [incident_id],
        "scenario_id": scenario_id,
        "exercise_mode": "deferred",
        "internal_url": f"http://blueteam_{room_id}:8010",
        "status": "created",
        "blue_team_members": [],
        "red_team_members": [],
        "created_by": created_by,
        "created_at": _now_iso(),
        "prefired_by": None,
        "prefired_at": None,
        "attack_started_at": None,
        "attack_completed_at": None,
        "packaged_at": None,
        "blue_started_at": None,
        "blue_started_by": None,
    }

    _save_room(room)
    _record_participant(room, created_by, "creator")

    return room


def ensure_room_for_incident(incident_id: str, scenario_id: str) -> dict:
    """Idempotently ensure a Blue Team room exists for an attack's incident.

    Called when a red-team attack event is ingested without a pre-existing
    SOC-Manager-created room. If a room already carries this incident_id, it is
    activated (if still in a staging state) and returned. Otherwise a room is
    created under the shared exercise company so the whole (globally-visible)
    Blue Team sees it immediately.
    """
    existing = find_room_for_incident(incident_id)
    if existing is not None:
        if existing.get("status") in {"created", "packaged", "prefiring"}:
            existing["status"] = "active"
            existing.setdefault("attack_started_at", _now_iso())
            _save_room(existing)
        return existing

    company = company_store.ensure_exercise_company()
    room_id = str(uuid.uuid4())
    room = {
        "room_id": room_id,
        "company_id": company["id"],
        "incident_id": incident_id,
        "incidents": [incident_id],
        "scenario_id": scenario_id,
        "exercise_mode": "deferred",
        "internal_url": f"http://blueteam_{room_id}:8010",
        # Surface immediately as a live incident so the Blue Team dashboard
        # shows it as Active (a room to respond to) rather than the raw
        # "created" staging state.
        "status": "active",
        "auto_created": True,
        "blue_team_members": [],
        "red_team_members": [],
        "created_by": "system",
        "created_at": _now_iso(),
        "prefired_by": None,
        "prefired_at": None,
        "attack_started_at": _now_iso(),
        "attack_completed_at": None,
        "packaged_at": None,
        "blue_started_at": None,
        "blue_started_by": None,
    }
    _save_room(room)
    logger.info(
        "Auto-created Blue Team room %s for incident %s (scenario %s)",
        room_id, incident_id, scenario_id,
    )
    return room


def prefire_room(room_id: str, username: str) -> dict:
    """Mark a room as pre-fired/deferred.

    The actual attack and alert events still arrive through the existing
    red-team/signal/Blue Team event pipelines. This function records the room
    lifecycle gate used by the control plane.
    """
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot prefire a closed room")
    if room.get("blue_started_at"):
        raise RuntimeError("Cannot prefire after the Blue team has started")

    now = _now_iso()
    room.setdefault("exercise_mode", "deferred")
    room["status"] = "packaged"
    room["prefired_by"] = room.get("prefired_by") or username
    room["prefired_at"] = room.get("prefired_at") or now
    room["packaged_at"] = room.get("packaged_at") or now
    _save_room(room)
    return room


def start_blue_team(room_id: str, username: str) -> dict:
    """Start the deferred Blue-team timer when a Blue user launches TheHive."""
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot start a closed room")
    if room.get("exercise_mode", "deferred") == "deferred" and not room.get("packaged_at"):
        raise RuntimeError("Room is not packaged yet")

    members = room.setdefault("blue_team_members", [])
    if username not in members:
        members.append(username)
        _record_participant(room, username, "blue_team")
    if not room.get("blue_started_at"):
        room["blue_started_at"] = _now_iso()
        room["blue_started_by"] = username
    room["status"] = "blue_active"
    room["hive_launch_url"] = os.getenv("THEHIVE_PUBLIC_URL", "http://localhost:9000")

    # Same routing + replay as enter_room: point the signal-store at this room
    # and push the attack's stored detections into TheHive so the case the
    # analyst is about to open shows its alerts. Best-effort: starting the
    # exercise must not fail if the signal-store is unreachable.
    try:
        _configure_signal_store_incident(
            (room.get("incidents") or [room["incident_id"]])[0], room_id
        )
        _replay_signal_store_alerts(room)
    except Exception:
        logger.exception("Failed to route/replay signal-store for room %s on blue-start", room_id)

    _save_room(room)
    return room

def _ensure_room_hive(room: dict, username: str, *, as_manager: bool) -> Optional[str]:
    """Ensure the room has its OWN TheHive org + API key and that `username`
    exists in that org, so every member of the room sees the SAME incident -
    and only that incident (real isolation: a different room's cases live in
    a different org, invisible to this room's analysts).

    The first user to enter a room (its creator) becomes the room's SOC manager
    and administers the room's org; teammates who accept an invite are added to
    that same org. Best-effort by design: TheHive may be unreachable or its
    admin credentials unset. A failure here must never block a user from
    entering the room (an unentered room was the original blocker), so it is
    logged and the user still enters - just without a live Hive key.

    Per-room orgs were previously abandoned for a single shared org because
    the alert-raising pipeline (blue-team-api) used one hardcoded global Hive
    API key regardless of room, so a fresh per-room org always looked empty
    (the "zero alerts" bug). That pipeline is now room-aware (see
    apps/blue-team-api's room_hive_registry.resolve_room_hive_api_key, which
    reads `room["hive_api_key"]` - exactly the key provisioned here), so a
    real per-room org now actually receives that room's alerts.

    Org identity: reuses `room["hive_org"]` across re-entries. A room that
    doesn't have one yet first tries to claim a wiped, previously-released org
    from the reuse pool (see _acquire_pooled_org / spin_down_room) - TheHive
    can't delete orgs, so recycling closed rooms' orgs is the only way to cap
    total org count. Only when the pool is empty does this mint a genuinely
    new `room-<room_id>` org.

    Pipeline key = a dedicated per-room SERVICE account, not the human's own
    login. TheHive gives a user exactly ONE API key, tied to whichever org
    they were FIRST created in - confirmed live: adding an EXISTING user to a
    second org and renewing their key still returns a key scoped to their
    original org, not the new one. So reusing a returning analyst's own
    account for `room["hive_api_key"]` silently gives the pipeline a key for
    their OLD org, not this room's - the observable/case data then lands
    somewhere this room's org can't see, looking exactly like "nothing got
    attached". A service account (`svc-<room_id>@thehive.local`) is always
    freshly minted per room, so it can never collide with an existing
    identity and always resolves to the correct org.
    """
    from core import hive_provisioner

    org = room.get("hive_org")
    is_new_org = org is None
    reused_from_pool = False
    if is_new_org:
        org = _acquire_pooled_org()
        if org:
            reused_from_pool = True
            hive_provisioner.wipe_org(org)
        else:
            org = f"room-{room['room_id']}"

    user = user_store.get_user_by_username(username)
    # The creator administers the room's org (admin profile); teammates keep
    # analyst-level access but land in the same org.
    if as_manager:
        attense_role = "soc_manager"
    elif user and user.get("role") in {"soc_l1", "soc_l2", "soc_manager"}:
        attense_role = user["role"]
    else:
        attense_role = "soc_l1"

    try:
        if not reused_from_pool:
            # A pooled org already exists in TheHive (just wiped by
            # wipe_org above) - only a genuinely new org needs creating.
            hive_provisioner.create_org(org)
        room["hive_org"] = org
        # The human's own login, for web-login/browsing this org in TheHive's
        # UI - never used as the pipeline key (see docstring), so no key
        # renewal needed here regardless of role.
        hive_provisioner.create_user_in_org(
            org, username, attense_role=attense_role, renew_key=False
        )
    except Exception:
        logger.exception(
            "TheHive provisioning failed for %s in room %s", username, room.get("room_id")
        )
        return None

    # Only the room's SOC manager triggers pipeline-account provisioning, and
    # only if the room doesn't already have one.
    key = None
    if as_manager and not room.get("hive_api_key"):
        service_login = f"svc-{room['room_id']}@thehive.local"
        try:
            key = hive_provisioner.create_user_in_org(
                org, service_login, attense_role="soc_manager", renew_key=True
            )
        except Exception:
            logger.exception(
                "Could not provision Hive pipeline account for room %s", room.get("room_id")
            )

    # First time this room's org is minted BRAND NEW (not reused from the
    # pool): authorise it on the webhook (static allow-list, needs a TheHive
    # restart - see authorize_org_for_webhook) and register its CaseCreated
    # notification rule (live, no restart), so this room's cases auto-attach
    # attacker evidence like any other room's. A reused pooled org already has
    # both from when it was first minted - skipping them here is the whole
    # point of pooling (no restart on every room). Best-effort - a failure
    # here degrades auto-attach for this room only, it must never block the
    # room entry that already succeeded above.
    if is_new_org and not reused_from_pool:
        try:
            hive_provisioner.authorize_org_for_webhook(org)
        except Exception:
            logger.exception("Could not authorise org '%s' on the TheHive webhook", org)
        if key:
            hive_provisioner.ensure_notification_rule(org, key)

    if as_manager:
        room["soc_manager_username"] = username
        if key:
            room["hive_api_key"] = key
    return key


def hive_credentials(username: str) -> dict:
    """The TheHive web-login credentials for THIS analyst, dynamically.

    Each analyst logs into TheHive as themselves, not a shared/static account:
    `username` is the login, and the password is derived (report Phase 5 -
    deterministic from a server secret, so it's reproducible without ever
    persisting a plaintext password) from that same username. Every caller
    that shows these credentials goes through ensure_member_hive_access first
    (see _thehive_envelope), which provisions this exact account into the
    alert org - so the credentials returned here are guaranteed to already
    work, even the first time this user touches a Hive-backed room.
    """
    from core import hive_provisioner

    return {
        "login": username,
        "password": hive_provisioner.derive_password(username),
    }


def ensure_member_hive_access(username: str) -> None:
    """Provision `username` into the alert org with a known web-login password,
    without minting/renewing an API key or touching room state.

    Called wherever a user is about to be shown their TheHive credentials
    (_thehive_envelope, room_lobby) so those credentials are guaranteed to
    work even if this user has never formally entered/accepted this - or any -
    room before (e.g. clicking "View Report" / "Open in TheHive" on a room they
    only ever saw via Blue Team's global room visibility). Idempotent and
    best-effort: a provisioning failure must never block showing the room.
    """
    from core import hive_provisioner

    org = hive_provisioner.alert_org()
    user = user_store.get_user_by_username(username)
    role = user.get("role") if user else None
    attense_role = role if role in {"soc_l1", "soc_l2", "soc_manager"} else "soc_l1"
    try:
        hive_provisioner.create_org(org)
        hive_provisioner.create_user_in_org(
            org, username, attense_role=attense_role, renew_key=False
        )
    except Exception:
        logger.exception("Failed to ensure Hive access for %s", username)


def enter_room(
    room_id: str,
    username: str,
    mode: str = "solo",
    teammates: Optional[list[str]] = None,
) -> dict:
    """A Blue Team user enters a room, optionally inviting teammates by email.

    The first user to enter becomes the room's SOC manager and provisions the
    shared TheHive org/key the whole room uses. Invited teammates are recorded
    as pending members; they see an in-app invite (list_invites_for_email) and
    join through accept_invite. Once every invited member has joined, the room
    is ready and all members launch into the same TheHive incident.
    """
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot enter a closed room")

    emails: list[str] = []
    for raw in (teammates or []):
        email = (raw or "").strip().lower()
        if email and email != username.lower() and email not in emails:
            emails.append(email)
    team_mode = mode == "team" and bool(emails)
    room["entry_mode"] = "team" if team_mode else "solo"

    # The first user to enter becomes the room's SOC manager and mints the
    # shared Hive key. Always (re)provision the entering user's own TheHive
    # account + web password - including on re-entry - so a returning creator
    # (or a user whose account predates password provisioning) can still log in.
    is_manager = room.get("soc_manager_username") in (None, username)
    _ensure_room_hive(room, username, as_manager=is_manager)

    members = room.setdefault("blue_team_members", [])
    if username not in members:
        members.append(username)
        _record_participant(room, username, "blue_team")

    status = room.setdefault("member_status", {})
    status[username] = "joined"

    invited = room.setdefault("invited_emails", [])
    for email in emails:
        if email not in invited:
            invited.append(email)
        status.setdefault(email, "pending")

    if not room.get("blue_started_at"):
        room["blue_started_at"] = _now_iso()
        room["blue_started_by"] = username
    room["status"] = "blue_active"
    room["hive_launch_url"] = os.getenv("THEHIVE_PUBLIC_URL", "http://localhost:9000")

    # Route live Wazuh alerts to this room's incident, and give the signal-store
    # the room so it can stamp X-Room-Id on raise-alert calls (required for the
    # alerts to reach TheHive). Best-effort: entry must not fail if the
    # signal-store is unreachable.
    try:
        _configure_signal_store_incident(
            (room.get("incidents") or [room["incident_id"]])[0], room_id
        )
    except Exception:
        logger.exception("Failed to route signal-store to room %s on entry", room_id)

    # Deferred exercises: the attack's detections fired before anyone was in the
    # room, so push them into TheHive now - the analyst opens a case that
    # already shows its alerts. Best-effort for the same reason as above.
    try:
        _replay_signal_store_alerts(room)
    except Exception:
        logger.exception("Failed to replay stored alerts for room %s on entry", room_id)

    _save_room(room)
    return room


def accept_invite(room_id: str, username: str, email: Optional[str] = None) -> dict:
    """An invited Blue Team user joins a room they were invited to, landing in
    the room's shared TheHive org so they see the same incident as the team."""
    room = _load_room(room_id)
    if room.get("status") == "closed":
        raise RuntimeError("Cannot join a closed room")

    _ensure_room_hive(room, username, as_manager=False)

    members = room.setdefault("blue_team_members", [])
    if username not in members:
        members.append(username)
        _record_participant(room, username, "blue_team")

    status = room.setdefault("member_status", {})
    status[username] = "joined"
    if email:
        status[email.strip().lower()] = "joined"
    room["hive_launch_url"] = os.getenv("THEHIVE_PUBLIC_URL", "http://localhost:9000")
    _save_room(room)
    return room


def list_invites_for_email(email: str) -> list[dict]:
    """Return open rooms that have invited `email` but which it hasn't joined."""
    email = (email or "").strip().lower()
    if not email:
        return []
    out: list[dict] = []
    seen: set[str] = set()

    def _scan(rooms: list[dict]) -> None:
        for room in rooms:
            rid = room.get("room_id")
            if not rid or rid in seen or room.get("status") == "closed":
                continue
            invited = [e.lower() for e in room.get("invited_emails", [])]
            member_status = room.get("member_status", {})
            if email in invited and member_status.get(email) != "joined":
                out.append(room)
                seen.add(rid)

    _scan(_iter_rooms_from_db())
    _scan(_iter_rooms_from_files())
    return out


def room_lobby(room_id: str) -> dict:
    """A lightweight join-status view of a room, for the lobby's poll loop.

    Avoids the heavy report generation of GET /{room_id}; returns each member's
    join state and whether everyone invited has joined (all_joined), the gate
    used by the frontend before launching the whole team into TheHive.
    """
    room = _load_room(room_id)
    invited = [e.lower() for e in room.get("invited_emails", [])]
    member_status = room.get("member_status", {})
    members = []
    creator = room.get("soc_manager_username") or room.get("blue_started_by")
    if creator:
        members.append({"id": creator, "role": "SOC Manager", "status": "joined"})
    for email in invited:
        members.append({"id": email, "role": "Analyst", "status": member_status.get(email, "pending")})
    all_joined = all(member_status.get(email) == "joined" for email in invited)
    return {
        "room_id": room_id,
        "entry_mode": room.get("entry_mode", "solo"),
        "members": members,
        "all_joined": all_joined,
        "hive_launch_url": room.get("hive_launch_url") or os.getenv("THEHIVE_PUBLIC_URL", "http://localhost:9000"),
        "status": room.get("status"),
    }


def record_incident_event(room_id: str, event_type: str, timestamp: str) -> dict:
    """Update room lifecycle timestamps from incident events."""
    room = _load_room(room_id)
    if event_type == "malicious_action_executed":
        room["attack_started_at"] = room.get("attack_started_at") or timestamp
        room["attack_completed_at"] = timestamp
        # Activate the room so the Blue Team can enter it now that an attack fired.
        if room.get("status") in {"created", "packaged", "prefiring"}:
            room["status"] = "active"
    elif event_type == "alert_raised":
        room["packaged_at"] = room.get("packaged_at") or timestamp
        if room.get("status") in {"created", "prefiring"}:
            room["status"] = "packaged"
    _save_room(room)
    return room


def spin_up_blueteam(room_id: str) -> dict:
    room = _load_room(room_id)
    if room["status"] in {"active", "blue_active"}:
        return room

    # Prefer the room's own shared Hive key (provisioned when the room's SOC
    # manager - its creator - first entered). Every member of the room uses this
    # same key, so they all see the same TheHive incident. Fall back to the
    # company's SOC-manager key for classic CISO-provisioned rooms.
    runtime_keys: dict = {}
    hive_api_key = room.get("hive_api_key")
    if not hive_api_key:
        soc_manager = next(
            (
                user
                for user in user_store.get_users_by_company(room["company_id"])
                if user.get("role") == "soc_manager"
            ),
            None,
        )
        runtime_keys = user_store.get_blue_team_runtime_keys(soc_manager["id"]) if soc_manager else {}
        hive_api_key = runtime_keys.get("hive_api_key") or (soc_manager or {}).get("hive_key")
    if not hive_api_key:
        raise RuntimeError(
            f"No SOC manager with a Hive API key found for company {room['company_id']}"
        )

    environment = {
        "INCIDENT_ID": (room.get("incidents") or [room["incident_id"]])[0],
        "HIVE_URL": "http://thehive:9000",
        "HIVE_API_KEY": hive_api_key,
        "SANDBOX_URL": "http://target-agent:80",
    }
    if runtime_keys.get("cortex_api_key"):
        environment["CORTEX_API_KEY"] = runtime_keys["cortex_api_key"]

    client = None
    container = None
    container_name = f"blueteam_{room_id}"
    try:
        client = docker.from_env()
        container = client.containers.run(
            image=BLUETEAM_IMAGE,
            name=container_name,
            environment=environment,
            network=DOCKER_NETWORK,
            detach=True,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            container.reload()
            state = container.attrs.get("State", {})
            health = state.get("Health", {}).get("Status")
            if health == "healthy":
                break
            if state.get("Status") in {"exited", "dead"} or health == "unhealthy":
                raise RuntimeError(
                    f"Blue Team container became {health or state.get('Status')}"
                )
            time.sleep(2)
        else:
            raise RuntimeError("Blue Team container did not become healthy within 90 seconds")
        _configure_signal_store_incident((room.get("incidents") or [room["incident_id"]])[0], room_id)
        room["status"] = "active"
        _save_room(room)
    except Exception as exc:
        # Best-effort teardown of whatever container this attempt created.
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                logger.exception(
                    "Failed to force-remove Blue Team container %s during cleanup",
                    container_name,
                )
        # Re-check the container is actually gone; a lingering container keeps
        # room["port"] bound and would block any retry of this room.
        if client is not None:
            try:
                leftover = client.containers.list(all=True, filters={"name": container_name})
            except Exception:
                logger.exception(
                    "Could not verify removal of Blue Team container %s", container_name
                )
            else:
                if leftover:
                    logger.error(
                        "Blue Team container %s still present after force-remove: %s",
                        container_name,
                        [c.id for c in leftover],
                    )
        raise RuntimeError(f"Failed to start Blue Team room {room_id}: {exc}") from exc

    return room


def spin_down_room(room_id: str) -> dict:
    room = _load_room(room_id)

    if room.get("status") == "closed":
        return room

    if room["status"] == "created":
        if room.get("port") is not None: # Legacy rooms created before ports were internal-only.
            port_pool.release(room["port"])
        if room.get("hive_org"):
            _release_org_to_pool(room["hive_org"])
        room["status"] = "closed"
        room["closed_at"] = room.get("closed_at") or _now_iso()
        for member in room.get("red_team_members", []):
            _record_participant(room, member, "red_team", completed_at=room.get("closed_at"))
        for member in room.get("blue_team_members", []):
            _record_participant(room, member, "blue_team", completed_at=room.get("closed_at"))
        _save_room(room)
        return room

    try:
        client = docker.from_env()
        container = client.containers.get(f"blueteam_{room_id}")
        container.stop()
        container.remove()
    except docker.errors.NotFound:
        logger.info("No dedicated Blue Team container found for room %s; closing room state only", room_id)
    except Exception as exc:
        raise RuntimeError(f"Failed to stop Blue Team room {room_id}: {exc}") from exc

    if room.get("port") is not None: # Legacy rooms created before ports were internal-only.
        port_pool.release(room["port"])
    room["status"] = "closed"
    room["closed_at"] = room.get("closed_at") or _now_iso()
    for member in room.get("red_team_members", []):
        _record_participant(room, member, "red_team", completed_at=room.get("closed_at"))
    for member in room.get("blue_team_members", []):
        _record_participant(room, member, "blue_team", completed_at=room.get("closed_at"))
    try:
        _configure_signal_store_incident(None)
    except RuntimeError:
        # The room is already safely closed. Keep teardown idempotent, but
        # retain a clear operational signal that the mapper needs attention.
        logger.exception("Failed to clear active signal-store incident for room %s", room_id)
    _generate_final_reports(room)
    if room.get("hive_org"):
        _release_org_to_pool(room["hive_org"])
    _save_room(room)
    return room

def _generate_final_reports(room: dict) -> None:
    """On exercise end, run the evaluation pipeline for each of the room's
    incidents, write each markdown report (to /attense/actions/), and store a
    compact scored summary under room["final_reports"] (this is the ERD's
    "Room --generates--> AI report").

    Best-effort by design: wrapped per incident so a scoring/IO failure (or an
    incident with no events to score) is logged and skipped rather than
    blocking room teardown. The room is already stopped/closed at this point.
    """
    reports = []
    for incident_id in (room.get("incidents") or []):
        try:
            from pipeline.run_pipeline import build_and_write_report

            result = build_and_write_report(incident_id)
        except Exception:
            logger.exception(
                "Final report generation failed for incident %s", incident_id
            )
            continue
        if result is None:
            continue
        reports.append({
            "incident_id": result["incident_id"],
            "final_score": result["final_score"],
            "verdict": result["verdict"],
            "outcome": result["outcome"],
            "report_path": result["report_path"],
            "member_reports": result.get("member_reports", []),
        })
    if reports:
        room["final_reports"] = reports


def get_room(room_id: str) -> dict:
    """Return a room from the database-backed store."""
    return _load_room(room_id)


def add_incident(room_id: str, incident_id: str) -> dict:
    """Associate an incident with a room (idempotent). Returns the room."""
    room = _load_room(room_id)
    incidents = room.setdefault("incidents", [])
    if incident_id not in incidents:
        incidents.append(incident_id)
        _save_room(room)
    return room



def _iter_rooms_from_db(company_id: Optional[str] = None) -> list[dict]:
    _ensure_room_db_schema()
    with connection() as conn, conn.cursor() as cur:
        if company_id is None:
            cur.execute('SELECT metadata FROM "Room" WHERE room_key IS NOT NULL ORDER BY room_id DESC')
        else:
            cur.execute(
                'SELECT metadata FROM "Room" WHERE room_key IS NOT NULL AND company_key = %s ORDER BY room_id DESC',
                (company_id,),
            )
        return [dict(row["metadata"]) for row in cur.fetchall()]


def _iter_rooms_from_files(company_id: Optional[str] = None) -> list[dict]:
    if not ROOMS_DIR.exists():
        return []
    rooms = []
    for path in ROOMS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as room_file:
                room = json.load(room_file)
        except (OSError, json.JSONDecodeError):
            continue
        if company_id is None or room.get("company_id") == company_id:
            rooms.append(room)
            try:
                _save_room(room)
            except Exception:
                logger.exception("Failed to backfill room %s into database", room.get("room_id"))
    return rooms


def find_room_for_incident(incident_id: str) -> Optional[dict]:
    """Return the room whose designated/associated incidents include incident_id."""
    for room in _iter_rooms_from_db():
        if room.get("incident_id") == incident_id or incident_id in room.get("incidents", []):
            return room
    for room in _iter_rooms_from_files():
        if room.get("incident_id") == incident_id or incident_id in room.get("incidents", []):
            return room
    return None


def find_room_id_for_incident(incident_id: str) -> Optional[str]:
    """Return the room_id whose designated or associated incidents include
    incident_id, or None if no room matches."""
    room = find_room_for_incident(incident_id)
    return room.get("room_id") if room else None


def join_room_as_red_team(room_id: str, username: str) -> dict:
    """Add username to the room's red_team_members (idempotent). Membership
    is permissive: a red_team user may belong to more than one room; see
    user_store.set_active_room for the most-recently-joined tie-break."""
    room = _load_room(room_id)
    members = room.setdefault("red_team_members", [])
    if username not in members:
        members.append(username)
        _save_room(room)
        _record_participant(room, username, "red_team")
    return room

def get_room_if_member(room_id: str, username: str) -> Optional[dict]:
    """Return the room if it still exists, isn't closed, and username is
    actually a red_team_members entry - None otherwise. Used to validate a
    user's active_room_id pointer hasn't gone stale (room closed/deleted)."""
    try:
        room = _load_room(room_id)
    except ValueError:
        return None
    if room.get("status") == "closed":
        return None
    if username not in room.get("red_team_members", []):
        return None
    return room


def find_room_for_red_team_member(username: str) -> Optional[dict]:
    """Return the first non-closed room containing username as a red member."""
    for room in _iter_rooms_from_db():
        if room.get("status") != "closed" and username in room.get("red_team_members", []):
            return room
    for room in _iter_rooms_from_files():
        if room.get("status") != "closed" and username in room.get("red_team_members", []):
            return room
    return None


def list_rooms_for_company(company_id: Optional[str]) -> list[dict]:
    """Return DB-backed rooms for company_id, or every room for CISO."""
    rooms = _iter_rooms_from_db(company_id)
    if rooms:
        return rooms
    return _iter_rooms_from_files(company_id)
