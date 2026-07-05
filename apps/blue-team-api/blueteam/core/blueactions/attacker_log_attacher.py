"""
attacker_log_attacher.py - Attach Attacker Activity to a Hive Case
===================================================================
When an analyst promotes an alert to a case (Hive ``Case/Create`` webhook),
this service pulls the attacker's evidence from the target-agent, correlates
it to the incident, and writes it into the case as:

    1. An "Attacker Activity Log" task whose task-logs are the attacker's
       actions in chronological order (LetsDefend-style log timeline).
    2. IOC observables (source IPs, uploaded filenames) for the case.

Correlation (per design): time window anchored at ``incident.start_time``,
refined by the attacker ``source_ip`` when it can be resolved from the
incident's alert metadata; otherwise all lab events in the window.

Attach-once-successful: a case is enriched a single time once real attacker
evidence is found. If the ``case/create`` webhook fires before the attack has
happened (or before the target-agent has recorded it), there is nothing to
attach yet - the case is queued and retried by the background poller
(``retry_pending``, driven from ``main.py``'s lifespan) every few seconds
until evidence appears or ``pending_timeout_seconds`` elapses, at which point
it is dropped so a genuinely attack-free case doesn't get polled forever.

Every external call is non-fatal - a down target-agent or Hive simply yields
a case without the enrichment, never a failed webhook.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Callable, Optional

from ...infrastructure.sandbox.lab_evidence_connector import LabEvidenceConnector
from ...infrastructure.thehive.hive_client import HiveClient

logger = logging.getLogger(__name__)

ACTIVITY_TASK_TITLE = "Attacker Activity Log"

# How long a case with no correlated evidence yet stays queued for retry
# before we give up (e.g. a case created for an attack that never happens).
DEFAULT_PENDING_TIMEOUT_SECONDS = 30 * 60

# Metadata keys (across incident events) that may carry the attacker's IP.
_SOURCE_IP_KEYS = ("source_ip", "src_ip", "attacker_ip", "src", "sourceIp")

# Pure navigation / health-check noise - high frequency, zero attack signal.
# Dropped from the activity log so the real attacker actions stand out.
# Denylist (not allowlist) so a new/unknown attack signature is never hidden.
_NOISE_EVENT_TYPES = frozenset({"portal_visited", "route_discovered"})

# Keys inside an event's `extra` that hold the attacker's actual input/payload
# (the "command they ran"). Rendered into the log line so an analyst sees the
# real request content, not just the event name. Ordered by usefulness.
_PAYLOAD_KEYS = (
    "host_param", # command injection: e.g. "127.0.0.1; id; uname -a"
    "query", # XSS: the submitted script payload
    "path_param", # directory traversal: e.g. "../../../../etc/passwd"
    "new_email", # CSRF: the value the forged request set
    "filename", # malicious upload
    "username", # brute-force / auth
    "payload", # generic
    "referer", # CSRF lure origin
    "failure_count", # brute-force volume
)


def _attacker_input(ev: dict) -> str:
    """Extract the attacker's actual input/command from an event's `extra`.

    Returns a compact 'key=value; ...' string of the meaningful payload fields,
    or '' if the event carries no attacker-supplied data.
    """
    extra = ev.get("extra")
    if not isinstance(extra, dict) or not extra:
        return ""
    parts = [
        f"{k}={extra[k]!r}"
        for k in _PAYLOAD_KEYS
        if extra.get(k) not in (None, "", "none")
    ]
    if not parts: # unknown event with some context - show a little of it
        parts = [f"{k}={v!r}" for k, v in list(extra.items())[:3]]
    return "; ".join(parts)


class AttackerLogAttacher:
    """
    Enriches a Hive case with the correlated attacker activity for an incident.

    Parameters
    ----------
    hive_resolver : room_id -> HiveClient. Called per attempt (not cached) so
        each case is written through ITS OWN room's TheHive org - see
        infrastructure/thehive/room_hive_registry.py.
    lab_connector : LabEvidenceConnector for reading attacker evidence.
    """

    def __init__(
        self,
        hive_resolver: Callable[[Optional[str]], HiveClient],
        lab_connector: LabEvidenceConnector,
        lookback_seconds: int = 3600,
        pending_timeout_seconds: int = DEFAULT_PENDING_TIMEOUT_SECONDS,
    ) -> None:
        self.hive_resolver = hive_resolver
        self.lab = lab_connector
        # Attacker activity PRECEDES detection: an alert is raised after the
        # malicious traffic already hit the target. So the correlation window
        # must look BACK from the incident anchor, not forward. lookback_seconds
        # is how far before start_time/detection_time we still collect evidence.
        self.lookback_seconds = lookback_seconds
        self.pending_timeout_seconds = pending_timeout_seconds
        self._enriched_cases: set[str] = set() # case_ids successfully enriched
        # case_ids with no evidence yet, waiting on retry_pending():
        # case_id -> (incident, room_id, first_attempt_monotonic)
        self._pending: dict[str, tuple[Any, Optional[str], float]] = {}

    def attach(self, case_id: str, incident: Any, room_id: Optional[str] = None) -> bool:
        """
        Attach the attacker activity log + IOCs to *case_id* for *incident*.

        *room_id* selects which TheHive org's client writes the case (falls
        back to the shared org when None/unresolvable - see
        `room_hive_registry.resolve_room_hive_api_key`).

        Returns True if enrichment ran now, False if it was skipped (already
        done) or queued for retry (no correlated events yet - see
        ``retry_pending``). Never raises.
        """
        if not case_id:
            logger.debug("[AttackerLogAttacher] No case_id - skipping enrichment.")
            return False
        if case_id in self._enriched_cases:
            logger.debug(
                "[AttackerLogAttacher] Case %s already enriched - skipping (attach-once).",
                case_id,
            )
            return False

        if self._try_attach(case_id, incident, room_id):
            return True

        if case_id not in self._pending:
            self._pending[case_id] = (incident, room_id, time.monotonic())
            logger.info(
                "[AttackerLogAttacher] Case %s queued for retry - no attacker evidence yet.",
                case_id,
            )
        return False

    def retry_pending(self) -> None:
        """
        Retry attaching for every case still waiting on attacker evidence.

        Called periodically by the background poller (see main.py's
        lifespan). Drops a case once it either gets attached or has been
        pending longer than ``pending_timeout_seconds``, so a case with no
        attack behind it isn't polled forever. Never raises.
        """
        if not self._pending:
            return
        now = time.monotonic()
        for case_id, (incident, room_id, first_attempt) in list(self._pending.items()):
            if self._try_attach(case_id, incident, room_id):
                del self._pending[case_id]
                continue
            if now - first_attempt >= self.pending_timeout_seconds:
                logger.info(
                    "[AttackerLogAttacher] Giving up on case %s after %.0fs - "
                    "still no correlated attacker evidence.",
                    case_id, self.pending_timeout_seconds,
                )
                del self._pending[case_id]
                self._enriched_cases.add(case_id)

    def _try_attach(self, case_id: str, incident: Any, room_id: Optional[str]) -> bool:
        """One attach attempt. Returns True iff events were found and attached."""
        try:
            since = self._incident_start_epoch(incident)
            source_ip = self._resolve_source_ip(incident)
            events = self.lab.fetch_events(since_epoch=since, source_ip=source_ip)

            # Drop navigation/health-check noise so attacker actions stand out.
            events = [e for e in events
                      if e.get("event_type") not in _NOISE_EVENT_TYPES]

            if not events:
                logger.debug(
                    "[AttackerLogAttacher] No correlated attacker events for case %s "
                    "(incident=%s) yet.",
                    case_id, getattr(incident, "incident_id", "?"),
                )
                return False

            hive = self.hive_resolver(room_id)
            self._write_activity_task(hive, case_id, incident, events)
            self._add_iocs(hive, case_id, events)

            self._enriched_cases.add(case_id)
            logger.info(
                "[AttackerLogAttacher] Attached %d attacker events to case %s (incident=%s).",
                len(events), case_id, getattr(incident, "incident_id", "?"),
            )
            return True
        except Exception as exc: # never break the webhook or the poller
            logger.warning(
                "[AttackerLogAttacher] Enrichment failed for case %s (non-fatal): %s",
                case_id, exc,
            )
            return False

    # -- Internal helpers ------------------------------------------------------

    def _write_activity_task(self, hive: HiveClient, case_id: str, incident: Any, events: list[dict]) -> None:
        """Create the activity task and append one log line per attacker event."""
        task = hive.create_task(case_id, ACTIVITY_TASK_TITLE)
        task_id = task.get("id") or task.get("_id")
        if not task_id:
            logger.warning(
                "[AttackerLogAttacher] Could not create '%s' task on case %s - "
                "skipping log timeline.",
                ACTIVITY_TASK_TITLE, case_id,
            )
            return

        # Summary header first, then one entry per attacker action.
        hive.add_task_log(
            task_id,
            f"**Attacker activity for incident `{getattr(incident, 'incident_id', '?')}`** "
            f"- {len(events)} action(s) correlated from the target.",
        )
        for ev in events:
            hive.add_task_log(task_id, self._format_event(ev))

    @staticmethod
    def _format_event(ev: dict) -> str:
        """Render one lab event as a single task-log line."""
        ts = ev.get("ts")
        when = (
            datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            if isinstance(ts, (int, float)) else "--:--:--"
        )
        method = ev.get("method") or "-"
        path = ev.get("path") or "-"
        src = ev.get("source_ip") or "-"
        etype = ev.get("event_type") or "event"
        msg = ev.get("learner_message") or ""
        severity = ev.get("severity") or "info"
        command = _attacker_input(ev)
        line = f"`{when}` **{etype}** ({severity}) - `{method} {path}` from `{src}`"
        if command:
            line += f"\n> 🛠 command: `{command}`"
        if msg:
            line += f"\n> {msg}"
        return line

    def _add_iocs(self, hive: HiveClient, case_id: str, events: list[dict]) -> None:
        """Add IOC observables: distinct source IPs and uploaded filenames."""
        seen_ips: set[str] = set()
        seen_files: set[str] = set()

        for ev in events:
            ip = ev.get("source_ip")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                hive.add_observable(case_id, "ip", ip)

            extra = ev.get("extra") or {}
            filename = extra.get("filename") or extra.get("file") or extra.get("saved_as")
            if filename and filename not in seen_files:
                seen_files.add(filename)
                hive.add_observable(case_id, "filename", filename)

    def _incident_start_epoch(self, incident: Any) -> float:
        """
        Resolve the correlation window start as an epoch timestamp.

        Anchors on start_time, then detection_time, and subtracts the lookback
        so attacker activity that occurred BEFORE the alert was raised is still
        captured. Falls back to 0.0 (all events) if neither timestamp is set -
        better to over-include than miss attacker activity.
        """
        for attr in ("start_time", "detection_time"):
            value = getattr(incident, attr, None)
            if isinstance(value, datetime):
                return max(0.0, value.timestamp() - self.lookback_seconds)
        return 0.0

    @staticmethod
    def _resolve_source_ip(incident: Any) -> str | None:
        """
        Find the attacker's source IP from the incident's event metadata, if any.

        Scans all events' metadata for a known IP key. Returns the first match,
        or None (-> no IP filter, include all events in the window).
        """
        for event in getattr(incident, "events", []) or []:
            meta = getattr(event, "metadata", None) or {}
            if not isinstance(meta, dict):
                continue
            for key in _SOURCE_IP_KEYS:
                ip = meta.get(key)
                if ip:
                    return str(ip)
        return None
