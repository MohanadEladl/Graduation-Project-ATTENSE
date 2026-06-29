"""
output.py – Dispatch StandardEvents to the configured destination.

OUTPUT_MODE=file  → append one JSON line per event to OUTPUT_PATH
OUTPUT_MODE=http  → POST each event to EVENT_STORE_URL (with retry backoff)
OUTPUT_MODE=both  → do both of the above for each event
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import httpx
from tenacity import (
    RetryError,
    retry,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from app.config import settings
from attense_core.models.event import Event

logger = logging.getLogger("signal-mapper.output")

# ── File output ───────────────────────────────────────────────────────────────

_file_lock = threading.Lock()
_file_initialised = False


def _ensure_output_dir(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def write_file(event: Event) -> None:
    """Append *event* as a single JSON line to the configured output file."""
    global _file_initialised
    path = settings.output_path

    with _file_lock:
        if not _file_initialised:
            _ensure_output_dir(path)
            _file_initialised = True

        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict()) + "\n")
            logger.debug("[output/file] Written event_id=%s", event.event_id)
        except OSError as exc:
            logger.error("[output/file] Write failed: %s", exc)


# ── HTTP output ───────────────────────────────────────────────────────────────

def _to_raise_alert_request(event: Event) -> dict:
    """
    Reshape an internal StandardEvent into the JSON body that the blue-team
    /blueteam/raise-alert endpoint expects (RaiseAlertRequest).

    Lives here, not in blueteam, so blueteam stays untouched and the
    signal-store remains the single boundary that knows about both schemas.
    """
    md = event.metadata or {}
    raw_ref = md.get("raw_ref") or {}
    return {
        "incident_id": event.incident_id,
        "scenario_id": event.scenario_id,
        "siem_id":     event.actor_id or "wazuh-manager",
        "target_id":   event.target_id or "unknown",
        "target_type": event.target_type or "host",
        "rule_name":   md.get("description")
                       or (f"wazuh_rule_{md.get('wazuh_rule_id')}"
                           if md.get("wazuh_rule_id") else None),
        "severity":    md.get("severity") or "medium",
        "raw_log":     raw_ref.get("full_log") or md.get("description"),
    }


_http_client: httpx.Client | None = None
_http_lock = threading.Lock()


def _get_http_client() -> httpx.Client:
    global _http_client
    with _http_lock:
        if _http_client is None:
            _http_client = httpx.Client(timeout=10.0)
    return _http_client


def _build_retry_poster():
    """Build a retrying POST function using the current settings."""
    @retry(
        wait=wait_exponential(
            min=settings.http_retry_min_wait,
            max=settings.http_retry_max_wait,
        ),
        stop=stop_after_attempt(settings.http_retry_attempts),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def _post(event: Event) -> None:
        url = settings.event_store_url
        body = _to_raise_alert_request(event)
        resp = _get_http_client().post(
            url,
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        logger.debug(
            "[output/http] POST %s → HTTP %s (event_id=%s)",
            url, resp.status_code, event.event_id,
        )

    return _post


_retry_poster = None
_retry_lock = threading.Lock()


def post_event(event: Event) -> None:
    """POST *event* to the configured event store, with exponential backoff."""
    global _retry_poster
    with _retry_lock:
        if _retry_poster is None:
            _retry_poster = _build_retry_poster()

    try:
        _retry_poster(event)
    except (RetryError, httpx.HTTPError, Exception) as exc:
        logger.error(
            "[output/http] All %d attempts failed for event_id=%s: %s",
            settings.http_retry_attempts, event.event_id, exc,
        )


# ── Combined dispatch ─────────────────────────────────────────────────────────

def dispatch(event: Event) -> None:
    """
    Emit *event* to the configured output.

    Mode is controlled by the ``OUTPUT_MODE`` environment variable:
    * ``file``  → append to ``OUTPUT_PATH``
    * ``http``  → POST to ``EVENT_STORE_URL``
    * ``both``  → append to ``OUTPUT_PATH`` AND POST to ``EVENT_STORE_URL``
    """
    mode = settings.output_mode.lower().strip()
    if mode == "http":
        post_event(event)
    elif mode == "both":
        write_file(event)
        post_event(event)
    elif mode == "file":
        write_file(event)
    else:
        logger.warning(
            "[output] Unknown OUTPUT_MODE=%r – falling back to 'file'.", mode
        )
        write_file(event)
