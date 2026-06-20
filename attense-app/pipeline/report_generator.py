"""
pipeline/report_generator.py — Gemini Markdown Report Generator

Takes the dict returned by generate_report() plus the sorted events list
and asks Gemini (via Vertex AI) to produce a structured markdown incident report.

Config (read from environment — set values in pipeline/.env and export before running):
    VERTEX_PROJECT_ID  — GCP project ID
    VERTEX_LOCATION    — Vertex AI region (default: global)
    VERTEX_MODEL       — model name     (default: gemini-3.5-flash)

Falls back to a plain-text formatted report if the Gemini call fails.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import timedelta
from typing import Optional

import vertexai
from google.api_core import exceptions as google_exceptions
from vertexai.generative_models import GenerativeModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ATTENSE_app.events.event import Event

logger = logging.getLogger(__name__)

VERTEX_PROJECT_ID = os.environ.get("VERTEX_PROJECT_ID", "")
VERTEX_LOCATION   = os.environ.get("VERTEX_LOCATION",   "global")
VERTEX_MODEL      = os.environ.get("VERTEX_MODEL",      "gemini-3.5-flash")

# TTD threshold from constants (300s = 5 min)
TTD_EXCELLENT_THRESHOLD = 300


# ── Formatting helpers ────────────────────────────────────────────────────────

def _fmt_td(td: Optional[timedelta]) -> str:
    if td is None:
        return "N/A"
    total = int(td.total_seconds())
    if total < 0:
        total = abs(total)
    h, rem = divmod(total, 3600)
    m, s   = divmod(rem, 60)
    parts  = []
    if h:
        parts.append(f"{h} hour{'s' if h != 1 else ''}")
    if m:
        parts.append(f"{m} minute{'s' if m != 1 else ''}")
    parts.append(f"{s} second{'s' if s != 1 else ''}")
    return " ".join(parts)


def _grade(outcome: str, ttd: Optional[timedelta]) -> str:
    if outcome == "SUCCESS":
        ttd_secs = ttd.total_seconds() if ttd else float("inf")
        return "Excellent" if ttd_secs <= TTD_EXCELLENT_THRESHOLD else "Acceptable"
    if outcome == "PARTIAL":
        return "Acceptable"
    if outcome == "INCOMPLETE":
        return "Needs Review"
    return "Failed"  # FAILURE or FALSE_POSITIVE


def _outcome_explanation(outcome: str) -> str:
    return {
        "SUCCESS":       "The incident was detected and fully contained.",
        "PARTIAL":       "The incident was detected but containment was never completed.",
        "FAILURE":       "The attacker was never detected — the incident went unnoticed.",
        "FALSE_POSITIVE":"An alert was raised but no actual attack occurred.",
        "INCOMPLETE":    "The incident is still in progress or data is missing.",
    }.get(outcome, outcome)


def _analyst_action_lines(events: list[Event]) -> str:
    lines = []
    for ev in events:
        if ev.actor_type != "blue_team":
            continue
        detail = (ev.metadata or {}).get("detail", "")
        offset = (ev.metadata or {}).get("t_offset_sec", "")
        ts_str = ev.timestamp.strftime("%H:%M:%S") if ev.timestamp else "?"
        offset_str = f" (t=+{offset}s)" if offset != "" else ""
        lines.append(f"- {ts_str}{offset_str}  **{ev.actor_id}**  →  {ev.event_type}  |  {detail}")
    return "\n".join(lines) if lines else "- No analyst actions recorded."


# ── Gemini call ───────────────────────────────────────────────────────────────

def _call_gemini(prompt: str) -> Optional[str]:
    if not VERTEX_PROJECT_ID:
        logger.warning("[report_generator] VERTEX_PROJECT_ID not set — skipping Gemini")
        return None
    try:
        vertexai.init(project=VERTEX_PROJECT_ID, location=VERTEX_LOCATION)
        model = GenerativeModel(VERTEX_MODEL)
        response = model.generate_content(prompt)
        return response.text
    except google_exceptions.PermissionDenied as exc:
        logger.error("[report_generator] Gemini permission denied (check ADC credentials): %s", exc)
    except google_exceptions.ResourceExhausted as exc:
        logger.error("[report_generator] Gemini quota/rate-limit exceeded: %s", exc)
    except google_exceptions.NotFound as exc:
        logger.error("[report_generator] Gemini model not found (%s): %s", VERTEX_MODEL, exc)
    except google_exceptions.ServiceUnavailable as exc:
        logger.error("[report_generator] Gemini service unavailable: %s", exc)
    except google_exceptions.GoogleAPICallError as exc:
        logger.error("[report_generator] Gemini API error (%s): %s", type(exc).__name__, exc)
    except google_exceptions.RetryError as exc:
        logger.error("[report_generator] Gemini request timed out after retries: %s", exc)
    return None


# ── Fallback plain formatter ──────────────────────────────────────────────────

def _plain_report(report: dict, events: list[Event]) -> str:
    outcome = report["outcome"]
    grade   = _grade(outcome, report["ttd"])
    lines = [
        f"# Incident Report: {report['incident_id']}",
        f"**Scenario:** {report['scenario_id']}",
        f"**Status:** {report['status']}",
        f"**Outcome:** {outcome} — {_outcome_explanation(outcome)}",
        f"**Grade:** {grade}",
        "",
        "## Timing",
        f"- Time to Detect (TTD): {_fmt_td(report['ttd'])}",
        f"- Time to Contain (TTC): {_fmt_td(report['ttc'])}",
        "",
        "## Analyst Actions",
        _analyst_action_lines(events),
    ]
    return "\n".join(lines)


# ── Public entry point ────────────────────────────────────────────────────────

def generate(report: dict, events: list[Event]) -> str:
    """
    Produce a markdown incident report.
    Tries Gemini first; falls back to plain formatter if the call fails.
    """
    outcome  = report["outcome"]
    ttd      = report["ttd"]
    ttc      = report["ttc"]
    grade    = _grade(outcome, ttd)

    action_lines = _analyst_action_lines(events)

    prompt = f"""You are a senior SOC analyst writing a formal incident response report in markdown.
Use the structured data below. Output ONLY the markdown — no commentary before or after.

---
Incident ID:   {report['incident_id']}
Scenario ID:   {report['scenario_id']}
Final Status:  {report['status']}
Outcome:       {outcome} — {_outcome_explanation(outcome)}
Grade:         {grade}

Time to Detect (TTD):  {_fmt_td(ttd)}
Time to Contain (TTC): {_fmt_td(ttc)}

Analyst Actions (chronological):
{action_lines}
---

Write a markdown report with these exact sections:
1. `# Incident Report: {report['incident_id']}`
2. `## Summary` — 2-3 sentences describing what happened and how the team responded
3. `## Timeline` — bullet list of analyst actions in plain English (who did what, when)
4. `## Metrics` — TTD, TTC, Outcome, Grade in a markdown table
5. `## Assessment` — one paragraph grading the response: was it fast enough, complete, any gaps?

Grade guide: Excellent = SUCCESS + TTD ≤ 5 min | Acceptable = SUCCESS + TTD > 5 min or PARTIAL | Needs Review = INCOMPLETE | Failed = FAILURE or FALSE_POSITIVE
"""

    md = _call_gemini(prompt)
    if md:
        return md.strip()
    return _plain_report(report, events)
