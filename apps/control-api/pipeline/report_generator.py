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

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from attense_core.models.event import Event

# google-genai is optional: its latest releases require pydantic>=2.12.5,
# which conflicts with this project's pinned pydantic==2.10.6 (the StandardEvent
# contract and everything built on it). Import lazily so a missing/incompatible
# package degrades to the plain-text fallback below, the same as a missing
# VERTEX_PROJECT_ID -- never a hard crash at module import time.
try:
    from google import genai
    from google.genai import errors as genai_errors
    _GENAI_AVAILABLE = True
except ImportError:
    genai = None
    genai_errors = None
    _GENAI_AVAILABLE = False

logger = logging.getLogger(__name__)

VERTEX_PROJECT_ID = os.environ.get("VERTEX_PROJECT_ID", "")
VERTEX_LOCATION   = os.environ.get("VERTEX_LOCATION",   "global")
VERTEX_MODEL      = os.environ.get("VERTEX_MODEL",      "gemini-3.5-flash")

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


def _fmt_scoring_rules(rules: list[dict]) -> str:
    """
    Format the 9-rule breakdown for the Gemini prompt.
    Each rule is labelled [PASS], [FAIL], or [N/A ] so Gemini can immediately
    identify which rules need explaining without parsing the status string.
    """
    _label = {"triggered": "[FAIL]", "passed": "[PASS]", "not_applicable": "[N/A ]"}
    lines: list[str] = []
    for r in rules:
        label   = _label.get(r["status"], "[????]")
        penalty = f"  ({r['penalty_points']} pts)" if r["status"] == "triggered" else ""
        lines.append(f"  {label} {r['rule_id']}  {r['description']}{penalty}")
        for ev_line in r.get("evidence", []):
            lines.append(f"         Evidence: {ev_line}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _fmt_attack_context(report: dict) -> str:
    """
    Format mitre_attack and response_framework fields for the Gemini prompt.
    Renders verbatim from the rule JSON — no interpretation added here.
    """
    mitre = report.get("mitre_attack", {})
    fw    = report.get("response_framework", {})
    lines: list[str] = []

    for tech in mitre.get("primary", []):
        lines.append(
            f"  MITRE ATT&CK Primary:  "
            f"{tech['technique_id']} — {tech['technique_name']} ({tech['tactic']})"
        )
    for tech in mitre.get("related", []):
        lines.append(
            f"  MITRE ATT&CK Related:  "
            f"{tech['technique_id']} — {tech['technique_name']} ({tech['tactic']})"
        )
    if mitre.get("mapping_note"):
        lines.append(f"  ATT&CK Mapping Note:   {mitre['mapping_note']}")

    if fw.get("name"):
        lines.append(f"  Response Framework:    {fw['name']}")
    if fw.get("note"):
        lines.append(f"  Framework Note:        {fw['note']}")

    return "\n".join(lines) if lines else "  (no attack context available)"


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
    if not _GENAI_AVAILABLE:
        logger.warning("[report_generator] google-genai not installed — skipping Gemini")
        return None
    if not VERTEX_PROJECT_ID:
        logger.warning("[report_generator] VERTEX_PROJECT_ID not set — skipping Gemini")
        return None
    try:
        client = genai.Client(
            vertexai=True,
            project=VERTEX_PROJECT_ID,
            location=VERTEX_LOCATION,
        )
        response = client.models.generate_content(
            model=VERTEX_MODEL,
            contents=prompt,
        )
        return response.text
    except genai_errors.ClientError as exc:
        # New SDK has no per-status subclasses; all 4xx are ClientError — branch on exc.code
        if exc.code == 403:
            logger.error("[report_generator] Gemini permission denied (check ADC credentials): %s", exc)
        elif exc.code == 429:
            logger.error("[report_generator] Gemini quota/rate-limit exceeded: %s", exc)
        elif exc.code == 404:
            logger.error("[report_generator] Gemini model not found (%s): %s", VERTEX_MODEL, exc)
        else:
            logger.error("[report_generator] Gemini client error (HTTP %s): %s", exc.code, exc)
    except genai_errors.ServerError as exc:
        logger.error("[report_generator] Gemini service unavailable: %s", exc)
    except genai_errors.APIError as exc:
        logger.error("[report_generator] Gemini API error (%s): %s", type(exc).__name__, exc)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        # SDK source (_api_client.py line 544) names exactly these two types as the
        # network-level exceptions that escape APIError wrapping after retries are exhausted.
        # auth_exceptions.TransportError only appears in the async/aiohttp path — not here.
        logger.error("[report_generator] Gemini network error (%s): %s", type(exc).__name__, exc)
    return None


# ── Fallback plain formatter ──────────────────────────────────────────────────

def _plain_report(report: dict, events: list[Event]) -> str:
    outcome = report["outcome"]
    lines = [
        f"# Incident Report: {report['incident_id']}",
        f"**Scenario:** {report['scenario_id']}",
        f"**Status:** {report['status']}",
        f"**Outcome:** {outcome} — {_outcome_explanation(outcome)}",
        f"**Score:** {report.get('final_score', 'N/A')} / 100  "
        f"(**Verdict:** {report.get('verdict', 'N/A')})",
        f"**Penalty:** {report.get('penalty_total', 'N/A')} pts",
        "",
        "## Timing",
        f"- Time to Detect (TTD): {_fmt_td(report['ttd'])}",
        f"- Time to Contain (TTC): {_fmt_td(report['ttc'])}",
        "",
        "## Analyst Actions",
        _analyst_action_lines(events),
        "",
        "## Score Breakdown",
        _fmt_scoring_rules(report.get("scoring_rules", [])),
    ]
    return "\n".join(lines)


# ── Public entry point ────────────────────────────────────────────────────────

def generate(report: dict, events: list[Event]) -> str:
    """
    Produce a markdown incident report.
    Tries Gemini first; falls back to plain formatter if the call fails.
    """
    outcome        = report["outcome"]
    ttd            = report["ttd"]
    ttc            = report["ttc"]
    action_lines   = _analyst_action_lines(events)
    rule_block     = _fmt_scoring_rules(report.get("scoring_rules", []))
    attack_context = _fmt_attack_context(report)

    prompt = f"""You are a senior SOC analyst writing a formal incident response report in markdown.
Use the structured data below. Output ONLY the markdown — no commentary before or after.

---
Incident ID:   {report['incident_id']}
Scenario ID:   {report['scenario_id']}
Final Status:  {report['status']}
Outcome:       {outcome} — {_outcome_explanation(outcome)}

Time to Detect (TTD):  {_fmt_td(ttd)}
Time to Contain (TTC): {_fmt_td(ttc)}

Score:         {report['final_score']} / 100
Verdict:       {report['verdict']}
Penalty Total: {report['penalty_total']} pts

Attack Context (cite verbatim — do not elaborate beyond what is written here):
{attack_context}

Rule Breakdown (9 rules — [PASS] passed | [FAIL] triggered, penalty shown | [N/A ] not applicable):
{rule_block}

Analyst Actions (chronological):
{action_lines}
---

Write a markdown report with these exact sections:

1. `# Incident Report: {report['incident_id']}`

2. `## Summary` — 2-3 sentences: what attack type occurred, how the team responded, and what the final score ({report['final_score']}/100, verdict: {report['verdict']}) reflects about their performance.

3. `## Timeline` — bullet list of analyst actions in plain English (who did what, when).

4. `## Metrics` — markdown table with columns Metric / Value, rows: TTD, TTC, Outcome, Score, Verdict, Penalty.

5. `## Score Breakdown` — for each [FAIL] rule above: one bullet explaining in plain English what the rule required, what the evidence shows happened (or didn't happen), and how many points it cost. If there are no [FAIL] rules, write a single sentence confirming the response was clean. For [N/A ] rules, do not mention them here.

6. `## Attack Context` — one short paragraph citing the ATT&CK techniques and response framework VERBATIM from the Attack Context block above. Copy the technique IDs, names, and notes exactly as written. Do NOT add interpretation, external knowledge, or detail beyond what appears in ATT&CK Mapping Note and Framework Note above.

7. `## Assessment` — one paragraph that narrates and explains the computed result. Reference specific rule IDs (e.g. "R02 was triggered because...") to justify the score. Do NOT form an independent judgment of the response quality — your role is to translate the rule engine's output into plain English. A high score means explain why the rules passed; a low score means explain what the triggered rules reveal about the response gaps.
"""

    md = _call_gemini(prompt)
    if md:
        return md.strip()
    return _plain_report(report, events)
