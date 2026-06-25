"""
Zero-Day Detection Agent — with MITRE ATT&CK Integration
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from io import StringIO

import httpx
from tenacity import (
    RetryError,
    retry,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from google import genai
    from google.genai import errors as genai_errors
    _GENAI_AVAILABLE = True
except ImportError:
    genai = None
    genai_errors = None
    _GENAI_AVAILABLE = False

from app.mitre_attack import get_technique_summary, match_techniques

logger = logging.getLogger("zeroday-agent")

_MARKDOWN_FENCE_RE = re.compile(r"```json|```")

# ─── Gemini Client (lazy singleton, aligned with project pattern) ────────────

_client = None

VERTEX_PROJECT_ID = os.environ.get("VERTEX_PROJECT_ID", "")
VERTEX_LOCATION = os.environ.get("VERTEX_LOCATION", "us-central1")
GEMINI_MODEL = os.environ.get("VERTEX_MODEL", "gemini-2.5-flash")


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not _GENAI_AVAILABLE:
        logger.warning("google-genai not installed — Gemini analysis unavailable")
        return None

    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if api_key:
        _client = genai.Client(api_key=api_key)
        return _client

    if VERTEX_PROJECT_ID:
        try:
            _client = genai.Client(
                vertexai=True,
                project=VERTEX_PROJECT_ID,
                location=VERTEX_LOCATION,
            )
            return _client
        except Exception as exc:
            logger.error("Failed to create Vertex AI client: %s", exc)
    return None


# ─── ATTENSE Cyber Range containers (verified against compose files) ─────────

CONTAINERS = {
    "attense_target_agent":         "target-agent",
    "attense_wazuh_manager":        "wazuh-manager",
    "attense_signal_store":         "signal-store",
    "attense_app":                  "attense-app",
    "attense-attackbox":            "attackbox",
    "attense_red_team_backend":     "red-team-backend",
    "attense_red_team_frontend":    "red-team-frontend",
    "attense_zap":                  "zap",
    "attense_ollama":               "ollama",
    "attense_thehive":              "thehive",
    "attense_cortex":               "cortex",
    "attense_cassandra":            "cassandra",
    "attense_elasticsearch":        "elasticsearch",
    "attense_react":                "attense-react",
    "attense_wazuh_agent_watchdog": "wazuh-agent-watchdog",
}

BLUETEAM_URL = os.environ.get("BLUETEAM_URL", "http://attense-app:8010")
ROOM_ID = os.environ.get("ROOM_ID", "default")
# Scoring pipeline (control-api event ingest) — same endpoint the red-team
# engine posts malicious_action_executed to (see red-team-api/core/event_sink.py).
ATTENSE_APP_URL = os.environ.get("ATTENSE_APP_URL", "http://attense-app:8020")
EVENTS_SECRET = os.environ.get("RED_TEAM_EVENTS_SECRET", "")
# Correlation (report Phase 4: one exercise = one incident). The shared exercise
# incident_id/scenario_id are provided via env, so a zero-day detection attaches
# to the SAME incident the exercise is scoring instead of minting its own ticket
# (mirrors signal-mapper/app/mapper.py:_resolve_incident_id).
INCIDENT_ID = os.environ.get("INCIDENT_ID", "")
SCENARIO_ID = os.environ.get("SCENARIO_ID", "ZERO-DAY-01")
LOG_TAIL_LINES = 150
LOG_MAX_CHARS = 3000
MAX_API_TURNS = 3
MAX_OUTPUT_TOKENS = 8192
PARALLEL_WORKERS = 8


# ─── Shared helpers ──────────────────────────────────────────────────────────

def _empty_analysis(**overrides) -> dict:
    base = {
        "zero_day_detected": False, "confidence": "LOW", "severity": "UNKNOWN",
        "classification": "UNKNOWN", "kill_chain_stage": "Unknown",
        "closest_mitre_technique": {
            "id": "UNKNOWN", "name": "Unknown", "tactic": "Unknown",
            "url": "", "match_level": "NONE", "why_zero_day": "N/A",
        },
        "anomalies": [], "attack_vector": "N/A", "affected_containers": [],
        "kill_chain_analysis": "N/A", "reasoning": "N/A", "recommendation": "N/A",
    }
    base.update(overrides)
    return base


def _truncate_at_line(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars]
    last_nl = cut.rfind("\n")
    return cut[:last_nl] if last_nl > 0 else cut


def _parse_json_response(text: str) -> dict | None:
    clean = _MARKDOWN_FENCE_RE.sub("", text).strip()
    for i, ch in enumerate(clean):
        if ch == "{":
            try:
                return json.loads(clean[i:])
            except json.JSONDecodeError:
                continue
    return None


# ─── Log Collection (parallel) ───────────────────────────────────────────────

def _collect_one(container: str, label: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(LOG_TAIL_LINES), container],
            capture_output=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        logs = result.stdout + result.stderr
        return {
            "container": label,
            "timestamp": datetime.now().isoformat(),
            "logs": logs if logs.strip() else "[No logs available]",
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"container": label, "timestamp": datetime.now().isoformat(),
                "logs": "", "error": "Timeout"}
    except Exception as e:
        return {"container": label, "timestamp": datetime.now().isoformat(),
                "logs": "", "error": str(e)}


def collect_all_logs() -> list[dict]:
    logger.info("Collecting logs from ATTENSE containers...")
    results = {}
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
        futures = {
            pool.submit(_collect_one, cid, label): (cid, label)
            for cid, label in CONTAINERS.items()
        }
        for future in as_completed(futures):
            cid, label = futures[future]
            data = future.result()
            results[cid] = data
            if data["error"]:
                logger.warning("  %s: %s", label, data["error"])
            else:
                logger.info("  %s: OK", label)

    return [results[cid] for cid in CONTAINERS if cid in results]


# ─── MITRE Pre-Analysis ─────────────────────────────────────────────────────

def pre_analyze_mitre(all_logs: list[dict]) -> dict:
    return {
        log["container"]: match_techniques(log["logs"])
        for log in all_logs
        if log.get("logs") and not log.get("error")
    }


def _format_mitre_context(mitre_matches: dict) -> str:
    parts = ["PRE-MATCHED MITRE ATT&CK TECHNIQUES (from keyword scan):"]
    for container, matches in mitre_matches.items():
        if matches:
            parts.append(f"\n  Container: {container}")
            for m in matches:
                parts.append(f"    -> {m['technique_id']} [{m['tactic']}] {m['technique_name']}")
                parts.append(f"       Matched keywords: {', '.join(m['matched_keywords'])}")
        else:
            parts.append(f"\n  Container: {container} -- No known technique keywords matched")
    return "\n".join(parts)


# ─── Alert dispatch — both planes, correlated + deduplicated ─────────────────
#
# A confirmed zero-day is sent to BOTH consumers:
#   1. the blue-team analyst dashboard  → POST :8010/blueteam/raise-alert
#      (RaiseAlertRequest + X-Room-Id; mirrors signal-mapper/app/output.py)
#   2. the control-api scoring pipeline → POST :8020/api/incidents/events
#      (canonical StandardEvent; mirrors red-team-api/core/event_sink.py)
#
# Both carry the SHARED exercise incident_id (INCIDENT_ID env) so the detection
# joins the one-exercise-one-incident timeline instead of minting its own ticket
# (report Phase 4). The watcher re-scans every cycle, so dispatch is deduplicated
# by a detection fingerprint — a persistent attack is reported once, not every
# interval. Transport uses tenacity retry, the same library signal-mapper and
# control-api use.

HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_MIN_WAIT = 2
HTTP_RETRY_MAX_WAIT = 10

_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

_http_client: httpx.Client | None = None
_last_posted_fingerprint: str | None = None


def _get_http_client() -> httpx.Client:
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(timeout=10.0)
    return _http_client


def _resolve_incident_id() -> str:
    """The shared exercise incident_id (INCIDENT_ID env), or a generated id in
    standalone mode. Mirrors signal-mapper/app/mapper.py:_resolve_incident_id —
    correlate to the exercise instead of splitting it into a separate incident."""
    return INCIDENT_ID or f"zeroday-{uuid.uuid4()}"


def _detection_fingerprint(analysis: dict) -> str:
    """Stable id for a *distinct* detection — drives both dedup and an
    idempotent StandardEvent event_id (so a replay is ignored by the store)."""
    mitre = analysis.get("closest_mitre_technique", {})
    basis = "|".join([
        analysis.get("classification", "UNKNOWN"),
        str(mitre.get("id", "?")),
        ",".join(sorted(analysis.get("affected_containers", []))),
    ])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


def _to_raise_alert_request(analysis: dict, incident_id: str) -> dict:
    """Reshape a zero-day analysis into the blue-team RaiseAlertRequest body."""
    mitre = analysis.get("closest_mitre_technique", {})
    classification = analysis.get("classification", "UNKNOWN")
    return {
        "incident_id": incident_id,
        "scenario_id": SCENARIO_ID,
        "siem_id": "zeroday-agent",
        "target_id": "target-agent",
        "target_type": "host",
        "rule_name": f"zero_day_{classification.lower()}",
        "severity": _SEVERITY_MAP.get(analysis.get("severity"), "high"),
        "raw_log": "\n".join([
            f"[ZERO-DAY AGENT] Classification: {classification}",
            f"Closest MITRE: {mitre.get('id', '?')} - {mitre.get('name', '?')} (match: {mitre.get('match_level', '?')})",
            f"Attack Vector: {analysis.get('attack_vector', 'Unknown')}",
            f"Kill Chain Stage: {analysis.get('kill_chain_stage', 'Unknown')}",
            f"Reasoning: {analysis.get('reasoning', 'N/A')[:500]}",
        ]),
    }


def _to_standard_event(analysis: dict, incident_id: str, fingerprint: str) -> dict:
    """Build the canonical StandardEvent the scoring pipeline ingests (report
    Phase 2). Mirrors red-team-api/core/event_sink.py — same contract, but a
    separate container so it can't import attense_core. Emitted as an
    `alert_raised` detection by the `system` actor; the fingerprint-derived
    event_id makes a replay idempotent in the durable store."""
    mitre = analysis.get("closest_mitre_technique", {})
    return {
        "schema_version": "1.0",
        "event_id": f"zeroday-{fingerprint}",
        "incident_id": incident_id,
        "source_event_id": fingerprint,
        "scenario_id": SCENARIO_ID,
        "actor_id": "zeroday-agent",
        "actor_type": "system",
        "target_id": "target-agent",
        "target_type": "host",
        "event_type": "alert_raised",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "outcome": "detected",
        "metadata": {
            "source_component": "zeroday-agent",
            "classification": analysis.get("classification", "UNKNOWN"),
            "severity": analysis.get("severity", "UNKNOWN"),
            "confidence": analysis.get("confidence", "UNKNOWN"),
            "kill_chain_stage": analysis.get("kill_chain_stage", "Unknown"),
            "closest_mitre_id": mitre.get("id", "?"),
            "closest_mitre_name": mitre.get("name", "?"),
            "match_level": mitre.get("match_level", "?"),
            "attack_vector": analysis.get("attack_vector", "Unknown"),
            "affected_containers": analysis.get("affected_containers", []),
        },
    }


@retry(
    wait=wait_exponential(min=HTTP_RETRY_MIN_WAIT, max=HTTP_RETRY_MAX_WAIT),
    stop=stop_after_attempt(HTTP_RETRY_ATTEMPTS),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def _post_json(url: str, payload: dict, headers: dict) -> httpx.Response:
    resp = _get_http_client().post(
        url,
        content=json.dumps(payload),
        headers={"Content-Type": "application/json", **headers},
    )
    resp.raise_for_status()
    return resp


def _send(label: str, url: str, payload: dict, headers: dict) -> bool:
    """POST one payload with retry; never raises (a dead consumer must not stop
    the other dispatch or the watcher loop)."""
    try:
        resp = _post_json(url, payload, headers)
        logger.info("%s posted: %s -> %s", label, url, resp.status_code)
        return True
    except httpx.HTTPStatusError as exc:
        logger.error("%s rejected: HTTP %s: %s", label, exc.response.status_code, exc)
        return False
    except (RetryError, httpx.HTTPError, Exception) as exc:
        logger.error("%s failed after %d attempts: %s", label, HTTP_RETRY_ATTEMPTS, exc)
        return False


def dispatch_alert(analysis: dict) -> dict:
    """Send a confirmed zero-day to both the analyst dashboard and the scoring
    pipeline, correlated to the shared exercise incident and deduplicated across
    watcher cycles. Returns a result dict (``skipped`` when already reported)."""
    global _last_posted_fingerprint
    fingerprint = _detection_fingerprint(analysis)
    if fingerprint == _last_posted_fingerprint:
        logger.info("Same zero-day as last report (fp=%s) — skipping duplicate dispatch", fingerprint)
        return {"skipped": True, "fingerprint": fingerprint}

    incident_id = _resolve_incident_id()
    dashboard_ok = _send(
        "Blue Team alert", f"{BLUETEAM_URL}/blueteam/raise-alert",
        _to_raise_alert_request(analysis, incident_id), {"X-Room-Id": ROOM_ID},
    )
    scoring_ok = _send(
        "Scoring event", f"{ATTENSE_APP_URL}/api/incidents/events",
        _to_standard_event(analysis, incident_id, fingerprint),
        {"Authorization": f"Bearer {EVENTS_SECRET}"},
    )
    # Only remember the detection once it has landed somewhere, so a transient
    # outage retries on the next cycle instead of being silently swallowed.
    if dashboard_ok or scoring_ok:
        _last_posted_fingerprint = fingerprint
    return {
        "skipped": False, "fingerprint": fingerprint, "incident_id": incident_id,
        "dashboard": dashboard_ok, "scoring": scoring_ok,
    }


# ─── Gemini AI Analysis ─────────────────────────────────────────────────────

_SYSTEM_PROMPT_TEMPLATE = """You are a senior cybersecurity analyst and MITRE ATT&CK expert.
You are analyzing logs from the ATTENSE Cyber Range -- a Red Team vs Blue Team simulation lab with these containers:
- target-agent: Purposefully vulnerable Flask web app (the victim)
- wazuh-manager: Wazuh SIEM manager (detects attacks)
- signal-store: Detection pipeline (anomaly detection + LLM triage)
- attense-app: Blue Team dashboard and case management
- attackbox: Lightweight pen-test tools container
- red-team-backend: FastAPI attack controller
- red-team-frontend: React UI for Red Team
- zap: OWASP ZAP proxy
- ollama: Local LLM inference
- thehive: Case management (TheHive)
- cortex: Active response engine
- cassandra/elasticsearch: Backend databases

YOUR MISSION: Detect ZERO-DAY attacks using the MITRE ATT&CK framework.

MITRE ATT&CK FRAMEWORK -- KNOWN TECHNIQUES:
{techniques}

HOW TO CLASSIFY BEHAVIOR:
1. KNOWN ATTACK: Behavior fully matches a MITRE technique -> NOT a zero-day
2. ZERO-DAY VARIANT: Behavior partially matches a technique but execution method is unknown/novel -> ZERO-DAY
3. TRUE ZERO-DAY: Behavior matches NO technique at all -> ZERO-DAY (most severe)

KEY ZERO-DAY INDICATORS:
- Exploit technique not listed in any ATT&CK sub-technique
- Unknown/novel payload delivery method
- Unexpected system behavior with no matching CVE pattern
- Memory corruption or crash that leads to access via unknown path
- Attack achieves goal through completely undocumented method
- Cross-container behavior that doesn't follow any known kill chain

CRITICAL -- DO NOT FLAG THESE AS ZERO-DAY:
- Service health issues (Connection refused, service not running, DNS failures)
- Container restart/watchdog repair cycles
- Missing Elasticsearch indices or database errors
- Authentication failures from misconfiguration (not brute force)
- Application build errors (e.g. missing files, pre-transform errors)
- Normal tool initialization (e.g. ZAP loading extensions)
- Agent enrollment conflicts (duplicate name, stale agents)
These are OPERATIONAL ISSUES, not attacks. Classify them as NORMAL.
Only flag as zero-day when there is clear evidence of malicious exploitation.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{{
  "zero_day_detected": true/false,
  "confidence": "HIGH/MEDIUM/LOW",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "classification": "TRUE_ZERO_DAY / ZERO_DAY_VARIANT / KNOWN_ATTACK / NORMAL",
  "kill_chain_stage": "Reconnaissance/Initial Access/Execution/Persistence/Privilege Escalation/Defense Evasion/Credential Access/Discovery/Lateral Movement/Collection/Command and Control/Exfiltration/Impact",
  "closest_mitre_technique": {{
    "id": "T1XXX", "name": "Technique Name", "tactic": "Tactic Name",
    "url": "https://attack.mitre.org/techniques/TXXX",
    "match_level": "FULL/PARTIAL/NONE",
    "why_zero_day": "What makes this different from the known technique"
  }},
  "anomalies": [{{
    "container": "container_name", "observation": "what was observed",
    "mitre_technique": "T1XXX or UNKNOWN", "mitre_tactic": "tactic name",
    "is_known_technique": true/false, "zero_day_indicator": "why this is novel/unknown",
    "timestamp": "when"
  }}],
  "attack_vector": "description of the full attack vector",
  "affected_containers": ["list"],
  "kill_chain_analysis": "step by step breakdown using MITRE ATT&CK stages",
  "reasoning": "your step-by-step reasoning for the zero-day conclusion",
  "recommendation": "what the blue team should do immediately"
}}"""


def _build_logs_text(all_logs: list[dict]) -> str:
    parts = []
    for log in all_logs:
        parts.append(f"\n{'=' * 60}")
        parts.append(f"CONTAINER: {log['container']}")
        parts.append(f"TIMESTAMP: {log['timestamp']}")
        if log.get("error"):
            parts.append(f"ERROR: {log['error']}")
        else:
            parts.append(f"LOGS:\n{_truncate_at_line(log['logs'], LOG_MAX_CHARS)}")
    return "\n".join(parts)


def _call_gemini(client, model: str, system_prompt: str, messages: list) -> str | None:
    try:
        response = client.models.generate_content(
            model=model,
            contents=messages,
            config=genai.types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=MAX_OUTPUT_TOKENS,
            ),
        )
        return response.text.strip()
    except genai_errors.ClientError as exc:
        if exc.code == 429:
            logger.warning("Gemini rate limit hit — waiting 55s before retry...")
            time.sleep(55)
            response = client.models.generate_content(
                model=model,
                contents=messages,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                ),
            )
            return response.text.strip()
        logger.error("Gemini client error (HTTP %s): %s", exc.code, exc)
    except genai_errors.ServerError as exc:
        logger.error("Gemini service unavailable: %s", exc)
    except genai_errors.APIError as exc:
        logger.error("Gemini API error (%s): %s", type(exc).__name__, exc)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.error("Gemini network error (%s): %s", type(exc).__name__, exc)
    return None


def analyze_with_gemini(all_logs: list[dict], mitre_matches: dict) -> dict:
    client = _get_client()
    if client is None:
        logger.warning("No valid Gemini credentials — returning empty analysis")
        return _empty_analysis(reasoning="No API credentials configured")

    logger.info("Starting Gemini AI + MITRE ATT&CK analysis...")

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(techniques=get_technique_summary())
    logs_text = _build_logs_text(all_logs)
    mitre_context = _format_mitre_context(mitre_matches)

    user_prompt = f"""Analyze these container logs for zero-day attacks using MITRE ATT&CK.

{mitre_context}

CONTAINER LOGS:
{logs_text}

Think step by step:
1. What MITRE techniques are clearly visible?
2. Is there ANY behavior that does NOT fit a known technique?
3. Does the attack achieve its goal through an unknown/novel method?
4. What is the closest MITRE technique, and HOW does this deviate from it?
5. Final verdict: known attack, zero-day variant, or true zero-day?

Respond ONLY with the JSON object."""

    messages = [{"role": "user", "parts": [{"text": user_prompt}]}]

    for turn in range(MAX_API_TURNS):
        logger.info("  Analysis turn %d/%d...", turn + 1, MAX_API_TURNS)
        text = _call_gemini(client, GEMINI_MODEL, system_prompt, messages)

        if text is None:
            logger.warning("Gemini returned no response — returning empty analysis")
            return _empty_analysis(reasoning="Gemini API call failed")

        result = _parse_json_response(text)
        if result:
            logger.info("  MITRE analysis complete")
            return result

        messages.append({"role": "model", "parts": [{"text": text}]})
        messages.append({"role": "user", "parts": [{"text": "Your response was not valid JSON. Respond ONLY with the JSON object, no markdown or extra text."}]})

    return _empty_analysis(reasoning=f"JSON parsing failed after {MAX_API_TURNS} attempts")


# ─── Report Generator ───────────────────────────────────────────────────────

_BADGE_MAP = {
    "TRUE_ZERO_DAY": "TRUE ZERO-DAY", "ZERO_DAY_VARIANT": "ZERO-DAY VARIANT",
    "KNOWN_ATTACK": "KNOWN ATTACK", "NORMAL": "NORMAL BEHAVIOR", "UNKNOWN": "UNKNOWN",
}


def generate_report(analysis: dict, all_logs: list[dict], mitre_matches: dict) -> str:
    now = datetime.now()
    report_id = now.strftime("%Y%m%d_%H%M%S")
    classification = analysis.get("classification", "UNKNOWN")
    mitre = analysis.get("closest_mitre_technique", {})
    buf = StringIO()
    w = buf.write

    w("# Zero-Day Detection Report -- MITRE ATT&CK Mapped\n\n")
    w(f"**Report ID:** ZD-{report_id}\n")
    w(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
    w(f"**Classification:** {_BADGE_MAP.get(classification, 'UNKNOWN')}\n")
    w("**Platform:** ATTENSE Cyber Range\n\n---\n\n")

    w("## Executive Summary\n\n| Field | Value |\n|-------|-------|\n")
    w(f"| Zero-Day Detected | {'YES' if analysis.get('zero_day_detected') else 'NO'} |\n")
    w(f"| Classification | {classification} |\n")
    w(f"| Confidence | {analysis.get('confidence', 'N/A')} |\n")
    w(f"| Severity | {analysis.get('severity', 'N/A')} |\n")
    w(f"| Kill Chain Stage | {analysis.get('kill_chain_stage', 'N/A')} |\n")
    w(f"| Attack Vector | {analysis.get('attack_vector', 'N/A')} |\n")
    w(f"| Affected Containers | {', '.join(analysis.get('affected_containers', [])) or 'None'} |\n\n---\n\n")

    w("## MITRE ATT&CK Mapping\n\n| Field | Value |\n|-------|-------|\n")
    w(f"| Closest Technique | [{mitre.get('id', 'N/A')}] {mitre.get('name', 'N/A')} |\n")
    w(f"| Tactic | {mitre.get('tactic', 'N/A')} |\n")
    w(f"| Match Level | {mitre.get('match_level', 'N/A')} |\n")
    w(f"| Reference | {mitre.get('url', 'N/A')} |\n\n")
    w(f"**Why this is a Zero-Day (deviation from known technique):**\n{mitre.get('why_zero_day', 'N/A')}\n\n---\n\n")

    w(f"## Kill Chain Analysis (MITRE ATT&CK Stages)\n\n{analysis.get('kill_chain_analysis', 'No kill chain analysis available.')}\n\n---\n\n")

    w("## Pre-Matched Techniques (Keyword Scan)\n\n")
    for container, matches in mitre_matches.items():
        w(f"### {container}\n")
        if matches:
            for m in matches:
                w(f"- **{m['technique_id']}** [{m['tactic']}] {m['technique_name']}\n")
                w(f"  - Keywords: `{', '.join(m['matched_keywords'])}`\n")
                w(f"  - {m['url']}\n")
        else:
            w("_No known MITRE technique keywords matched -- suspicious!_\n\n")

    w("\n---\n\n## Detected Anomalies\n\n")
    anomalies = analysis.get("anomalies", [])
    if anomalies:
        for i, a in enumerate(anomalies, 1):
            known = a.get("is_known_technique", True)
            tag = "Known Technique" if known else "ZERO-DAY INDICATOR"
            w(f"### Anomaly {i} -- {a.get('container', 'Unknown')} {tag}\n\n")
            w("| Field | Value |\n|-------|-------|\n")
            w(f"| Observation | {a.get('observation', 'N/A')} |\n")
            w(f"| MITRE Technique | {a.get('mitre_technique', 'UNKNOWN')} |\n")
            w(f"| MITRE Tactic | {a.get('mitre_tactic', 'N/A')} |\n")
            w(f"| Known Technique | {'Yes' if known else '**No -- Zero-Day Indicator**'} |\n")
            w(f"| Zero-Day Indicator | {a.get('zero_day_indicator', 'N/A')} |\n")
            w(f"| Timestamp | {a.get('timestamp', 'N/A')} |\n\n")
    else:
        w("_No anomalies detected._\n\n")

    w(f"---\n\n## AI Reasoning\n\n{analysis.get('reasoning', 'No reasoning provided.')}\n\n")
    w(f"---\n\n## Blue Team Recommendation\n\n{analysis.get('recommendation', 'No recommendation provided.')}\n\n")

    w("---\n\n## Container Log Summary\n\n| Container | Status | Log Lines | MITRE Matches |\n|-----------|--------|-----------|---------------|\n")
    for log in all_logs:
        status = "Error" if log.get("error") else "OK"
        lines = len(log.get("logs", "").splitlines())
        mc = len(mitre_matches.get(log["container"], []))
        w(f"| {log['container']} | {status} | {lines} | {f'{mc} technique(s)' if mc else 'None matched'} |\n")

    w("\n---\n\n## MITRE ATT&CK References\n\n")
    w("- Framework Overview: https://attack.mitre.org\n")
    w("- Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/\n")
    w("- Linux Techniques: https://attack.mitre.org/matrices/enterprise/linux/\n\n")
    w("---\n\n*Report generated by Zero-Day Detection Agent | ATTENSE Cyber Range | MITRE ATT&CK v14 | Powered by Gemini AI*\n")

    report = buf.getvalue()
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, f"report_{report_id}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    logger.info("Report saved: %s", report_path)
    return report_path


# ─── Alert ───────────────────────────────────────────────────────────────────

def send_alert(analysis: dict):
    classification = analysis.get("classification", "UNKNOWN")
    mitre = analysis.get("closest_mitre_technique", {})

    if analysis.get("zero_day_detected"):
        logger.critical(
            "%s DETECTED | Severity: %s | Confidence: %s | "
            "Kill Chain: %s | Closest ATT&CK: %s -- %s | "
            "Match Level: %s | Containers: %s",
            classification.replace("_", " "),
            analysis.get("severity", "UNKNOWN"),
            analysis.get("confidence", "UNKNOWN"),
            analysis.get("kill_chain_stage", "UNKNOWN"),
            mitre.get("id", "?"), mitre.get("name", "?"),
            mitre.get("match_level", "?"),
            ", ".join(analysis.get("affected_containers", [])),
        )
    else:
        logger.info(
            "Classification: %s | Closest MITRE: %s -- %s | No zero-day behavior detected.",
            classification, mitre.get("id", "?"), mitre.get("name", "?"),
        )


# ─── Main ────────────────────────────────────────────────────────────────────

def run_agent():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("=" * 60)
    logger.info("  ZERO-DAY DETECTION AGENT + MITRE ATT&CK")
    logger.info("  Connected to ATTENSE Cyber Range")
    logger.info("=" * 60)

    all_logs = collect_all_logs()

    logger.info("Running MITRE ATT&CK keyword pre-scan...")
    mitre_matches = pre_analyze_mitre(all_logs)
    total = sum(len(v) for v in mitre_matches.values())
    logger.info("  Found %d technique matches across containers", total)

    valid_logs = [log for log in all_logs if not log.get("error") and log.get("logs", "").strip()]
    if valid_logs:
        analysis = analyze_with_gemini(valid_logs, mitre_matches)
    else:
        logger.warning("No logs collected -- check if ATTENSE containers are running")
        analysis = _empty_analysis(
            reasoning="No container logs could be collected.",
            recommendation="Ensure ATTENSE containers are running: docker-compose up -d",
        )

    send_alert(analysis)

    if analysis.get("zero_day_detected"):
        result = dispatch_alert(analysis)
        if result.get("skipped"):
            logger.info("Agent run complete. Zero-day already reported (no new alert/report).")
            return analysis, None
        report_path = generate_report(analysis, all_logs, mitre_matches)
        logger.info("Agent run complete. Report: %s", report_path)
        return analysis, report_path

    logger.info("Agent run complete. No report generated (no zero-day detected).")
    return analysis, None


if __name__ == "__main__":
    run_agent()
