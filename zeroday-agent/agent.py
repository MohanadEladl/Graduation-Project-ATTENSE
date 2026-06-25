"""
Zero-Day Detection Agent — with MITRE ATT&CK Integration
"""

import subprocess
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from io import StringIO
from dotenv import load_dotenv
from mitre_attack import get_technique_summary, match_techniques

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

load_dotenv()

_MARKDOWN_FENCE_RE = re.compile(r"```json|```")

# ─── Gemini Client (lazy singleton) ─────────────────────────────────────────

_client = None
_genai = None


def _get_client():
    global _client, _genai
    if _client is not None:
        return _client
    from google import genai
    _genai = genai
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if api_key:
        _client = genai.Client(api_key=api_key)
        return _client
    project_id = os.environ.get("VERTEX_PROJECT_ID", "")
    if project_id:
        location = os.environ.get("VERTEX_LOCATION", "us-central1")
        try:
            _client = genai.Client(vertexai=True, project=project_id, location=location)
            return _client
        except Exception:
            pass
    return None


# ─── ATTENSE Cyber Range containers (from docker-compose.yml v6) ─────────────

CONTAINERS = {
    "attense_target_agent":          "target-agent",
    "attense_wazuh_manager":         "wazuh-manager",
    "attense_signal_store":          "signal-store",
    "attense_app":                   "attense-app",
    "attense-attackbox":             "attackbox",
    "attense_red_team_backend":      "red-team-backend",
    "attense_red_team_frontend":     "red-team-frontend",
    "attense_zap":                   "zap",
    "attense_ollama":                "ollama",
    "attense_thehive":               "thehive",
    "attense_cortex":                "cortex",
    "attense_cassandra":             "cassandra",
    "attense_elasticsearch":         "elasticsearch",
    "attense_react":                 "attense-react",
    "attense_wazuh_agent_watchdog":  "wazuh-agent-watchdog",
}

BLUETEAM_URL = os.environ.get("BLUETEAM_URL", "http://localhost:8010")
GEMINI_MODEL = os.environ.get("VERTEX_MODEL", "gemini-2.5-flash")
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
    # Find each '{' and try parsing from there — avoids greedy over-matching
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
    print("\n📦 Collecting logs from ATTENSE containers...")
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
            icon = "✅" if not data["error"] else "⚠️"
            print(f"  {icon} {label}")

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


# ─── Blue Team API ───────────────────────────────────────────────────────────

def post_to_attense(analysis: dict) -> bool:
    mitre = analysis.get("closest_mitre_technique", {})
    classification = analysis.get("classification", "UNKNOWN")
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    payload = {
        "incident_id": f"zeroday-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "scenario_id": "ZERO-DAY-01",
        "siem_id": "zeroday-agent",
        "target_id": "target-agent",
        "target_type": "host",
        "rule_name": f"zero_day_{classification.lower()}",
        "severity": severity_map.get(analysis.get("severity", "HIGH"), "high"),
        "raw_log": "\n".join([
            f"[ZERO-DAY AGENT] Classification: {classification}",
            f"Closest MITRE: {mitre.get('id', '?')} - {mitre.get('name', '?')} (match: {mitre.get('match_level', '?')})",
            f"Attack Vector: {analysis.get('attack_vector', 'Unknown')}",
            f"Kill Chain Stage: {analysis.get('kill_chain_stage', 'Unknown')}",
            f"Reasoning: {analysis.get('reasoning', 'N/A')[:500]}",
        ]),
    }

    url = f"{BLUETEAM_URL}/blueteam/raise-alert"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        print(f"\n📡 Alert posted to ATTENSE Blue Team API: {url}")
        print(f"   Response: {json.dumps(result, indent=2)[:300]}")
        return True
    except urllib.error.URLError as e:
        print(f"\n⚠️  Could not reach ATTENSE Blue Team API at {url}")
        print(f"   Error: {e}")
        print("   (Is the ATTENSE platform running? docker-compose up -d)")
        return False
    except Exception as e:
        print(f"\n⚠️  Failed to post alert: {e}")
        return False


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


def _call_gemini_once(client, model: str, system_prompt: str, messages: list) -> str:
    response = client.models.generate_content(
        model=model,
        contents=messages,
        config=_genai.types.GenerateContentConfig(
            system_instruction=system_prompt,
            max_output_tokens=MAX_OUTPUT_TOKENS,
        ),
    )
    return response.text.strip()


def _call_gemini(client, model: str, system_prompt: str, messages: list) -> str:
    try:
        return _call_gemini_once(client, model, system_prompt, messages)
    except Exception as e:
        err = str(e)
        if "429" not in err and "RESOURCE_EXHAUSTED" not in err:
            raise
        print(f"  ⚠️  Rate limit hit. Waiting 55s before retry...")
        time.sleep(55)
        return _call_gemini_once(client, model, system_prompt, messages)


def _demo_offline_analysis() -> dict:
    return {
        "zero_day_detected": True,
        "confidence": "HIGH",
        "severity": "CRITICAL",
        "classification": "ZERO_DAY_VARIANT",
        "kill_chain_stage": "Initial Access",
        "closest_mitre_technique": {
            "id": "T1190", "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190",
            "match_level": "PARTIAL",
            "why_zero_day": "T1190 covers exploiting public-facing apps, but this attack uses a novel memory corruption path via negative Content-Length causing a SIGSEGV in libssl.so -- no CVE, no IDS signature, no matching ATT&CK sub-technique.",
        },
        "anomalies": [
            {"container": "target-agent", "observation": "Malformed HTTP request with Content-Length: -1 triggered SIGSEGV and leaked memory address, leading to root shell via unknown exploit path",
             "mitre_technique": "UNKNOWN", "mitre_tactic": "Initial Access", "is_known_technique": False,
             "zero_day_indicator": "Memory corruption via negative Content-Length is not a documented sub-technique of T1190", "timestamp": "14:23:55-14:23:57"},
            {"container": "attackbox", "observation": "custom_payload tool used with --mode corrupt; execution path flagged as UNKNOWN by the attack tool itself",
             "mitre_technique": "UNKNOWN", "mitre_tactic": "Execution", "is_known_technique": False,
             "zero_day_indicator": "Attack tool's own playbook does not recognize the execution path", "timestamp": "14:23:55-14:23:57"},
            {"container": "wazuh-manager", "observation": "Multiple UNMATCHED rules fired -- SIEM could not classify the initial access vector",
             "mitre_technique": "UNKNOWN", "mitre_tactic": "Defense Evasion", "is_known_technique": False,
             "zero_day_indicator": "Wazuh has no signature for this exploit method; Rule 0 fired twice", "timestamp": "14:23:57"},
        ],
        "attack_vector": "Novel HTTP memory corruption: Content-Length: -1 -> segfault in libssl.so.1.1 -> memory leak -> root shell.",
        "affected_containers": ["target-agent", "attackbox", "wazuh-manager", "signal-store", "attense-app"],
        "kill_chain_analysis": "1. RECON (T1595): nmap\n2. CRED (T1110): hydra FAILED\n3. RECON (T1595.002): nikto\n4. INITIAL ACCESS (ZERO-DAY): Content-Length: -1\n5. EXEC (ZERO-DAY): /bin/bash\n6. PERSIST (T1505.003+T1053.003)\n7. CRED (T1003.008): /etc/shadow\n8. C2 (T1059.004): reverse shell",
        "reasoning": "[OFFLINE ANALYSIS]\nNovel memory corruption path not matching any T1190 sub-technique.",
        "recommendation": "1. Isolate target-agent\n2. WAF rule for negative Content-Length\n3. Patch Apache + libssl.so\n4. Custom Wazuh rule for SIGSEGV",
    }


def analyze_with_gemini(all_logs: list[dict], mitre_matches: dict, demo: bool = False) -> dict:
    client = _get_client()
    if client is None:
        print("\n🤖 No valid credentials -- using offline rule-based analysis...")
        return _demo_offline_analysis() if demo else _empty_analysis(reasoning="No API credentials configured")

    print("\n🤖 Starting Gemini AI + MITRE ATT&CK analysis...")

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
        print(f"  🔄 Analysis turn {turn + 1}/{MAX_API_TURNS}...")
        try:
            text = _call_gemini(client, GEMINI_MODEL, system_prompt, messages)
        except Exception as e:
            print(f"  ⚠️  API error: {str(e)[:200]}")
            if demo:
                print(f"  Falling back to offline demo analysis...")
                return _demo_offline_analysis()
            print(f"  Returning empty analysis (no false alerts).")
            return _empty_analysis(reasoning=f"API error: {str(e)[:200]}")

        result = _parse_json_response(text)
        if result:
            print(f"  ✅ MITRE analysis complete")
            return result

        messages.append({"role": "model", "parts": [{"text": text}]})
        messages.append({"role": "user", "parts": [{"text": "Your response was not valid JSON. Respond ONLY with the JSON object, no markdown or extra text."}]})

    return _empty_analysis(reasoning=f"JSON parsing failed after {MAX_API_TURNS} attempts")


# ─── Report Generator ───────────────────────────────────────────────────────

_BADGE_MAP = {
    "TRUE_ZERO_DAY": "🔴 TRUE ZERO-DAY", "ZERO_DAY_VARIANT": "🟠 ZERO-DAY VARIANT",
    "KNOWN_ATTACK": "🟡 KNOWN ATTACK", "NORMAL": "🟢 NORMAL BEHAVIOR", "UNKNOWN": "⚪ UNKNOWN",
}


def generate_report(analysis: dict, all_logs: list[dict], mitre_matches: dict) -> str:
    now = datetime.now()
    report_id = now.strftime("%Y%m%d_%H%M%S")
    classification = analysis.get("classification", "UNKNOWN")
    mitre = analysis.get("closest_mitre_technique", {})
    buf = StringIO()
    w = buf.write

    w(f"# 🚨 Zero-Day Detection Report -- MITRE ATT&CK Mapped\n\n")
    w(f"**Report ID:** ZD-{report_id}\n")
    w(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
    w(f"**Classification:** {_BADGE_MAP.get(classification, '⚪ UNKNOWN')}\n")
    w(f"**Platform:** ATTENSE Cyber Range\n\n---\n\n")

    w("## Executive Summary\n\n| Field | Value |\n|-------|-------|\n")
    w(f"| Zero-Day Detected | ⚠️ YES |\n")
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
            tag = "⚠️ Known Technique" if known else "🚨 ZERO-DAY INDICATOR"
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
        status = "❌ Error" if log.get("error") else "✅ OK"
        lines = len(log.get("logs", "").splitlines())
        mc = len(mitre_matches.get(log["container"], []))
        w(f"| {log['container']} | {status} | {lines} | {f'{mc} technique(s)' if mc else '⚠️ None matched'} |\n")

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

    print(f"\n📄 Report saved: {report_path}")
    return report_path


# ─── Alert ───────────────────────────────────────────────────────────────────

def send_alert(analysis: dict):
    classification = analysis.get("classification", "UNKNOWN")
    mitre = analysis.get("closest_mitre_technique", {})

    if analysis.get("zero_day_detected"):
        print("\n" + "🚨" * 20)
        print(f"   ⚠️  {classification.replace('_', ' ')} DETECTED ⚠️")
        print("🚨" * 20)
        print(f"   Severity    : {analysis.get('severity', 'UNKNOWN')}")
        print(f"   Confidence  : {analysis.get('confidence', 'UNKNOWN')}")
        print(f"   Kill Chain  : {analysis.get('kill_chain_stage', 'UNKNOWN')}")
        print(f"   Closest ATT&CK: {mitre.get('id', '?')} -- {mitre.get('name', '?')}")
        print(f"   Match Level : {mitre.get('match_level', '?')} (deviation = zero-day)")
        print(f"   Containers  : {', '.join(analysis.get('affected_containers', []))}")
        print("🚨" * 20 + "\n")
    else:
        print(f"\n✅ Classification: {classification}")
        print(f"   Closest MITRE: {mitre.get('id', '?')} -- {mitre.get('name', '?')}")
        print("   No zero-day behavior detected.\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def run_agent():
    print("=" * 60)
    print("   🛡️  ZERO-DAY DETECTION AGENT + MITRE ATT&CK")
    print("   📡 Connected to ATTENSE Cyber Range")
    print("=" * 60)

    all_logs = collect_all_logs()

    print("\n🗺️  Running MITRE ATT&CK keyword pre-scan...")
    mitre_matches = pre_analyze_mitre(all_logs)
    total = sum(len(v) for v in mitre_matches.values())
    print(f"  Found {total} technique matches across containers")

    valid_logs = [l for l in all_logs if not l.get("error") and l.get("logs", "").strip()]
    if valid_logs:
        analysis = analyze_with_gemini(valid_logs, mitre_matches)
    else:
        print("⚠️  No logs collected -- check if ATTENSE containers are running")
        analysis = _empty_analysis(
            reasoning="No container logs could be collected.",
            recommendation="Ensure ATTENSE containers are running: docker-compose up -d",
        )

    send_alert(analysis)

    if analysis.get("zero_day_detected"):
        post_to_attense(analysis)
        report_path = generate_report(analysis, all_logs, mitre_matches)
        print(f"✅ Agent run complete. Report: {report_path}")
        return analysis, report_path

    print("✅ Agent run complete. No report generated (no zero-day detected).")
    return analysis, None


if __name__ == "__main__":
    run_agent()
