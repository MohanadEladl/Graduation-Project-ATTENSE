"""
backend/report_agent.py — AI-augmented mission report generator.

The agent receives:
  • The learner's timeline (browser actions + terminal commands + lab events)
  • The variant they picked + its ideal_commands
  • Their progress result from lab_progress.compute()

It returns a structured coaching report:
  {
    grade, score, success, duration_seconds,
    summary,
    what_you_did_right: [{title, detail}],
    what_you_missed:    [{title, detail, how_to_fix}],
    ideal_approach:     [{step, title, command, why}],
    vulnerability_explained: {...},
    defensive_controls: [...],
    evidence_timeline:  [...],
    task_results:       [...],
    mitre_tactics:      ["TA0001 Initial Access", ...],
    mitre_techniques:   [{id, name, tactic, exercised, note}, ...],
    mitre_analysis:     "MITRE-grounded threat narrative from Ollama (or fallback)",
    ai_coaching:        same string as mitre_analysis (kept for back-compat),
    ai_model:           "ollama/<model>" | "rule-based-fallback",
  }

The MITRE analysis is grounded: the real ATT&CK technique IDs each attack
module declares (module.mitre) are fed to the model, and a deterministic
technique-mapping is computed from the operator's evidence so the structured
ATT&CK table still renders even when the model is unreachable.

Priority chain:
  1. attense-analyst Ollama model (MITRE-specialised — see
     red-team/ollama/Modelfile.attense-analyst; falls back to llama3.2:3b if
     the derived model hasn't been built)
  2. Rules-based fallback (if no Ollama container is reachable)
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

# ── Vulnerability metadata per module (used by both AI + fallback path) ─────
VULN_INFO: Dict[str, Dict[str, Any]] = {
    "recon": {
        "name":              "Information Disclosure / Attack-Surface Exposure",
        "cvss_category":     "MEDIUM",
        "what_it_is":        "Public-facing pages leak internal route names, software versions, and developer comments that help an attacker plan deeper attacks.",
        "why_it_matters":    "Recon is the foundation of every breach. Hidden routes, commented-out dev paths, and verbose server banners shorten the time-to-exploit by hours.",
        "real_world_example":"The 2017 Equifax breach was preceded by Apache-Struts version disclosure on a forgotten endpoint.",
        "defenses": [
            {"control": "Strip developer comments at build", "implementation": "Use a minifier that removes <!-- … --> in production HTML."},
            {"control": "Remove server-version banners",    "implementation": "Set `ServerTokens Prod` (Apache) or `server_tokens off` (nginx)."},
            {"control": "Block directory enumeration",       "implementation": "Add a per-IP rate limit (10 req/s) on 404 paths."},
        ],
    },
    "brute_force": {
        "name":              "Authentication — No Rate Limit / No Lockout",
        "cvss_category":     "HIGH",
        "what_it_is":        "The login endpoint accepts unlimited password attempts without throttling or account lockout, and leaks whether a username exists.",
        "why_it_matters":    "Attackers can spray common passwords across many accounts or hammer one account with a leaked password list — a billion logins cost ~$5 in cloud compute today.",
        "real_world_example":"In 2019 a credential-stuffing attack on Dunkin' Donuts compromised tens of thousands of accounts that reused leaked passwords.",
        "defenses": [
            {"control": "Per-account rate limit",  "implementation": "Use Redis to track failed-attempt counts per username — lock for 15 min after 5 failures."},
            {"control": "Per-IP rate limit",       "implementation": "Add a sliding-window limiter (10 req/min) on /auth/login."},
            {"control": "Identical error messages","implementation": "Always return `Invalid credentials` — never reveal whether the username exists."},
            {"control": "MFA",                     "implementation": "Require a second factor (TOTP, WebAuthn) for any admin account."},
        ],
    },
    "xss": {
        "name":              "Reflected Cross-Site Scripting (XSS)",
        "cvss_category":     "HIGH",
        "what_it_is":        "User input is rendered into the HTML response without escaping. An attacker can inject `<script>` or event-handler payloads that run in another user's browser.",
        "why_it_matters":    "XSS leads to session theft, credential phishing, and full account takeover. It bypasses HTTPS — the browser executes the script with the victim's full privileges.",
        "real_world_example":"In 2018 British Airways suffered an XSS-based card-skimmer (Magecart) that stole 380,000 customers' payment data.",
        "defenses": [
            {"control": "Context-aware output encoding", "implementation": "Use a templating engine with autoescape ON. Never use |safe / `dangerouslySetInnerHTML` for user input."},
            {"control": "Content Security Policy",       "implementation": "Set CSP `script-src 'self'; object-src 'none'; base-uri 'self'` and never `'unsafe-inline'`."},
            {"control": "HttpOnly + Secure cookies",     "implementation": "Mark session cookies HttpOnly so XSS can't read them; Secure so they only travel over HTTPS."},
        ],
    },
    "cmd_injection": {
        "name":              "OS Command Injection",
        "cvss_category":     "CRITICAL",
        "what_it_is":        "User input is concatenated into a shell command. Shell metacharacters (`;`, `|`, `$()`, backticks) inject and run arbitrary commands on the server.",
        "why_it_matters":    "Command injection means full remote code execution — the attacker runs as the app's UID and can read secrets, pivot to other hosts, and install backdoors.",
        "real_world_example":"In 2019 a single command-injection bug in a Citrix appliance (CVE-2019-19781) led to network breaches at the U.S. Census Bureau and multiple Fortune 500 companies.",
        "defenses": [
            {"control": "Use parameterized APIs",       "implementation": "Replace shell calls with `subprocess.run(['/bin/ping', '-c', '2', host], shell=False)` — the array form, not a string."},
            {"control": "Strict input validation",      "implementation": "Allow only `[a-zA-Z0-9.-]` for hostnames; reject everything else."},
            {"control": "Run with minimum privileges",  "implementation": "App should run as a non-root user with no shell, in a read-only filesystem with no /etc/passwd to leak."},
        ],
    },
    "dir_traversal": {
        "name":              "Path Traversal",
        "cvss_category":     "HIGH",
        "what_it_is":        "A `path` parameter is concatenated to a base directory without normalization. `../` sequences escape the intended directory and disclose arbitrary files.",
        "why_it_matters":    "Path traversal leaks /etc/passwd, SSH keys, .env files, application source code, and database credentials. It's often the first step before full RCE.",
        "real_world_example":"In 2021 a Microsoft Exchange traversal bug (CVE-2021-26858) was used in the HAFNIUM attacks against 250,000+ servers worldwide.",
        "defenses": [
            {"control": "Canonicalize paths",          "implementation": "Resolve `os.path.realpath(base + path)` and verify it `startswith(base)` before opening the file."},
            {"control": "Allowlist filenames",         "implementation": "Maintain a list of allowed document IDs; never accept a free-form path from the client."},
            {"control": "Serve files via signed URLs", "implementation": "Generate time-limited S3-style URLs so the app never reads the filesystem from a user-supplied path."},
        ],
    },
    "file_upload": {
        "name":              "Unrestricted Dangerous File Upload",
        "cvss_category":     "HIGH",
        "what_it_is":        "The upload endpoint accepts any filename and any content. Dangerous extensions (.php, .jsp, .sh) are stored unchanged.",
        "why_it_matters":    "If the storage directory is served by the application server, an uploaded file becomes executable — instant RCE. Even when files are static, they can host phishing pages, malware, or stored XSS.",
        "real_world_example":"The 2019 Magento commerce breach used an unrestricted upload bug to plant card-skimming JavaScript across thousands of merchant sites.",
        "defenses": [
            {"control": "Validate content, not filename","implementation": "Use libmagic / mimetypes to verify the real file type — reject anything outside an explicit allowlist (jpg, png, pdf)."},
            {"control": "Rename uploads on save",        "implementation": "Use a UUID + the validated extension. Never trust the user-supplied filename."},
            {"control": "Serve uploads from a separate domain","implementation": "Put `static-uploads.example.com` on a domain WITHOUT any script-execution handlers."},
        ],
    },
    "csrf": {
        "name":              "Cross-Site Request Forgery",
        "cvss_category":     "MEDIUM",
        "what_it_is":        "State-changing endpoints accept POSTs without verifying the request's origin. An attacker can trick a logged-in victim into submitting a malicious form from a third-party site.",
        "why_it_matters":    "CSRF lets the attacker perform any action as the victim — change email, transfer funds, escalate privileges — without ever stealing credentials.",
        "real_world_example":"In 2008 a CSRF flaw in YouTube allowed attackers to add videos to anyone's favorites and subscribe them to channels.",
        "defenses": [
            {"control": "CSRF tokens on every state-changing form","implementation": "Hidden token signed with the session; server rejects POSTs missing/wrong token."},
            {"control": "SameSite=Strict cookies",                 "implementation": "Cookies marked SameSite=Strict are not sent on cross-site requests at all."},
            {"control": "Origin/Referer header check",             "implementation": "On every POST, verify `Origin == https://yourapp` before accepting."},
        ],
    },
}


def _gather_evidence_text(progress: dict, timeline: list) -> str:
    """Build a compact textual summary the LLM can read."""
    lines: List[str] = []
    if progress.get("variant_name"):
        lines.append(f"Variant chosen: {progress['variant_name']}")
    lines.append(f"Progress: {progress.get('progress_percent', 0)}% — "
                 f"success={progress.get('success', False)}")
    lines.append(f"Tasks ({len(progress.get('tasks', []))}):")
    for i, t in enumerate(progress.get("tasks", [])):
        mark = "✓" if t.get("complete") else "✗"
        lines.append(f"  {mark} {i+1}. {t['title']}  ({t.get('match_count',0)}/{t.get('min_count',1)})")
    lines.append("Timeline (first 40 events):")
    for x in timeline[:40]:
        ts = x.get("ts", 0.0)
        lines.append(f"  [{x.get('channel','?'):<8}] {x.get('kind','?'):<22} — {(x.get('summary') or '')[:120]}")
    if len(timeline) > 40:
        lines.append(f"  … (+{len(timeline)-40} more)")
    return "\n".join(lines)


def _attack_evidence_lines(session) -> List[str]:
    """Pull the concrete attack-outcome lines from the session log — the ACTUAL
    payloads/commands the operator fired and their per-step result markers
    (REFLECTED / EXECUTED / DISCLOSED / ACCEPTED / CREDENTIAL FOUND / ...).

    The lab evidence timeline only carries vague descriptions ("a script-like
    payload was submitted"); the real specifics that let the model cite
    evidence verbatim live in the execution log. This is the grounding the
    'be specific to their evidence' instruction depends on.
    """
    try:
        with session.log_lock:
            raw = [str(e.get("line", "")) for e in session.logs]
    except Exception:
        raw = []

    import re as _re
    markers = (
        "REFLECTED", "EXECUTED", "DISCLOSED", "ACCEPTED", "STATE CHANGED",
        "CREDENTIAL FOUND", "Summary:",
    )
    out: List[str] = []
    seen: set = set()
    for ln in raw:
        s = ln.strip()
        if not s:
            continue
        marker = next((m for m in markers if m in s), None)
        if not marker:
            continue
        # Keep the payload/command (text after a '|', '→' or '->' separator) and
        # the marker; drop timestamps, step counters, leading tick glyphs and
        # internal "[variant-label]" tokens so the model never quotes engine
        # internals.
        parts = _re.split(r"\s*(?:\||→|->)\s*", s, maxsplit=1)
        payload = parts[1].strip() if len(parts) > 1 else _re.sub(r"\[[^\]]*\]", "", s).strip()
        payload = _re.sub(r"^[✓✗\-–—\s]+", "", payload)
        clean = f"{marker}: {payload}" if marker != "Summary:" else payload
        clean = _re.sub(r"\s{2,}", " ", clean).strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
        if len(out) >= 12:
            break
    return out


def _mitre_from_module(session) -> Dict[str, Any]:
    """Pull the module's declared MITRE ATT&CK metadata (tactics + techniques).

    Every attack module declares a class-level `mitre = {tactics, techniques}`.
    This is the ground truth we feed the model so it never invents technique IDs.
    """
    module = getattr(session, "module", None)
    mitre  = getattr(module, "mitre", None) or {}
    tactics = [str(t) for t in (mitre.get("tactics") or [])]
    techniques: List[Dict[str, str]] = []
    for t in (mitre.get("techniques") or []):
        techniques.append({
            "id":     t.get("id", ""),
            "name":   t.get("name", ""),
            "tactic": t.get("tactic", ""),
        })
    return {"tactics": tactics, "techniques": techniques}


def _mitre_technique_mapping(mitre: dict, progress: dict, task_results: list) -> List[Dict[str, Any]]:
    """Mark which ATT&CK techniques the operator actually exercised.

    Evidence-grounded heuristic (the technique chain is authored in execution
    order, kill-chain first):
      • success  → the whole chain was exercised.
      • partial  → credit the first N techniques, N scaled by completed-task ratio.
      • none     → nothing exercised.
    Deterministic, so this table renders even when the model is unreachable.
    """
    techniques = mitre.get("techniques", [])
    if not techniques:
        return []
    n      = len(techniques)
    done   = sum(1 for t in task_results if t.get("completed"))
    total  = len(task_results) or 1
    if progress.get("success"):
        credited = n
    else:
        credited = round((done / total) * n)
    rows: List[Dict[str, Any]] = []
    for i, t in enumerate(techniques):
        exercised = i < credited
        rows.append({
            **t,
            "exercised": exercised,
            "note": ("Exercised — your evidence demonstrates this technique."
                     if exercised else
                     "Not reached — part of the chain you didn't complete."),
        })
    return rows


def _sanitize_narrative(text: str) -> str:
    """Deterministic clean-up of the model's prose. The local 3B model owns the
    substance; this guarantees the formatting it can't reliably self-enforce:
    no leaked engine tokens or echoed prompt labels, cited payloads kept inline
    (not split into their own paragraph), and at most three paragraphs.
    """
    import re
    if not text:
        return text
    t = text.strip()

    # 1. Drop meta-labels the model sometimes echoes back from the prompt.
    t = re.sub(
        r"(?i)\b(approved defensive controls?|operator (?:task-?ladder )?evidence|"
        r"concrete attack evidence|task-?ladder)\b\s*:?", "", t)
    # 2. Remove leaked internal event identifiers and bracketed engine tokens.
    t = re.sub(r"\[(?:e|evidence)\]", "", t)
    t = re.sub(r"\[[A-Za-z0-9 _\-/]+\]", "", t)          # [relative-basic], [1/5]
    t = re.sub(r"`?\b[a-z]+(?:_[a-z]+)+\b`?", "", t)     # csrf_lure_submitted, file_viewer_used
    # 3. Strip inline outcome-marker labels the model copies from the evidence
    #    block (e.g. "REFLECTED: <script>" -> "<script>").
    t = re.sub(r"(?i)\b(reflected|executed|disclosed|accepted|state changed|"
               r"credential found)\s*:\s*", "", t)
    # 4. Tidy punctuation/whitespace left behind by the removals.
    t = re.sub(r"`\s*`", "", t)                           # empty code spans
    t = re.sub(r"\(\s+", "(", t)
    t = re.sub(r"\s+\)", ")", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\s+([,.;:])", r"\1", t)

    # 4. Re-flow paragraphs: merge short fragments (e.g. a payload left on its
    #    own line) into the previous paragraph, then hard-cap at three.
    paras = [re.sub(r"\s*\n\s*", " ", p).strip()
             for p in re.split(r"\n\s*\n", t) if p.strip()]
    merged: List[str] = []
    for p in paras:
        if merged and len(p.split()) < 8:
            merged[-1] = (merged[-1] + " " + p).strip()
        else:
            merged.append(p)
    if len(merged) > 3:
        merged = merged[:2] + [" ".join(merged[2:])]
    merged = [re.sub(r"\s{2,}", " ", p).strip(" -–—:") for p in merged if p.strip()]
    return "\n\n".join(merged).strip()


def _ai_mitre_analysis(progress: dict, timeline: list, vuln: dict,
                       mitre: dict, grade: str, score: int,
                       session=None) -> Dict[str, Any]:
    """MITRE-grounded threat-analysis narrative from the local analyst model.

    ON by default (set REPORT_AI_COACH=0 to disable). The caller caches the
    finished report on the session, so this cold-model latency is paid ONCE per
    session — not on every report view. Grounds the model on the module's real
    ATT&CK technique IDs; falls back to the base model, then to rule-based prose.
    """
    if os.getenv("REPORT_AI_COACH", "1") != "1":
        return {"analysis": None, "model": "rule-based-fallback"}

    import json as _json
    import urllib.request as _ur
    import urllib.error as _ue

    ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
    primary    = os.getenv("OLLAMA_MODEL", "attense-analyst")
    fallback   = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.2:3b")
    # CPU inference is slow: a cold 3B load + ~400-token generation runs ~30-50s.
    # The report is cached after first generation and the UI shows a spinner, so a
    # generous one-time budget is the right trade for a real MITRE narrative.
    timeout    = int(os.getenv("REPORT_AI_TIMEOUT", "90"))

    evidence_text = _gather_evidence_text(progress, timeline)
    tactics_line  = ", ".join(mitre.get("tactics", [])) or "—"
    tech_lines    = "; ".join(
        f"{t['id']} {t['name']} ({t['tactic']})" for t in mitre.get("techniques", [])
    ) or "—"

    # Concrete payloads/commands the operator actually fired — the specifics the
    # model must cite. Without this the narrative can only paraphrase technique names.
    attack_lines = _attack_evidence_lines(session) if session is not None else []
    attack_block = (
        "Concrete attack evidence — the exact payloads/commands the operator "
        "fired and their outcomes (CITE at least one of these verbatim):\n"
        + "\n".join(f"  {ln}" for ln in attack_lines) + "\n\n"
    ) if attack_lines else ""

    # The CORRECT, curated defenses for THIS vulnerability. Feeding them at
    # request time (instead of letting the model recall from memory) is what
    # stops a small model from bleeding in another vuln class's mitigations.
    defenses = vuln.get("defenses", []) or []
    defense_block = (
        "Approved defensive controls for THIS vulnerability — recommend ONLY "
        "from this list, never a control for a different vulnerability:\n"
        + "\n".join(f"  - {d.get('control','')}: {d.get('implementation','')}" for d in defenses)
        + "\n\n"
    ) if defenses else ""

    prompt = (
        f"Vulnerability: {vuln.get('name', 'Unknown')}.\n"
        f"Grade: {grade} ({score}/100), success={progress.get('success', False)}.\n"
        f"ATT&CK tactics in play: {tactics_line}.\n"
        f"ATT&CK technique IDs in play: {tech_lines}.\n"
        f"{attack_block}"
        f"{defense_block}"
        f"Operator task-ladder evidence:\n{evidence_text}\n\n"
        "Write the threat-analysis section now. Ground it strictly on the "
        "technique IDs above; reference at least one concrete payload or command "
        "from the attack evidence; and for the defense, recommend ONLY a control "
        "from the approved list — do not mention any other vulnerability's defense."
    )

    def _try(model: str) -> Optional[str]:
        payload = _json.dumps({
            "model":   model,
            "prompt":  prompt,
            "stream":  False,
            # Keep the model resident for 30 min so back-to-back reports don't
            # each pay the cold-load cost.
            "keep_alive": "30m",
            "options": {"temperature": 0.3, "num_predict": 320},
        }).encode()
        req = _ur.Request(
            ollama_url + "/api/generate",
            data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with _ur.urlopen(req, timeout=timeout) as resp:
            body = _json.loads(resp.read().decode("utf-8"))
            text = (body.get("response") or "").strip()
            if len(text) <= 60:
                return None
            return _sanitize_narrative(text)

    # 1. Specialised analyst model. On 404 (not built yet) fall back to base.
    for model in (primary, fallback):
        try:
            text = _try(model)
            if text:
                return {"analysis": text, "model": f"ollama/{model}"}
        except _ue.HTTPError:
            continue  # model missing / server error → try the next one
        except (_ue.URLError, OSError, TimeoutError, ValueError):
            break     # container unreachable → stop, use rule-based fallback

    return {"analysis": None, "model": "rule-based-fallback"}


def warm_up_model() -> None:
    """Best-effort: load the analyst model into Ollama's memory at boot so the
    operator's first report doesn't pay the cold-load cost. Safe to call in a
    daemon thread — swallows every error and returns quickly.
    """
    if os.getenv("REPORT_AI_COACH", "1") != "1":
        return
    import json as _json
    import urllib.request as _ur

    ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
    model      = os.getenv("OLLAMA_MODEL", "attense-analyst")
    payload = _json.dumps({
        "model": model,
        "prompt": "ok",
        "stream": False,
        "keep_alive": "30m",
        "options": {"num_predict": 1},
    }).encode()
    req = _ur.Request(
        ollama_url + "/api/generate",
        data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _ur.urlopen(req, timeout=120):
            pass
    except Exception:
        pass


def _rule_based_coaching(progress: dict, vuln: dict) -> str:
    """Fallback prose — variant-aware and technique-specific."""
    pct          = progress.get("progress_percent", 0)
    variant_name = progress.get("variant_name") or "default"
    difficulty   = (progress.get("variant_difficulty") or "").lower()
    vuln_name    = vuln.get("name", "this vulnerability")
    tasks        = progress.get("tasks", [])
    missed_tasks = [t.get("title", "") for t in tasks if not t.get("complete")]

    if progress.get("success"):
        diff_note = (
            f" This was the '{variant_name}' variant (difficulty: {difficulty}) — "
            f"passing it means you have the technique-specific intuition, not just the concept."
            if difficulty in ("medium", "hard") else
            f" You used the '{variant_name}' approach, which is the baseline technique for {vuln_name}."
        )
        opening = (
            f"You completed {vuln_name} via the '{variant_name}' variant with a {pct}% task-completion score."
            + diff_note
        )
        followup = (
            "The most valuable next step is the harder variant of this module — same vulnerability, "
            "tighter filters. Compare your approach against the ideal-approach commands below to find "
            "where you can reduce noise and improve precision."
            if difficulty in ("", "easy") else
            "You are now ready for chaining this technique — look for scenarios where "
            f"{vuln_name} is the entry point into a deeper attack chain."
        )
    elif pct >= 50:
        missed_str = ", ".join(f'"{t}"' for t in missed_tasks[:3]) if missed_tasks else "the final step"
        opening = (
            f"You reached {pct}% on the '{variant_name}' variant of {vuln_name}. "
            f"The evidence engine received your early probes but the following "
            f"step(s) did not fully fire: {missed_str}."
        )
        followup = (
            "Check the 'Ideal Approach' commands below for the exact success indicators. "
            "Each missed step needs a specific observable output — a 302 redirect, a reflected "
            "tag in the page source, or a server error containing the file content. "
            "Run the command, capture the output, and confirm that indicator is present before moving on."
        )
    else:
        opening = (
            f"The '{variant_name}' variant of {vuln_name} was not completed — "
            f"the success criteria require specific event types that did not fire in your session."
        )
        followup = (
            "Run the 'Ideal Approach' commands below one at a time and read each response. "
            "The lab's evidence engine records every matching server event — if your output "
            "matches the expected indicator and the task still does not tick, check that you "
            "are hitting the correct endpoint with the correct parameter name."
        )
    return opening + "\n\n" + followup


def _grade(progress: dict, browser_vs_attackbox: tuple) -> tuple:
    """Return (grade_letter, score 0-100).

    Scoring breakdown (max 100):
      40  — mission success (all required event types fired)
      40  — task completion ratio
      20  — evidence depth (target-agent events, capped at 10)
      +10 — difficulty bonus: Hard variant passed
       +5 — difficulty bonus: Medium variant passed
      -10 — penalty: lab mode, more browser clicks than attackbox tool use
    """
    score = 0.0
    success = bool(progress.get("success"))
    if success:
        score += 40

    tasks = progress.get("tasks", [])
    if tasks:
        done = len(progress.get("completed_tasks", []))
        score += (done / len(tasks)) * 40

    ev_count = len(progress.get("evidence", []))
    score += min(ev_count / 10.0, 1.0) * 20

    # Difficulty bonus: passing a harder variant proves deeper mastery
    difficulty = (progress.get("variant_difficulty") or "").lower()
    if success:
        if difficulty == "hard":
            score += 10
        elif difficulty == "medium":
            score += 5

    # Penalty: lab mode where learner relied on browser instead of tools
    browser_n, attackbox_n = browser_vs_attackbox
    if browser_n > attackbox_n > 0:
        score -= 10

    score = max(0, min(100, int(round(score))))
    if score >= 90 and success: grade = "S"
    elif score >= 75 and success: grade = "A"
    elif score >= 55 and success: grade = "B"
    elif score >= 30: grade = "C"
    else: grade = "F"
    return grade, score


def _mutation_adaptability(session, progress: dict, timeline: list) -> Dict[str, Any]:
    """Score adaptation separately from raw mission success."""
    mutation_events = [
        dict(x) for x in getattr(session, "mutation_timeline", [])
        if x.get("status") == "fired"
    ]
    if not mutation_events:
        return {"timeline": [], "score": None, "grade": None}

    started_at = session.mission_started_at or 0.0
    success_at = getattr(session, "learning_completed_at", None)
    last_activity = max((x.get("ts", 0.0) for x in timeline), default=0.0)
    rows: List[Dict[str, Any]] = []
    adapted_count = 0

    for ev in mutation_events:
        fired_at = ev.get("fired_at") or ev.get("fire_at")
        post_events = [x for x in timeline if fired_at and x.get("ts", 0.0) >= fired_at]
        adapted = bool(progress.get("success") and success_at and fired_at and success_at >= fired_at)
        if adapted:
            adapted_count += 1
        response_seconds = (
            int(round(success_at - fired_at))
            if adapted and success_at and fired_at else None
        )
        rows.append({
            "id": ev.get("id"),
            "mutation_id": ev.get("mutation_id"),
            "label": ev.get("label"),
            "description": ev.get("description"),
            "taunt": ev.get("taunt"),
            "why": ev.get("why"),
            "selected_by": ev.get("selected_by"),
            "color": ev.get("color"),
            "fired_at": fired_at,
            "delta_s": round(fired_at - started_at, 2) if fired_at and started_at else None,
            "adapted": adapted,
            "response_seconds": response_seconds,
            "post_mutation_events": len(post_events),
        })

    activity_bonus = 10 if last_activity and any(
        x.get("fired_at") and last_activity > x["fired_at"] for x in mutation_events
    ) else 0
    score = int(round((adapted_count / len(mutation_events)) * 90 + activity_bonus))
    score = max(0, min(100, score))
    if score >= 90: grade = "S"
    elif score >= 75: grade = "A"
    elif score >= 55: grade = "B"
    elif score >= 30: grade = "C"
    else: grade = "F"
    return {"timeline": rows, "score": score, "grade": grade}


def generate(session, events: list, timeline: list,
             progress: dict, mode: str = "tutorial") -> Dict[str, Any]:
    """Produce the full structured report."""
    module_id  = getattr(session.module, "module_id", None) or getattr(session, "module_id", None)
    module_name = getattr(session.module, "name", None) or module_id
    variant_id = getattr(session, "variant_id", None) or progress.get("variant_id")

    # Look up variant — best effort
    try:
        from backend import lab_progress
        variant = lab_progress.get_variant_spec(module_id, variant_id) or {}
    except Exception:
        variant = {}

    vuln = VULN_INFO.get(module_id, {
        "name":              module_id or "Unknown",
        "cvss_category":     "INFO",
        "what_it_is":        "—",
        "why_it_matters":    "—",
        "real_world_example":"—",
        "defenses":          [],
    })

    # Browser vs AttackBox event count for grading penalty
    browser_n   = sum(1 for e in events if e.get("via") == "browser")
    attackbox_n = sum(1 for e in events if e.get("via") == "attackbox")

    # Score & grade
    grade, score = _grade(progress, (browser_n, attackbox_n))

    # Task results with feedback strings
    task_results: List[Dict[str, Any]] = []
    for t in progress.get("tasks", []):
        ok = bool(t.get("complete"))
        fb = ("Well done — this step's evidence fired as expected."
              if ok else
              f"Missed — needed {t.get('min_count',1)} matching event(s), saw {t.get('match_count',0)}.")
        task_results.append({
            "title":          t.get("title"),
            "completed":      ok,
            "evidence_count": t.get("match_count", 0),
            "min_count":      t.get("min_count", 1),
            "feedback":       fb,
        })

    # Specific "did right" / "missed" lines
    did_right: List[Dict[str, str]] = []
    missed:    List[Dict[str, str]] = []
    for t in task_results:
        if t["completed"]:
            did_right.append({
                "title":  t["title"],
                "detail": f"Completed with {t['evidence_count']} supporting event(s).",
            })
        else:
            missed.append({
                "title":      t["title"],
                "detail":     f"Required {t['min_count']} event(s) — observed {t['evidence_count']}.",
                "how_to_fix": "Follow the ideal-approach command below for this step.",
            })

    if not missed and progress.get("success"):
        did_right.append({
            "title":  "Clean execution",
            "detail": "Every required success event fired. The vulnerability was conclusively demonstrated.",
        })

    # Ideal approach — from the variant's ideal_commands
    ideal_approach: List[Dict[str, Any]] = []
    cmds = variant.get("ideal_commands", [])
    for i, cmd in enumerate(cmds, start=1):
        ideal_approach.append({
            "step":    i,
            "title":   f"Step {i}",
            "command": cmd,
            "why":     "" if cmd.startswith("#") else "Execute and observe the response.",
        })

    # Defensive controls
    defensive = [{"control": d["control"], "implementation": d["implementation"]}
                 for d in vuln.get("defenses", [])]

    # Evidence timeline (chronological)
    started_at = session.mission_started_at or 0.0
    ev_timeline: List[Dict[str, Any]] = []
    for x in timeline:
        ev_timeline.append({
            "timestamp":   x.get("ts", 0.0),
            "delta_s":     round((x.get("ts", 0.0) - started_at), 2) if started_at else None,
            "channel":     x.get("channel", "?"),
            "kind":        x.get("kind", "?"),
            "description": x.get("summary", ""),
        })

    duration = None
    if progress.get("evidence"):
        last_ts = max((e.get("timestamp") or 0.0) for e in progress["evidence"])
        if last_ts and started_at:
            duration = int(round(last_ts - started_at))

    # MITRE ATT&CK — module ground truth + which techniques the operator exercised
    mitre            = _mitre_from_module(session)
    mitre_techniques = _mitre_technique_mapping(mitre, progress, task_results)

    # AI MITRE-grounded threat analysis — attense-analyst model or rule-based fallback
    coach = _ai_mitre_analysis(progress, timeline, vuln, mitre, grade, score, session=session)
    if not coach.get("analysis"):
        coach["analysis"] = _rule_based_coaching(progress, vuln)

    mutation_eval = _mutation_adaptability(session, progress, timeline)

    summary = (
        f"Variant '{progress.get('variant_name') or variant_id or 'default'}' attempted in "
        f"{mode} mode. {progress.get('progress_percent', 0)}% of the task ladder completed. "
        f"{('Success criteria met.' if progress.get('success') else 'Success criteria NOT met yet.')}"
    )

    return {
        "session_id":   session.session_id,
        "module_id":    module_id,
        "module_name":  module_name,
        "generated_at": time.time(),
        "mode":         mode,
        "variant_id":   variant_id,
        "variant_name": variant.get("name") or progress.get("variant_name"),
        "grade":        grade,
        "score":        score,
        "duration_seconds": duration,
        "success":      bool(progress.get("success")),

        "summary":            summary,
        "mitre_tactics":      mitre.get("tactics", []),
        "mitre_techniques":   mitre_techniques,
        "mitre_analysis":     coach["analysis"],
        "ai_coaching":        coach["analysis"],   # back-compat alias
        "ai_model":           coach["model"],

        "what_you_did_right": did_right,
        "what_you_missed":    missed,
        "ideal_approach":     ideal_approach,
        "vulnerability_explained": {
            "name":              vuln.get("name"),
            "cvss_category":     vuln.get("cvss_category"),
            "what_it_is":        vuln.get("what_it_is"),
            "why_it_matters":    vuln.get("why_it_matters"),
            "real_world_example":vuln.get("real_world_example"),
        },
        "defensive_controls": defensive,
        "evidence_timeline":  ev_timeline,
        "task_results":       task_results,
        "mutation_timeline":  mutation_eval["timeline"],
        "adaptability_score": mutation_eval["score"],
        "adaptability_grade": mutation_eval["grade"],

        "channel_breakdown": {
            "browser":   browser_n,
            "attackbox": attackbox_n,
        },
    }
