"""
modules/recon.py — Reconnaissance / Target Fingerprinting.

Probes the target for HTTP headers, server version, reachable routes,
and response timings. This is always the first module an operator runs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_KNOWN_ROUTES = [
    "/", "/search?q=test", "/auth/login", "/system/ping?host=127.0.0.1",
    "/files/read?path=readme.txt", "/files/upload", "/profile/",
]


class ReconModule(BaseModule):
    module_id = "recon"
    name = "Reconnaissance"
    description = "HTTP fingerprinting and route discovery against the target application."
    category = Category.RECON
    scenario_id = "PRE-ATTACK"
    severity = Severity.INFO
    # MITRE ATT&CK mapping — Reconnaissance precedes every other module.
    mitre = {
        "tactics": ["TA0043 Reconnaissance"],
        "techniques": [
            {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"},
            {"id": "T1595.003", "name": "Active Scanning: Wordlist Scanning", "tactic": "Reconnaissance"},
            {"id": "T1592.002", "name": "Gather Victim Host Information: Software", "tactic": "Reconnaissance"},
        ],
    }
    lab = {
        "target_path": "/",
        "vulnerable_component": "Entire application surface",
        "story": (
            "Before attacking, you need to map the target. Fingerprint the web "
            "stack, enumerate which routes are exposed, and turn that into a "
            "route→vulnerability map that drives every later module."
        ),
        "learner_steps": [
            {"action": "Banner-grab the server to fingerprint the web stack.",
             "technique": "T1592.002 Gather Victim Host Information: Software",
             "command": "curl -sI http://target-agent/",
             "expected": "Response headers reveal the Server banner / framework (Werkzeug + Flask)."},
            {"action": "Enumerate content and hidden routes with a wordlist.",
             "technique": "T1595.003 Active Scanning: Wordlist Scanning",
             "command": "ffuf -u http://target-agent/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401",
             "expected": "Routes such as /search, /auth/login, /system/ping, /files/read, /profile/ are discovered."},
            {"action": "Probe every route and record status code + latency.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "for p in / /search /auth/login /system/ping /files/read /profile/; do curl -s -o /dev/null -w \"%{http_code}  $p\\n\" http://target-agent$p; done",
             "expected": "A status/latency map of every reachable endpoint."},
            {"action": "Read the HTML source for comments and version leaks.",
             "technique": "T1592.002 Gather Victim Host Information: Software",
             "command": "curl -s http://target-agent/ | grep -iE \"<!--|version|powered\"",
             "expected": "Comments / markup reveal stack details that guide the exploit modules."},
            {"action": "Compile the attack-surface inventory for downstream modules.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "# map each route to a candidate weakness: /search→XSS, /system/ping→cmd-i, /files/read→LFI, /files/upload→upload, /profile/update→CSRF, /auth/login→brute-force",
             "expected": "A route→vulnerability map ready to drive the exploit modules."},
        ],
        "detection_rule": "Wazuh web-scanner signature / sequential path probes from one IP",
        "success_markers": [
            "Every known route returns a status code in the log",
            "Summary: 'Probed N endpoints, N reachable'",
        ],
        "quick_probe": "/",
    }
    steps = [
        {'title': 'Fingerprint the web stack', 'tactic': 'Reconnaissance',
         'technique': 'T1592.002 Gather Victim Host Information: Software',
         'command': 'curl -sI http://target-agent/',
         'hint': 'Capture Server, X-Powered-By, cookies', 'expected': 'Banner of the target web stack'},
        {'title': 'Enumerate exposed routes', 'tactic': 'Reconnaissance',
         'technique': 'T1595.003 Active Scanning: Wordlist Scanning',
         'command': 'for p in / /search /auth/login /system/ping /files/read /profile/; do curl -s -o /dev/null -w "%{http_code} $p\\n" http://target-agent$p; done',
         'hint': 'Probe / /search /auth/login /system/ping /files/read /profile/', 'expected': 'Status code + latency per route'},
        {'title': 'Compile route inventory', 'tactic': 'Reconnaissance',
         'technique': 'T1595.002 Active Scanning: Vulnerability Scanning',
         'command': '# categorize reachable vs redirected vs forbidden endpoints',
         'hint': 'Categorize reachable vs redirected vs forbidden endpoints', 'expected': 'Route map ready for downstream modules'},
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="extra_paths",
                display_name="Extra Paths",
                description="Comma-separated additional paths to probe (optional)",
                default="",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []

        # ── Header fingerprint ────────────────────────────────────────────
        self._log(log_fn, "Fingerprinting target headers...")
        r = self._get(target.base_url + "/", label="header-probe", timeout=target.timeout)
        steps.append(r)

        if r.success:
            interesting = ["Server", "X-Powered-By", "X-Frame-Options"]
            for h in interesting:
                val = r.detail  # We can parse from full response in a future version
                self._log(log_fn, f"  Header check: {h}")

        # ── Route probe ───────────────────────────────────────────────────
        routes = list(_KNOWN_ROUTES)
        extra = opts.get("extra_paths", "")
        if extra:
            routes += [p.strip() for p in extra.split(",") if p.strip()]

        self._log(log_fn, f"Probing {len(routes)} routes...")
        for route in routes:
            url = target.base_url + route
            r = self._get(url, label=route, timeout=target.timeout)
            symbol = "✓" if r.success and (r.status_code or 0) < 500 else "✗"
            self._log(log_fn, f"  [{symbol}] {r.status_code}  {route}")
            steps.append(r)

        reachable = sum(1 for s in steps if s.success and (s.status_code or 0) < 500)
        summary = f"Probed {len(steps)} endpoints, {reachable} reachable."
        return self._make_result(target, steps, summary, started)
