"""
Test fixtures for the Zero-Day Detection Agent.
Demo logs and offline analysis results extracted from the original demo.py.
"""

import pytest


DEMO_LOGS = [
    {
        "container": "red-team-backend",
        "timestamp": "2024-01-15T14:23:01",
        "logs": """
[14:23:01] Red Team Agent started -- target: 192.168.1.105
[14:23:02] Phase 1: Reconnaissance
[14:23:02] Running nmap -sV -O 192.168.1.105  (T1595 - Active Scanning)
[14:23:08] Open ports: 22/ssh, 80/http, 443/https, 8080/http-proxy
[14:23:09] OS detected: Ubuntu 22.04 LTS
[14:23:10] Phase 2: Initial Access Attempt
[14:23:10] Brute force SSH with hydra (T1110 - Brute Force)
[14:23:45] Hydra result: 0 valid passwords found
[14:23:46] SSH brute force FAILED -- switching to web vector
[14:23:47] Running nikto on port 80 (T1595.002 - Vulnerability Scanning)
[14:23:52] Nikto found: Apache/2.4.41 - outdated
[14:23:53] Attempting standard exploits for CVE-2021-41773... FAILED
[14:23:54] Attempting standard exploits for CVE-2021-42013... FAILED
[14:23:55] [!!] Sending malformed HTTP request with Content-Length: -1
[14:23:55] [!!] Unexpected server response: SIGSEGV signal leaked in HTTP header
[14:23:56] [!!] Server leaked memory address: 0x7fff5fbff8a0
[14:23:56] [!!] Sending crafted payload targeting leaked address...
[14:23:57] [!!] Received /bin/sh prompt -- ROOT ACCESS OBTAINED
[14:23:57] [!!] Method: UNKNOWN -- not in any known exploit database
[14:23:57] [!!] No matching CVE -- this is a novel memory corruption path
""",
        "error": None,
    },
    {
        "container": "attackbox",
        "timestamp": "2024-01-15T14:23:05",
        "logs": """
[14:23:05] Attackbox ready
[14:23:06] Executing: nmap -sV 192.168.1.105
[14:23:10] Executing: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.105
[14:23:45] Hydra finished: 0 valid credentials
[14:23:47] Executing: nikto -h http://192.168.1.105
[14:23:52] nikto completed: Apache/2.4.41 detected
[14:23:55] Executing: custom_payload --target 192.168.1.105:80 --mode corrupt
[14:23:56] [WARN] Server sent SIGSEGV in response header -- unexpected
[14:23:56] [WARN] Memory address leaked -- feeding back to exploit chain
[14:23:57] [WARN] Received shell -- execution path UNKNOWN -- not logged in playbook
[14:23:57] [WARN] Root shell obtained -- no matching exploit module used
""",
        "error": None,
    },
    {
        "container": "target-agent",
        "timestamp": "2024-01-15T14:23:10",
        "logs": """
[14:23:01] Apache httpd 2.4.41 started on port 80
[14:23:02] sshd: started on port 22
[14:23:08] sshd: 47 failed login attempts from 192.168.1.200 (brute force detected)
[14:23:09] auth.log: Maximum authentication attempts exceeded for root
[14:23:52] access.log: GET /cgi-bin/ 404 (nikto scan detected)
[14:23:55] access.log: POST / HTTP/1.1 Content-Length: -1 (malformed request)
[14:23:55] kernel: segfault in libssl.so.1.1 at address 0x7fff5fbff8a0
[14:23:55] kernel: core dumped
[14:23:56] apache2: child process 4821 received SIGSEGV
[14:23:57] CRITICAL: process /bin/bash spawned by www-data (uid=33)
[14:23:57] CRITICAL: outbound TCP connection from /bin/bash to 192.168.1.200:4444
[14:23:57] CRITICAL: /tmp/.x backdoor file created by www-data
[14:23:58] CRITICAL: crontab modified by www-data -- persistence established
[14:23:58] CRITICAL: /etc/shadow read by www-data (uid=33) -- credential access
[14:23:59] No SQLi patterns in access.log
[14:23:59] No XSS patterns in access.log
[14:23:59] No known RCE CVE match found in IDS rules
""",
        "error": None,
    },
    {
        "container": "wazuh-manager",
        "timestamp": "2024-01-15T14:23:15",
        "logs": """
[14:23:09] Rule 5710 FIRED: Multiple SSH login failures -- source 192.168.1.200 (T1110)
[14:23:52] Rule 31151 FIRED: Web scan detected -- nikto signatures (T1595)
[14:23:55] Rule 550 FIRED: Integrity checksum changed (core dump file)
[14:23:57] Rule 5902 FIRED: New process spawned by web server user (T1059.004)
[14:23:57] Rule 0 FIRED: [UNMATCHED] Outbound connection from web process -- no rule covers this path
[14:23:57] Rule 0 FIRED: [UNMATCHED] Root shell via HTTP handler -- no CVE match
[14:23:58] Rule 5003 FIRED: Crontab modification detected (T1053.003)
[14:23:58] Rule 5503 FIRED: Sensitive file /etc/shadow accessed (T1003.008)
[14:23:58] ALERT LEVEL 15: Attack progression observed but initial vector UNKNOWN
[14:23:59] ALERT LEVEL 15: Cannot classify exploit method -- no signature match
[14:23:59] ALERT LEVEL 15: Flagging for manual review -- possible zero-day
""",
        "error": None,
    },
    {
        "container": "signal-store",
        "timestamp": "2024-01-15T14:23:18",
        "logs": """
[14:23:09] Published: brute_force_alert -> attense-app [T1110]
[14:23:52] Published: web_scan_alert -> attense-app [T1595]
[14:23:57] Published: reverse_shell_alert -> attense-app [T1059.004]
[14:23:57] ERROR: Cannot classify event type 'unknown_exploit_vector' -- no handler
[14:23:58] Published: crontab_modified -> attense-app [T1053.003]
[14:23:58] Published: shadow_access -> attense-app [T1003.008]
[14:23:59] WARNING: 3 events in unclassified queue -- no MITRE mapping found
""",
        "error": None,
    },
    {
        "container": "attense-app",
        "timestamp": "2024-01-15T14:23:20",
        "logs": """
[14:23:09] ALERT displayed: SSH Brute Force [T1110 - Credential Access]
[14:23:52] ALERT displayed: Web Scan [T1595 - Reconnaissance]
[14:23:57] ALERT displayed: Reverse Shell [T1059.004 - Execution]
[14:23:58] ALERT displayed: Crontab Persistence [T1053.003 - Persistence]
[14:23:58] ALERT displayed: Credential Access /etc/shadow [T1003.008]
[14:23:59] WARNING: 3 alerts received with no MITRE classification
[14:23:59] WARNING: Cannot display unclassified alerts -- unknown attack type
[14:23:59] RECOMMENDATION: Manual investigation required for unclassified events
""",
        "error": None,
    },
]


DEMO_OFFLINE_ANALYSIS = {
    "zero_day_detected": True,
    "confidence": "HIGH",
    "severity": "CRITICAL",
    "classification": "ZERO_DAY_VARIANT",
    "kill_chain_stage": "Initial Access",
    "closest_mitre_technique": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190",
        "match_level": "PARTIAL",
        "why_zero_day": (
            "T1190 covers exploiting public-facing apps, but this attack uses "
            "a novel memory corruption path via negative Content-Length causing "
            "a SIGSEGV in libssl.so -- no CVE, no IDS signature, no matching "
            "ATT&CK sub-technique."
        ),
    },
    "anomalies": [
        {
            "container": "target-agent",
            "observation": (
                "Malformed HTTP request with Content-Length: -1 triggered "
                "SIGSEGV and leaked memory address, leading to root shell "
                "via unknown exploit path"
            ),
            "mitre_technique": "UNKNOWN",
            "mitre_tactic": "Initial Access",
            "is_known_technique": False,
            "zero_day_indicator": (
                "Memory corruption via negative Content-Length is not a "
                "documented sub-technique of T1190"
            ),
            "timestamp": "14:23:55-14:23:57",
        },
        {
            "container": "attackbox",
            "observation": (
                "custom_payload tool used with --mode corrupt; execution path "
                "flagged as UNKNOWN by the attack tool itself"
            ),
            "mitre_technique": "UNKNOWN",
            "mitre_tactic": "Execution",
            "is_known_technique": False,
            "zero_day_indicator": (
                "Attack tool's own playbook does not recognize the execution path"
            ),
            "timestamp": "14:23:55-14:23:57",
        },
        {
            "container": "wazuh-manager",
            "observation": (
                "Multiple UNMATCHED rules fired -- SIEM could not classify "
                "the initial access vector"
            ),
            "mitre_technique": "UNKNOWN",
            "mitre_tactic": "Defense Evasion",
            "is_known_technique": False,
            "zero_day_indicator": (
                "Wazuh has no signature for this exploit method; Rule 0 fired twice"
            ),
            "timestamp": "14:23:57",
        },
    ],
    "attack_vector": (
        "Novel HTTP memory corruption: Content-Length: -1 -> segfault in "
        "libssl.so.1.1 -> memory leak -> root shell."
    ),
    "affected_containers": [
        "target-agent", "attackbox", "wazuh-manager",
        "signal-store", "attense-app",
    ],
    "kill_chain_analysis": (
        "1. RECON (T1595): nmap\n"
        "2. CRED (T1110): hydra FAILED\n"
        "3. RECON (T1595.002): nikto\n"
        "4. INITIAL ACCESS (ZERO-DAY): Content-Length: -1\n"
        "5. EXEC (ZERO-DAY): /bin/bash\n"
        "6. PERSIST (T1505.003+T1053.003)\n"
        "7. CRED (T1003.008): /etc/shadow\n"
        "8. C2 (T1059.004): reverse shell"
    ),
    "reasoning": (
        "[OFFLINE ANALYSIS]\n"
        "Novel memory corruption path not matching any T1190 sub-technique."
    ),
    "recommendation": (
        "1. Isolate target-agent\n"
        "2. WAF rule for negative Content-Length\n"
        "3. Patch Apache + libssl.so\n"
        "4. Custom Wazuh rule for SIGSEGV"
    ),
}


@pytest.fixture
def demo_logs():
    return DEMO_LOGS


@pytest.fixture
def demo_analysis():
    return DEMO_OFFLINE_ANALYSIS
