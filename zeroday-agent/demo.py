"""
Demo Mode -- MITRE ATT&CK Edition (ATTENSE Integrated)
Simulates realistic container logs from the ATTENSE Cyber Range:
- Known attacks (T1595, T1110) -> correctly identified as NOT zero-day
- Unknown SSL memory corruption exploit -> flagged as zero-day
  (closest: T1190, but execution method is completely novel)
- Posts findings to ATTENSE Blue Team API if platform is running
"""

import json

from agent import analyze_with_gemini, generate_report, send_alert, pre_analyze_mitre, post_to_attense

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
        "error": None
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
        "error": None
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
        "error": None
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
        "error": None
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
        "error": None
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
        "error": None
    }
]


def run_demo():
    print("=" * 60)
    print("   🎭  ZERO-DAY AGENT -- DEMO MODE (ATTENSE Integrated)")
    print("   Simulated ATTENSE Cyber Range logs + zero-day scenario")
    print("=" * 60)

    print("\n📦 Using simulated ATTENSE container logs...")
    for log in DEMO_LOGS:
        print(f"  ✅ {log['container']}")

    print("\n🗺️  Running MITRE ATT&CK keyword pre-scan...")
    mitre_matches = pre_analyze_mitre(DEMO_LOGS)
    total = sum(len(v) for v in mitre_matches.values())
    print(f"  Found {total} technique matches")

    for container, matches in mitre_matches.items():
        if matches:
            ids = [m["technique_id"] for m in matches]
            print(f"  ✅ {container}: {', '.join(ids)}")
        else:
            print(f"  ⚠️  {container}: No known techniques matched")

    print("\n🤖 Sending to Gemini AI for deep MITRE analysis...")
    analysis = analyze_with_gemini(DEMO_LOGS, mitre_matches, demo=True)

    send_alert(analysis)

    if analysis.get("zero_day_detected"):
        post_to_attense(analysis)
        report_path = generate_report(analysis, DEMO_LOGS, mitre_matches)
        print(f"\n📄 Report: {report_path}")
    else:
        print("\n📄 No report generated (no zero-day detected).")

    print("\n📊 Full Analysis JSON:")
    print(json.dumps(analysis, indent=2))

    return analysis


if __name__ == "__main__":
    run_demo()
