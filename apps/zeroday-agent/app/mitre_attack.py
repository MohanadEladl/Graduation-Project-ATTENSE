"""
MITRE ATT&CK Knowledge Base
Covers techniques most relevant to Red Team / Blue Team lab environments.
"""

MITRE_TECHNIQUES = {
    "T1595": {
        "tactic": "Reconnaissance",
        "name": "Active Scanning",
        "subtechniques": {"T1595.001": "Scanning IP Blocks", "T1595.002": "Vulnerability Scanning"},
        "keywords": ["nmap", "masscan", "zmap", "ping sweep", "arp-scan", "port scan", "host discovery"],
        "url": "https://attack.mitre.org/techniques/T1595",
    },
    "T1592": {
        "tactic": "Reconnaissance",
        "name": "Gather Victim Host Information",
        "subtechniques": {},
        "keywords": ["os fingerprint", "service version", "banner grab", "os detection"],
        "url": "https://attack.mitre.org/techniques/T1592",
    },
    "T1190": {
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
        "subtechniques": {},
        "keywords": ["exploit", "vulnerability", "cve", "rce", "remote code execution",
                     "web exploit", "buffer overflow", "segfault", "sigsegv", "core dump",
                     "memory corruption", "heap spray", "use after free"],
        "url": "https://attack.mitre.org/techniques/T1190",
    },
    "T1078": {
        "tactic": "Initial Access",
        "name": "Valid Accounts",
        "subtechniques": {"T1078.001": "Default Accounts", "T1078.003": "Local Accounts"},
        "keywords": ["valid credential", "default password", "admin login", "authenticated", "login success"],
        "url": "https://attack.mitre.org/techniques/T1078",
    },
    "T1059": {
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter",
        "subtechniques": {"T1059.004": "Unix Shell", "T1059.006": "Python", "T1059.007": "JavaScript"},
        "keywords": ["/bin/sh", "/bin/bash", "bash -i", "sh -i", "cmd.exe",
                     "powershell", "python -c", "perl -e", "ruby -e"],
        "url": "https://attack.mitre.org/techniques/T1059",
    },
    "T1203": {
        "tactic": "Execution",
        "name": "Exploitation for Client Execution",
        "subtechniques": {},
        "keywords": ["client exploit", "browser exploit", "document exploit", "pdf exploit"],
        "url": "https://attack.mitre.org/techniques/T1203",
    },
    "T1053": {
        "tactic": "Persistence",
        "name": "Scheduled Task/Job",
        "subtechniques": {"T1053.003": "Cron"},
        "keywords": ["crontab", "cron job", "scheduled task", "at command", "systemd timer"],
        "url": "https://attack.mitre.org/techniques/T1053",
    },
    "T1136": {
        "tactic": "Persistence",
        "name": "Create Account",
        "subtechniques": {"T1136.001": "Local Account"},
        "keywords": ["useradd", "adduser", "new user", "create account", "passwd"],
        "url": "https://attack.mitre.org/techniques/T1136",
    },
    "T1505": {
        "tactic": "Persistence",
        "name": "Server Software Component",
        "subtechniques": {"T1505.003": "Web Shell"},
        "keywords": ["webshell", "web shell", "backdoor", ".php shell", "c99", "r57",
                     "hidden file", ".hidden", "/tmp/.", "hidden_backdoor"],
        "url": "https://attack.mitre.org/techniques/T1505",
    },
    "T1068": {
        "tactic": "Privilege Escalation",
        "name": "Exploitation for Privilege Escalation",
        "subtechniques": {},
        "keywords": ["privilege escalation", "privesc", "root exploit", "kernel exploit",
                     "suid", "sudo exploit", "setuid"],
        "url": "https://attack.mitre.org/techniques/T1068",
    },
    "T1070": {
        "tactic": "Defense Evasion",
        "name": "Indicator Removal",
        "subtechniques": {"T1070.002": "Clear Linux or Mac System Logs", "T1070.003": "Clear Command History"},
        "keywords": ["clear log", "rm -rf /var/log", "history -c", "unset histfile",
                     "log deletion", "remove evidence"],
        "url": "https://attack.mitre.org/techniques/T1070",
    },
    "T1036": {
        "tactic": "Defense Evasion",
        "name": "Masquerading",
        "subtechniques": {},
        "keywords": ["rename process", "fake process name", "disguise", "masquerade"],
        "url": "https://attack.mitre.org/techniques/T1036",
    },
    "T1110": {
        "tactic": "Credential Access",
        "name": "Brute Force",
        "subtechniques": {"T1110.001": "Password Guessing", "T1110.003": "Password Spraying"},
        "keywords": ["brute force", "hydra", "medusa", "john", "hashcat", "crack",
                     "password attempt", "login failed", "authentication failure", "invalid password"],
        "url": "https://attack.mitre.org/techniques/T1110",
    },
    "T1003": {
        "tactic": "Credential Access",
        "name": "OS Credential Dumping",
        "subtechniques": {"T1003.008": "/etc/passwd and /etc/shadow"},
        "keywords": ["/etc/shadow", "/etc/passwd", "credential dump", "mimikatz",
                     "lsass", "shadow file", "passwd file"],
        "url": "https://attack.mitre.org/techniques/T1003",
    },
    "T1046": {
        "tactic": "Discovery",
        "name": "Network Service Discovery",
        "subtechniques": {},
        "keywords": ["service scan", "port discovery", "nmap -sV", "service version",
                     "open port", "banner grab"],
        "url": "https://attack.mitre.org/techniques/T1046",
    },
    "T1082": {
        "tactic": "Discovery",
        "name": "System Information Discovery",
        "subtechniques": {},
        "keywords": ["uname", "hostname", "systeminfo", "cat /etc/os-release",
                     "whoami", "id command", "system info"],
        "url": "https://attack.mitre.org/techniques/T1082",
    },
    "T1021": {
        "tactic": "Lateral Movement",
        "name": "Remote Services",
        "subtechniques": {"T1021.004": "SSH"},
        "keywords": ["ssh lateral", "remote login", "psexec", "winrm", "rdp"],
        "url": "https://attack.mitre.org/techniques/T1021",
    },
    "T1005": {
        "tactic": "Collection",
        "name": "Data from Local System",
        "subtechniques": {},
        "keywords": ["data collection", "file search", "find /", "grep -r", "sensitive file"],
        "url": "https://attack.mitre.org/techniques/T1005",
    },
    "T1071": {
        "tactic": "Command and Control",
        "name": "Application Layer Protocol",
        "subtechniques": {"T1071.001": "Web Protocols (HTTP/S)"},
        "keywords": ["command and control", "beacon", "callback", "http tunnel",
                     "dns tunnel", "c&c", "covert channel"],
        "url": "https://attack.mitre.org/techniques/T1071",
    },
    "T1059.004": {
        "tactic": "Command and Control",
        "name": "Reverse Shell",
        "subtechniques": {},
        "keywords": ["reverse shell", "nc -e", "netcat", "bash -i >& /dev/tcp",
                     "outbound shell", "connect back", "shell on port 4444"],
        "url": "https://attack.mitre.org/techniques/T1059/004",
    },
    "T1041": {
        "tactic": "Exfiltration",
        "name": "Exfiltration Over C2 Channel",
        "subtechniques": {},
        "keywords": ["exfiltrate", "data sent", "upload to", "curl POST", "wget --post",
                     "outbound data", "data leak"],
        "url": "https://attack.mitre.org/techniques/T1041",
    },
    "T1499": {
        "tactic": "Impact",
        "name": "Endpoint Denial of Service",
        "subtechniques": {},
        "keywords": ["dos", "denial of service", "flood", "ddos", "service crash",
                     "resource exhaustion"],
        "url": "https://attack.mitre.org/techniques/T1499",
    },
}

_TECHNIQUE_INDEX = []
_summary_parts = []
for _tid, _info in MITRE_TECHNIQUES.items():
    _TECHNIQUE_INDEX.append((
        _tid, _info["name"], _info["tactic"], _info["url"],
        _info["keywords"], [kw.lower() for kw in _info["keywords"]],
    ))
    _summary_parts.append(f"  {_tid} [{_info['tactic']}] {_info['name']}: {', '.join(_info['keywords'][:5])}")
    for _stid, _stname in _info.get("subtechniques", {}).items():
        _summary_parts.append(f"    └─ {_stid}: {_stname}")
_TECHNIQUE_SUMMARY = "\n".join(_summary_parts)
del _summary_parts


def get_technique_summary() -> str:
    return _TECHNIQUE_SUMMARY


def match_techniques(log_text: str) -> list[dict]:
    text_lower = log_text.lower()
    matches = []
    for tid, name, tactic, url, keywords, keywords_lower in _TECHNIQUE_INDEX:
        matched = [kw for kw, kw_low in zip(keywords, keywords_lower) if kw_low in text_lower]
        if matched:
            matches.append({
                "technique_id": tid,
                "technique_name": name,
                "tactic": tactic,
                "matched_keywords": matched,
                "url": url,
            })
    return matches
