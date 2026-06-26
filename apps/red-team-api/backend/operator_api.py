"""
backend/operator_api.py — Operator Mode endpoints for AttackBox + ZAP.

Provides REST endpoints that let the React frontend:
  - check AttackBox/ZAP container status
  - execute safe commands inside the AttackBox container
  - query ZAP proxy history & send repeater requests

Safety:
  - Commands are executed only inside the attackbox container via Docker SDK.
  - External domains / public IPs are blocked.
  - Only target-agent (local lab) is an approved target.
  - Destructive system commands are blocked.
  - docker.sock is mounted read-only for exec access.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

import json
import docker as docker_sdk
from docker.errors import DockerException, NotFound as DockerNotFound


# ── Configuration ────────────────────────────────────────────────────────────
ATTACKBOX_CONTAINER = os.getenv("ATTACKBOX_CONTAINER", "attense_attackbox")
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
# No baked-in default key (check-secrets requires ZAP_API_KEY and rejects the
# stock "attense-lab-key"); empty fails loudly rather than using a known key.
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

# Approved local lab targets
ALLOWED_TARGETS = {"target-agent", "http://target-agent", "http://target-agent:80"}
ALLOWED_HOSTNAME_RE = re.compile(r"^target-agent(:\d+)?$")

# All hostnames that are explicitly allowed (internal Docker network only)
ALLOWED_HOSTS: frozenset = frozenset({
    "target-agent", "localhost", "127.0.0.1", "0.0.0.0",
    "attackbox", "signal-store", "blueteam", "wazuh.manager",
    "zap", "ollama", "red-team-backend",
})

# Tools we recognise from command prefixes
KNOWN_TOOLS = {"curl", "nmap", "hydra", "ffuf", "gobuster", "jq", "python3",
               "nc", "ncat", "wget", "cat", "head", "tail", "grep", "echo",
               "wc", "sort", "uniq", "tr", "awk", "sed", "ls", "pwd", "id",
               "whoami", "hostname", "dig", "nslookup", "ping", "host", "bash"}

# Blocked command patterns (destructive, escape-attempt, or privilege-escalation)
BLOCKED_PATTERNS = [
    r"\brm\s+-rf\b", r"\brm\s+-r\b", r"\bmkfs\b", r"\bdd\s+if=",
    r"\bchmod\s+777\b", r"\bchown\b", r"\bshutdown\b", r"\breboot\b",
    r"\bpoweroff\b", r"\binit\s+[06]\b", r"\bkill\s+-9\s+1\b",
    r"\bdocker\b", r"\bkubectl\b", r"\bsudo\b", r"\bsu\s+",
    r"\bapt\b", r"\bapk\b", r"\byum\b", r"\bpip\s+install\b",
    r"\bpython.*-c\s+['\"].*import\s+os\b",
    r"\b/dev/sd[a-z]\b", r"\b/dev/null\b.*>",
    r"\biptables\b", r"\broute\b",
    r"\bwget\s.*-O\s*/", r"\bcurl\s.*-o\s*/",
]
BLOCKED_RE = [re.compile(p, re.IGNORECASE) for p in BLOCKED_PATTERNS]

# Max command output length (bytes) to prevent memory exhaustion
MAX_OUTPUT_LEN = 65536
# Max command execution time (seconds)
MAX_EXEC_TIMEOUT = 30


# ── Utility: detect tool from command ────────────────────────────────────────
def _detect_tool(cmd: str) -> str:
    """Extract the first token and map it to a known tool name."""
    first = cmd.strip().split()[0] if cmd.strip() else ""
    # Handle paths like /usr/bin/curl
    basename = os.path.basename(first)
    return basename if basename in KNOWN_TOOLS else "unknown"


# ── Safety: validate command targets ─────────────────────────────────────────
def _is_public_ip(host: str) -> bool:
    """Return True if host resolves to a public (non-private) IP."""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_global
    except ValueError:
        pass
    # Try resolving hostname
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in infos:
            addr = ipaddress.ip_address(sockaddr[0])
            if addr.is_global:
                return True
    except (socket.gaierror, OSError):
        pass
    return False


def _looks_external(host: str) -> bool:
    """Return True if host is an external/public target that should be blocked."""
    h = host.lower().strip()
    if not h:
        return False
    if h in ALLOWED_HOSTS:
        return False
    if ALLOWED_HOSTNAME_RE.match(h):
        return False
    # Any IP that is not already in ALLOWED_HOSTS (above) is blocked.
    # This covers private RFC1918 ranges (10.x, 192.168.x, 172.16.x-31.x)
    # which have is_global=False but must not be reachable from the lab.
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # Any hostname with a dot that is not explicitly allowed → treat as external.
    # This catches google.com, 8.8.8.8, example.com without needing DNS resolution.
    if "." in h:
        return True
    return False


def _extract_hostnames(cmd: str) -> list[str]:
    """Extract all target hostnames from a command string (URLs and positional args)."""
    hosts: list[str] = []
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    # URLs with scheme
    for m in re.finditer(r"https?://([^/:@\s]+)", cmd):
        hosts.append(m.group(1))

    # Flag-based targets (-u, -t, -U, -H, --url, --target)
    for m in re.finditer(r"(?:^|\s)(?:-[tuUH]|--url|--target)\s+(\S+)", cmd):
        val = re.sub(r"^https?://", "", m.group(1)).split("/")[0].split(":")[0]
        hosts.append(val)

    # Tool-specific positional argument extraction
    if not tokens:
        return hosts
    tool_name = os.path.basename(tokens[0])
    args = tokens[1:]

    if tool_name == "nmap":
        # nmap [opts] TARGET — all non-flag tokens are targets
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                # flags that consume the next token
                if tok in ("-p", "-iL", "-oN", "-oX", "-oG", "-oA",
                           "--script", "-e", "-S", "--source-port",
                           "--data-length", "--ttl", "--max-retries",
                           "--host-timeout", "--scan-delay",
                           "--min-rate", "--max-rate", "-T"):
                    skip_next = True
                continue
            hosts.append(tok.split(":")[0].split("/")[0])

    elif tool_name in ("nc", "ncat", "netcat"):
        # nc [opts] HOST PORT — first non-flag arg is the host
        non_flags = [t for t in args if not t.startswith("-")]
        if non_flags:
            hosts.append(non_flags[0])

    elif tool_name == "hydra":
        # hydra [opts] HOST [service] — first non-flag before http-post-form etc.
        non_flags: list[str] = []
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                if tok in ("-l", "-L", "-p", "-P", "-t", "-f", "-s",
                           "-o", "-b", "-w", "-W", "-c", "-e", "-m",
                           "-u", "-x", "-I"):
                    skip_next = True
                continue
            non_flags.append(tok)
        if non_flags:
            hosts.append(non_flags[0].split(":")[0])

    elif tool_name == "wget":
        # wget [opts] URL — bare args without scheme
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                if tok in ("-O", "--output-document", "-P",
                           "--directory-prefix", "-U", "--user-agent",
                           "--referer"):
                    skip_next = True
                continue
            h = re.sub(r"^https?://", "", tok).split("/")[0].split(":")[0]
            if h:
                hosts.append(h)

    elif tool_name == "ping":
        # ping [opts] HOST — last non-flag token is the target
        non_flags = [t for t in args if not t.startswith("-")]
        if non_flags:
            hosts.append(non_flags[-1])

    elif tool_name in ("dig", "nslookup"):
        # dig [@server] name [type] — first non-@ non-type token is the hostname
        # nslookup name [server]   — first non-flag token is the hostname
        for tok in args:
            if tok.startswith("-") or tok.startswith("@"):
                continue
            # Skip DNS record type tokens (A, AAAA, MX, TXT, ANY, NS, SOA…)
            if re.match(r"^(A|AAAA|MX|TXT|ANY|NS|SOA|CNAME|PTR|SRV|CAA)$", tok, re.IGNORECASE):
                continue
            hosts.append(tok)
            break  # first qualifying token is the query name

    elif tool_name == "host":
        # host [opts] name [server] — first positional token (after flags) is the name
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                # -t, -c, -W, -R consume the next token as their value
                if tok in ("-t", "-c", "-W", "-R"):
                    skip_next = True
                continue
            hosts.append(tok)
            break

    return hosts


def validate_command(cmd: str) -> Optional[str]:
    """Return an error message if the command should be rejected, else None."""
    stripped = cmd.strip()
    if not stripped:
        return "Empty command."

    # Check blocked patterns (destructive / privilege-escalation)
    for pattern in BLOCKED_RE:
        if pattern.search(stripped):
            return "Blocked: command matches a restricted pattern."

    # Extract and validate all target hostnames
    hosts = _extract_hostnames(stripped)
    for h in hosts:
        h_clean = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0].lower().strip()
        if not h_clean:
            continue
        if _looks_external(h_clean):
            return (
                f"Blocked: external target '{h_clean}' is not allowed. "
                "Approved target: target-agent."
            )

    return None


# ── Docker SDK client ────────────────────────────────────────────────────────
def _docker_client() -> "docker_sdk.DockerClient":
    return docker_sdk.from_env()


# ── AttackBox status ─────────────────────────────────────────────────────────
def get_attackbox_status() -> Dict[str, Any]:
    """Check if the attackbox container is reachable via the Docker SDK."""
    try:
        client = _docker_client()
        container = client.containers.get(ATTACKBOX_CONTAINER)
        exit_code, output = container.exec_run("echo alive", demux=False)
        output_bytes = output if isinstance(output, bytes) else b"".join(output)
        if exit_code == 0 and b"alive" in output_bytes:
            return {"status": "running", "container": ATTACKBOX_CONTAINER}
        return {"status": "error", "detail": output_bytes.decode("utf-8", errors="replace").strip()}
    except DockerNotFound:
        return {"status": "stopped", "detail": "attackbox container not found"}
    except (DockerException, Exception) as e:
        return {"status": "error", "detail": str(e)}


def exec_in_attackbox(command: str) -> Dict[str, Any]:
    """Execute a command inside the attackbox container via Docker SDK."""
    err = validate_command(command)
    if err:
        return {"status": "blocked", "command": command, "output": err, "tool": _detect_tool(command)}

    tool = _detect_tool(command)

    try:
        client = _docker_client()
        container = client.containers.get(ATTACKBOX_CONTAINER)
        exit_code, output = container.exec_run(
            ["bash", "-c", command],
            demux=False,
            socket=False,
        )
        raw = output if isinstance(output, bytes) else b"".join(output) if output else b""
        text = raw.decode("utf-8", errors="replace")
        stdout_part = text[:MAX_OUTPUT_LEN]
        return {
            "status": "ok",
            "command": command,
            "output": stdout_part.strip(),
            "tool": tool,
            "exit_code": exit_code,
        }
    except DockerNotFound:
        return {
            "status": "error",
            "command": command,
            "output": "attackbox container not found.",
            "tool": tool,
        }
    except (DockerException, Exception) as e:
        return {
            "status": "error",
            "command": command,
            "output": str(e),
            "tool": tool,
        }


# ── Evidence recording ───────────────────────────────────────────────────────
_evidence_log: List[Dict[str, Any]] = []
_evidence_max = 500

def record_tool_evidence(
    tool: str,
    command: str,
    module_id: Optional[str] = None,
    output_preview: str = "",
) -> Dict[str, Any]:
    """Record a tool command as evidence for Check Progress."""
    ev = {
        "id": len(_evidence_log),
        "ts": time.time(),
        "event_type": "tool_command_observed",
        "tool": tool,
        "command": command,
        "module_id": module_id,
        "target": "target-agent",
        "learner_message": _tool_message(tool, command),
        "output_preview": (output_preview[:200] if output_preview else ""),
        "severity": "info",
    }
    _evidence_log.append(ev)
    if len(_evidence_log) > _evidence_max:
        del _evidence_log[:len(_evidence_log) - _evidence_max]
    return ev


def get_tool_evidence(since: float = 0.0, limit: int = 100) -> List[Dict[str, Any]]:
    """Return tool evidence events after `since`."""
    return [e for e in _evidence_log if e["ts"] >= since][-limit:]


def _tool_message(tool: str, command: str) -> str:
    """Generate a learner-facing evidence description."""
    cmd_short = command[:80] + ("…" if len(command) > 80 else "")
    messages = {
        "nmap":     f"Nmap scan was executed against the local target.",
        "hydra":    f"Hydra brute-force tool was used against the local login form.",
        "curl":     f"curl request was sent to the local target.",
        "ffuf":     f"ffuf fuzzer was run against the local target.",
        "gobuster": f"Gobuster directory scan was run against the local target.",
        "nc":       f"Netcat connection was opened to the local target.",
        "ncat":     f"Ncat connection was opened to the local target.",
        "wget":     f"wget request was sent to the local target.",
        "python3":  f"Python3 script was executed in the AttackBox.",
    }
    return messages.get(tool, f"Tool command executed: {cmd_short}")


# ── ZAP status ───────────────────────────────────────────────────────────────
def get_zap_status() -> Dict[str, Any]:
    """Check if the ZAP API is reachable."""
    try:
        url = f"{ZAP_API_URL}/JSON/core/view/version/?apikey={ZAP_API_KEY}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": "running",
                "version": data.get("version", "unknown"),
            }
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return {"status": "offline", "detail": "ZAP API not reachable"}


def get_zap_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch proxy history from ZAP API."""
    try:
        url = (f"{ZAP_API_URL}/JSON/core/view/messages/"
               f"?apikey={ZAP_API_KEY}&baseurl=http://target-agent&start=0&count={limit}")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            messages = data.get("messages", [])
            return [{
                "id": m.get("id"),
                "timestamp": m.get("timestamp"),
                "method": m.get("requestHeader", "").split(" ")[0] if m.get("requestHeader") else "",
                "url": m.get("requestHeader", "").split(" ")[1] if len(m.get("requestHeader", "").split(" ")) > 1 else "",
                "status_code": m.get("responseHeader", "").split(" ")[1] if len(m.get("responseHeader", "").split(" ")) > 1 else "",
                "response_length": len(m.get("responseBody", "")),
            } for m in messages]
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, IndexError):
        return []


def zap_repeater_send(method: str, path: str, headers: Optional[Dict] = None,
                      body: Optional[str] = None) -> Dict[str, Any]:
    """Send a request through ZAP to the local target-agent only."""
    # Safety: only allow target-agent paths
    if not path.startswith("/"):
        path = "/" + path
    url = f"http://target-agent{path}"

    try:
        # Use ZAP's sendRequest API. Inject the AttenseAttackBox User-Agent so
        # target-agent's detect_via() classifies this as via=attackbox and the
        # event credits operator-mode progress (otherwise it'd be via=unknown).
        request_header = (
            f"{method.upper()} {url} HTTP/1.1\r\n"
            f"Host: target-agent\r\n"
            f"User-Agent: AttenseAttackBox-ZAP/1.0\r\n"
        )
        # Preserve caller-supplied headers EXCEPT Host/User-Agent which we own.
        if headers:
            for k, v in headers.items():
                if k.lower() in ("host", "user-agent"):
                    continue
                request_header += f"{k}: {v}\r\n"
        if body:
            request_header += f"Content-Length: {len(body)}\r\n"
        request_header += "\r\n"
        full_request = request_header + (body or "")

        api_url = (f"{ZAP_API_URL}/JSON/core/action/sendRequest/"
                   f"?apikey={ZAP_API_KEY}"
                   f"&request={urllib.parse.quote(full_request)}"
                   f"&followRedirects=false")
        req = urllib.request.Request(api_url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {"status": "ok", "response": data}
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
        return {"status": "error", "detail": str(e)}

