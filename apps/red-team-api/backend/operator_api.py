"""
backend/operator_api.py - Operator Mode endpoints for AttackBox + ZAP.

Provides REST endpoints that let the React frontend:
  - check AttackBox/ZAP container status
  - execute safe commands inside the AttackBox container
  - query ZAP proxy history & send repeater/fuzzer requests
  - reverse-proxy Operator-mode browser traffic through ZAP (Burp-style
    Proxy History) via browse_through_zap

Safety:
  - Commands are executed only inside the attackbox container via Docker SDK,
    wrapped in `bash -c` (curriculum commands use pipes/loops/redirects/shell
    variables freely -- see lab_progress.py's ideal_commands) with an
    enforced wall-clock timeout.
  - "Simple" TOOL-arg... commands (no shell control-flow/comments/variable
    assignment) must additionally name an approved tool -- rejects
    unexpected binaries the destructive-pattern blocklist doesn't already
    cover. Scripted/looped commands skip this extra gate and rely on the
    blocklist alone, same as before this module was hardened.
  - External domains / public IPs are blocked.
  - Only target-agent (local lab) is an approved target.
  - Destructive system commands are blocked.
  - docker.sock is mounted read-only for exec access.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

import docker as docker_sdk
import requests
from docker.errors import DockerException, NotFound as DockerNotFound


# -- Configuration ------------------------------------------------------------
ATTACKBOX_CONTAINER = os.getenv("ATTACKBOX_CONTAINER", "attense_attackbox")
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
# No baked-in default key (check-secrets requires ZAP_API_KEY and rejects the
# stock "attense-lab-key"); empty fails loudly rather than using a known key.
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_ALLOWED_HOSTS = {"target-agent"}
ZAP_ALLOWED_SCHEMES = {"http", "https"}

# -- Browser-through-ZAP proxy (Operator Mode) --------------------------------
# The Operator lab browser loads the target via /target-zap/... which the
# backend reverse-proxies to http://target-agent/op/... USING ZAP as the HTTP
# forward proxy, so every click/form/navigation is recorded in ZAP history
# (Burp-Proxy-History style) while staying strictly local (target-agent only).
ZAP_PROXY_URL = os.getenv("ZAP_PROXY_URL", ZAP_API_URL)  # ZAP's single port is proxy+API
# Deliberately NOT a completing-tool User-Agent: detect_via must classify this
# as "browser", so casual clicking never satisfies operator-mode missions --
# those still require Repeater/Fuzzer/AttackBox (see lab_progress OPERATOR_TOOL_VIA).
BROWSER_PROXY_UA = "Mozilla/5.0 (X11; AttenseLabBrowser) AppleWebKit/537.36 (KHTML, like Gecko) OperatorMode Safari/537.36"
# Request headers we never forward upstream (hop-by-hop, or we set our own).
_PROXY_DROP_REQ_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding", "x-forwarded-prefix", "user-agent",
}
# Response headers we strip before returning to the iframe.
_PROXY_DROP_RESP_HEADERS = {
    "transfer-encoding", "content-encoding", "content-length", "connection",
    "keep-alive", "x-frame-options", "content-security-policy",
    "strict-transport-security",
}
# App-level (non-operator) route prefixes on the target that must NOT be
# rewritten under /op/ (telemetry script, static assets, containment webhook).
_APP_LEVEL_PREFIXES = ("lab/", "static/", "containment")

# Approved local lab targets
ALLOWED_TARGETS = {"target-agent", "http://target-agent", "http://target-agent:80"}
ALLOWED_HOSTNAME_RE = re.compile(r"^target-agent(:\d+)?$")

# All hostnames that are explicitly allowed (internal Docker network only)
ALLOWED_HOSTS: frozenset = frozenset({
    "target-agent", "localhost", "127.0.0.1", "0.0.0.0",
    "attackbox", "signal-store", "blueteam", "wazuh.manager",
    "zap", "ollama", "red-team-backend",
})

# Tools we recognise from command prefixes. Kept generous (matches everything
# the curriculum's ideal_commands actually use - see lab_progress.py) since
# this is only enforced for "simple" commands; see _is_simple_command.
KNOWN_TOOLS = {"curl", "nmap", "hydra", "ffuf", "gobuster", "jq", "python3",
               "nc", "ncat", "wget", "cat", "head", "tail", "grep", "echo",
               "printf", "wc", "sort", "uniq", "tr", "awk", "sed", "ls", "pwd",
               "id", "whoami", "hostname", "dig", "nslookup", "ping", "host"}
ALLOWED_TOOLS = KNOWN_TOOLS  # "bash" deliberately excluded - see _is_simple_command

# Shell control-flow keywords: a command starting with one of these is a
# scripted/looped example (curriculum's brute_force wordlist-building blocks),
# not a plain "TOOL arg..." invocation - it skips the tool-allowlist gate and
# relies on BLOCKED_PATTERNS alone, unchanged from before this module hardened.
_SHELL_KEYWORDS = {"for", "while", "until", "if", "then", "elif", "else", "fi",
                   "do", "done", "case", "esac", "select", "function", "in"}
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

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
    # -o/-O written to an arbitrary path is an exfil/overwrite risk, but
    # "-o /dev/null" is the single most common curl/wget idiom for discarding
    # output (used throughout the curriculum's ideal_commands) - carve it out.
    r"\bwget\s.*-O\s*(?!/dev/null\b)/", r"\bcurl\s.*-o\s*(?!/dev/null\b)/",
]
BLOCKED_RE = [re.compile(p, re.IGNORECASE) for p in BLOCKED_PATTERNS]

# Max command output length (bytes) to prevent memory exhaustion
MAX_OUTPUT_LEN = 65536
# Max command execution time (seconds), enforced via the `timeout` coreutil so
# a hung command can't tie up the shared AttackBox container indefinitely.
MAX_EXEC_TIMEOUT = 30


# -- Utility: detect tool from command ----------------------------------------
def _detect_tool(cmd: str) -> str:
    """Extract the first token and map it to a known tool name."""
    first = cmd.strip().split()[0] if cmd.strip() else ""
    # Handle paths like /usr/bin/curl
    basename = os.path.basename(first)
    return basename if basename in KNOWN_TOOLS else "unknown"


def _is_simple_command(tokens: List[str]) -> bool:
    """True when `tokens` looks like a single TOOL arg... invocation - no
    shell control-flow keyword, comment, or variable assignment leading it.

    The curriculum's ideal_commands include scripted, multi-line examples
    (loops that build a wordlist file, `VAR=value` assignments) alongside the
    much more common single-command case. Only the simple case gets the extra
    tool-allowlist gate below; scripted examples fall back to the
    already-working BLOCKED_PATTERNS-only check, exactly as before.
    """
    if not tokens:
        return False
    first = tokens[0]
    if first.startswith("#"):
        return False
    if first in _SHELL_KEYWORDS:
        return False
    if _ASSIGNMENT_RE.match(first):
        return False
    return True


# -- Safety: validate command targets -----------------------------------------
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
    # Any hostname with a dot that is not explicitly allowed -> treat as external.
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
        # nmap [opts] TARGET - all non-flag tokens are targets
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
        # nc [opts] HOST PORT - first non-flag arg is the host
        non_flags = [t for t in args if not t.startswith("-")]
        if non_flags:
            hosts.append(non_flags[0])

    elif tool_name == "hydra":
        # hydra [opts] HOST [service] - first non-flag before http-post-form etc.
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
        # wget [opts] URL - bare args without scheme
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
        # ping [opts] HOST - last non-flag token is the target
        non_flags = [t for t in args if not t.startswith("-")]
        if non_flags:
            hosts.append(non_flags[-1])

    elif tool_name in ("dig", "nslookup"):
        # dig [@server] name [type] - first non-@ non-type token is the hostname
        # nslookup name [server] - first non-flag token is the hostname
        for tok in args:
            if tok.startswith("-") or tok.startswith("@"):
                continue
            # Skip DNS record type tokens (A, AAAA, MX, TXT, ANY, NS, SOA...)
            if re.match(r"^(A|AAAA|MX|TXT|ANY|NS|SOA|CNAME|PTR|SRV|CAA)$", tok, re.IGNORECASE):
                continue
            hosts.append(tok)
            break  # first qualifying token is the query name

    elif tool_name == "host":
        # host [opts] name [server] - first positional token (after flags) is the name
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

    # Check blocked patterns (destructive / privilege-escalation) - applies to
    # every command regardless of shape (simple or scripted).
    for pattern in BLOCKED_RE:
        if pattern.search(stripped):
            return "Blocked: command matches a restricted pattern."

    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = []

    # Simple "TOOL arg..." commands must also name an approved tool - this
    # rejects unexpected binaries (vi, ssh, openssl, telnet, ...) the pattern
    # blocklist above doesn't already cover. Scripted/looped commands (rarer;
    # curriculum's wordlist-building examples) skip this extra gate.
    if _is_simple_command(tokens):
        tool = os.path.basename(tokens[0])
        if tool not in ALLOWED_TOOLS:
            return f"Blocked: '{tool}' is not an approved lab tool."

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


# -- Docker SDK client --------------------------------------------------------
def _docker_client() -> "docker_sdk.DockerClient":
    return docker_sdk.from_env()


# -- AttackBox status ---------------------------------------------------------
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
    """Execute a command inside the attackbox container via Docker SDK.

    Wrapped in `bash -c` (not a tokenized/no-shell exec) so the curriculum's
    pipes/loops/redirects/shell-variable examples keep working; `timeout`
    enforces MAX_EXEC_TIMEOUT so a hung command can't tie up the container
    other concurrent learners share.
    """
    err = validate_command(command)
    if err:
        return {"status": "blocked", "command": command, "output": err, "tool": _detect_tool(command)}

    tool = _detect_tool(command)
    exec_cmd = ["timeout", "--kill-after=2s", f"{MAX_EXEC_TIMEOUT}s", "bash", "-c", command]

    try:
        client = _docker_client()
        container = client.containers.get(ATTACKBOX_CONTAINER)
        exit_code, output = container.exec_run(
            exec_cmd,
            demux=False,
            socket=False,
        )
        raw = output if isinstance(output, bytes) else b"".join(output) if output else b""
        text = raw.decode("utf-8", errors="replace")
        stdout_part = text[:MAX_OUTPUT_LEN]
        if exit_code in (124, 137):
            return {
                "status": "timeout",
                "command": command,
                "output": f"Command timed out after {MAX_EXEC_TIMEOUT}s and was terminated.",
                "tool": tool,
                "exit_code": exit_code,
            }
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


# -- Evidence recording -------------------------------------------------------
_evidence_log: List[Dict[str, Any]] = []
_evidence_max = 500
_zap_history: List[Dict[str, Any]] = []
_zap_history_lock = threading.Lock()


def record_tool_evidence(
    tool: str,
    command: str,
    module_id: Optional[str] = None,
    output_preview: str = "",
    *,
    session_id: Optional[str] = None,
    event_type: str = "tool_command_observed",
    learner_message: Optional[str] = None,
    severity: str = "info",
    via: str = "attackbox",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record a tool command as evidence for Check Progress."""
    ev = {
        "id": len(_evidence_log),
        "ts": time.time(),
        "event_type": event_type,
        "tool": tool,
        "command": command,
        "module_id": module_id,
        "session_id": session_id,
        "target": "target-agent",
        "via": via,
        "learner_message": learner_message or _tool_message(tool, command, event_type),
        "output_preview": (output_preview[:200] if output_preview else ""),
        "severity": severity,
        "extra": dict(extra or {}),
    }
    _evidence_log.append(ev)
    if len(_evidence_log) > _evidence_max:
        del _evidence_log[:len(_evidence_log) - _evidence_max]
    return ev


def get_tool_evidence(since: float = 0.0, limit: int = 100, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return tool evidence events after `since`, optionally scoped to one session.

    `session_id` keeps one learner's AttackBox commands from showing up as
    another concurrent learner's evidence, since the AttackBox container
    itself is shared by every session.
    """
    out = [e for e in _evidence_log if e["ts"] >= since]
    if session_id:
        out = [e for e in out if e.get("session_id") == session_id]
    return out[-limit:]


def _tool_message(tool: str, command: str, event_type: str = "tool_command_observed") -> str:
    """Generate a learner-facing evidence description."""
    cmd_short = command[:80] + ("..." if len(command) > 80 else "")
    zap_messages = {
        "zap_repeater_request": "ZAP Repeater sent a request to the local target.",
        "zap_fuzzer_started": "ZAP Fuzzer started payload testing against the local target.",
        "zap_fuzzer_payload_tested": "ZAP Fuzzer tested a payload against the local target.",
        "zap_fuzzer_completed": "ZAP Fuzzer completed payload testing.",
        "zap_fuzzer_match_found": "ZAP Fuzzer found a likely success or response outlier.",
    }
    if event_type in zap_messages:
        return zap_messages[event_type]
    messages = {
        "nmap": f"Nmap scan was executed against the local target.",
        "hydra": f"Hydra brute-force tool was used against the local login form.",
        "curl": f"curl request was sent to the local target.",
        "ffuf": f"ffuf fuzzer was run against the local target.",
        "gobuster": f"Gobuster directory scan was run against the local target.",
        "nc": f"Netcat connection was opened to the local target.",
        "ncat": f"Ncat connection was opened to the local target.",
        "wget": f"wget request was sent to the local target.",
        "python3": f"Python3 script was executed in the AttackBox.",
    }
    return messages.get(tool, f"Tool command executed: {cmd_short}")


# -- ZAP status ---------------------------------------------------------------
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


def normalize_zap_target_path(raw_path: str) -> str:
    """Normalize a user-supplied ZAP target to a local target-agent path."""
    raw = (raw_path or "/").strip()
    if not raw:
        return "/"
    if any(ch in raw for ch in ("\r", "\n")):
        raise ValueError("Blocked: external targets are not allowed. Approved target: target-agent.")

    if re.match(r"^https?://", raw, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(raw)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        if scheme not in ZAP_ALLOWED_SCHEMES or host not in ZAP_ALLOWED_HOSTS:
            raise ValueError("Blocked: external targets are not allowed. Approved target: target-agent.")
        path = parsed.path or "/"
        if "://" in path:
            raise ValueError("Blocked: external targets are not allowed. Approved target: target-agent.")
        if parsed.query:
            path += "?" + parsed.query
        return path

    if raw.startswith("//") or "://" in raw:
        raise ValueError("Blocked: external targets are not allowed. Approved target: target-agent.")
    if raw.startswith("target-agent/"):
        raw = raw[len("target-agent"):]
    if not raw.startswith("/"):
        raw = "/" + raw
    if "://" in raw:
        raise ValueError("Blocked: external targets are not allowed. Approved target: target-agent.")
    return raw


# Truncation limits so a huge captured response can never break the UI.
MAX_HISTORY_BODY_LEN = 20000
MAX_HISTORY_HEADER_LEN = 8000


def _truncate(text: Any, limit: int) -> str:
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    if len(s) > limit:
        return s[:limit] + f"\n...[truncated {len(s) - limit} more chars]"
    return s


def _headers_to_str(headers: Any) -> str:
    if headers is None:
        return ""
    if isinstance(headers, str):
        return headers
    try:
        return "\n".join(f"{k}: {v}" for k, v in dict(headers).items())
    except Exception:
        return str(headers)


def _record_zap_history(method: str, path: str, *,
                        full_url: Optional[str] = None,
                        status_code: str = "0",
                        request_headers: Any = None,
                        request_body: Any = "",
                        response_headers: Any = None,
                        response_body: Any = "",
                        response_length: int = 0,
                        source: str = "zap",
                        session_id: Optional[str] = None,
                        module_id: Optional[str] = None) -> Dict[str, Any]:
    """Record one request/response into ZAP tool history.

    Stores the full Burp-like detail (method, url, path, request headers+body,
    response status+headers+body+length, source, session/module, timestamp) with
    safe truncation so oversized bodies can't break the Inspector UI.
    """
    url = full_url or f"http://target-agent{path}"
    row = {
        "id": len(_zap_history),
        "timestamp": time.time(),
        "method": (method or "").upper(),
        # Keep url/status_code for older consumers; add explicit new field names.
        "url": url,
        "full_url": url,
        "path": path,
        "request_headers": _truncate(_headers_to_str(request_headers), MAX_HISTORY_HEADER_LEN),
        "request_body": _truncate(request_body, MAX_HISTORY_BODY_LEN),
        "status_code": str(status_code),
        "response_status": str(status_code),
        "response_headers": _truncate(_headers_to_str(response_headers), MAX_HISTORY_HEADER_LEN),
        "response_body": _truncate(response_body, MAX_HISTORY_BODY_LEN),
        "response_length": response_length,
        "source": source,
        "session_id": session_id,
        "module_id": module_id,
    }
    with _zap_history_lock:
        _zap_history.append(row)
        if len(_zap_history) > _evidence_max:
            del _zap_history[:len(_zap_history) - _evidence_max]
    return row


def get_zap_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch ZAP tool history (newest last). Includes Operator browser traffic
    proxied through ZAP (source="browser") plus Repeater/Fuzzer requests."""
    with _zap_history_lock:
        local = list(_zap_history)[-limit:]
    if local:
        return local
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
                      body: Optional[str] = None,
                      *,
                      module_id: Optional[str] = None,
                      session_id: Optional[str] = None,
                      via: str = "zap_repeater",
                      record_event: bool = True) -> Dict[str, Any]:
    """Send a request through ZAP to the local target-agent only."""
    try:
        safe_path = normalize_zap_target_path(path)
    except ValueError as exc:
        return {"status": "blocked", "detail": str(exc)}
    url = f"http://target-agent{safe_path}"

    try:
        # Use ZAP's sendRequest API. Inject the AttenseAttackBox User-Agent so
        # target-agent's detect_via() classifies this as via=attackbox and the
        # event credits operator-mode progress (otherwise it'd be via=unknown).
        # Also pass the session id so target-agent can attribute the resulting
        # evidence to this learner rather than leaving it session-unscoped.
        request_header = (
            f"{method.upper()} {url} HTTP/1.1\r\n"
            f"Host: target-agent\r\n"
            f"User-Agent: AttenseAttackBox-ZAP/1.0\r\n"
        )
        if session_id:
            request_header += f"X-Attense-Session: {session_id}\r\n"
        headers = dict(headers or {})
        has_ct = any(k.lower() == "content-type" for k in headers)
        if body and not has_ct and not body.lstrip().startswith("{"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        # Preserve caller-supplied headers EXCEPT Host/User-Agent which we own.
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
            parsed = _parse_zap_response(data)
            status_code = parsed.get("status_code", "0")
            length = int(parsed.get("length") or 0)
            _record_zap_history(
                method, safe_path, full_url=url, status_code=status_code,
                request_headers=request_header, request_body=body or "",
                response_headers=parsed.get("_resp_header", ""),
                response_body=parsed.get("_body", ""),
                response_length=length, source=via,
                session_id=session_id, module_id=module_id,
            )
            if record_event:
                record_tool_evidence(
                    tool="zap_repeater",
                    command=f"{method.upper()} {safe_path}",
                    module_id=module_id,
                    session_id=session_id,
                    event_type="zap_repeater_request",
                    severity="info",
                    via="zap_repeater",
                    extra={
                        "path": safe_path,
                        "method": method.upper(),
                        "status_code": status_code,
                        "response_length": length,
                    },
                )
            return {
                "status": "ok",
                "path": safe_path,
                "url": url,
                "response": data,
                "parsed": {k: v for k, v in parsed.items() if not k.startswith("_")},
                # Surface the response detail directly so the Repeater/Inspector
                # can show headers + body without re-parsing the raw ZAP reply.
                "response_status": status_code,
                "response_headers": parsed.get("_resp_header", ""),
                "response_body": _truncate(parsed.get("_body", ""), MAX_HISTORY_BODY_LEN),
                "response_length": length,
                "request_headers": request_header,
                "request_body": body or "",
            }
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
        return {"status": "error", "detail": str(e)}


# Cap the wordlist so the Fuzzer can't be turned into a real flood against the
# lab target. 200 is plenty for the planted credentials + a mini leaked list.
FUZZER_MAX_PAYLOADS = 200


def _parse_zap_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Pull status code, body length, and body text out of a ZAP sendRequest reply."""
    try:
        msg = (data.get("sendRequest") or [{}])[0]
    except (AttributeError, IndexError, TypeError):
        msg = {}
    resp_header = msg.get("responseHeader", "") or ""
    body = msg.get("responseBody", "") or ""
    parts = resp_header.split(" ")
    status_code = parts[1] if len(parts) > 1 else "0"
    return {"status_code": status_code, "length": len(body),
            "_body": body, "_resp_header": resp_header}


def zap_fuzzer_send(method: str, path: str, body_template: str,
                    marker: str = "§", payloads: Optional[List[str]] = None,
                    headers: Optional[Dict] = None,
                    grep: Optional[str] = None,
                    *,
                    module_id: Optional[str] = None,
                    session_id: Optional[str] = None) -> Dict[str, Any]:
    """ZAP Intruder-style fuzzer: replace `marker` in body_template with each
    payload and replay through ZAP, one request per payload (target-agent only).

    `grep` is Burp Intruder's "Grep - Match": if set, each row reports whether
    the response body contains that string (used for username enumeration, where
    matching "Incorrect password" is far more reliable than eyeballing length).

    Returns [{payload, status_code, length, grep_match, status_hit, length_hit,
    grep_hit, hit}]. `hit` is the anomaly worth highlighting.
    """
    payloads = [p for p in (payloads or []) if p != ""]
    try:
        safe_path = normalize_zap_target_path(path)
    except ValueError as exc:
        return {"status": "blocked", "detail": str(exc)}
    if marker not in body_template:
        return {"status": "error",
                "detail": f"Marker '{marker}' not found in the request body"}
    # Burp Intruder baseline: with no payloads, send the base request once
    # (item 0) - marker stripped from the body - instead of erroring.
    base_request = not payloads
    if base_request:
        payloads = [""]
    if len(payloads) > FUZZER_MAX_PAYLOADS:
        payloads = payloads[:FUZZER_MAX_PAYLOADS]
    payload_count = len(payloads)

    record_tool_evidence(
        tool="zap_fuzzer",
        command=f"{method.upper()} {safe_path}",
        module_id=module_id,
        session_id=session_id,
        event_type="zap_fuzzer_started",
        severity="info",
        via="zap_fuzzer",
        extra={
            "path": safe_path,
            "method": method.upper(),
            "payload_count": payload_count,
            "grep": grep,
        },
    )

    # Default the form Content-Type when the caller didn't set one and the body
    # isn't JSON. Without it Flask never parses request.form, so every login
    # 401s and the valid credential never stands out - the whole point here.
    headers = dict(headers or {})
    has_ct = any(k.lower() == "content-type" for k in headers)
    if not has_ct and body_template and not body_template.lstrip().startswith("{"):
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    grep_l = grep.lower() if grep else None
    results: List[Dict[str, Any]] = []
    for payload in payloads:
        body = body_template.replace(marker, payload)
        label = "(base request)" if base_request else payload
        r = zap_repeater_send(
            method=method,
            path=safe_path,
            headers=headers,
            body=body,
            module_id=module_id,
            session_id=session_id,
            via="zap_fuzzer",
            record_event=False,
        )
        if r.get("status") == "ok":
            parsed = _parse_zap_response(r.get("response", {}))
            resp_body = parsed.pop("_body", "")
            grep_match = bool(grep_l and grep_l in resp_body.lower())
            row = {"payload": label, "grep_match": grep_match, **parsed}
            results.append(row)
            record_tool_evidence(
                tool="zap_fuzzer",
                command=f"{method.upper()} {safe_path}",
                module_id=module_id,
                session_id=session_id,
                event_type="zap_fuzzer_payload_tested",
                severity="info",
                via="zap_fuzzer",
                extra={
                    "path": safe_path,
                    "method": method.upper(),
                    "payload": label,
                    "status_code": row.get("status_code"),
                    "response_length": row.get("length"),
                    "grep": grep,
                    "grep_match": grep_match,
                },
            )
        else:
            row = {"payload": label, "status_code": "ERR",
                   "length": 0, "grep_match": False,
                   "detail": r.get("detail", "")}
            results.append(row)
            record_tool_evidence(
                tool="zap_fuzzer",
                command=f"{method.upper()} {safe_path}",
                module_id=module_id,
                session_id=session_id,
                event_type="zap_fuzzer_payload_tested",
                severity="warning",
                via="zap_fuzzer",
                extra={
                    "path": safe_path,
                    "method": method.upper(),
                    "payload": label,
                    "status_code": "ERR",
                    "response_length": 0,
                    "error": r.get("detail", ""),
                },
            )

    # Anomaly detection - matching how Burp Intruder is read:
    #   . GREP MATCH -> username enumeration: the response for a valid user
    #                  contains "Incorrect password"; invalid users don't. This
    #                  is the reliable tell (length is noisy when the app
    #                  reflects the username, so we don't flag on length here).
    #   . STATUS outlier -> password brute force: one login returns 302, rest 401.
    ok_rows = [r for r in results if r["status_code"] not in ("ERR", "0")]
    codes = [r["status_code"] for r in ok_rows]
    lengths = [r["length"] for r in ok_rows]
    modal_status = max(set(codes), key=codes.count) if codes else None
    modal_length = max(set(lengths), key=lengths.count) if lengths else None
    grep_used = grep_l is not None
    for row in results:
        sc = row["status_code"]
        valid = sc not in ("ERR", "0")
        status_hit = valid and (sc.startswith("3") or (modal_status is not None and sc != modal_status))
        length_hit = valid and (modal_length is not None and row["length"] != modal_length)
        grep_hit = bool(row.get("grep_match"))
        row["status_hit"] = bool(status_hit)
        row["length_hit"] = bool(length_hit)
        row["grep_hit"] = grep_hit
        # When a grep string is supplied it is the authoritative tell (username
        # enumeration); otherwise fall back to status/length outliers.
        row["hit"] = grep_hit if grep_used else bool(status_hit or length_hit)

    hit_rows = [r for r in results if r.get("hit")]
    for row in hit_rows:
        record_tool_evidence(
            tool="zap_fuzzer",
            command=f"{method.upper()} {safe_path}",
            module_id=module_id,
            session_id=session_id,
            event_type="zap_fuzzer_match_found",
            severity="high",
            via="zap_fuzzer",
            extra={
                "path": safe_path,
                "method": method.upper(),
                "payload": row.get("payload"),
                "status_code": row.get("status_code"),
                "response_length": row.get("length"),
                "grep": grep,
                "grep_match": row.get("grep_match"),
                "status_hit": row.get("status_hit"),
                "length_hit": row.get("length_hit"),
            },
        )

    record_tool_evidence(
        tool="zap_fuzzer",
        command=f"{method.upper()} {safe_path}",
        module_id=module_id,
        session_id=session_id,
        event_type="zap_fuzzer_completed",
        severity="info",
        via="zap_fuzzer",
        extra={
            "path": safe_path,
            "method": method.upper(),
            "payload_count": payload_count,
            "grep": grep,
            "modal_status": modal_status,
            "modal_length": modal_length,
            "match_count": len(hit_rows),
            "success_or_outlier_found": bool(hit_rows),
        },
    )

    return {"status": "ok", "path": safe_path, "modal_status": modal_status,
            "modal_length": modal_length, "grep": grep, "results": results}


def _zap_browse_target_path(path: str) -> Optional[str]:
    """Map an incoming /target-zap/<path> tail to a target-agent path.

    Operator surfaces live under /op/*; the injected telemetry script, static
    assets and the containment webhook are app-level and stay un-prefixed.
    Returns None if the path tries to smuggle a scheme/host (defense in depth).
    """
    raw = path or ""
    # Reject any smuggled scheme/host BEFORE stripping leading slashes -
    # "//evil.com/" must be caught here, not after lstrip("/") has already
    # eaten the very "//" prefix this check looks for. nginx also collapses
    # "http://" to "http:/", so guard on the ":/" shape too - no legitimate
    # /op path contains it.
    if "://" in raw or ":/" in raw or raw.startswith("//"):
        return None
    safe = raw.lstrip("/")
    if not safe:
        return "/op/"
    if safe.startswith(_APP_LEVEL_PREFIXES):
        return "/" + safe
    return "/op/" + safe


def browse_through_zap(method: str, path: str, query_string: str = "", *,
                       req_headers: Optional[Dict[str, str]] = None,
                       body: bytes = b"",
                       host: str = "target-agent",
                       session_id: Optional[str] = None,
                       module_id: Optional[str] = None) -> Dict[str, Any]:
    """Reverse-proxy one Operator-mode browser request through ZAP to the local
    target, so it lands in ZAP history like Burp Proxy History.

    Local-only by construction: the upstream host is always target-agent and the
    path is validated by _zap_browse_target_path - an external target can never
    be reached through this endpoint.

    Returns {status_code, headers: [(k, v), ...], content: bytes}. Multiple
    Set-Cookie headers are preserved; Location is rewritten host-relative so
    redirects stay inside the /target-zap iframe.
    """
    target_path = _zap_browse_target_path(path)
    if target_path is None:
        return {"status_code": 400,
                "headers": [("Content-Type", "text/plain; charset=utf-8")],
                "content": b"Blocked: only local target-agent paths are allowed."}

    url = f"http://target-agent{target_path}"
    if query_string:
        url += "?" + query_string

    fwd: Dict[str, str] = {}
    for k, v in (req_headers or {}).items():
        if k.lower() in _PROXY_DROP_REQ_HEADERS:
            continue
        fwd[k] = v
    # We own these three headers.
    fwd["Host"] = host or "target-agent"          # so target emits frontend-origin URLs
    fwd["User-Agent"] = BROWSER_PROXY_UA          # browser channel (non-completing)
    fwd["X-Forwarded-Prefix"] = "/target-zap"     # keeps links/forms inside the iframe
    fwd["Accept-Encoding"] = "identity"           # avoid gzip so we can pass bytes verbatim
    if session_id:
        fwd["X-Attense-Session"] = session_id

    try:
        r = requests.request(
            method, url, headers=fwd, data=body or None,
            proxies={"http": ZAP_PROXY_URL}, allow_redirects=False, timeout=25,
        )
    except requests.RequestException as exc:
        return {"status_code": 502,
                "headers": [("Content-Type", "text/plain; charset=utf-8")],
                "content": f"ZAP proxy error: {exc}".encode("utf-8")}

    # Record full request/response into ZAP tool history (Burp-Proxy-History
    # style). source="browser" so it shows up but never completes a mission.
    try:
        req_body_str = body.decode("utf-8", "replace") if body else ""
    except Exception:
        req_body_str = ""
    try:
        resp_body_str = r.content.decode("utf-8", "replace") if r.content else ""
    except Exception:
        resp_body_str = ""
    try:
        _record_zap_history(
            method, target_path, full_url=url, status_code=str(r.status_code),
            request_headers=fwd, request_body=req_body_str,
            response_headers=r.headers, response_body=resp_body_str,
            response_length=len(r.content), source="browser",
            session_id=session_id, module_id=module_id,
        )
    except Exception:
        pass

    out_headers: List[tuple] = []
    # Preserve every Set-Cookie individually (requests collapses them otherwise).
    raw = getattr(getattr(r, "raw", None), "headers", None)
    set_cookies = raw.getlist("Set-Cookie") if raw is not None and hasattr(raw, "getlist") else []
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in _PROXY_DROP_RESP_HEADERS or lk == "set-cookie":
            continue
        if lk == "location":
            # Make redirects host-relative so they resolve against the frontend
            # origin under /target-zap/ instead of escaping to target-agent.
            v = re.sub(r"^https?://[^/]+", "", v)
        out_headers.append((k, v))
    for c in set_cookies:
        out_headers.append(("Set-Cookie", c))

    return {"status_code": r.status_code, "headers": out_headers, "content": r.content}
