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

import ipaddress
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

import json
import docker as docker_sdk


# ── Configuration ────────────────────────────────────────────────────────────
ATTACKBOX_CONTAINER = os.getenv("ATTACKBOX_CONTAINER", "attense_attackbox")
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "attense-lab-key")
ZAP_ALLOWED_HOSTS = {"target-agent"}
ZAP_ALLOWED_SCHEMES = {"http", "https"}

# Approved local lab target
BLOCKED_EXTERNAL_MSG = "Blocked: external targets are not allowed. Approved target: target-agent."
ALLOWED_TARGETS = {"target-agent", "http://target-agent", "http://target-agent:80"}
ALLOWED_HOSTNAME_RE = re.compile(r"^target-agent(:\d+)?$")

# Only these tools are supported in the student AttackBox.
ALLOWED_TOOLS = {
    "curl", "nmap", "hydra", "ffuf", "gobuster", "wget", "nc", "ncat",
    "jq", "grep", "cat", "echo", "ls", "sed", "awk", "head", "tail",
    "wc", "sort", "uniq", "tr", "pwd",
}
SHELL_WRAPPER_TOOLS = {"bash", "sh", "python", "python3", "perl", "ruby", "node"}

# Tools we recognise from command prefixes, including blocked tools so the UI
# can explain what was refused.
KNOWN_TOOLS = ALLOWED_TOOLS | SHELL_WRAPPER_TOOLS | {
    "dig", "nslookup", "ping", "host", "docker", "sudo", "su",
}

# Blocked command patterns (destructive, escape-attempt, or privilege-escalation)
BLOCKED_PATTERNS = [
    r"\brm\s+-rf\b", r"\brm\s+-r\b", r"\bmkfs\b", r"\bdd\s+if=",
    r"\bchmod\s+777\b", r"\bchown\b", r"\bshutdown\b", r"\breboot\b",
    r"\bpoweroff\b", r"\binit\s+[06]\b", r"\bkill\s+-9\s+1\b",
    r"\bdocker\b", r"\bkubectl\b", r"\bsudo\b", r"\bsu\s+",
    r"\bapt\b", r"\bapk\b", r"\byum\b", r"\bpip\s+install\b",
    r"\bpython[0-9.]*\s+-c\b", r"\bperl\s+-e\b", r"\bruby\s+-e\b", r"\bnode\s+-e\b",
    r"\bbash\s+-l?c\b", r"\bsh\s+-c\b",
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
    if ALLOWED_HOSTNAME_RE.match(h):
        return False
    # Any IP that is not the approved target hostname is blocked.
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
    return True


def _split_command(cmd: str) -> list[str]:
    return shlex.split(cmd, posix=True)


def _host_from_url_or_bare(value: str) -> Optional[str]:
    raw = (value or "").strip().strip("'\"")
    if not raw:
        return None
    if re.match(r"^https?://", raw, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(raw)
        return parsed.hostname
    if raw.startswith("target-agent/"):
        return "target-agent"
    host = raw.split("/")[0].split(":")[0]
    if host == "target-agent":
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if "." in host:
        return host
    return None


def _consume_next_option(tool_name: str, token: str) -> bool:
    common = {
        "-o", "--output", "-H", "--header", "-A", "--user-agent",
        "-d", "--data", "--data-raw", "--data-binary", "--form", "-F",
    }
    by_tool = {
        "curl": common | {"-X", "--request", "-b", "--cookie", "-c", "--cookie-jar", "-u", "--user"},
        "wget": {"-O", "--output-document", "-P", "--directory-prefix", "-U", "--user-agent", "--referer"},
        "nmap": {"-p", "-iL", "-oN", "-oX", "-oG", "-oA", "--script", "-e", "-S",
                 "--source-port", "--data-length", "--ttl", "--max-retries",
                 "--host-timeout", "--scan-delay", "--min-rate", "--max-rate", "-T"},
        "hydra": {"-l", "-L", "-p", "-P", "-t", "-s", "-o", "-b", "-w", "-W", "-c",
                  "-e", "-m", "-x"},
        "ffuf": {"-w", "-H", "-X", "-d", "-b", "-mode", "-mc", "-fc", "-fs", "-fw", "-fl",
                 "-ac", "-rate", "-t", "-timeout", "-replay-proxy"},
        "gobuster": {"-w", "-x", "-m", "-k", "-t", "-a", "-p", "-c", "-H", "--wordlist", "--extensions"},
        "nc": {"-p", "-s", "-w", "-i"},
        "ncat": {"-p", "-s", "-w", "-i"},
    }
    return token in by_tool.get(tool_name, set())


def _extract_hostnames(cmd: str) -> list[str]:
    """Extract target hostnames from a command string without using a shell."""
    hosts: list[str] = []
    tokens = _split_command(cmd)
    if not tokens:
        return hosts

    for tok in tokens:
        if re.match(r"^https?://", tok, re.IGNORECASE):
            h = _host_from_url_or_bare(tok)
            if h:
                hosts.append(h)

    tool_name = os.path.basename(tokens[0])
    args = tokens[1:]

    if tool_name in ("curl", "wget"):
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                skip_next = _consume_next_option(tool_name, tok)
                continue
            h = _host_from_url_or_bare(tok)
            if h:
                hosts.append(h)

    elif tool_name in ("ffuf", "gobuster"):
        for idx, tok in enumerate(args):
            if tok in ("-u", "--url") and idx + 1 < len(args):
                h = _host_from_url_or_bare(args[idx + 1])
                if h:
                    hosts.append(h)

    elif tool_name == "nmap":
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                skip_next = _consume_next_option(tool_name, tok)
                continue
            h = _host_from_url_or_bare(tok)
            if h:
                hosts.append(h)

    elif tool_name in ("nc", "ncat", "netcat"):
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                skip_next = _consume_next_option(tool_name, tok)
                continue
            h = _host_from_url_or_bare(tok)
            if h:
                hosts.append(h)
                break

    elif tool_name == "hydra":
        skip_next = False
        for tok in args:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                skip_next = _consume_next_option(tool_name, tok)
                continue
            h = _host_from_url_or_bare(tok)
            if h:
                hosts.append(h)
                break

    return hosts


def validate_command(cmd: str) -> Optional[str]:
    """Return an error message if the command should be rejected, else None."""
    stripped = cmd.strip()
    if not stripped:
        return "Empty command."

    try:
        tokens = _split_command(stripped)
    except ValueError:
        return "Blocked: command could not be parsed safely."
    if not tokens:
        return "Empty command."

    control_tokens = {"|", ";", "&&", "||", ">", ">>", "<", "<<", "(", ")"}
    if any(tok in control_tokens or "$(" in tok or "`" in tok for tok in tokens):
        return BLOCKED_EXTERNAL_MSG

    tool = os.path.basename(tokens[0])
    if tool in SHELL_WRAPPER_TOOLS:
        return BLOCKED_EXTERNAL_MSG
    if tool not in ALLOWED_TOOLS:
        return BLOCKED_EXTERNAL_MSG

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
            return BLOCKED_EXTERNAL_MSG

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
        if exit_code == 0 and b"alive" in output:
            return {"status": "running", "container": ATTACKBOX_CONTAINER}
        return {"status": "error", "detail": output.decode("utf-8", errors="replace").strip()}
    except docker_sdk.errors.NotFound:
        return {"status": "stopped", "detail": "attackbox container not found"}
    except docker_sdk.errors.DockerException as e:
        return {"status": "error", "detail": str(e)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def exec_in_attackbox(command: str) -> Dict[str, Any]:
    """Execute a command inside the attackbox container via Docker SDK."""
    err = validate_command(command)
    if err:
        return {"status": "blocked", "command": command, "output": err, "tool": _detect_tool(command)}

    tool = _detect_tool(command)
    tokens = _split_command(command)
    exec_cmd = ["timeout", "--kill-after=2s", f"{MAX_EXEC_TIMEOUT}s", *tokens]

    try:
        client = _docker_client()
        container = client.containers.get(ATTACKBOX_CONTAINER)
        exit_code, output = container.exec_run(
            exec_cmd,
            demux=False,
            socket=False,
        )
        raw = output or b""
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
    except docker_sdk.errors.NotFound:
        return {
            "status": "error",
            "command": command,
            "output": "attackbox container not found.",
            "tool": tool,
        }
    except docker_sdk.errors.DockerException as e:
        return {
            "status": "error",
            "command": command,
            "output": str(e),
            "tool": tool,
        }
    except Exception as e:
        return {
            "status": "error",
            "command": command,
            "output": str(e),
            "tool": tool,
        }


# ── Evidence recording ───────────────────────────────────────────────────────
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


def get_tool_evidence(since: float = 0.0, limit: int = 100) -> List[Dict[str, Any]]:
    """Return tool evidence events after `since`."""
    return [e for e in _evidence_log if e["ts"] >= since][-limit:]


def _tool_message(tool: str, command: str, event_type: str = "tool_command_observed") -> str:
    """Generate a learner-facing evidence description."""
    cmd_short = command[:80] + ("…" if len(command) > 80 else "")
    zap_messages = {
        "zap_repeater_request": "ZAP Repeater sent a request to the local target.",
        "zap_fuzzer_started": "ZAP Fuzzer started payload testing against the local target.",
        "zap_fuzzer_payload_tested": "ZAP Fuzzer tested a payload against the local target.",
        "zap_fuzzer_completed": "ZAP Fuzzer completed payload testing.",
        "zap_fuzzer_match_found": "ZAP Fuzzer found a likely success or response outlier.",
        "tool_used": "A local lab tool was used.",
    }
    if event_type in zap_messages:
        return zap_messages[event_type]
    messages = {
        "nmap":     f"Nmap scan was executed against the local target.",
        "hydra":    f"Hydra brute-force tool was used against the local login form.",
        "curl":     f"curl request was sent to the local target.",
        "ffuf":     f"ffuf fuzzer was run against the local target.",
        "gobuster": f"Gobuster directory scan was run against the local target.",
        "nc":       f"Netcat connection was opened to the local target.",
        "ncat":     f"Ncat connection was opened to the local target.",
        "wget":     f"wget request was sent to the local target.",
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


def normalize_zap_target_path(raw_path: str) -> str:
    """Normalize a user-supplied ZAP target to a local target-agent path."""
    raw = (raw_path or "/").strip()
    if not raw:
        return "/"
    if any(ch in raw for ch in ("\r", "\n")):
        raise ValueError(BLOCKED_EXTERNAL_MSG)

    if re.match(r"^https?://", raw, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(raw)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        if scheme not in ZAP_ALLOWED_SCHEMES or host not in ZAP_ALLOWED_HOSTS:
            raise ValueError(BLOCKED_EXTERNAL_MSG)
        path = parsed.path or "/"
        if "://" in path:
            raise ValueError(BLOCKED_EXTERNAL_MSG)
        if parsed.query:
            path += "?" + parsed.query
        return path

    if raw.startswith("//") or "://" in raw:
        raise ValueError(BLOCKED_EXTERNAL_MSG)
    if raw.startswith("target-agent/"):
        raw = raw[len("target-agent"):]
    if not raw.startswith("/"):
        raw = "/" + raw
    if "://" in raw:
        raise ValueError(BLOCKED_EXTERNAL_MSG)
    return raw


def _record_zap_history(method: str, path: str,
                        status_code: str = "0",
                        response_length: int = 0,
                        source: str = "zap") -> Dict[str, Any]:
    row = {
        "id": len(_zap_history),
        "timestamp": time.time(),
        "method": method.upper(),
        "url": f"http://target-agent{path}",
        "path": path,
        "status_code": status_code,
        "response_length": response_length,
        "source": source,
    }
    with _zap_history_lock:
        _zap_history.append(row)
        if len(_zap_history) > _evidence_max:
            del _zap_history[:len(_zap_history) - _evidence_max]
    return row


def get_zap_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch ZAP tool history. Normal Lab Browser traffic is not proxied here."""
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
        # Use ZAP's sendRequest API. Inject a tool-specific User-Agent so the
        # target-agent evidence can distinguish Repeater and Fuzzer activity.
        user_agent = "AttenseZAPFuzzer/1.0" if via == "zap_fuzzer" else "AttenseZAPRepeater/1.0"
        request_header = (
            f"{method.upper()} {url} HTTP/1.1\r\n"
            f"Host: target-agent\r\n"
            f"User-Agent: {user_agent}\r\n"
        )
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

        import urllib.parse
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
            _record_zap_history(method, safe_path, status_code, length, via)
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
                "parsed": {k: v for k, v in parsed.items() if k != "_body"},
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
    return {"status_code": status_code, "length": len(body), "_body": body}


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
    # (item 0) — marker stripped from the body — instead of erroring.
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
    # 401s and the valid credential never stands out — the whole point here.
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

    # Anomaly detection — matching how Burp Intruder is read:
    #   • GREP MATCH → username enumeration: the response for a valid user
    #                  contains "Incorrect password"; invalid users don't. This
    #                  is the reliable tell (length is noisy when the app
    #                  reflects the username, so we don't flag on length here).
    #   • STATUS outlier → password brute force: one login returns 302, rest 401.
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

