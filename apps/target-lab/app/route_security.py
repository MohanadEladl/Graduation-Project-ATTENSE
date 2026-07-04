"""Shared attack-pattern helpers for target-lab guided and operator routes."""
from __future__ import annotations

import re
import socket

XSS_PAYLOAD_MARKERS = (
"<script",
"</script",
"onerror=",
"onload=",
"onclick=",
"onmouseover=",
"javascript:",
"<svg",
"<img ",
"<iframe",
)

XSS_EFFECTIVE_MARKERS = (
"onerror=",
"onload=",
"onclick=",
"onmouseover=",
"javascript:",
"<svg",
"<img ",
"<iframe",
)

SHELL_SEPARATORS = (";", "|", "&&", "||", "`", "$(")
# Substring markers for common RCE-proof command output. Safe against real
# ping output, which only ever contains "PING", "bytes from", "time=",
# "ttl=", and packet-loss/round-trip stats - none of these strings appear
# there, so this stays false-positive-safe while covering more commands
# than the original id/cat-/etc/passwd/ls-la/uname-a set (uid=, root:,
# /bin/, /etc/, drwx, -rwx, Linux ).
COMMAND_OUTPUT_INDICATORS = (
"uid=", "root:", "/bin/", "/etc/", "drwx", "-rwx", "Linux ",
"PATH=",                 # env
"eth0", "lo:",           # ifconfig / ip addr interface names
"inet addr:", "inet ",   # ifconfig / ip addr address lines
)
SENSITIVE_FILE_MARKERS = ("root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:")

# `whoami`/`hostname`/`cat /etc/hostname` all print the container's actual
# hostname or a bare username with no other distinguishing text, so they
# can't be caught by a fixed substring list - resolved once at import time.
_CONTAINER_HOSTNAME = socket.gethostname().strip()

# Injected-command output is concatenated with the ping command's own
# output (e.g. "127.0.0.1;whoami" runs both, so `value` contains ping's
# multi-line output followed by whoami's), so these patterns are checked
# per-line rather than against the whole string.
_ABSOLUTE_PATH_ONLY_RE = re.compile(r"^/[\w./-]+$")          # `pwd`-style
_BARE_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")  # `whoami`-style

GUIDED_DANGEROUS_UPLOAD_EXTENSIONS = (
".php",
".phtml",
".jsp",
".jspx",
".asp",
".aspx",
".sh",
".py",
".pl",
".cgi",
".html",
".htm",
".svg",
".js",
".exe",
)

OPERATOR_BLOCKED_UPLOAD_EXTENSIONS = (
".php",
".phps",
".exe",
".sh",
".py",
".pl",
".cgi",
".jsp",
".jspx",
".asp",
".aspx",
)

OPERATOR_DANGEROUS_BUT_ACCEPTED_EXTENSIONS = (
".phtml",
".svg",
".html",
".htm",
".js",
)


def _contains(value: str, markers: tuple[str, ...], *, case_sensitive: bool = False) -> bool:
    haystack = value if case_sensitive else value.lower()
    needles = markers if case_sensitive else tuple(marker.lower() for marker in markers)
    return any(marker in haystack for marker in needles)


def has_xss_payload(value: str) -> bool:
    return bool(value) and _contains(value, XSS_PAYLOAD_MARKERS)


def has_effective_xss_payload(value: str) -> bool:
    return bool(value) and _contains(value, XSS_EFFECTIVE_MARKERS)


def has_shell_separator(value: str) -> bool:
    return bool(value) and _contains(value, SHELL_SEPARATORS, case_sensitive=True)


def has_command_output_indicator(value: str) -> bool:
    if not value:
        return False
    if _contains(value, COMMAND_OUTPUT_INDICATORS, case_sensitive=True):
        return True
    # `hostname` / `cat /etc/hostname` output appearing anywhere in the
    # (ping output + injected command output) blob.
    if _CONTAINER_HOSTNAME and _CONTAINER_HOSTNAME in value:
        return True
    # `whoami` (bare username) / `pwd` (bare absolute path) output: checked
    # per-line since injected-command output is appended after ping's own
    # multi-line output, not the entire value.
    for line in value.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _ABSOLUTE_PATH_ONLY_RE.match(stripped) or _BARE_USERNAME_RE.match(stripped):
            return True
    return False


def has_traversal_pattern(path: str) -> bool:
    value = path or ""
    lowered = value.lower()
    return (
    ".." in value
    or "%2e%2e" in lowered
    or value.startswith("/etc/")
    or value.startswith("/proc/")
    or "passwd" in lowered
    or "shadow" in lowered
    )


def has_sensitive_file_content(content: str) -> bool:
    return bool(content) and _contains(content, SENSITIVE_FILE_MARKERS, case_sensitive=True)


def has_extension(filename: str, extensions: tuple[str, ...]) -> bool:
    lowered = (filename or "").lower()
    return any(lowered.endswith(extension) for extension in extensions)