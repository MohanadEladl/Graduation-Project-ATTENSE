"""Shared attack-pattern helpers for target-lab guided and operator routes."""
from __future__ import annotations

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
COMMAND_OUTPUT_INDICATORS = ("uid=", "root:", "/bin/", "/etc/", "drwx", "-rwx", "Linux ")
SENSITIVE_FILE_MARKERS = ("root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:")

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
    return bool(value) and _contains(value, COMMAND_OUTPUT_INDICATORS, case_sensitive=True)


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