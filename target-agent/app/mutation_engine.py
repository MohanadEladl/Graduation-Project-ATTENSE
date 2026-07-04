"""
target-agent/app/mutation_engine.py — In-memory mutation state for the vulnerable target app.

Mutations change the behaviour of vulnerable routes mid-mission to force
the learner to adapt. Each mutation is keyed by session_id and module_id.
"""
import threading

MUTATIONS = {
    "brute_force": [
        {
            "id": "bf_delay",
            "module_id": "brute_force",
            "label": "Rate Limiter Added",
            "description": "A 2-second delay is injected on every login attempt.",
            "hint": "Try spacing your requests or using a slower wordlist.",
            "impact": "HIGH",
        },
        {
            "id": "bf_lockout",
            "module_id": "brute_force",
            "label": "Account Lockout Enabled",
            "description": "After 5 failed attempts the account is locked for 60 seconds.",
            "hint": "Watch for 403 responses and rotate your target accounts.",
            "impact": "HIGH",
        },
    ],
    "xss": [
        {
            "id": "xss_encode",
            "module_id": "xss",
            "label": "Output Encoding Partial",
            "description": "Angle brackets are HTML-encoded, but event handlers are still injectable.",
            "hint": "Try event-handler based payloads: onerror=, onload=.",
            "impact": "MEDIUM",
        },
        {
            "id": "xss_csp",
            "module_id": "xss",
            "label": "CSP Header Added",
            "description": "A Content-Security-Policy header blocks inline scripts.",
            "hint": "Look for script-src bypasses or data-uri techniques.",
            "impact": "CRITICAL",
        },
        {
            "id": "xss_script_filtered",
            "module_id": "xss",
            "label": "Script Tag Filtered",
            "description": "<script> tags are stripped before reflection.",
            "hint": "Use event-handler payloads: onerror, onload, onfocus.",
            "impact": "MEDIUM",
        },
    ],
    "cmd_injection": [
        {
            "id": "ci_filter_pipe",
            "module_id": "cmd_injection",
            "label": "Pipe Filtered",
            "description": "The pipe character | is stripped from the host input.",
            "hint": "Try other separators: semicolon, backtick, $().",
            "impact": "MEDIUM",
        },
        {
            "id": "ci_filter_semi",
            "module_id": "cmd_injection",
            "label": "Semicolon Filtered",
            "description": "Semicolons are stripped from the host input.",
            "hint": "Try pipe or backtick injection instead.",
            "impact": "MEDIUM",
        },
    ],
    "dir_traversal": [
        {
            "id": "dt_dotdot_filtered",
            "module_id": "dir_traversal",
            "label": "Dot-Dot Filtered",
            "description": "The sequence ../ is stripped from the path input.",
            "hint": "Try URL encoding: ..%2f or double encoding: ..%252f.",
            "impact": "HIGH",
        },
        {
            "id": "dt_absolute_path_only",
            "module_id": "dir_traversal",
            "label": "Absolute Path Blocked",
            "description": "Paths starting with / are rejected — only relative paths are allowed.",
            "hint": "Use relative traversal from the app root without a leading slash.",
            "impact": "MEDIUM",
        },
    ],
    "file_upload": [
        {
            "id": "fu_extension_blocklist",
            "module_id": "file_upload",
            "label": "Extension Blocklist Active",
            "description": "Common executable extensions (.php, .py, .sh) are rejected.",
            "hint": "Try double extensions (.php.jpg), null bytes, or uncommon executable types.",
            "impact": "HIGH",
        },
        {
            "id": "fu_mime_check",
            "module_id": "file_upload",
            "label": "MIME Type Check Added",
            "description": "The server now validates Content-Type must match image/*.",
            "hint": "Intercept the upload and set Content-Type: image/jpeg while keeping the .php payload.",
            "impact": "HIGH",
        },
    ],
    "csrf": [
        {
            "id": "csrf_referer_check",
            "module_id": "csrf",
            "label": "Referer Check Partial",
            "description": "The server validates that the Referer header originates from the same host.",
            "hint": "Try omitting the Referer header entirely — some implementations only block wrong origins.",
            "impact": "MEDIUM",
        },
        {
            "id": "csrf_json_only",
            "module_id": "csrf",
            "label": "JSON-Only Update",
            "description": "The state-changing endpoint now only accepts application/json, breaking form-based CSRF.",
            "hint": "Use fetch() with a CORS-preflighted JSON body to bypass the simple-request restriction.",
            "impact": "HIGH",
        },
    ],
}


class MutationEngine:
    """Thread-safe in-memory mutation state keyed by session_id."""

    def __init__(self):
        self._state: dict = {}   # {session_id: {module_id: mutation_id or None}}
        self._lock = threading.Lock()

    def get_active(self, session_id: str, module_id: str):
        """Return the active mutation dict for (session_id, module_id), or None."""
        with self._lock:
            session_state = self._state.get(session_id, {})
            mutation_id = session_state.get(module_id)
            if mutation_id is None:
                mutation_id = self._state.get("*", {}).get(module_id)
            if mutation_id is None:
                return None
            for m in MUTATIONS.get(module_id, []):
                if m["id"] == mutation_id:
                    return m
            return None

    def set_mutation(self, session_id: str, module_id: str, mutation_id: str) -> dict:
        """
        Activate a mutation. Returns the mutation dict.
        Raises KeyError if module_id or mutation_id not found in MUTATIONS.
        """
        if module_id not in MUTATIONS:
            raise KeyError("Unknown module_id: " + module_id)
        mutation_dict = None
        for m in MUTATIONS[module_id]:
            if m["id"] == mutation_id:
                mutation_dict = m
                break
        if mutation_dict is None:
            raise KeyError("Unknown mutation_id: " + mutation_id)
        with self._lock:
            if session_id not in self._state:
                self._state[session_id] = {}
            self._state[session_id][module_id] = mutation_id
        return mutation_dict

    def clear_mutation(self, session_id: str, module_id: str) -> None:
        """Deactivate any mutation for (session_id, module_id)."""
        with self._lock:
            if session_id in self._state:
                self._state[session_id].pop(module_id, None)

    def list_active(self, session_id: str) -> list:
        """Return list of all active mutations for a session_id as dicts with module_id included."""
        result = []
        with self._lock:
            session_state = dict(self._state.get(session_id, {}))
            for module_id, mutation_id in self._state.get("*", {}).items():
                session_state.setdefault(module_id, mutation_id)
        for module_id, mutation_id in session_state.items():
            for m in MUTATIONS.get(module_id, []):
                if m["id"] == mutation_id:
                    entry = dict(m)
                    entry["module_id"] = module_id
                    result.append(entry)
                    break
        return result


_engine = MutationEngine()


def get_active(session_id, module_id):
    return _engine.get_active(session_id, module_id)


def request_keys(req) -> list:
    """Candidate session keys for proxied iframe, API, and direct tool traffic."""
    keys = [
        req.headers.get("X-Attense-Session"),
        req.cookies.get("attense_sid"),
        req.args.get("__attense_sid"),
        req.form.get("__attense_sid") if getattr(req, "form", None) is not None else None,
        req.remote_addr,
        "*",
    ]
    seen = set()
    out = []
    for key in keys:
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def get_active_for_request(req, module_id):
    for key in request_keys(req):
        active = get_active(key, module_id)
        if active:
            return active
    return None


def set_mutation(session_id, module_id, mutation_id):
    return _engine.set_mutation(session_id, module_id, mutation_id)


def clear_mutation(session_id, module_id):
    return _engine.clear_mutation(session_id, module_id)


def list_active(session_id):
    result = _engine.list_active(session_id)
    with _flat_lock:
        active = set(_flat_active.get(session_id, set())) | set(_flat_active.get("*", set()))
    for mid in sorted(active):
        meta = FLAT_MUTATIONS.get(mid)
        if not meta:
            continue
        result.append({
            "id": mid,
            "mutation_id": mid,
            "module_id": meta.get("module"),
            "label": meta.get("name"),
            "description": meta.get("description"),
            "affected_endpoint": meta.get("affected_endpoint"),
        })
    return result


# ─── v8 compatibility aliases ────────────────────────────────────────────────
# The Phase 3 plan added /lab/mutations/activate and /lab/mutations/deactivate
# endpoints with a flat mutation_id (not module_id + mutation_id).
# These helpers bridge the two APIs by extracting the module prefix.

FLAT_MUTATIONS = {
    "bf_json_required": {
        "module": "brute_force", "name": "JSON Body Required",
        "description": "Login endpoint now only accepts application/json. curl form posts will fail.",
        "affected_endpoint": "/auth/login",
    },
    "bf_endpoint_renamed": {
        "module": "brute_force", "name": "Endpoint Renamed",
        "description": "Login moved from /auth/login to /auth/signin.",
        "affected_endpoint": "/auth/signin",
    },
    "xss_script_filtered": {
        "module": "xss", "name": "Script Tag Filtered",
        "description": "<script> tags are stripped. Use event handlers: onerror, onload.",
        "affected_endpoint": "/search",
    },
    "xss_param_renamed": {
        "module": "xss", "name": "Parameter Renamed",
        "description": "Query parameter changed from 'q' to 'query'.",
        "affected_endpoint": "/search",
    },
    "cmd_semicolon_filtered": {
        "module": "cmd_injection", "name": "Semicolon Filtered",
        "description": "The ; character is stripped. Use && or | instead.",
        "affected_endpoint": "/system/ping",
    },
    "cmd_param_renamed": {
        "module": "cmd_injection", "name": "Parameter Renamed",
        "description": "Parameter changed from 'host' to 'target'.",
        "affected_endpoint": "/system/ping",
    },
    "dt_dotdot_filtered": {
        "module": "dir_traversal", "name": "Dot-Dot Filtered",
        "description": "The sequence ../ is stripped from path input. Try URL encoding.",
        "affected_endpoint": "/files/read",
    },
    "fu_extension_blocklist": {
        "module": "file_upload", "name": "Extension Blocklist Active",
        "description": "Executable extensions (.php, .py, .sh) are rejected.",
        "affected_endpoint": "/files/upload",
    },
    "csrf_referer_check": {
        "module": "csrf", "name": "Referer Check Partial",
        "description": "Referer header is validated. Try omitting it entirely.",
        "affected_endpoint": "/profile/update",
    },
}

# Per-session active flat mutation_ids (separate from the module-keyed engine)
import threading as _threading
_flat_lock = _threading.Lock()
_flat_active: dict = {}   # session_id -> set of mutation_ids


def activate(session_id: str, mutation_id: str) -> None:
    """Activate a flat mutation_id for a session."""
    if mutation_id not in FLAT_MUTATIONS:
        raise KeyError(f"Unknown mutation: {mutation_id}")
    with _flat_lock:
        _flat_active.setdefault(session_id, set()).add(mutation_id)


def deactivate(session_id: str, mutation_id: str) -> None:
    """Deactivate a flat mutation_id for a session."""
    with _flat_lock:
        _flat_active.get(session_id, set()).discard(mutation_id)


def get_flat_active(session_id: str) -> set:
    """Return the set of active flat mutation_ids for a session."""
    with _flat_lock:
        return set(_flat_active.get(session_id, set())) | set(_flat_active.get("*", set()))


def get_flat_active_for_request(req) -> set:
    active = set()
    for key in request_keys(req):
        active |= get_flat_active(key)
    return active


def status(session_id: str) -> dict:
    """Return activation status dict for a session."""
    import time as _time
    with _flat_lock:
        active = list(_flat_active.get(session_id, set()))
    return {
        "session_id": session_id,
        "mutations": [{"id": m} for m in active],
    }


def reset_flat(session_id: str = None) -> None:
    """Clear flat mutations for one session or all sessions."""
    global _flat_active
    with _flat_lock:
        if session_id is None:
            _flat_active = {}
        else:
            _flat_active.pop(session_id, None)
