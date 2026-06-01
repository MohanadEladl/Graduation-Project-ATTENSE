# ZAP (OWASP Zed Attack Proxy) — Red Team Component

> OWASP ZAP is the open-source web security scanner/proxy used by the Red Team
> as the primary pentesting and traffic interception tool in the ATTENSE Cyber Range.

---

## What is ZAP?

**ZAP (Zed Attack Proxy)** is an open-source security tool maintained by OWASP.
In this project it acts as a **man-in-the-middle HTTP proxy** between the attacker
and the vulnerable target application, giving the Red Team full visibility and
control over every request and response.

---

## Role in the Architecture

```
Red Team UI / AttackBox
        │
        ▼
    ZAP Proxy  ←── intercepts & logs all HTTP traffic
        │
        ▼
  target-agent (vulnerable Flask app on port 8081)
        │
        ▼
  Wazuh SIEM  →  signal-store  →  blueteam /raise-alert
```

ZAP sits between the attacker and the target, recording every interaction
so attacks are traceable and verifiable.

---

## What ZAP is Used For

| Role | Details |
|---|---|
| **HTTP Proxy** | Intercepts all traffic between the attacker and `target-agent` |
| **Request History** | Logs every HTTP request/response for post-attack analysis |
| **Repeater** | Lets the red team replay or craft custom HTTP requests manually |
| **Attack Evidence** | In **Lab mode**, attacks MUST go through ZAP or AttackBox — browser clicks alone do NOT count as valid evidence |

---

## Configuration

| Setting | Value |
|---|---|
| Internal URL (container-to-container) | `http://zap:8080` |
| API Key | `attense-lab-key` |
| Start flag | `-silent` (skips add-on auto-updates for faster boot) |
| Host exposure | **Not exposed** — only accessible inside `attense_net` via the Red Team backend |

Configured via environment variables in `docker-compose.yml`:

```yaml
ZAP_API_URL: "http://zap:8080"
ZAP_API_KEY: "attense-lab-key"
```

---

## API Endpoints (via Red Team Backend at `http://localhost:8000`)

All ZAP interactions are proxied through the Red Team backend's Operator API
(`backend/operator_api.py`). ZAP itself is not directly accessible from the host.

### `GET /api/operator/zap/status`
Check whether the ZAP proxy is online and reachable.

**Response example:**
```json
{
  "status": "online",
  "version": "2.14.0"
}
```

---

### `GET /api/operator/zap/history?limit=50`
Fetch the proxy traffic history — all HTTP messages ZAP has intercepted
to/from `target-agent`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | `int` | `50` | Max number of messages to return |

**Response example:**
```json
{
  "messages": [
    {
      "id": "1",
      "method": "GET",
      "url": "http://target-agent/search?q=<script>alert(1)</script>",
      "responseCode": "200"
    }
  ]
}
```

---

### `POST /api/operator/zap/repeater/send`
Send a crafted HTTP request through ZAP to the target agent.
Used to manually replay or modify attacks.

**Request body:**
```json
{
  "method": "GET",
  "path": "/search?q=<script>alert(1)</script>",
  "headers": {
    "X-Custom-Header": "value"
  },
  "body": ""
}
```

> **Note:** Requests are sent with the `AttenseAttackBox-ZAP/1.0` User-Agent header
> so the target-agent can identify them as legitimate lab traffic.

---

## Lab Mode Requirement

In **Lab mode** (`session_type: lab`), the Red Team must use either the
**AttackBox terminal** or **ZAP** to perform attacks. Browser-only interactions
are rejected as insufficient evidence.

This enforces realistic pentesting behaviour and ensures every attack step
produces a verifiable artifact (terminal output or ZAP proxy log entry).

---

## Relevant Source Files

| File | Description |
|---|---|
| [`backend/operator_api.py`](backend/operator_api.py) | ZAP status check, history fetch, and repeater logic |
| [`backend/main.py`](backend/main.py) | FastAPI routes that expose ZAP endpoints (`/api/operator/zap/*`) |
| [`backend/lab_progress.py`](backend/lab_progress.py) | Lab mode validation — enforces ZAP/AttackBox evidence requirement |
| [`backend/lab_analysis.py`](backend/lab_analysis.py) | Attack analysis — detects if ZAP was used for the attack step |
