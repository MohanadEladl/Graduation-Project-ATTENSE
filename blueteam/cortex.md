# Cortex-Lite: Threat Intelligence Enrichment Module (Option B)

Add a lightweight `cortex/` enrichment module inside the BlueTeam that gives analysts real threat intelligence **during the investigation phase** — without adding a Cortex process or any new container.

---

## What This Solves

Right now the investigation flow is:
```
raise_alert → investigate_alert → confirm/deny
```
The analyst receives raw alert data but has **no enrichment** to base their decision on.

After this change:
```
raise_alert → [enrich IOCs automatically] → investigate_alert (analyst sees enrichment) → confirm/deny
```
The analyst sees IP reputation + VirusTotal results attached to the alert before deciding.

---

## User Review Required

> [!IMPORTANT]
> **API Keys Required**: VirusTotal and AbuseIPDB are free but require API key registration.
> - AbuseIPDB free tier: 1,000 checks/day → https://www.abuseipdb.com/register
> - VirusTotal free tier: 500 lookups/day → https://www.virustotal.com/gui/join-us
>
> Keys are passed as environment variables — no hardcoding. The module works in **graceful degradation mode** (returns empty enrichment) if keys are missing or APIs are unreachable.

> [!NOTE]
> **No new containers, no new processes.** This is pure Python inside the existing BlueTeam FastAPI service. Zero Docker changes needed.

---

## Open Questions

> [!IMPORTANT]
> **When should enrichment trigger?**
> - **Option 1 (Recommended)**: Automatically when `raise_alert` is called — enrichment is ready before the analyst even opens the alert.
> - **Option 2**: On-demand via a new `POST /blueteam/enrich` endpoint — analyst requests enrichment manually.
>
> Option 1 is more realistic (SOAR-style auto-enrichment). Option 2 gives more control for demos. Please confirm which you prefer.

---

## Proposed Changes

### New Module: `blueteam/infrastructure/cortex/`

This follows the exact same pattern as `infrastructure/thehive/` and `infrastructure/sandbox/`.

#### [NEW] `infrastructure/cortex/__init__.py`
Empty package marker.

#### [NEW] `infrastructure/cortex/virustotal_client.py`
Calls the VirusTotal API v3 to look up:
- **IP addresses** → malicious votes, country, ASN, last analysis stats
- **URLs** → malicious/suspicious vote counts
- **File hashes** → malware family, detection ratio (e.g. 42/72 engines flagged)

Returns a structured `VTResult` dataclass. Returns empty result gracefully if API key is missing.

#### [NEW] `infrastructure/cortex/abuseipdb_client.py`
Calls AbuseIPDB API v2 to look up:
- **IP reputation** → abuse confidence score (0–100%), total reports, country, ISP, usage type
- Confidence ≥ 50% → HIGH risk, ≥ 20% → MEDIUM, < 20% → LOW

Returns a structured `AbuseIPResult` dataclass. Graceful degradation if key missing.

#### [NEW] `infrastructure/cortex/enrichment_service.py`
Orchestrator that:
1. Extracts IOCs from a `RaiseAlertRequest` (source IP from `raw_log`, `target_id`, `siem_id`)
2. Calls VT + AbuseIPDB in parallel (using `asyncio.gather` or `httpx` concurrent)
3. Returns a unified `EnrichmentReport` with all results and a computed `risk_score`

---

### Modified: `config/settings.py`

Add two new optional fields:
```python
virustotal_api_key: str = ""    # empty = enrichment disabled gracefully
abuseipdb_api_key: str = ""     # empty = enrichment disabled gracefully
```

---

### Modified: `api/dependencies.py`

Add a new provider:
```python
def get_enrichment_service() -> EnrichmentService:
    settings = get_settings()
    return EnrichmentService(
        vt_api_key=settings.virustotal_api_key,
        abuse_api_key=settings.abuseipdb_api_key,
    )
```

---

### Modified: `api/router.py`

**Option 1 (auto-enrich on raise_alert):**
- `api_raise_alert` injects `EnrichmentService` via `Depends()`
- Calls `enrichment_service.enrich(body)` after the alert is raised
- Enrichment result is attached to the `ActionResponse` (new optional `enrichment` field)

**Option 2 (on-demand endpoint):**
- New `POST /blueteam/enrich` endpoint
- Request body: `{ "incident_id": "...", "ioc": "1.2.3.4", "ioc_type": "ip" }`
- Returns `EnrichmentReport` directly

---

### Modified: `schemas/responses/action_response.py`

Add optional enrichment field:
```python
enrichment: dict | None = None  # populated when Cortex-lite runs
```

---

### Modified: `docker-compose.yml`

Add new env vars to the `blueteam` service:
```yaml
VIRUSTOTAL_API_KEY: ""      # fill in with real key
ABUSEIPDB_API_KEY: ""       # fill in with real key
```

---

### Modified: `requirments.txt`

No new packages needed — `httpx` is already installed and handles all HTTP calls.

---

## File Summary

```
blueteam/
├── infrastructure/
│   └── cortex/                          ← NEW
│       ├── __init__.py                  ← NEW
│       ├── virustotal_client.py         ← NEW
│       ├── abuseipdb_client.py          ← NEW
│       └── enrichment_service.py        ← NEW
├── config/
│   └── settings.py                      ← MODIFY (add 2 API key fields)
├── api/
│   ├── dependencies.py                  ← MODIFY (add get_enrichment_service)
│   └── router.py                        ← MODIFY (wire enrichment into raise_alert or new endpoint)
├── schemas/responses/
│   └── action_response.py               ← MODIFY (add optional enrichment field)
└── docker-compose.yml                   ← MODIFY (add env vars)
```

---

## Verification Plan

### Automated
- Run the BlueTeam API with empty API keys → enrichment returns gracefully with `null`
- Run with mock keys → verify error handling doesn't crash the alert flow
- Check `GET /health` still returns `ok`

### Manual
- With real AbuseIPDB key: POST to `/blueteam/raise-alert` with a known-bad IP → verify `enrichment.abuse_confidence_score` is > 0
- With real VT key: include a known malicious hash in `raw_log` → verify detection ratio in response
- Confirm that if both keys are empty, the normal alert workflow is completely unaffected
