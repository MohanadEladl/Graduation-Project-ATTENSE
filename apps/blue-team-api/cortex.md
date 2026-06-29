# Cortex-Lite: Threat Intelligence Enrichment Module (Option B)

Add a lightweight `cortex/` enrichment module inside the BlueTeam that gives analysts real threat intelligence **during the investigation phase** â€” without adding a Cortex process or any new container.

---

## What This Solves

Right now the investigation flow is:
```
raise_alert â†’ investigate_alert â†’ confirm/deny
```
The analyst receives raw alert data but has **no enrichment** to base their decision on.

After this change:
```
raise_alert â†’ [enrich IOCs automatically] â†’ investigate_alert (analyst sees enrichment) â†’ confirm/deny
```
The analyst sees IP reputation + VirusTotal results attached to the alert before deciding.

---

## User Review Required

> [!IMPORTANT]
> **API Keys Required**: VirusTotal and AbuseIPDB are free but require API key registration.
> - AbuseIPDB free tier: 1,000 checks/day â†’ https://www.abuseipdb.com/register
> - VirusTotal free tier: 500 lookups/day â†’ https://www.virustotal.com/gui/join-us
>
> Keys are passed as environment variables â€” no hardcoding. The module works in **graceful degradation mode** (returns empty enrichment) if keys are missing or APIs are unreachable.

> [!NOTE]
> **No new containers, no new processes.** This is pure Python inside the existing BlueTeam FastAPI service. Zero Docker changes needed.

---

## Open Questions

> [!IMPORTANT]
> **When should enrichment trigger?**
> - **Option 1 (Recommended)**: Automatically when `raise_alert` is called â€” enrichment is ready before the analyst even opens the alert.
> - **Option 2**: On-demand via a new `POST /blueteam/enrich` endpoint â€” analyst requests enrichment manually.
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
- **IP addresses** â†’ malicious votes, country, ASN, last analysis stats
- **URLs** â†’ malicious/suspicious vote counts
- **File hashes** â†’ malware family, detection ratio (e.g. 42/72 engines flagged)

Returns a structured `VTResult` dataclass. Returns empty result gracefully if API key is missing.

#### [NEW] `infrastructure/cortex/abuseipdb_client.py`
Calls AbuseIPDB API v2 to look up:
- **IP reputation** â†’ abuse confidence score (0â€“100%), total reports, country, ISP, usage type
- Confidence â‰¥ 50% â†’ HIGH risk, â‰¥ 20% â†’ MEDIUM, < 20% â†’ LOW

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

### Modified: `requirements.txt`

No new packages needed â€” `httpx` is already installed and handles all HTTP calls.

---

## File Summary

```
blueteam/
â”œâ”€â”€ infrastructure/
â”‚   â””â”€â”€ cortex/                          â† NEW
â”‚       â”œâ”€â”€ __init__.py                  â† NEW
â”‚       â”œâ”€â”€ virustotal_client.py         â† NEW
â”‚       â”œâ”€â”€ abuseipdb_client.py          â† NEW
â”‚       â””â”€â”€ enrichment_service.py        â† NEW
â”œâ”€â”€ config/
â”‚   â””â”€â”€ settings.py                      â† MODIFY (add 2 API key fields)
â”œâ”€â”€ api/
â”‚   â”œâ”€â”€ dependencies.py                  â† MODIFY (add get_enrichment_service)
â”‚   â””â”€â”€ router.py                        â† MODIFY (wire enrichment into raise_alert or new endpoint)
â”œâ”€â”€ schemas/responses/
â”‚   â””â”€â”€ action_response.py               â† MODIFY (add optional enrichment field)
â””â”€â”€ docker-compose.yml                   â† MODIFY (add env vars)
```

---

## Verification Plan

### Automated
- Run the BlueTeam API with empty API keys â†’ enrichment returns gracefully with `null`
- Run with mock keys â†’ verify error handling doesn't crash the alert flow
- Check `GET /health` still returns `ok`

### Manual
- With real AbuseIPDB key: POST to `/blueteam/raise-alert` with a known-bad IP â†’ verify `enrichment.abuse_confidence_score` is > 0
- With real VT key: include a known malicious hash in `raw_log` â†’ verify detection ratio in response
- Confirm that if both keys are empty, the normal alert workflow is completely unaffected
