# Implementation Prompt — Red Team Portal (Option B: Deferred Room Creation)

## Context: What Already Exists

This is the ATTENSE cyber-range platform. Do NOT rewrite existing services — extend them minimally.

### Already built and working — do not touch internals:
- `apps/red-team-api/backend/main.py` — FastAPI app, web-shell endpoints, attack execution
- `apps/red-team-api/backend/operator_api.py` — AttackBox container command execution, ZAP bridge
- `apps/red-team-api/backend/session_manager.py` — red-team session lifecycle
- `apps/red-team-api/backend/lab_progress.py` — learner mission progress tracking
- `apps/control-api/main.py` — central coordinator FastAPI app
- `apps/control-api/core/room_manager.py` — `create_room()`, `spin_up_blueteam()`, `spin_down_room()` already exist
- `apps/control-api/api/rooms_router.py` — `/api/rooms/create` (POST, requires `soc_manager` role), `/api/rooms/{id}/start` (POST)

### The design decision (Option B — Deferred):
The red team runs their attack scenario entirely inside the AttackBox container using the existing web shell. When the attack is **complete**, the operator clicks "Finalize → Create Room". This action:
1. Calls a new endpoint on `red-team-api` to mark the session as completed
2. `red-team-api` calls `control-api` to create and immediately start a room, seeding it with the scenario that was just run
3. The blue team is now able to see and enter the room — scoring starts when they join

---

## What You Must Build

### Part 1 — `apps/red-team-api` (Backend changes)

#### 1a. New endpoint in `apps/red-team-api/backend/main.py`

Add a `POST /api/operator/finalize-session` endpoint. It should:
- Accept a JSON body: `{ "session_id": str, "scenario_id": str, "company_id": str }`
- Call the internal helper `_create_room_on_control_api(scenario_id, company_id)` (see 1b)
- Mark the red-team session as `"completed"` in `session_manager.py` (add a `complete_session(session_id)` method there)
- Return `{ "room_id": str, "status": "room_created" }` on success
- Return HTTP 502 if the control-api call fails, with `{ "detail": "Room creation failed: <reason>" }`

Do not remove or modify any existing endpoints.

#### 1b. New internal helper in `apps/red-team-api/backend/main.py`

```python
def _create_room_on_control_api(scenario_id: str, company_id: str) -> dict:
    """
    Call control-api to create + immediately start a room.
    Uses a service-to-service token (env var CONTROL_API_SERVICE_TOKEN).
    Raises RuntimeError on failure.
    """
```

The call sequence:
1. `POST http://{CONTROL_API_URL}/api/rooms/create` with `Authorization: Bearer {CONTROL_API_SERVICE_TOKEN}` and body `{ "scenario_id": scenario_id }`
2. On success, take `room_id` from response
3. `POST http://{CONTROL_API_URL}/api/rooms/{room_id}/start` with same auth header
4. Return the full room object from step 3

`CONTROL_API_URL` defaults to `http://control-api:8000`. `CONTROL_API_SERVICE_TOKEN` must be read from env — raise `RuntimeError("CONTROL_API_SERVICE_TOKEN not set")` if missing.

#### 1c. `apps/control-api/dependencies/auth.py` — service token support

Currently `require_session` only validates user JWTs. Add a second dependency `require_session_or_service` that also accepts the service token:
- If `Authorization: Bearer {CONTROL_API_SERVICE_TOKEN}` is presented, return a synthetic session dict `{ "role": "soc_manager", "company_id": <from X-Company-ID header>, "username": "redteam-service" }`
- Otherwise fall through to the existing JWT validation

Update `apps/control-api/api/rooms_router.py` to use `require_session_or_service` on `/create` and `/{room_id}/start` only (the other endpoints keep `require_session`).

Add `CONTROL_API_SERVICE_TOKEN` to `apps/control-api/.env` and `secrets/ATTENSE.env`.

---

### Part 2 — `frontends/red-team` (UI addition only)

The existing red-team frontend (`frontends/red-team/src/`) already has the attack web shell. **Do not restructure it.** Add one new page/view.

#### New file: `frontends/red-team/src/pages/FinalizeSession.jsx`

This page is shown after the operator has completed an attack in the web shell. It is reached via a "Finalize Attack" button that already exists (or add it) in the session completion flow.

UI requirements:
- Show a summary card: scenario name, session duration, number of commands executed (pull from existing session state)
- A prominent **"Create Room for Blue Team"** button
- On click: call `POST /api/operator/finalize-session` with `{ session_id, scenario_id, company_id }`
- Loading state while waiting
- On success: show a green confirmation banner — `"Room {room_id} is ready. Blue team can now join."` — and disable the button
- On failure: show the error message from the API in a red alert, allow retry

Design: match the existing dark theme of the red-team frontend. No new CSS libraries. Use the same color tokens/variables already defined in the project.

#### Wire up routing

In `frontends/red-team/src/App.jsx` (or wherever routing lives), add a route `/finalize` → `FinalizeSession`. Add a navigation link or button from the session complete state to `/finalize`.

---

### Part 3 — Environment / Config

Add to `docker-compose.yml` under `red-team-backend` service:
```yaml
environment:
  - CONTROL_API_URL=http://control-api:8000
  - CONTROL_API_SERVICE_TOKEN=${CONTROL_API_SERVICE_TOKEN}
```

Add `CONTROL_API_SERVICE_TOKEN=<generate a random 32-char hex string>` to `.env` and `secrets/ATTENSE.env`.

---

## What You Must NOT Do

- Do not change how existing attack modules work
- Do not change `room_manager.py` internals — only call its existing `create_room()` and `spin_up_blueteam()` through the router
- Do not add a database — room state is stored in the existing JSON file approach in `room_manager.py`
- Do not add authentication to the red-team frontend (it is internal-only)
- Do not touch `apps/blue-team-api/` — that is a separate task

---

## Verification Checklist

- [ ] `POST /api/operator/finalize-session` on red-team-api returns `{ "room_id": "...", "status": "room_created" }` when control-api is running
- [ ] A room JSON file is created under the `rooms/` directory in control-api after finalization
- [ ] The room is in `"active"` state (blue team can join)
- [ ] If `CONTROL_API_SERVICE_TOKEN` is missing, the endpoint returns 502 with a clear error message
- [ ] The FinalizeSession UI page renders, calls the endpoint, and shows success/failure correctly
- [ ] No existing web-shell or attack functionality is broken
