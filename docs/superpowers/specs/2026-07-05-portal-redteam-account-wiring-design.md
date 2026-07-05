# Portal login → Red Team account wiring

Date: 2026-07-05
Status: approved (pending user spec review)

## Problem

Today the ATTENSE portal (`frontends/portal/red-login.html`) is a fully mocked
login: it steps through email → OTP → role/team with `setTimeout`s and never
calls a backend, and never redirects anywhere at the end. The red-team app
(`frontends/red-team`) has its own mocked `Login.jsx` and stores an operator
profile in `localStorage` (`attense_account`), which `Settings → Account`
renders via `src/lib/account.js`. The two are unrelated: logging in at the
portal has no effect on what Settings shows in the red-team app.

A real auth backend already exists (`attense-app`'s `apps/control-api`,
`POST /api/auth/login`, `GET /api/auth/me`, Postgres-backed `User` table with
a `red_team` role) but neither frontend talks to it.

Goal: logging in at the portal as a red_team user should result in that
person's real identity (display name, email, role) appearing in the red-team
app's Settings → Account panel.

## Approach

**Serve the portal from the red-team frontend's nginx container, and proxy
`/control-api/` to `attense-app:8020`.** This puts the portal and the
red-team app on the same origin (`127.0.0.1:3000`), so:
- the login token can be stored in `localStorage` and read directly by the
  app (no cross-origin token handoff via URL fragments)
- the app's API calls to the auth backend need no CORS changes

Rejected alternative: keep the portal as a separate, unserved origin, add it
to `attense-app`'s CORS allow-list, and pass the session token to the app via
a URL fragment on redirect. This works but adds a second trusted CORS origin,
puts the token in browser history/referrers transiently, and buys nothing —
the portal has no server of its own today, so giving it a home in an
existing container is free.

## Components

### 1. Backend — extend `GET /api/auth/me`
File: `apps/control-api/api/auth_router.py`

Add `email` and `display_name` (= `username`, there is no separate full-name
field for red_team users) to the response. Both come from the `user` dict
already fetched via `user_store.get_user_by_username` — no new query.

### 2. Serving — red-team nginx + Docker image
Files: `frontends/red-team/nginx.conf`, `frontends/red-team/Dockerfile`

- Copy `frontends/portal/*` into the image at `/usr/share/nginx/html/portal/`.
- Add an nginx location block proxying `/control-api/` to
  `http://attense-app:8020/`, using the same `resolver 127.0.0.11 valid=10s`
  + variable `proxy_pass` pattern already used for `/api/`, `/target/`, etc.
  (so a recreated `attense-app` container doesn't 502 the portal — this
  repo has hit that exact stale-DNS bug before).

### 3. Portal login
File: `frontends/portal/red-login.html`

Replace the mock `handleContinue` with a real
`POST /control-api/api/auth/login { username, password }`.
- On 200: store `{ token }` in `localStorage` as `attense_session_token`,
  skip straight to the existing step-4 "Access Granted" screen, then
  `window.location.href = '/'` to enter the red-team app.
- On 401: show the existing error box; no token stored, no redirect, stay
  on step 1.

The existing step-2 (OTP) and step-3 (role/team picker) screens are removed
from this flow. They don't correspond to anything the backend knows about —
backend roles are `ciso` / `soc_manager` / `soc_l1` / `soc_l2` / `red_team`,
not the CISO/SOC Analyst/IR Lead/Threat Hunter options shown there — and
there is no OTP backend. Keeping them would mean collecting input the login
silently discards. `role` (and the "CISO → reporting dashboard" copy branch)
in step 4 is unused for this flow.

### 4. Red-team account hydration
Files: `frontends/red-team/src/lib/account.js`, `frontends/red-team/src/App.jsx`

Add `hydrateFromSession()`:
- If `attense_session_token` is absent, no-op.
- Else call `GET /control-api/api/auth/me` with header
  `X-Session-Token: <token>` (matches `dependencies/auth.py`'s
  `require_session`, which reads that header — not a Bearer token).
- On success, `saveAccount({ name: display_name, email, role: mapRole(role) })`.
- On 401 (expired/invalid token), clear `attense_session_token` and leave the
  existing local `DEFAULT_ACCOUNT` in place (no forced redirect — out of
  scope, see below).

Call `hydrateFromSession()` once on `App.jsx` mount so it also covers a
direct refresh of the app with a token already in storage, not just the
moment right after login.

Role mapping: backend role `red_team` → account label `"Red Team Operator"`
(already the `DEFAULT_ACCOUNT.role` string in `account.js`, so this is just
making the real value flow into the same field).

### 5. Logout
Add a `logout()` in `account.js` that clears `attense_session_token` and
navigates to `/portal/red-login.html`. Wire it to whatever sign-out control
exists in Settings today (or add a minimal one if none exists).

## Data flow

```
red-login.html (portal, same origin as app)
  → POST /control-api/api/auth/login {username, password}
  → 200: store token in localStorage["attense_session_token"]
  → redirect to "/"

red-team app (App.jsx mount)
  → hydrateFromSession()
  → GET /control-api/api/auth/me   (X-Session-Token: <token>)
  → saveAccount({ name: display_name, email, role })

Settings → Account panel
  → reads via getAccount() (unchanged) → shows the logged-in person
```

## Error handling

- Wrong credentials at login: existing error UI, no state changes.
- `/api/auth/me` unreachable or 401 at hydration time: clear the stale
  token, keep whatever account is already in local storage (don't crash
  Settings or force a redirect loop).
- nginx → attense-app proxy failure (container restarted, DNS stale): covered
  by the existing resolver/variable pattern, matches prior fix for the same
  class of bug on this repo (blue-team/red-team frontends, see memory
  `project_nginx_stale_dns`).

## Testing

No red_team account exists by default (users are created by a
`soc_manager`), so testing requires seeding one first:

1. **Seed a red_team user** via curl/PowerShell against `attense-app`:
   - `POST http://127.0.0.1:8020/api/company/register-with-manager`
     `{ company_name, manager_username, manager_email, manager_password }`
   - `POST http://127.0.0.1:8020/api/auth/login` as the manager → token
   - `POST http://127.0.0.1:8020/api/company/{company_id}/users`
     with `X-Session-Token: <manager token>`,
     `{ username, email, password, role: "red_team", type: "intermediate" }`
2. **Rebuild the frontend image** — portal files and the nginx proxy are
   baked in at build time:
   `docker compose build red-team-frontend && docker compose up -d red-team-frontend`
3. **End-to-end browser test:**
   - Open `http://127.0.0.1:3000/portal/red-login.html`, log in with the
     seeded credentials
   - Confirm redirect to `http://127.0.0.1:3000/`
   - DevTools → Application → Local Storage → `attense_session_token` present
   - `/settings` → Account tab → name/email/role match the seeded user, not
     `DEFAULT_ACCOUNT`
4. **Negative test:** wrong password → error shown, no token, no redirect.
5. **Hydration-on-refresh test:** with a valid token already in storage,
   hard-refresh `/` directly (skip login) → Settings still populates.
6. **Backend-only check:**
   `curl -H "X-Session-Token: <token>" http://127.0.0.1:8020/api/auth/me`
   → confirm `email` and `display_name` appear in the response.
7. **Regression check:** confirm the room/incident_id fields `/api/auth/me`
   already returns for `red_team` sessions are unaffected by the new fields.

## Out of scope

- Self-service red-team registration (currently requires a `soc_manager`).
- The blue-team portal pages (`blue-login.html`, etc.) — same pattern could
  apply later but is not part of this change.
- Full route-guarding of the red-team app behind auth (today all routes are
  reachable without a token; this change only makes Settings reflect a real
  identity *when* one is present).
- Token expiry/refresh UX beyond "invalid token → clear it, fall back to
  local default."
