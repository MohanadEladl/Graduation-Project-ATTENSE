# Implementation Prompt — Blue Team Frontend Portal

## Context: What Already Exists

This is the ATTENSE cyber-range platform. A fully working backend already exists. You are building the **missing frontend** for blue-team analysts and SOC managers.

### Existing roles in the system (from `user_store.py`):
| Role | Description |
|------|-------------|
| `soc_l1` | Junior analyst — enters rooms, responds to incidents |
| `soc_l2` | Senior analyst — same as L1, more complex scenarios |
| `soc_manager` | Team lead — creates rooms, sees team-wide reports |
| `ciso` | Cross-company oversight (not relevant to this portal) |

### Existing API endpoints you MUST use (all on `control-api`, default `http://localhost:8000`):
| Method | Path | Who can call | Returns |
|--------|------|-------------|---------|
| POST | `/api/auth/login` | anyone | `{ token, role }` |
| GET | `/api/auth/me` | authenticated | `{ username, role, hive_key?, room_id? }` |
| GET | `/api/rooms` | authenticated | list of room objects for the user's company |
| GET | `/api/rooms/{room_id}` | authenticated | room detail + `incidents_detail[]` with report |
| POST | `/api/rooms/{room_id}/start` | `soc_manager` | starts the room (spins up blue-team containers) |
| DELETE | `/api/rooms/{room_id}` | `soc_manager` | closes the room |

### Room object shape (from `room_manager.py`):
```json
{
  "room_id": "uuid",
  "scenario_id": "scenario name",
  "company_id": "uuid",
  "status": "pending | active | closed",
  "created_by": "username",
  "created_at": "ISO timestamp",
  "incidents": ["incident_id_1"],
  "incidents_detail": [
    {
      "incident_id": "uuid",
      "status": "open | detected | contained | resolved",
      "report": { ... scored report object ... }
    }
  ]
}
```

### Report object shape (from `pipeline/report_generator.py`):
```json
{
  "analyst_id": "username",
  "incident_id": "uuid",
  "scenario_id": "string",
  "mttd_minutes": 12.4,
  "mttc_minutes": 8.1,
  "mttr_minutes": 20.0,
  "score": 78,
  "grade": "B",
  "skills": {
    "detection": 85,
    "containment": 72,
    "recovery": 76
  },
  "narrative": "AI-generated paragraph summarizing analyst performance",
  "generated_at": "ISO timestamp"
}
```

---

## What You Must Build

### Location: `frontends/blue-team/`

Create a **new Vite + React** application. Initialize with:
```bash
npx create-vite@latest . --template react
```

Then install only: `react-router-dom`, `axios`

Do NOT install: Tailwind, Material UI, Ant Design, or any other UI framework. Write all styles in plain CSS.

---

### Project Structure

```
frontends/blue-team/
├── index.html
├── vite.config.js          # proxy /api → control-api:8000
├── package.json
├── src/
│   ├── main.jsx
│   ├── App.jsx             # routing
│   ├── api.js              # axios instance with token interceptor
│   ├── styles/
│   │   └── global.css      # design system tokens + global styles
│   ├── context/
│   │   └── AuthContext.jsx # current user state (token, role, username)
│   ├── pages/
│   │   ├── LoginPage.jsx
│   │   ├── DashboardPage.jsx
│   │   ├── RoomLobbyPage.jsx
│   │   └── ReportPage.jsx
│   └── components/
│       ├── Navbar.jsx
│       ├── RoomCard.jsx
│       ├── ScoreGauge.jsx
│       ├── ReportCard.jsx
│       └── ProtectedRoute.jsx
```

---

### Design System (`src/styles/global.css`)

The UI must feel **premium and dark-themed** — this is a professional SOC tool.

Define CSS custom properties:
```css
:root {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-card: #1c2230;
  --border: #30363d;
  --accent: #2563eb;        /* blue — brand colour */
  --accent-hover: #1d4ed8;
  --success: #22c55e;
  --warning: #f59e0b;
  --danger: #ef4444;
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
  --font: 'Inter', system-ui, sans-serif;
  --radius: 8px;
  --shadow: 0 4px 24px rgba(0,0,0,0.4);
}
```

Import Inter from Google Fonts. Apply dark background globally. All cards use `--bg-card` with `--border` border and `--shadow`. Buttons use `--accent` with hover transition. No flat/plain colours.

---

### Page Descriptions

#### `LoginPage.jsx`
- Centered card on dark background, ATTENSE logo text at top
- Username + password fields
- Login button (calls `POST /api/auth/login`, stores token in `localStorage`, sets AuthContext)
- On error show inline "Invalid credentials" in red
- On success: redirect to `/dashboard`

---

#### `DashboardPage.jsx` — **Personal overview** (all blue roles)

Top section — greeting card: `"Welcome back, {username}"`, role badge, last login time

Middle section — **"My Recent Activity"**: show the last 3 rooms the user participated in, each as a `RoomCard` (status chip, scenario name, date, "View Report" button)

Bottom section — **"Enter a Room"**: a single `CTA` button → navigates to `/lobby`

If the user is `soc_manager`: add a fourth section **"Team Overview"** with:
- Total rooms this month
- Average team score
- A "See Full Team Report" button → navigates to `/report?view=team`

Data source: `GET /api/rooms` — filter by `status: "active"` or `status: "closed"`.

---

#### `RoomLobbyPage.jsx` — **Room browser**

Header: "Available Rooms" with a status filter (All / Active / Pending / Closed)

Grid of `RoomCard` components. Each card shows:
- Scenario name (styled as the room title)
- Status chip: green=active, yellow=pending, grey=closed
- Created by + date
- Number of analysts in the room (from `room.incidents` length as a proxy)
- **"Enter Room"** button — only enabled when `status === "active"`
  - On click: navigate to `/report?room_id={room_id}` (the detail/working view)
- If user is `soc_manager` and status is `"pending"`: show **"Start Room"** button → calls `POST /api/rooms/{room_id}/start`
- If user is `soc_manager`: show a **"Close Room"** icon button → calls `DELETE /api/rooms/{room_id}` with confirmation dialog

Poll `GET /api/rooms` every 15 seconds to keep status live (use `setInterval` in `useEffect`, clean up on unmount).

---

#### `ReportPage.jsx` — **Role-aware reporting view**

This page handles two modes controlled by query params:

**Mode 1: Single room report** (`?room_id={id}`)  
- Call `GET /api/rooms/{room_id}`
- Show the room header (scenario, date, status)
- For each entry in `incidents_detail`: show a `ReportCard` if the incident has a report
- If `status !== "resolved"` for the incident: show a pulsing "Incident in progress…" placeholder instead of the report
- **Analyst** sees only their own incidents (filter by `incident.report.analyst_id === username`)
- **SOC Manager** sees ALL analysts' incidents in this room, plus a team summary card at the top

**Mode 2: Team overview** (`?view=team`) — `soc_manager` only  
- Call `GET /api/rooms` to get all closed rooms
- Compute and display:
  - Average score across all analysts
  - Top performer (highest score)
  - Weakest skill across team (lowest category average)
- List every closed room as an expandable row. Clicking a row loads that room's report inline (calls `GET /api/rooms/{id}`)
- Each row can expand to show individual analyst `ReportCard`s

---

### Component Descriptions

#### `RoomCard.jsx`
Props: `room`, `onEnter`, `onStart`, `onClose`, `currentRole`  
Renders a card with gradient border-left colored by status (blue=active, amber=pending, grey=closed). Hover lifts the card with `transform: translateY(-2px)`.

#### `ScoreGauge.jsx`
Props: `score` (0–100), `grade` (A/B/C/D/F)  
A circular SVG gauge — stroke-dasharray animation on mount showing the score. Color: green ≥80, amber 60–79, red <60. Show numeric score in centre and grade letter below.

#### `ReportCard.jsx`
Props: `report`  
Shows:
- `ScoreGauge` on the left
- Skill bars on the right (detection / containment / recovery) as animated horizontal progress bars
- `narrative` text below in a styled blockquote
- MTTD / MTTC / MTTR as three metric pills at the bottom

#### `ProtectedRoute.jsx`
Wraps a route — if no token in context, redirect to `/login`. Optionally accepts `allowedRoles` prop — if role doesn't match, show a 403 message.

---

### Routing (`App.jsx`)

```
/login              → LoginPage (public)
/dashboard          → DashboardPage (protected)
/lobby              → RoomLobbyPage (protected)
/report             → ReportPage (protected)
*                   → redirect to /dashboard
```

---

### Auth flow (`src/api.js` + `AuthContext.jsx`)

- On login, store `token` in `localStorage`
- Axios instance adds `Authorization: Bearer {token}` to every request
- On 401 response, clear token and redirect to `/login`
- `AuthContext` exposes `{ user, token, login(token, role, username), logout() }`
- On app mount, if token exists call `GET /api/auth/me` to rehydrate user state

---

### `vite.config.js`

```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,   // port 3000 is taken by red-team frontend
    proxy: {
      '/api': {
        target: 'http://localhost:8000',   // control-api
        changeOrigin: true,
      }
    }
  }
})
```

---

### Backend Addition Required

#### New endpoint: `GET /api/rooms/my-history`

Add to `apps/control-api/api/rooms_router.py`:
- Returns all rooms where the calling analyst appears in `incidents_detail.report.analyst_id`
- This allows the Dashboard to show personal history without the frontend scanning all rooms
- Protected by `require_session`, available to all blue roles
- Response: list of room objects (same shape as `GET /api/rooms`) filtered and sorted by `created_at` descending, limited to 10

---

## What You Must NOT Do

- Do not modify `blue-team-api` — the portal talks to `control-api` only
- Do not add a database — all state lives in the existing JSON files via control-api
- Do not touch the red-team frontend (`frontends/red-team/`)
- Do not use Tailwind, Bootstrap, or any CSS framework
- Do not store the token in a cookie — localStorage only for now
- Do not build the actual incident response terminal/TheHive view — that is a separate task

---

## Verification Checklist

- [ ] `npm run dev` starts on port 3001 with no errors
- [ ] Login with a `soc_l1` user works and lands on Dashboard
- [ ] Login with a `soc_manager` user shows the Team Overview section on Dashboard
- [ ] Lobby page loads and shows all company rooms with correct status chips
- [ ] SOC manager can click "Start Room" and the room status changes to active after refresh
- [ ] Report page shows `ScoreGauge` and skill bars for a resolved incident
- [ ] Report page in team mode shows all analysts for SOC manager, only self for L1/L2
- [ ] On expired/missing token, any protected page redirects to `/login`
- [ ] No console errors on any page
