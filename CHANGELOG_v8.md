# ATTENSE v8 — Multi-Phase Build

This release implements all 4 phases from the v8 plan:

## Phase 1 — Multi-Variant Attacks (21 variants across 7 modules)

Each module now offers 3 attack variants. Learner picks one before/during the mission.

  • brute_force:   password_spray, credential_stuffing, hydra_targeted
  • xss:           reflected, alternate_context, stored_attempt
  • cmd_injection: semicolon_basic, pipe_redirect, subshell
  • dir_traversal: plain, encoded, absolute
  • file_upload:   wrong_extension, mime_spoof, polyglot
  • csrf:          basic_forgery, lure_page, json_bypass
  • recon:         manual, wordlist, comment_hunting

Each variant ships with:
  - Name + description + difficulty (Easy/Medium/Hard)
  - List of techniques (informational tags)
  - Per-variant task ladder (replaces the default tasks_tutorial/tasks_lab)
  - Per-variant success_event_types (replaces default success criteria)
  - ideal_commands: literal curl/hydra/gobuster commands the operator should run

Code:
  - red-team/backend/lab_progress.py — added MODULE_VARIANTS dict + helpers
    get_variant_spec() and list_variants(); compute() accepts variant_id
  - red-team/backend/main.py        — POST /api/sessions/{sid}/variant
                                       GET  /api/modules/{module_id}/variants
  - red-team/backend/session_manager.py — variant_id field on SessionRecord
  - red-team/frontend/src/api/client.js — variants() + sessions.setVariant()
  - red-team/frontend/src/components/VariantPicker.jsx — radio-card picker
  - red-team/frontend/src/routes/Workspace.jsx — picker mounted in MissionSidebar

## Phase 2 — Granular Action Tracing

Every click, form submit, and page view inside the lab-browser iframe is now
captured as evidence. Combined with the existing terminal-command capture and
the existing lab-event stream, this gives a unified timeline per session.

Code:
  - red-team/backend/action_trace.py — in-memory ring buffer of browser actions
  - red-team/backend/main.py        — POST /api/lab/actions
                                       GET  /api/sessions/{sid}/timeline
  - target-agent/app/main.py        — Flask after_request hook that injects
    a <script src="/lab/__attense_trace.js"> tag into every HTML response.
    The script listens for click / submit / page_view events and POSTs them
    to /api/lab/actions (same-origin via the nginx /api/ proxy).
  - red-team/frontend/src/routes/Workspace.jsx — postMessage's the current
    session_id into the iframe so the injected script knows which session
    to attribute clicks to.

## Phase 3 — AI Report Agent

A new agent generates a coaching report after every mission. It uses Claude
Haiku via the Anthropic Messages API when ANTHROPIC_API_KEY is set, and
falls back to a hand-written rules-based template otherwise. The lab works
fully air-gapped without the API key.

The report includes:
  - Grade (S/A/B/C/F) + score 0–100
  - Variant played + mode + duration
  - AI coaching paragraph (or rules-based fallback)
  - "What you did right" cards
  - "What you missed" cards with how-to-fix hints
  - "Ideal approach" — the variant's exact ideal_commands as numbered steps
  - Vulnerability deep dive (what / why / real-world example)
  - Defensive controls (2–4 per module with concrete implementation notes)
  - Action replay timeline (every browser click + terminal cmd + lab event)
  - Channel breakdown (how many events from browser vs attackbox)

Grade formula:
  base 0 → +40 if success → +(tasks_done/total)*40 → +min(20, evidence_count*2)
  − 10 penalty if mode=operator but browser events outnumber attackbox events

Code:
  - red-team/backend/report_agent.py — new module, 400+ lines
  - red-team/backend/main.py        — /api/sessions/{sid}/report rewritten
    to use report_agent + variant + unified timeline

## Phase 4 — Unified Mission Report UI

The Reports list page now opens a single in-depth `/report/:sid` page that
replaces the three previous overlapping report routes.

The page has 9 sections rendered with staggered Framer Motion fade-ups:

  1. Header — big grade letter (gold S, cyan A, green B, orange C, red F),
     score, variant badge, mode badge, success/incomplete badge, 4 stat cards
  2. AI Coaching summary card (purple-tinted)
  3. Task Results grid (one card per task, green check or red X)
  4. What You Did Right (green cards)
  5. What You Missed (orange cards with cyan how-to-fix highlight)
  6. Ideal Approach (numbered steps with copyable code blocks)
  7. Vulnerability Deep Dive (red-tinted, with WHAT IS / WHY / REAL-WORLD)
  8. Defensive Controls (cyan grid)
  9. Action Replay timeline (max-height scroll, channel-colored badges)

Plus bottom CTAs: ⚡ RE-ATTEMPT THIS MISSION / TRY ANOTHER VARIANT
Plus top toolbar: BACK TO REPORTS / REVIEW SESSION / ↻ REGENERATE

Code:
  - red-team/frontend/src/routes/MissionReport.jsx — fully rewritten (482 lines)
  - red-team/frontend/src/routes/Reports.jsx — clicking any row navigates
    to /report/:sid; added an explicit VIEW REPORT → button
  - red-team/frontend/src/routes/Workspace.jsx — MissionCompleteSummary now
    has a VIEW FULL REPORT → link

## What stays unchanged

- blueteam/, signal-store/, wazuh-manager/ — completely untouched
- docker-compose.yml — untouched
- TheHive — untouched
- The 6 vulnerable Flask routes still emit the same canonical event types
- AttackBox tools (curl, hydra, ffuf, gobuster, nmap, python3) — unchanged
- Tutorial / Lab modes still work the same way (variant=None → legacy behaviour)
- Guided mode (default tutorial) is unchanged — no regression

## Verified before shipping

  ✓ 143 Python files parse clean (`ast.parse`)
  ✓ 39 frontend JS/JSX files parse clean (esbuild)
  ✓ docker-compose.yml validates as YAML
  ✓ Functional test passes:
    - All 7 modules expose exactly 3 variants (21 total)
    - compute() picks variant tasks correctly
    - report_agent.generate() produces valid structured output
    - Successful run → grade A/S
    - Partial run (1/3 tasks) → grade F with non-empty "missed" array
    - Rule-based fallback works when ANTHROPIC_API_KEY is unset

## Known limitations (honest)

- I could not run `docker compose up --build` in my dev sandbox.
- I could not visually QA the new MissionReport page or variant picker.
- The AI agent costs ~$0.01–0.03 per Claude Haiku call when API key is set.
  Caching is enabled per session (report_cache) — repeated visits don't re-bill.
- The target-agent after_request hook tries to wrap every HTML response.
  In edge cases (e.g. streaming responses, partial templates) it may not
  inject — the try/except guarantees it never breaks a page.
- Browser-action capture uses postMessage from parent → iframe. If the iframe
  navigates to a new domain (it shouldn't, but if), session attribution stops.

## How to enable the AI agent

Set ANTHROPIC_API_KEY on the red-team-backend container:

  # docker-compose.override.yml
  services:
    red-team-backend:
      environment:
        ANTHROPIC_API_KEY: "sk-ant-..."

If not set, the report falls back to the rules-based coach. Both code paths
have been tested.
