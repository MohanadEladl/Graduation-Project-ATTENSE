# Mutation Timeline Report Section — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the Mutation Timeline section inside `MissionReport.jsx` so learners see each mid-mission shift, whether they adapted, their response time, and an adaptability grade separate from their raw mission score.

**Architecture:** The backend already produces `mutation_timeline` (array of shift rows), `adaptability_score` (0–100), and `adaptability_grade` (S/A/B/C/F) in the `/api/sessions/{sid}/report` response. This plan is entirely frontend — one new component rendered inside `MissionReport.jsx` between the Action Replay section and the re-attempt CTA, guarded by `report.mutation_timeline?.length > 0`.

**Tech Stack:** React 18, Framer Motion (already used throughout), inline styles matching the existing dark-terminal aesthetic (no new CSS files, no new dependencies).

---

## File Map

| Action | File | What changes |
|--------|------|--------------|
| Modify | `red-team/frontend/src/routes/MissionReport.jsx` | Add `MutationTimelineSection` component + wire it between Action Replay and the CTA |

That's the only file. No backend changes, no new files.

---

### Task 1: Add the `MutationTimelineSection` component and render it in the report

**Files:**
- Modify: `red-team/frontend/src/routes/MissionReport.jsx`

The new section goes **after the Action Replay block** (after the closing `</motion.section>` for Action Replay, around line 421) and **before the re-attempt CTA** (`<motion.div {...fadeUp(0.45)} ...>` around line 423).

#### What the data looks like

The report API already returns these fields (from `report_agent.py`):

```json
{
  "mutation_timeline": [
    {
      "id": "abc123def4",
      "mutation_id": "bf_json_required",
      "label": "JSON Auth Only",
      "description": "The login portal rejects form posts and only accepts application/json.",
      "taunt": "Form auth is dead. I only speak JSON now. ADAPT.",
      "why": "Most learners default to form-encoding.",
      "selected_by": "ollama/llama3.2:3b",
      "color": "#fb923c",
      "fired_at": 1716700890.0,
      "delta_s": 97.4,
      "adapted": true,
      "response_seconds": 42,
      "post_mutation_events": 6
    }
  ],
  "adaptability_score": 85,
  "adaptability_grade": "A"
}
```

`delta_s` = seconds after mission start when the shift fired.
`adapted` = true if the learner completed the mission after the shift fired.
`response_seconds` = seconds from shift fire to mission success (null if not adapted).
`post_mutation_events` = how many timeline events happened after this shift (proxy for activity).

#### The component to add

Add this function **before** the `export default function MissionReport()` line in `MissionReport.jsx`:

```jsx
const ADAPT_GRADE_COLORS = {
  S: { fg: '#facc15', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.4)' },
  A: { fg: '#00c8ff', bg: 'rgba(0,200,255,0.06)',  bd: 'rgba(0,200,255,0.4)'  },
  B: { fg: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.4)' },
  C: { fg: '#fb923c', bg: 'rgba(251,146,60,0.06)', bd: 'rgba(251,146,60,0.4)' },
  F: { fg: '#ff4060', bg: 'rgba(255,21,53,0.06)',  bd: 'rgba(255,21,53,0.4)'  },
}

function MutationTimelineSection({ report }) {
  const shifts = report.mutation_timeline || []
  if (shifts.length === 0) return null

  const grade = report.adaptability_grade || 'F'
  const score = report.adaptability_score ?? 0
  const gc = ADAPT_GRADE_COLORS[grade] || ADAPT_GRADE_COLORS.F
  const adaptedCount = shifts.filter(s => s.adapted).length

  const fmtDelta = (s) => {
    if (s == null) return '—'
    const m = Math.floor(s / 60)
    const sec = Math.round(s % 60)
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  return (
    <motion.section {...fadeUp(0.42)} className="mb-5">
      {/* Section header */}
      <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
        <div>
          <div className="font-mono text-[9px] tracking-[0.3em] mb-1" style={{ color: '#f5c400' }}>
            MUTATION TIMELINE
          </div>
          <div className="text-[15px] font-semibold" style={{ color: '#edf0f8' }}>
            {shifts.length} shift{shifts.length !== 1 ? 's' : ''} fired — {adaptedCount} adapted
          </div>
        </div>

        {/* Adaptability grade badge */}
        <div
          className="flex items-center gap-3 px-4 py-2.5 rounded-xl"
          style={{ background: gc.bg, border: `1px solid ${gc.bd}` }}
        >
          <div>
            <div className="font-mono text-[8.5px] tracking-[0.28em] mb-0.5" style={{ color: gc.fg }}>
              ADAPTABILITY
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[28px] font-bold leading-none" style={{ color: gc.fg }}>
                {grade}
              </span>
              <span className="font-mono text-[12px]" style={{ color: gc.fg + 'aa' }}>
                {score}/100
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Shift rows */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ background: 'rgba(8,10,17,0.5)', border: '1px solid rgba(255,255,255,0.06)' }}
      >
        {shifts.map((shift, i) => {
          const adapted = shift.adapted
          const color = shift.color || '#fb923c'
          return (
            <div
              key={shift.id || i}
              className="px-4 py-3"
              style={{
                borderBottom: i < shifts.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                borderLeft: `3px solid ${color}`,
                background: adapted ? `${color}06` : 'transparent',
              }}
            >
              {/* Row header: timestamp + label + adapted badge */}
              <div className="flex items-center gap-3 flex-wrap mb-1.5">
                <span className="font-mono text-[10px] tabular-nums shrink-0" style={{ color: '#4a5280' }}>
                  T+{fmtDelta(shift.delta_s)}
                </span>
                <span
                  className="font-mono text-[9px] tracking-[0.14em] px-2 py-0.5 rounded shrink-0"
                  style={{ background: `${color}18`, border: `1px solid ${color}55`, color }}
                >
                  {shift.label || shift.mutation_id}
                </span>
                <span
                  className="font-mono text-[9px] tracking-[0.16em] px-2 py-0.5 rounded shrink-0 ml-auto"
                  style={adapted
                    ? { background: 'rgba(46,227,154,0.08)', border: '1px solid rgba(46,227,154,0.4)', color: '#2ee39a' }
                    : { background: 'rgba(255,21,53,0.08)',  border: '1px solid rgba(255,21,53,0.35)',  color: '#ff4060' }
                  }
                >
                  {adapted ? `ADAPTED in ${fmtDelta(shift.response_seconds)}` : 'DID NOT ADAPT'}
                </span>
              </div>

              {/* Taunt */}
              {shift.taunt && (
                <div
                  className="font-mono text-[10.5px] leading-relaxed mb-1"
                  style={{ color: '#c0c8e0' }}
                >
                  <span style={{ color: color + 'cc', marginRight: 6 }}>»</span>
                  {shift.taunt}
                </div>
              )}

              {/* Activity count */}
              <div className="font-mono text-[9px]" style={{ color: '#3e4860' }}>
                {shift.post_mutation_events} event{shift.post_mutation_events !== 1 ? 's' : ''} recorded after this shift
                {shift.selected_by ? ` · picked by ${shift.selected_by}` : ''}
              </div>
            </div>
          )
        })}
      </div>

      {/* Coaching note */}
      <div
        className="rounded-xl p-4 mt-3"
        style={{ background: 'rgba(245,196,0,0.04)', border: '1px solid rgba(245,196,0,0.18)' }}
      >
        <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#f5c400' }}>
          ADAPTABILITY NOTE
        </div>
        <div className="text-[11.5px] leading-relaxed" style={{ color: '#a0b0c8' }}>
          {score >= 90
            ? 'Excellent — you pivoted every time the environment shifted. This is the core of real red-teaming: staying effective when the target fights back.'
            : score >= 70
            ? 'Good adaptation. Review any shifts you missed and drill the alternative technique — in the field, a stalled attack is a failed attack.'
            : score >= 40
            ? 'Partial adaptation. When a mutation fires, stop and re-enumerate before pushing forward with the same payload. Identify what changed first.'
            : 'The mutations stopped your progress. Focus your next attempt on recognising when a technique has stopped working — the first 30 seconds after a shift are critical.'
          }
        </div>
      </div>
    </motion.section>
  )
}
```

#### Wire it into the render

Locate the Action Replay closing tag in `MissionReport.jsx` (the line that looks like `      )}` closing the `{(report.evidence_timeline || []).length > 0 && (` block, around line 421). Insert the new section directly after it:

```jsx
      {/* ── MUTATION TIMELINE ── */}
      {(report.mutation_timeline || []).length > 0 && (
        <MutationTimelineSection report={report} />
      )}
```

The full insertion point in context looks like this (so you can find it precisely):

```jsx
        </motion.section>
      )}

      {/* ── MUTATION TIMELINE ── */}
      {(report.mutation_timeline || []).length > 0 && (
        <MutationTimelineSection report={report} />
      )}

      {/* Re-attempt CTA */}
      <motion.div {...fadeUp(0.45)} className="flex justify-center gap-3 flex-wrap mt-8">
```

- [ ] **Step 1: Add `ADAPT_GRADE_COLORS` constant** after the existing `CHANNEL_COLOR` constant (around line 39 in `MissionReport.jsx`)

```jsx
const ADAPT_GRADE_COLORS = {
  S: { fg: '#facc15', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.4)' },
  A: { fg: '#00c8ff', bg: 'rgba(0,200,255,0.06)',  bd: 'rgba(0,200,255,0.4)'  },
  B: { fg: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.4)' },
  C: { fg: '#fb923c', bg: 'rgba(251,146,60,0.06)', bd: 'rgba(251,146,60,0.4)' },
  F: { fg: '#ff4060', bg: 'rgba(255,21,53,0.06)',  bd: 'rgba(255,21,53,0.4)'  },
}
```

- [ ] **Step 2: Add `MutationTimelineSection` component** — paste the full function body shown above directly before the `export default function MissionReport()` line.

- [ ] **Step 3: Wire the component into the render** — insert after the Action Replay `)}` closing line:

```jsx
      {/* ── MUTATION TIMELINE ── */}
      {(report.mutation_timeline || []).length > 0 && (
        <MutationTimelineSection report={report} />
      )}
```

- [ ] **Step 4: Also add a MUTATION badge to the header stats strip** — in the `<div className="grid grid-cols-2 md:grid-cols-4 gap-3">` block (around line 241), add a fifth stat conditionally:

Replace:
```jsx
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <HeroStat label="DURATION" value={fmtDuration(report.duration_seconds)} />
              <HeroStat label="EVENTS"   value={(report.evidence_timeline || []).length} />
              <HeroStat label="ATTACKBOX" value={report.channel_breakdown?.attackbox ?? '—'} />
              <HeroStat label="BROWSER"  value={report.channel_breakdown?.browser ?? '—'} />
            </div>
```

With:
```jsx
            <div className={`grid gap-3 ${(report.mutation_timeline || []).length > 0 ? 'grid-cols-2 md:grid-cols-5' : 'grid-cols-2 md:grid-cols-4'}`}>
              <HeroStat label="DURATION" value={fmtDuration(report.duration_seconds)} />
              <HeroStat label="EVENTS"   value={(report.evidence_timeline || []).length} />
              <HeroStat label="ATTACKBOX" value={report.channel_breakdown?.attackbox ?? '—'} />
              <HeroStat label="BROWSER"  value={report.channel_breakdown?.browser ?? '—'} />
              {(report.mutation_timeline || []).length > 0 && (
                <HeroStat
                  label="ADAPTABILITY"
                  value={`${report.adaptability_grade ?? '—'} · ${report.adaptability_score ?? 0}`}
                />
              )}
            </div>
```

- [ ] **Step 5: Verify the page renders for a non-mutation run** — load any existing mission report (one without `mutation_timeline`) and confirm nothing new renders and no console errors appear. The `MutationTimelineSection` returns `null` when `shifts.length === 0`, so it is a no-op for normal runs.

- [ ] **Step 6: Trigger a mutation run to test with real data**

  Open the app, navigate to Gauntlet → Mutation Mode, launch a Brute Force mission on Single Shift intensity. Complete or partially complete the mission. Navigate to the report. Confirm:
  - The "MUTATION TIMELINE" section appears
  - Each shift row shows the label badge, taunt text, adapted/did-not-adapt badge
  - The header stats strip shows a 5th cell "ADAPTABILITY"
  - The adaptability grade badge in the section header reflects `adaptability_grade` from the API

- [ ] **Step 7: Commit**

```bash
git add red-team/frontend/src/routes/MissionReport.jsx
git commit -m "feat: add Mutation Timeline section to mission report

Shows each mid-mission shift, adapt status, response time,
and adaptability grade (S/A/B/C/F) separate from mission score.
Backend fields mutation_timeline/adaptability_score/adaptability_grade
were already emitted by report_agent.py — this wires the frontend.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- ✅ "Mutation Timeline" section in report: Task 1, steps 2+3
- ✅ "When each shift hit": `delta_s` rendered as `T+{time}` in each row
- ✅ "Whether you adapted before the clock ran out": `adapted` badge per row
- ✅ "AI grade on your adaptability — a separate score from raw success": grade badge + `adaptability_score` in header, step 4

**Placeholder scan:** None. All code is complete and references only fields defined by the existing backend API contract.

**Type consistency:** `fadeUp`, `HeroStat` are used exactly as defined in the existing file. `ADAPT_GRADE_COLORS` is defined in step 1 before it's referenced in step 2.

---

## What Was Already Built (No Work Needed)

For reference — these items from the original brief were found fully implemented:

| Item | Location |
|------|----------|
| Launch panel (briefing + INITIATE button + intensity picker) | `Gauntlet.jsx:737–850` `MutationLaunchCard` |
| Random fire window (60–180s single, 50–130s escalating, 25–75s chaos) | `main.py:1031–1035` `_MUTATION_WINDOWS` |
| Ollama mutation-picker with deterministic fallback | `main.py:1088–1142` `_pick_mutation` |
| ShapeshiftOverlay 3-beat animation + sound | `ShapeshiftOverlay.jsx` |
| Workspace mutation-mode polling hook | `Workspace.jsx:1184–1216` |
| MutationBanner with typewriter taunt | `MutationBanner.jsx` |
| Backend adaptability scoring | `report_agent.py:217–268` `_mutation_adaptability` |
| Sound toggle (default OFF, localStorage) | `Workspace.jsx:1145,1236–1241` |
