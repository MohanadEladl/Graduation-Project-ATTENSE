/**
 * Workspace.jsx — Tutorial/Lab cyber-range mission interface (v6).
 *
 * Layout:
 *   ┌──────────┬──────────────────────────────┬───────────────┐
 *   │ Sidebar  │   LabBrowser (iframe)        │ LearningPanel │
 *   │ Mission  │   /target/<module path>      │ Tasks +       │
 *   │ Progress │   Address bar, Refresh       │ Evidence +    │
 *   │ Steps    │   Open in new tab            │ Defensive     │
 *   └──────────┴──────────────────────────────┴───────────────┘
 *
 * No CLI drawer. No options form. No target host/port input. The learner
 * interacts manually with the embedded vulnerable page; their actions
 * generate evidence in target-agent which the LearningPanel reads via
 * /api/sessions/<sid>/check-progress.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useSession } from '../hooks/useSession.js'
import { api } from '../api/client.js'
import { SeverityBadge, CATEGORY_ICON } from '../components/SeverityBadge.jsx'
import {
  briefingFor, targetUrlFor, targetPathFor,
  tutorialStepsFor, requiredToolsFor, labObjectiveFor,
} from '../data/missionBriefings.js'
import ModeSwitcher from '../components/ModeSwitcher.jsx'
import LabToolsStrip from '../components/LabToolsStrip.jsx'
import LabPanel from '../components/LabPanel.jsx'
import { VariantPicker } from '../components/VariantPicker.jsx'
import MutationBanner from '../components/MutationBanner.jsx'
import ShapeshiftOverlay from '../components/ShapeshiftOverlay.jsx'

const fmtTime = (s) => {
  const mm = Math.floor(s / 60).toString().padStart(2, '0')
  const ss = (s % 60).toString().padStart(2, '0')
  return `${mm}:${ss}`
}

const SEV_COLOR = {
  info:     { fg: '#8b9bba', bg: 'rgba(139,155,186,0.08)', bd: 'rgba(139,155,186,0.25)' },
  low:      { fg: '#7dd3fc', bg: 'rgba(125,211,252,0.08)', bd: 'rgba(125,211,252,0.3)' },
  medium:   { fg: '#facc15', bg: 'rgba(250,204,21,0.08)',  bd: 'rgba(250,204,21,0.3)'  },
  high:     { fg: '#fb923c', bg: 'rgba(251,146,60,0.08)',  bd: 'rgba(251,146,60,0.3)'  },
  critical: { fg: '#f87171', bg: 'rgba(248,113,113,0.08)', bd: 'rgba(248,113,113,0.35)' },
}

// ── Lab mode sidebar panel ───────────────────────────────────────────────────
function LabModePanel({ moduleId }) {
  const objective = labObjectiveFor(moduleId)
  const tools = requiredToolsFor(moduleId)
  return (
    <div className="space-y-3">
      <div className="rounded-xl p-4"
        style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.22)' }}>
        <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#7dd3fc' }}>
          LAB OBJECTIVE
        </div>
        <div className="text-[11.5px] text-attense-text leading-relaxed">
          {objective}
        </div>
      </div>
      {tools.length > 0 && (
        <div className="rounded-xl p-4"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim mb-2">
            AVAILABLE TOOLS
          </div>
          <div className="flex flex-wrap gap-1.5">
            {tools.map(t => (
              <span key={t} className="font-mono text-[10px] px-2 py-1 rounded"
                style={{ background: 'rgba(125,211,252,0.06)', border: '1px solid rgba(125,211,252,0.22)', color: '#9ae4ff' }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
      <div className="rounded-xl p-4"
        style={{ background: 'rgba(46,227,154,0.04)', border: '1px solid rgba(46,227,154,0.18)' }}>
        <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#2ee39a' }}>
          FREE EXPLORATION
        </div>
        <div className="text-[11px] text-attense-dim leading-relaxed">
          No step-by-step guidance. Use the Terminal and ZAP panels below to explore the target at your own pace.
          When you're done, visit Reports to see a full analysis of what you found and how you could improve.
        </div>
      </div>
    </div>
  )
}

// ── Mission sidebar ──────────────────────────────────────────────────────────
function MissionSidebar({
  snapshot, module, briefing,
  elapsed, timerRunning, isDone,
  progress, mode = 'tutorial',
  variantId, onVariantChange,
  collapsed, onToggle,
}) {
  const tasks = progress?.tasks || []
  const completedCount = (progress?.completed_tasks || []).length
  const totalTasks     = tasks.length || 3
  const pct = totalTasks > 0 ? (completedCount / totalTasks) * 100 : 0
  const isLab = mode === 'lab'
  const tutorialSteps = tutorialStepsFor(snapshot?.module_id)

  return (
    <motion.aside
      animate={{ width: collapsed ? 36 : 280 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
      className="shrink-0 flex flex-col overflow-hidden"
      style={{
        borderRight: '1px solid rgba(255,255,255,0.06)',
        background: 'rgba(7,9,15,0.55)',
      }}
    >
      {/* Collapse toggle strip */}
      <div className="shrink-0 flex items-center justify-end px-2 pt-2 pb-1">
        <button
          onClick={onToggle}
          title={collapsed ? 'Expand panel' : 'Collapse panel'}
          className="text-attense-dim hover:text-attense-red transition-colors p-1 rounded"
          style={{ border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)' }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            {collapsed
              ? <path d="M9 18l6-6-6-6"/>
              : <path d="M15 18l-6-6 6-6"/>
            }
          </svg>
        </button>
      </div>

      <AnimatePresence initial={false}>
        {!collapsed && (
          <motion.div
            key="sidebar-content"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="overflow-y-auto flex-1"
            style={{ padding: '4px 16px 18px' }}
          >
        {/* Mission hero */}
        <div
          className="rounded-xl p-4 mb-4"
          style={{
            background: 'rgba(255,255,255,0.02)',
            border: '1px solid rgba(255,255,255,0.08)',
          }}
        >
          <div className="flex items-start gap-3">
            <div
              className="shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-lg"
              style={{
                border: '1px solid rgba(255,21,53,0.4)',
                background: 'rgba(255,21,53,0.06)',
                color: '#ff4060',
              }}
            >
              {CATEGORY_ICON?.[module?.category] || '▪'}
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-mono text-[9px] tracking-[0.22em] text-attense-dim mb-1">
                {snapshot?.scenario_id || '—'}
              </div>
              <div className="text-[13.5px] font-semibold text-attense-text leading-tight mb-1.5">
                {snapshot?.module_name}
              </div>
              <SeverityBadge severity={snapshot?.severity} />
            </div>
          </div>
        </div>

        {/* Timer + progress */}
        <div
          className="rounded-xl p-4 mb-4"
          style={{
            background: 'rgba(255,255,255,0.02)',
            border: '1px solid rgba(255,255,255,0.08)',
          }}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-[9px] tracking-[0.32em] text-attense-dim">PROGRESS</span>
            <span className="font-mono text-[10px] text-attense-text tabular-nums">
              {completedCount}/{totalTasks}
            </span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: pct + '%',
                background: isDone || progress?.success
                  ? '#2ee39a'
                  : pct > 0
                    ? 'linear-gradient(90deg,#ff1535,#ff6b00)'
                    : '#3a4060',
                boxShadow: pct > 0 && !(isDone || progress?.success)
                  ? '0 0 6px rgba(255,21,53,0.5)' : 'none',
              }}
            />
          </div>
          <div
            className="flex items-center justify-between mt-3 pt-3"
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}
          >
            <span className="font-mono text-[9px] tracking-[0.28em] text-attense-dim">ELAPSED</span>
            <span
              className="font-mono text-[13px] font-semibold tabular-nums"
              style={{
                color: timerRunning ? '#ff4060' : (isDone ? '#2ee39a' : '#4a5280'),
              }}
            >
              {fmtTime(elapsed)}
            </span>
          </div>
        </div>

        {/* Variant picker — choose attack flavour */}
        {snapshot?.module_id && (
          <div
            className="rounded-xl p-4 mb-4"
            style={{
              background: 'rgba(125,211,252,0.02)',
              border: '1px solid rgba(125,211,252,0.1)',
            }}
          >
            <VariantPicker
              moduleId={snapshot.module_id}
              value={variantId}
              onChange={onVariantChange}
            />
          </div>
        )}

        {isLab ? (
          <LabModePanel moduleId={snapshot?.module_id} />
        ) : (
          <div
            className="rounded-xl p-4"
            style={{
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <div className="font-mono text-[9px] tracking-[0.32em] text-attense-dim mb-3">
              TUTORIAL STEPS
            </div>
            <div className="space-y-3">
              {tutorialSteps.length > 0 ? tutorialSteps.map((s, i) => {
                if (typeof s === 'string') {
                  return (
                    <div key={i} className="flex gap-2 text-[11.5px] text-attense-dim leading-relaxed">
                      <span className="shrink-0 text-attense-dim font-mono">{i + 1}.</span>
                      <span>{s}</span>
                    </div>
                  )
                }
                return (
                  <div
                    key={i}
                    className="rounded-lg p-3"
                    style={{
                      background: 'rgba(255,255,255,0.025)',
                      border: '1px solid rgba(255,21,53,0.16)',
                    }}
                  >
                    <div className="flex items-start gap-2 mb-2">
                      <span
                        className="shrink-0 rounded flex items-center justify-center font-mono text-[10px] font-bold"
                        style={{
                          width: 22, height: 22,
                          background: 'rgba(255,21,53,0.10)',
                          color: '#ff6b81',
                          border: '1px solid rgba(255,21,53,0.32)',
                        }}
                      >
                        {i + 1}
                      </span>
                      <div className="text-[12px] font-semibold leading-snug" style={{ color: '#e6e8ee' }}>
                        {s.title || `Step ${i + 1}`}
                      </div>
                    </div>

                    {s.concept && (
                      <div className="mb-2">
                        <div className="font-mono text-[8.5px] tracking-[0.18em] mb-0.5" style={{ color: '#ff6b81' }}>
                          CONCEPT
                        </div>
                        <div className="text-[10.5px] leading-relaxed" style={{ color: '#c0c5db' }}>
                          {s.concept}
                        </div>
                      </div>
                    )}

                    {s.why && (
                      <div className="mb-2">
                        <div className="font-mono text-[8.5px] tracking-[0.18em] mb-0.5" style={{ color: '#fbbf24' }}>
                          WHY IT MATTERS
                        </div>
                        <div className="text-[10.5px] leading-relaxed" style={{ color: '#9aa0c0' }}>
                          {s.why}
                        </div>
                      </div>
                    )}

                    {s.tryIt && (
                      <div
                        className="text-[10.5px] p-2 rounded leading-relaxed mb-2"
                        style={{
                          background: 'rgba(125,211,252,0.05)',
                          border: '1px solid rgba(125,211,252,0.16)',
                          color: '#cfe7fb',
                        }}
                      >
                        <span className="font-mono text-[8.5px] tracking-[0.16em]" style={{ color: '#7dd3fc' }}>
                          TRY IT
                        </span>
                        <div className="mt-1">{s.tryIt}</div>
                      </div>
                    )}

                    {Array.isArray(s.lookFor) && s.lookFor.length > 0 && (
                      <div className="mb-2">
                        <div className="font-mono text-[8.5px] tracking-[0.18em] mb-1" style={{ color: '#9be8c5' }}>
                          LOOK FOR
                        </div>
                        <ul className="space-y-1">
                          {s.lookFor.map((item, k) => (
                            <li key={k} className="flex gap-1.5 text-[10.5px] leading-relaxed" style={{ color: '#a8b0cc' }}>
                              <span className="shrink-0" style={{ color: '#2ee39a' }}>-</span>
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {s.observe && (
                      <div className="text-[10px] leading-relaxed" style={{ color: '#7a8194' }}>
                        <span className="font-mono tracking-[0.14em]" style={{ color: '#8b9bba' }}>OBSERVE:</span>{' '}
                        {s.observe}
                      </div>
                    )}
                  </div>
                )
              }) : (
                <div className="text-[11.5px] text-attense-dim leading-relaxed">
                  Click START, then explore the lab page.
                </div>
              )}
            </div>
          </div>
        )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.aside>
  )
}

// ── LabBrowser: iframe with browser-style chrome ────────────────────────────
// P0-1: iframe is NOT rendered until missionStarted is true.
// P1-9: address bar is editable — learner can type /target/... paths.
function LabBrowser({ moduleId, missionStarted, onNavigate, mode = 'tutorial', sid, mutationReloadKey = 0, isMutating = false }) {
  const initialSrc = targetUrlFor(moduleId, mode)
  const [addr, setAddr]       = useState(initialSrc)
  const [editAddr, setEditAddr] = useState('')
  const [editing, setEditing]   = useState(false)
  const [iframeKey, setIfk]   = useState(0)
  const [loading, setLoading] = useState(false)
  const iframeRef = useRef(null)

  // Reset iframe to module's home when the module OR mode changes. Switching
  // Tutorial ↔ Lab must reload the iframe at the new prefix
  // (/target → /target-op) so the harder backend serves the page.
  useEffect(() => {
    const src = targetUrlFor(moduleId, mode)
    setAddr(src)
    if (missionStarted) { setIfk(k => k + 1); setLoading(true) }
  }, [moduleId, mode])

  // When missionStarted flips to true, trigger iframe load
  useEffect(() => {
    if (missionStarted) { setIfk(k => k + 1); setLoading(true) }
  }, [missionStarted])

  useEffect(() => {
    if (missionStarted && mutationReloadKey > 0) {
      setIfk(k => k + 1)
      setLoading(true)
    }
  }, [mutationReloadKey, missionStarted])

  // Allow parent components (recon buttons, CSRF button) to navigate
  useEffect(() => {
    if (onNavigate) onNavigate.current = navigateTo
  })

  const normalizePath = (raw) => {
    let p = raw.trim()
    if (p.startsWith('http://') || p.startsWith('https://')) return null // block external
    if (!p.startsWith('/')) p = '/' + p
    // Re-prefix to whichever proxy this mode owns. Strip an existing prefix
    // first so toggling modes converts paths cleanly.
    if (p.startsWith('/target-op')) p = p.slice('/target-op'.length) || '/'
    else if (p.startsWith('/target')) p = p.slice('/target'.length) || '/'
    const proxy = (mode === 'lab') ? '/target-op' : '/target'
    return `${proxy}${p === '/' ? '/' : p}`
  }

  const navigateTo = (path) => {
    const p = normalizePath(path)
    if (!p) return
    setAddr(p)
    setIfk(k => k + 1)
    setLoading(true)
  }

  const handleAddrSubmit = (e) => {
    e?.preventDefault?.()
    const p = normalizePath(editAddr)
    if (p) { setAddr(p); setIfk(k => k + 1); setLoading(true) }
    setEditing(false)
  }

  const refresh = () => { setIfk(k => k + 1); setLoading(true) }
  const resetToModule = () => { setAddr(initialSrc); setIfk(k => k + 1); setLoading(true) }

  return (
    <section className="flex-1 flex flex-col min-w-0 overflow-hidden">
      {/* Browser chrome */}
      <div
        className="shrink-0 flex items-center gap-2 px-3 py-2"
        style={{
          background: 'rgba(0,0,0,0.4)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}
      >
        <button onClick={refresh} title="Refresh" disabled={!missionStarted}
          className="shrink-0 w-7 h-7 rounded flex items-center justify-center text-attense-dim hover:text-attense-red transition-colors disabled:opacity-30"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M23 4v6h-6M1 20v-6h6"/>
            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
          </svg>
        </button>
        <button onClick={resetToModule} title="Reset to module start page" disabled={!missionStarted}
          className="shrink-0 w-7 h-7 rounded flex items-center justify-center text-attense-dim hover:text-attense-mint transition-colors disabled:opacity-30"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 12a9 9 0 119 9"/><path d="M3 21v-9h9"/>
          </svg>
        </button>

        {/* Editable address bar */}
        {editing ? (
          <form onSubmit={handleAddrSubmit} className="flex-1 min-w-0 flex items-center gap-1">
            <input
              autoFocus
              value={editAddr}
              onChange={e => setEditAddr(e.target.value)}
              onBlur={() => setEditing(false)}
              placeholder="/target/search"
              className="flex-1 font-mono text-[11px] rounded px-3 py-1.5 outline-none"
              style={{ background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(0,200,255,0.3)', color: '#e8ecf4' }}
            />
            <button type="submit"
              className="font-mono text-[9px] tracking-wider px-2 py-1 rounded"
              style={{ background: 'rgba(0,200,255,0.12)', border: '1px solid rgba(0,200,255,0.3)', color: '#7dd3fc' }}
            >GO</button>
          </form>
        ) : (
          <div
            onClick={() => { if (missionStarted) { setEditAddr(addr); setEditing(true) } }}
            className="flex-1 min-w-0 flex items-center gap-2 rounded px-3 py-1 cursor-text"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}
          >
            <div className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{ background: missionStarted ? '#2ee39a' : '#4a5280' }} />
            <code className="font-mono text-[11px] text-attense-text truncate">{addr}</code>
          </div>
        )}

        <button
          onClick={() => window.open(addr, '_blank', 'noopener,noreferrer')}
          title="Open in a new tab" disabled={!missionStarted}
          className="shrink-0 font-mono text-[9.5px] tracking-[0.16em] px-2.5 py-1 rounded text-attense-dim hover:text-attense-red transition-colors flex items-center gap-1.5 disabled:opacity-30"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
          </svg>
          NEW TAB
        </button>
      </div>

      {/* Content area — placeholder before START, iframe after */}
      <div className="flex-1 min-h-0 relative" style={{ background: '#0c0f16' }}>
        {!missionStarted ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 p-8">
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
              style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ff4060" strokeWidth="1.5">
                <polygon points="5 3 19 12 5 21 5 3"/>
              </svg>
            </div>
            <div className="text-center">
              <div className="font-mono text-[10px] tracking-[0.32em] text-attense-dim mb-2">LAB ENVIRONMENT</div>
              <div className="text-[14px] font-semibold text-attense-text mb-1">Press START to load the target</div>
              <div className="text-[12px] text-attense-dim max-w-sm leading-relaxed">
                The vulnerable application will load here after you start the mission.
                Your interactions will be tracked as evidence.
              </div>
            </div>
          </div>
        ) : (
          <>
            {loading && (
              <div className="absolute inset-0 flex items-center justify-center font-mono text-[10px] tracking-widest text-attense-dim z-10"
                style={{ background: 'rgba(7,9,15,0.5)', pointerEvents: 'none' }}>
                LOADING TARGET…
              </div>
            )}
            <iframe
              ref={iframeRef}
              key={iframeKey}
              src={addr}
              title="Vulnerable lab target"
              onLoad={() => {
                setLoading(false)
                try {
                  const u = iframeRef.current?.contentWindow?.location
                  if (u && u.pathname) setAddr(u.pathname + (u.search || ''))
                } catch {/* cross-origin */}
                // Phase 2 — pass session id into iframe so the injected
                // trace script knows which session to attribute clicks to.
                try {
                  iframeRef.current?.contentWindow?.postMessage(
                    { type: '__attense_session', session_id: sid, backend: '' },
                    '*'
                  )
                } catch {/* same-origin, won't fail */}
              }}
              style={{
                width: '100%', height: '100%', border: 'none', background: 'white',
                pointerEvents: 'auto',
                filter: isMutating ? 'grayscale(1) contrast(1.2) saturate(0.2)' : 'none',
                transition: 'filter 260ms ease',
              }}
            />
          </>
        )}
      </div>
    </section>
  )
}

// ── Evidence card ───────────────────────────────────────────────────────────
function EvidenceCard({ card }) {
  const sev = SEV_COLOR[card.severity || 'info'] || SEV_COLOR.info
  const ts  = card.timestamp
    ? new Date(card.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false })
    : ''

  return (
    <div
      className="rounded-lg px-3 py-2.5 mb-2"
      style={{
        background: sev.bg,
        border: `1px solid ${sev.bd}`,
      }}
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="font-mono text-[9px] tracking-[0.16em]" style={{ color: sev.fg }}>
          {(card.severity || 'info').toUpperCase()}
        </div>
        <div className="font-mono text-[9px] text-attense-dim">{ts}</div>
      </div>
      <div className="text-[12px] font-semibold mb-1" style={{ color: '#e6e8ee' }}>
        {card.title}
      </div>
      <div className="text-[11px] leading-relaxed" style={{ color: '#9aa0c0' }}>
        {card.description}
      </div>
      {card.event_type && (
        <div className="font-mono text-[9px] text-attense-dim mt-1">
          event: {card.event_type}
        </div>
      )}
    </div>
  )
}

// ── Mission complete summary ────────────────────────────────────────────────
const DEFENSE_DETAILS = {
  brute_force: {
    what: 'Discovered valid credentials by trying multiple passwords on a form with no lockout.',
    why: 'The login endpoint has no rate limiting, no CAPTCHA, and no account lockout.',
    fixes: ['Rate limiting (e.g. 5 attempts per minute)', 'Account lockout after N failures', 'Multi-factor authentication (MFA)', 'Login attempt monitoring and alerting'],
  },
  xss: {
    what: 'Injected script-like payloads that reflected unescaped in the HTML response.',
    why: 'User input is rendered directly into the page without HTML-encoding.',
    fixes: ['Output encoding (HTML entities)', 'Content Security Policy (CSP) headers', 'Input validation and sanitization', 'Template auto-escaping (Jinja2, React JSX)'],
  },
  cmd_injection: {
    what: 'Chained OS commands via the ping form using shell metacharacters.',
    why: 'The host parameter is passed directly to os.popen() with no sanitization.',
    fixes: ['Never pass user input to shell commands', 'Use subprocess with shell=False and argument lists', 'Validate against a strict allowlist of hostnames', 'Principle of least privilege for the web process'],
  },
  dir_traversal: {
    what: 'Read sensitive system files by escaping the web root with ../ sequences.',
    why: 'The file path is concatenated without normalization or directory restriction.',
    fixes: ['Normalize paths with os.path.realpath()', 'Verify resolved path stays inside base directory', 'Use allowlisted file IDs instead of raw paths', 'Chroot or container-level path isolation'],
  },
  file_upload: {
    what: 'Uploaded files with dangerous extensions that were accepted and stored.',
    why: 'No extension validation, no MIME check, and files keep their original name.',
    fixes: ['Extension allowlist (only .jpg, .png, .pdf, etc.)', 'Rename files to random hashes on save', 'Store uploads outside executable paths', 'Scan uploads with antivirus/ClamAV'],
  },
  csrf: {
    what: 'A simulated attacker page changed profile data without the user\'s consent.',
    why: 'The profile update form has no CSRF token and doesn\'t check Origin/Referer.',
    fixes: ['CSRF tokens on every state-changing form', 'SameSite=Strict cookie attribute', 'Origin/Referer header validation', 'Re-authentication for sensitive actions'],
  },
  recon: {
    what: 'Mapped the attack surface by discovering hidden routes and internal info.',
    why: 'The app exposes too many internal details: version strings, debug comments, robots.txt.',
    fixes: ['Remove debug comments from production HTML', 'Minimize server version disclosure', 'Restrict robots.txt to only necessary entries', 'Monitor and alert on rapid endpoint enumeration'],
  },
}

function MissionCompleteSummary({ snapshot, briefing, progress, elapsed }) {
  const moduleId = snapshot?.module_id
  const sid = snapshot?.session_id
  const legacyDefense = DEFENSE_DETAILS[moduleId] || {}
  const defense = briefing?.defenseBreakdown || {}
  const mitigations = Array.isArray(defense.mitigations) && defense.mitigations.length > 0
    ? defense.mitigations
    : (legacyDefense.fixes || []).map(f => ({ name: f, implementation: '', verify: '' }))
  return (
    <div className="rounded-xl p-4 mb-4"
      style={{ background: 'rgba(46,227,154,0.06)', border: '1px solid rgba(46,227,154,0.3)' }}>
      <div className="flex items-center justify-between mb-2">
        <div className="font-mono text-[9px] tracking-[0.28em]" style={{ color: '#2ee39a' }}>
          ✓ MISSION COMPLETE
        </div>
        {sid && (
          <motion.a
            href={`/report/${sid}`}
            className="font-mono text-[9.5px] font-bold tracking-[0.14em] px-2.5 py-1 rounded"
            style={{
              background: 'rgba(46,227,154,0.12)',
              border: '1px solid rgba(46,227,154,0.45)',
              color: '#2ee39a',
              textDecoration: 'none',
            }}
            whileHover={{ background: 'rgba(46,227,154,0.2)', y: -1 }}
            whileTap={{ scale: 0.97 }}
          >VIEW FULL REPORT →</motion.a>
        )}
      </div>
      <div className="text-[13.5px] font-semibold text-attense-text mb-2">
        Vulnerability demonstrated successfully.
      </div>
      {legacyDefense.what && (
        <div className="text-[11.5px] text-attense-muted leading-relaxed mb-2">
          <strong style={{ color: '#c0c5db' }}>What you did:</strong> {legacyDefense.what}
        </div>
      )}
      {legacyDefense.why && (
        <div className="text-[11.5px] text-attense-muted leading-relaxed mb-3">
          <strong style={{ color: '#c0c5db' }}>Why it worked:</strong> {legacyDefense.why}
        </div>
      )}
      <div className="flex items-center gap-3 mb-3">
        <span className="font-mono text-[10px] text-attense-dim">TIME:</span>
        <span className="font-mono text-[12px] font-semibold tabular-nums" style={{ color: '#2ee39a' }}>
          {fmtTime(elapsed)}
        </span>
        <span className="font-mono text-[10px] text-attense-dim">·</span>
        <span className="font-mono text-[10px] text-attense-dim">EVIDENCE:</span>
        <span className="font-mono text-[12px] font-semibold tabular-nums text-attense-text">
          {progress?.evidence?.length || 0}
        </span>
      </div>
      {/* Defensive fixes */}
      {mitigations.length > 0 && (
        <div className="rounded-lg p-3 mt-2"
          style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.2)' }}>
          <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#7dd3fc' }}>
            {defense.title || 'HOW TO DEFEND'}
          </div>
          {defense.summary && (
            <div className="text-[11px] text-attense-muted leading-relaxed mb-2">
              {defense.summary}
            </div>
          )}
          <div className="space-y-2">
            {mitigations.map((m, i) => (
              <div key={i} className="text-[11px] text-attense-text leading-relaxed">
                <div className="flex gap-2">
                  <span style={{ color: '#7dd3fc' }} className="shrink-0">✦</span>
                  <span className="font-semibold" style={{ color: '#dbeafe' }}>{m.name}</span>
                </div>
                {m.implementation && (
                  <div className="ml-4 mt-0.5" style={{ color: '#a8b0cc' }}>
                    {m.implementation}
                  </div>
                )}
                {m.verify && (
                  <div className="ml-4 mt-0.5 font-mono text-[9.5px]" style={{ color: '#7a8194' }}>
                    VERIFY: {m.verify}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {progress?.defensive_insight && mitigations.length === 0 && (
        <div className="rounded-lg p-3 mt-2"
          style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.2)' }}>
          <div className="font-mono text-[9px] tracking-[0.28em] mb-1" style={{ color: '#7dd3fc' }}>
            DEFENSIVE INSIGHT
          </div>
          <div className="text-[11.5px] text-attense-text leading-relaxed">
            {progress.defensive_insight}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Quick-nav buttons for specific modules ──────────────────────────────────
const RECON_LINKS = [
  { label: 'Portal Home',  path: '/' },
  { label: 'Login',        path: '/auth/login' },
  { label: 'Search',       path: '/search' },
  { label: 'Diagnostics',  path: '/system/ping' },
  { label: 'File Viewer',  path: '/files/read?path=readme.txt' },
  { label: 'File Upload',  path: '/files/upload' },
  { label: 'Profile',      path: '/profile/' },
  { label: 'robots.txt',   path: '/robots.txt' },
  { label: 'security.txt', path: '/.well-known/security.txt' },
]

// ── LearningPanel (right column) ────────────────────────────────────────────
function LearningPanel({
  briefing, snapshot, progress,
  missionStarted, isCheckingProgress, onCheckProgress,
  isDone, elapsed,
  showAdvanced, onToggleAdvanced,
  onNavigateTo, onRestart,
  mode = 'tutorial',
  activeMutation = null,
  mutationFlipKey = 0,
  collapsed, onToggle,
}) {
  const evidence = progress?.evidence || []
  const success  = progress?.success
  const moduleId = snapshot?.module_id
  const isLab = mode === 'lab'
  const objective = isLab
    ? labObjectiveFor(moduleId)
    : (briefing?.objective || briefing?.background || '')
  const objectiveTitle = activeMutation
    ? 'MUTATION OBJECTIVE'
    : (isLab ? 'LAB OBJECTIVE' : 'TUTORIAL OBJECTIVE')
  const objectiveText = activeMutation?.objective || objective
  const objectiveColor = activeMutation?.color || (isLab ? '#7dd3fc' : '#ff4060')
  const requiredTools = isLab ? requiredToolsFor(moduleId) : []
  const [hintsRevealed, setHintsRevealed] = useState(0)

  // Build hint tiers from briefing
  const hints = useMemo(() => {
    const h = []
    if (briefing?.tip) h.push(briefing.tip)
    if (briefing?.watchFor) briefing.watchFor.forEach(w => h.push(w))
    return h
  }, [briefing])

  return (
    <motion.aside
      animate={{ width: collapsed ? 36 : 360 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
      className="shrink-0 overflow-hidden flex flex-col"
      style={{
        borderLeft: '1px solid rgba(255,255,255,0.06)',
        background: 'rgba(7,9,15,0.55)',
      }}
    >
      {/* Collapse toggle */}
      <div className="shrink-0 flex items-center justify-start px-2 pt-2 pb-1">
        <button
          onClick={onToggle}
          title={collapsed ? 'Expand panel' : 'Collapse panel'}
          className="text-attense-dim hover:text-attense-red transition-colors p-1 rounded"
          style={{ border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)' }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            {collapsed
              ? <path d="M15 18l-6-6 6-6"/>
              : <path d="M9 18l6-6-6-6"/>
            }
          </svg>
        </button>
      </div>
      <AnimatePresence initial={false}>
        {!collapsed && (
          <motion.div
            key="right-content"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="overflow-y-auto flex-1"
            style={{ padding: '4px 16px 16px' }}
          >
        {/* Mission complete summary at the top when done */}
        {success && (
          <MissionCompleteSummary
            snapshot={snapshot}
            briefing={briefing}
            progress={progress}
            elapsed={elapsed}
          />
        )}

        {/* Objective */}
        <motion.div
          key={`objective-${mutationFlipKey}-${activeMutation?.id || 'base'}`}
          initial={activeMutation ? { rotateX: -72, opacity: 0 } : false}
          animate={{ rotateX: 0, opacity: 1 }}
          transition={{ duration: 0.42, ease: [0.22, 1, 0.36, 1] }}
          className="rounded-xl p-4 mb-4"
          style={{
            transformStyle: 'preserve-3d',
            background: activeMutation
              ? `linear-gradient(135deg, ${objectiveColor}12 0%, rgba(7,9,15,0.62) 100%)`
              : isLab
              ? 'linear-gradient(135deg, rgba(125,211,252,0.06) 0%, rgba(14,165,233,0.04) 100%)'
              : 'linear-gradient(135deg, rgba(255,21,53,0.05) 0%, rgba(139,47,255,0.03) 100%)',
            border: activeMutation
              ? `1px solid ${objectiveColor}55`
              : isLab
              ? '1px solid rgba(125,211,252,0.25)'
              : '1px solid rgba(255,21,53,0.18)',
          }}
        >
          <div
            className="font-mono text-[9px] tracking-[0.28em] mb-2"
            style={{ color: objectiveColor }}
          >
            {objectiveTitle}
          </div>
          <div className="text-[12px] text-attense-text leading-relaxed">
            {objectiveText}
          </div>
          {activeMutation?.target_task && (
            <div
              className="mt-3 rounded-lg p-3 font-mono text-[10.5px] leading-relaxed"
              style={{ background: 'rgba(0,0,0,0.24)', border: `1px solid ${objectiveColor}30`, color: '#cfd6e8' }}
            >
              {activeMutation.target_task}
            </div>
          )}
        </motion.div>

        {/* Required tools — Lab Mode only */}
        {isLab && requiredTools.length > 0 && (
          <div
            className="rounded-xl p-4 mb-4"
            style={{
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim mb-2">
              REQUIRED TOOLS
            </div>
            <div className="flex flex-wrap gap-1.5">
              {requiredTools.map(t => (
                <span
                  key={t}
                  className="font-mono text-[10px] tracking-[0.06em] px-2 py-1 rounded"
                  style={{
                    background: 'rgba(125,211,252,0.06)',
                    border: '1px solid rgba(125,211,252,0.22)',
                    color: '#9ae4ff',
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
            <div className="font-mono text-[9.5px] text-attense-dim mt-3 leading-relaxed">
              All tools run inside the local ATTENSE lab. External targets are not supported.
            </div>
          </div>
        )}

        {/* Quick-nav buttons for recon */}
        {moduleId === 'recon' && missionStarted && (
          <div className="rounded-xl p-3 mb-4"
            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <div className="font-mono text-[9px] tracking-[0.32em] text-attense-dim mb-2">
              EXPLORE PAGES
            </div>
            <div className="flex flex-wrap gap-1.5">
              {RECON_LINKS.map(l => (
                <button key={l.path} onClick={() => onNavigateTo?.(l.path)}
                  className="font-mono text-[9px] px-2.5 py-1.5 rounded transition-colors"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#a8b0cc' }}
                >{l.label}</button>
              ))}
            </div>
          </div>
        )}

        {/* CSRF demo button */}
        {moduleId === 'csrf' && missionStarted && (
          <div className="rounded-xl p-3 mb-4"
            style={{ background: 'rgba(248,113,113,0.04)', border: '1px solid rgba(248,113,113,0.2)' }}>
            <div className="font-mono text-[9px] tracking-[0.32em] mb-2" style={{ color: '#f87171' }}>
              CSRF DEMO
            </div>
            <div className="flex gap-2">
              <button onClick={() => onNavigateTo?.('/profile/')}
                className="font-mono text-[9px] px-2.5 py-1.5 rounded transition-colors flex-1"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#a8b0cc' }}
              >Open Profile</button>
              <button onClick={() => onNavigateTo?.('/evil/csrf-demo')}
                className="font-mono text-[9px] px-2.5 py-1.5 rounded transition-colors flex-1"
                style={{ background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.25)', color: '#fca5a5' }}
              >Open CSRF Lure Page</button>
            </div>
          </div>
        )}

        {/* Check Progress button */}
        <button
          onClick={onCheckProgress}
          disabled={!missionStarted || isCheckingProgress}
          className="w-full font-mono text-[10.5px] font-bold tracking-[0.16em] px-4 py-2.5 rounded-lg transition-all duration-150 mb-4 flex items-center justify-center gap-2"
          style={{
            background: !missionStarted
              ? 'rgba(255,255,255,0.04)'
              : isCheckingProgress
                ? 'rgba(255,255,255,0.04)'
                : 'linear-gradient(135deg, #7dd3fc, #0ea5e9)',
            color: !missionStarted || isCheckingProgress ? '#3a4060' : '#0c0f16',
            border: !missionStarted ? '1px solid rgba(255,255,255,0.08)' : 'none',
            cursor: !missionStarted || isCheckingProgress ? 'not-allowed' : 'pointer',
          }}
        >
          {!missionStarted
            ? 'PRESS START FIRST'
            : isCheckingProgress
              ? 'CHECKING…'
              : 'CHECK PROGRESS ↻'}
        </button>

        {/* Evidence cards */}
        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-[9px] tracking-[0.32em] text-attense-dim">EVIDENCE</span>
            <span className="font-mono text-[10px] text-attense-dim">
              {evidence.length} card{evidence.length === 1 ? '' : 's'}
            </span>
          </div>
          {evidence.length === 0 ? (
            <div
              className="rounded-lg p-4 text-center"
              style={{
                background: 'rgba(255,255,255,0.02)',
                border: '1px dashed rgba(255,255,255,0.08)',
              }}
            >
              <div className="font-mono text-[10px] text-attense-dim leading-relaxed">
                {!missionStarted
                  ? 'Press START to begin tracking evidence.'
                  : 'Interact with the target page on the left, then click CHECK PROGRESS.'}
              </div>
            </div>
          ) : (
            evidence.map((c, i) => <EvidenceCard key={i} card={c} />)
          )}
        </div>

        {/* Revealable hints — Lab Mode only */}
        {isLab && hints.length > 0 && !success && (
          <div className="rounded-xl p-4 mb-4"
            style={{ background: 'rgba(250,204,21,0.03)', border: '1px solid rgba(250,204,21,0.15)' }}>
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-[9px] tracking-[0.32em]" style={{ color: '#fbbf24' }}>
                HINTS
              </span>
              <span className="font-mono text-[9px] text-attense-dim">
                {hintsRevealed}/{hints.length}
              </span>
            </div>
            {hints.slice(0, hintsRevealed).map((h, i) => (
              <div key={i} className="text-[11px] text-attense-text leading-relaxed mb-1.5 flex gap-2">
                <span style={{ color: '#fbbf24' }} className="shrink-0">💡</span>
                <span>{h}</span>
              </div>
            ))}
            {hintsRevealed < hints.length && (
              <button onClick={() => setHintsRevealed(v => v + 1)}
                className="w-full font-mono text-[9.5px] tracking-wider py-1.5 rounded mt-1 transition-colors"
                style={{ background: 'rgba(250,204,21,0.06)', border: '1px solid rgba(250,204,21,0.2)', color: '#fbbf24' }}
              >REVEAL HINT</button>
            )}
          </div>
        )}

        {/* Defensive insight (shown during mission, not at end) */}
        {progress?.defensive_insight && !success && (
          <div className="rounded-xl p-4 mb-4"
            style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.2)' }}>
            <div className="font-mono text-[9px] tracking-[0.28em] mb-1" style={{ color: '#7dd3fc' }}>
              HOW TO DEFEND
            </div>
            <div className="text-[11.5px] text-attense-text leading-relaxed">
              {progress.defensive_insight}
            </div>
          </div>
        )}

        {/* Restart Mission button */}
        {missionStarted && onRestart && (
          <button onClick={onRestart}
            className="w-full font-mono text-[9.5px] tracking-[0.22em] py-2 rounded-lg transition-colors mb-3"
            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', color: '#7a8194' }}
          >↺ RESTART MISSION</button>
        )}

        {/* Advanced / developer tools toggle */}
        <button
          onClick={onToggleAdvanced}
          className="w-full text-left font-mono text-[9.5px] tracking-[0.22em] text-attense-dim hover:text-attense-muted transition-colors py-2 flex items-center justify-between"
          style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}
        >
          <span>ADVANCED · INSTRUCTOR TOOLS</span>
          <span style={{ transform: showAdvanced ? 'rotate(90deg)' : '', transition: 'transform 0.15s' }}>›</span>
        </button>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.aside>
  )
}

// ── Advanced collapsed strip (bottom) ───────────────────────────────────────
// Only visible when the user opts in via the LearningPanel toggle. Holds
// the optional "Run Automated Scan" affordance for instructor demos.
function AdvancedTools({ open, snapshot, sid, onExecute, executing }) {
  if (!open) return null
  const attackDone = snapshot?.state === 'completed' || snapshot?.state === 'error'
  return (
    <div
      className="shrink-0"
      style={{
        background: 'rgba(0,0,0,0.4)',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '10px 16px',
      }}
    >
      <div className="flex items-center gap-3 flex-wrap">
        <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim">
          ADVANCED
        </div>
        <button
          onClick={onExecute}
          disabled={executing}
          className="font-mono text-[10px] tracking-[0.14em] px-3 py-1.5 rounded transition-colors"
          style={{
            background: executing ? 'rgba(255,255,255,0.04)' : 'rgba(245,196,0,0.06)',
            border: '1px solid rgba(245,196,0,0.25)',
            color: executing ? '#3a4060' : '#fbbf24',
            cursor: executing ? 'not-allowed' : 'pointer',
          }}
        >
          {executing ? 'RUNNING…' : 'RUN AUTOMATED SCAN'}
        </button>
        {attackDone && (
          <Link
            to={`/attack-report/${sid}`}
            className="font-mono text-[10px] tracking-[0.14em] px-3 py-1.5 rounded transition-colors"
            style={{
              background: 'rgba(255,64,96,0.07)',
              border: '1px solid rgba(255,64,96,0.3)',
              color: '#ff4060',
            }}
          >
            VIEW ATTACK REPORT →
          </Link>
        )}
        {!attackDone && (
          <span className="font-mono text-[9.5px] text-attense-dim">
            (runs the backend scanner — an attack report will be available after)
          </span>
        )}
      </div>
    </div>
  )
}

// ── Main Workspace ──────────────────────────────────────────────────────────
export default function Workspace() {
  const { sid }  = useParams()
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const replay   = search.get('replay') === '1'
  const mutationQuery = search.get('mutation') === '1'
  const mutationIntensityParam = search.get('intensity') || 'single'

  const { snapshot, logs, running, start, reset } = useSession(sid, { replay })

  const [module, setModule] = useState(null)
  const [error,  setError]  = useState(null)
  const [progress, setProgress] = useState(null)
  const [isCheckingProgress, setIsCheckingProgress] = useState(false)
  const [missionStarted, setMissionStarted] = useState(false)
  const [showAdvanced, setShowAdvanced]     = useState(false)
  const [executing, setExecuting]           = useState(false)
  const [labPanelMinimized, setLabPanelMinimized] = useState(false)
  const [leftCollapsed, setLeftCollapsed]   = useState(false)
  const [rightCollapsed, setRightCollapsed] = useState(false)
  const [reportReady, setReportReady]       = useState(false)
  const reportPrimedRef = useRef(false)
  const [activeMutations, setActiveMutations] = useState([])
  const [mutationStatus, setMutationStatus] = useState(null)
  const [shapeshiftEvent, setShapeshiftEvent] = useState(null)
  const [mutationReloadKey, setMutationReloadKey] = useState(0)
  const [mutationFlipKey, setMutationFlipKey] = useState(0)
  const [soundEnabled, setSoundEnabled] = useState(() => localStorage.getItem('attense_mutation_sound') === '1')
  const [mutationBannerDismissed, setMutationBannerDismissed] = useState(false)
  const prevMutationIdsRef = useRef('')
  const seenMutationEventsRef = useRef(new Set())
  const mutationArmRef = useRef(false)
  const mutationAutoStartRef = useRef(false)
  const modeHydratedRef = useRef(false)
  const isMutationRun = mutationQuery || Boolean(snapshot?.mutation_mode)
  const mutationIntensity = snapshot?.mutation_intensity || mutationIntensityParam

  // ── Browser panel resize ──────────────────────────────────────────────────
  const [browserWidth, setBrowserWidth]   = useState(null) // null = flex-1
  const browserColRef    = useRef(null)
  const isDraggingRef    = useRef(false)
  const dragStartXRef    = useRef(0)
  const dragStartWidthRef = useRef(0)

  useEffect(() => {
    const onMove = (e) => {
      if (!isDraggingRef.current) return
      const dx = e.clientX - dragStartXRef.current
      const next = Math.max(280, Math.min(window.innerWidth * 0.82, dragStartWidthRef.current + dx))
      setBrowserWidth(next)
    }
    const onUp = () => {
      if (!isDraggingRef.current) return
      isDraggingRef.current = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
  }, [])

  // Mutation polling — every 5s, silently
  useEffect(() => {
    if (!sid) return
    let cancelled = false
    const poll = () => {
      api.sessions.mutationStatus(sid)
        .then(data => {
          if (!cancelled) {
            const incoming = data?.active || []
            const incomingKey = incoming.map(m => m.id).sort().join(',')
            setMutationStatus(data)
            setActiveMutations(incoming)
            if (incomingKey !== prevMutationIdsRef.current) {
              prevMutationIdsRef.current = incomingKey
              setMutationBannerDismissed(false)
            }
            const fired = (data?.timeline || []).filter(e => e.status === 'fired')
            for (const event of fired) {
              if (!seenMutationEventsRef.current.has(event.id)) {
                seenMutationEventsRef.current.add(event.id)
                if (isMutationRun && !replay) {
                  setShapeshiftEvent(event)
                  setMutationBannerDismissed(true)
                }
              }
            }
          }
        })
        .catch(() => {}) // silence — mutations are optional
    }
    poll()
    const id = setInterval(poll, isMutationRun ? 2000 : 5000)
    return () => { cancelled = true; clearInterval(id) }
  }, [sid, isMutationRun, replay])

  // Mode + Lab tool selection. Default mode is "tutorial" so Tutorial Mode
  // remains active across START and the learner sees no Lab tools by
  // default. Switching modes does NOT restart the mission, reset evidence,
  // or reload the iframe.
  const [mode, setMode] = useState('tutorial')
  const [selectedLabTool, setSelectedLabTool] = useState('terminal')
  // Active attack variant. Hydrated from session snapshot once available.
  const [variantId, setVariantId] = useState(null)
  const toolsVisible = mode === 'lab' || isMutationRun
  const activeMutation = activeMutations[activeMutations.length - 1] || null

  useEffect(() => {
    if (!modeHydratedRef.current && snapshot?.mode) {
      modeHydratedRef.current = true
      setMode(snapshot.mode)
    }
  }, [snapshot?.mode])

  const toggleMutationSound = () => {
    setSoundEnabled(v => {
      const next = !v
      localStorage.setItem('attense_mutation_sound', next ? '1' : '0')
      return next
    })
  }

  // When learner picks a different variant: persist + immediately re-fetch progress
  const handleVariantChange = async (v) => {
    setVariantId(v)
    if (sid) {
      try { await api.sessions.setVariant(sid, v) } catch {}
      try {
        const p = await api.sessions.checkProgress(sid, mode)
        setProgress(p)
      } catch {}
    }
  }

  // Timer
  const [elapsed, setElapsed] = useState(0)
  const timerStartRef    = useRef(null)
  const timerIntervalRef = useRef(null)

  const startTimer = () => {
    timerStartRef.current = Date.now()
    setElapsed(0)
    if (timerIntervalRef.current) clearInterval(timerIntervalRef.current)
    timerIntervalRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - timerStartRef.current) / 1000))
    }, 1000)
  }
  const stopTimer = () => {
    if (timerIntervalRef.current) {
      clearInterval(timerIntervalRef.current)
      timerIntervalRef.current = null
    }
  }
  useEffect(() => () => stopTimer(), [])

  // Load module metadata
  useEffect(() => {
    if (!snapshot?.module_id) return
    api.modules().then(mods => {
      const m = mods.find(x => x.module_id === snapshot.module_id)
      if (m) setModule(m); else setError(`Module ${snapshot.module_id} not found`)
    }).catch(e => setError(e.message))
  }, [snapshot?.module_id])

  // Hydrate variant from snapshot once available (no overwrite if already set)
  useEffect(() => {
    if (snapshot?.variant_id && variantId === null) {
      setVariantId(snapshot.variant_id)
    }
  }, [snapshot?.variant_id, variantId])

  // If the session already had mission_started_at on mount, restore timer
  useEffect(() => {
    if (snapshot?.mission_started_at && !missionStarted && !replay) {
      const elapsedSec = Math.max(0, Math.floor(Date.now() / 1000 - snapshot.mission_started_at))
      setMissionStarted(true)
      timerStartRef.current = Date.now() - elapsedSec * 1000
      setElapsed(elapsedSec)
      if (!timerIntervalRef.current) {
        timerIntervalRef.current = setInterval(() => {
          setElapsed(Math.floor((Date.now() - timerStartRef.current) / 1000))
        }, 1000)
      }
    }
  }, [snapshot?.mission_started_at, missionStarted, replay])

  // Mission complete → stop timer + pre-warm report cache + show banner
  useEffect(() => {
    if (!progress?.success) return
    stopTimer()
    if (!reportPrimedRef.current && sid) {
      reportPrimedRef.current = true
      api.sessions.getReport(sid)
        .then(() => setReportReady(true))
        .catch(() => setReportReady(true))
    }
  }, [progress?.success, sid])

  // Auto-poll progress every 8s while mission is active (not yet complete).
  // This removes the need for the learner to manually click CHECK PROGRESS
  // after every interaction — evidence cards update automatically.
  const progressPollRef = useRef(null)
  useEffect(() => {
    if (missionStarted && !progress?.success && !replay && sid) {
      progressPollRef.current = setInterval(() => {
        api.sessions.checkProgress(sid, mode)
          .then(p => setProgress(p))
          .catch(() => {})
      }, 8000)
    }
    return () => {
      if (progressPollRef.current) {
        clearInterval(progressPollRef.current)
        progressPollRef.current = null
      }
    }
  }, [missionStarted, progress?.success, replay, sid, mode])

  // Re-fetch progress immediately when mode changes (so the Lab ladder
  // becomes visible without waiting 8s for the next poll).
  useEffect(() => {
    if (missionStarted && sid) {
      api.sessions.checkProgress(sid, mode)
        .then(p => setProgress(p))
        .catch(() => {})
    }
  }, [mode, missionStarted, sid])

  const briefing = useMemo(() => briefingFor(snapshot?.module_id), [snapshot?.module_id])

  const handleStart = async () => {
    if (missionStarted) return
    try {
      await start()  // backend sets mission_started_at + starts internal timer
    } catch (e) { console.error('start failed', e) }
    setMissionStarted(true)
    startTimer()
    // First Check Progress runs automatically so the panel becomes useful
    setTimeout(() => handleCheckProgress(), 150)
  }

  useEffect(() => {
    if (!isMutationRun || !snapshot?.session_id || missionStarted || replay) return
    if (mutationAutoStartRef.current) return
    mutationAutoStartRef.current = true
    handleStart()
  }, [isMutationRun, snapshot?.session_id, missionStarted, replay])

  useEffect(() => {
    if (!isMutationRun || !missionStarted || !sid || replay) return
    if (mutationArmRef.current) return
    mutationArmRef.current = true
    api.sessions.scheduleMutation(sid, {
      module_id: snapshot?.module_id,
      intensity: mutationIntensity,
    })
      .then(data => {
        if (data?.event) {
          setMutationStatus(prev => ({ ...(prev || {}), next_fire_at: data.event.fire_at, status: 'scheduled' }))
        }
      })
      .catch(() => { mutationArmRef.current = false })
  }, [isMutationRun, missionStarted, sid, replay, snapshot?.module_id, mutationIntensity])

  const handleCheckProgress = async () => {
    if (!sid) return
    setIsCheckingProgress(true)
    try {
      const p = await api.sessions.checkProgress(sid, mode)
      setProgress(p)
    } catch (e) { console.error('check-progress failed', e) }
    finally { setIsCheckingProgress(false) }
  }

  const handleExit = async () => {
    stopTimer()
    if (replay) { navigate('/'); return }
    try { await reset() } catch {}
    navigate('/')
  }

  // P0-4: Restart Mission — creates a fresh attempt
  const labNavigateRef = useRef(null)

  const handleRestart = async () => {
    if (!sid) return
    try { await api.sessions.restart(sid) } catch (e) { console.error('restart failed', e) }
    setProgress(null)
    startTimer()
    if (labNavigateRef.current) {
      labNavigateRef.current(targetPathFor(snapshot?.module_id))
    }
    setTimeout(() => handleCheckProgress(), 300)
  }

  const handleNavigateTo = (path) => {
    if (labNavigateRef.current) labNavigateRef.current(path)
  }

  const handleAdvancedExecute = async () => {
    if (!sid) return
    setExecuting(true)
    try { await api.sessions.execute(sid) }
    catch (e) { console.error('execute failed', e) }
    finally {
      setExecuting(false)
      handleCheckProgress()
    }
  }

  const handleMutationReveal = () => {
    setMutationReloadKey(k => k + 1)
    setMutationFlipKey(k => k + 1)
    setMutationBannerDismissed(false)
    setTimeout(() => handleCheckProgress(), 450)
  }

  const handleMutationDone = () => {
    setShapeshiftEvent(null)
  }

  if (error) return (
    <div className="p-6 max-w-2xl mx-auto">
      <div
        className="rounded-lg p-4 font-mono text-[11px]"
        style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}
      >
        {error}
      </div>
      <Link to="/" className="inline-block mt-4 font-mono text-[11px] text-attense-muted hover:text-attense-red">← Back</Link>
    </div>
  )

  if (!snapshot) return (
    <div className="h-full flex items-center justify-center font-mono text-[11px] tracking-widest text-attense-dim">
      LOADING WORKSPACE…
    </div>
  )

  const state  = snapshot.state
  const isDone = progress?.success || state === 'completed'

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Top toolbar — mission info, mode buttons, and action buttons */}
      <div
        className="shrink-0 flex flex-wrap items-center gap-3 px-5 py-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <Link to="/"
          className="font-mono text-[9.5px] tracking-[0.22em] text-attense-dim hover:text-attense-red transition-colors shrink-0"
        >← EXIT MISSION</Link>

        {/* Mission title + status + timer */}
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="text-[13.5px] font-semibold text-attense-text truncate">
            {snapshot.module_name || 'Mission'}
          </div>
          <span
            className="font-mono text-[9px] tracking-[0.14em] px-2 py-0.5 rounded shrink-0"
            style={{
              color: isDone ? '#2ee39a' : missionStarted ? '#ff4060' : '#4a5280',
              background: isDone ? 'rgba(46,227,154,0.07)' : missionStarted ? 'rgba(255,21,53,0.08)' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isDone ? 'rgba(46,227,154,0.3)' : missionStarted ? 'rgba(255,21,53,0.3)' : 'rgba(255,255,255,0.08)'}`,
            }}
          >
            {isDone ? 'SUCCESS' : missionStarted ? 'IN PROGRESS' : 'IDLE'}
          </span>
          {missionStarted && (
            <span className="font-mono text-[11px] font-semibold tabular-nums shrink-0"
              style={{ color: isDone ? '#2ee39a' : '#ff4060' }}>{fmtTime(elapsed)}</span>
          )}
        </div>

        {/* Mode switcher — sits beside the timer */}
        <ModeSwitcher mode={mode} onChange={setMode} />

        {isMutationRun && (
          <span
            className="font-mono text-[9px] tracking-[0.16em] px-2 py-1 rounded shrink-0"
            style={{ background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.35)', color: '#fb923c' }}
          >
            MUTATION {mutationIntensity.toUpperCase()}
          </span>
        )}

        {isMutationRun && mutationStatus?.next_fire_at && (
          <span className="font-mono text-[9px] text-attense-dim shrink-0">
            SHIFT WINDOW ARMED
          </span>
        )}

        {isMutationRun && (
          <button
            onClick={toggleMutationSound}
            title={soundEnabled ? 'Disable mutation sound' : 'Enable mutation sound'}
            className="shrink-0 w-8 h-8 rounded flex items-center justify-center transition-colors"
            style={{ border: '1px solid rgba(255,255,255,0.08)', color: soundEnabled ? '#fb923c' : '#5a6580', background: soundEnabled ? 'rgba(251,146,60,0.08)' : 'rgba(255,255,255,0.02)' }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
              {soundEnabled ? <path d="M15 9.5a4 4 0 010 5M18 7a8 8 0 010 10" /> : <path d="M16 9l5 5M21 9l-5 5" />}
            </svg>
          </button>
        )}

        {/* Lab tools strip — only in Lab mode */}
        {toolsVisible && (
          <>
            <span
              className="hidden md:inline-block shrink-0"
              style={{
                width: 1, height: 22,
                background: 'rgba(255,255,255,0.10)',
              }}
            />
            <LabToolsStrip
              selectedTool={selectedLabTool}
              onSelect={setSelectedLabTool}
            />
          </>
        )}

        {/* Spacer */}
        <div className="flex-1" />

        {/* Action buttons */}
        {!replay && !missionStarted && (
          <button onClick={handleStart}
            className="font-mono text-[10.5px] font-bold tracking-[0.14em] px-5 py-2 rounded-lg transition-all duration-150 shrink-0"
            style={{ background: 'linear-gradient(135deg,#ff1535,#cc0020)', color: 'white', boxShadow: '0 0 14px rgba(255,21,53,0.35)' }}
          >START ▸</button>
        )}
        {!replay && missionStarted && !isDone && (
          <button onClick={handleCheckProgress} disabled={isCheckingProgress}
            className="font-mono text-[10.5px] font-bold tracking-[0.14em] px-4 py-2 rounded-lg transition-all duration-150 shrink-0"
            style={{ background: 'linear-gradient(135deg,#7dd3fc,#0ea5e9)', color: '#0c0f16', cursor: isCheckingProgress ? 'wait' : 'pointer' }}
          >{isCheckingProgress ? 'CHECKING…' : 'CHECK PROGRESS ↻'}</button>
        )}
        <button onClick={handleExit}
          className="font-mono text-[10.5px] tracking-[0.14em] px-3 py-2 rounded-lg text-attense-muted transition-colors shrink-0"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }}
        >{replay ? 'CLOSE' : 'EXIT'}</button>
      </div>

      {/* 3-column body */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        <MissionSidebar
          snapshot={snapshot} module={module} briefing={briefing}
          elapsed={elapsed} timerRunning={missionStarted && !isDone}
          isDone={isDone} progress={progress} mode={mode}
          variantId={variantId} onVariantChange={handleVariantChange}
          collapsed={leftCollapsed} onToggle={() => setLeftCollapsed(v => !v)}
        />
        {/* ── Drag handle on left edge of browser panel ── */}
        <div
          title="Drag to resize browser"
          onMouseDown={(e) => {
            isDraggingRef.current    = true
            dragStartXRef.current   = e.clientX
            dragStartWidthRef.current = browserColRef.current?.offsetWidth ?? browserWidth ?? 600
            document.body.style.cursor     = 'col-resize'
            document.body.style.userSelect = 'none'
            e.preventDefault()
          }}
          className="group shrink-0 flex items-center justify-center transition-colors"
          style={{
            width: 8,
            cursor: 'col-resize',
            background: 'transparent',
            borderLeft: '1px solid rgba(255,255,255,0.05)',
            position: 'relative',
            zIndex: 10,
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,21,53,0.08)'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
          {/* Grip dots */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, pointerEvents: 'none' }}>
            {[0,1,2,3].map(i => (
              <div key={i} style={{
                width: 2, height: 2, borderRadius: '50%',
                background: 'rgba(255,21,53,0.5)',
              }} />
            ))}
          </div>
        </div>

        {/* Middle column: LabBrowser (top) + LabPanel (bottom, Lab-only) */}
        <div
          ref={browserColRef}
          className="min-w-0 flex flex-col overflow-hidden"
          style={{ flex: browserWidth ? 'none' : '1', width: browserWidth ?? undefined }}
        >
          <MutationBanner
            mutations={mutationBannerDismissed ? [] : activeMutations}
            onDismiss={() => setMutationBannerDismissed(true)}
          />
          <div className="flex-1 min-h-0 flex overflow-hidden">
            <LabBrowser
              moduleId={snapshot.module_id}
              missionStarted={missionStarted}
              onNavigate={labNavigateRef}
              mode={mode}
              sid={sid}
              mutationReloadKey={mutationReloadKey}
              isMutating={Boolean(shapeshiftEvent)}
            />
          </div>
          {toolsVisible && (
            <motion.div
              className="shrink-0 overflow-hidden"
              animate={{ height: labPanelMinimized ? 42 : 320 }}
              transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            >
              <LabPanel
                selectedTool={selectedLabTool}
                minimized={labPanelMinimized}
                onToggleMinimize={() => setLabPanelMinimized(v => !v)}
              />
            </motion.div>
          )}
        </div>
        <LearningPanel
          briefing={briefing} snapshot={snapshot} progress={progress}
          missionStarted={missionStarted} isCheckingProgress={isCheckingProgress}
          onCheckProgress={handleCheckProgress} isDone={isDone} elapsed={elapsed}
          showAdvanced={showAdvanced} onToggleAdvanced={() => setShowAdvanced(v => !v)}
          onNavigateTo={handleNavigateTo} onRestart={handleRestart}
          mode={mode}
          activeMutation={activeMutation}
          mutationFlipKey={mutationFlipKey}
          collapsed={rightCollapsed} onToggle={() => setRightCollapsed(v => !v)}
        />
      </div>

      <AdvancedTools
        open={showAdvanced} snapshot={snapshot} sid={sid}
        onExecute={handleAdvancedExecute} executing={executing}
      />

      <ShapeshiftOverlay
        event={shapeshiftEvent}
        soundEnabled={soundEnabled}
        onReveal={handleMutationReveal}
        onDone={handleMutationDone}
      />

      {/* Report-ready banner — slides up on mission complete */}
      <AnimatePresence>
        {reportReady && (
          <motion.div
            key="report-banner"
            initial={{ y: 80, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 80, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            className="fixed bottom-5 left-1/2 z-50 flex items-center gap-4 px-5 py-3 rounded-2xl shadow-2xl"
            style={{
              transform: 'translateX(-50%)',
              background: 'rgba(7,9,15,0.97)',
              border: '1px solid rgba(46,227,154,0.4)',
              boxShadow: '0 0 30px rgba(46,227,154,0.15)',
              backdropFilter: 'blur(16px)',
            }}
          >
            <span className="text-[18px]">✓</span>
            <div>
              <div className="font-mono text-[10px] tracking-[0.2em] font-bold" style={{ color: '#2ee39a' }}>
                MISSION COMPLETE
              </div>
              <div className="font-mono text-[9.5px] text-attense-dim">
                Your full debrief report is ready.
              </div>
            </div>
            <Link
              to={`/report/${sid}`}
              className="font-mono text-[10px] font-bold tracking-[0.14em] px-4 py-2 rounded-xl transition-all"
              style={{
                background: 'linear-gradient(135deg, rgba(46,227,154,0.2), rgba(46,227,154,0.1))',
                border: '1px solid rgba(46,227,154,0.45)',
                color: '#2ee39a',
              }}
            >VIEW REPORT →</Link>
            <button
              onClick={() => setReportReady(false)}
              className="text-attense-dim hover:text-attense-text transition-colors font-mono text-[11px] ml-1"
              title="Dismiss"
            >✕</button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
