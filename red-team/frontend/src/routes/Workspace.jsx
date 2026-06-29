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
  requiredToolsFor, labObjectiveFor, tutorialStepsFor,
} from '../data/missionBriefings.js'
import ModeSwitcher from '../components/ModeSwitcher.jsx'
import LabToolsStrip from '../components/LabToolsStrip.jsx'
import LabPanel from '../components/LabPanel.jsx'
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

// ── Collapsible (minimizable) card used in the operator-mode sidebar ─────────
function CollapsibleCard({ label, color, defaultOpen = false, badge, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl overflow-hidden"
      style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.09)' }}>
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 px-3.5 py-2.5 text-left">
        <span className="font-mono text-[11px] tracking-[0.18em]" style={{ color }}>{label}</span>
        {badge && <span className="font-mono text-[10px] text-attense-dim">{badge}</span>}
        <span className="ml-auto text-attense-dim text-xs transition-transform" style={{ transform: open ? 'rotate(180deg)' : '' }}>▾</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }} className="overflow-hidden">
            <div className="px-3.5 pb-3.5 pt-0.5">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Lab mode sidebar panel ───────────────────────────────────────────────────
// Operator mode's single panel: Objective, Tools, Free Exploration and Hints,
// each minimizable so the workspace stays clean.
function LabModePanel({ moduleId, briefing }) {
  const objective = labObjectiveFor(moduleId)
  const tools = requiredToolsFor(moduleId)
  const [hintsRevealed, setHintsRevealed] = useState(0)
  const hints = useMemo(() => {
    const h = []
    if (briefing?.tip) h.push(briefing.tip)
    if (briefing?.watchFor) briefing.watchFor.forEach(w => h.push(w))
    return h
  }, [briefing])

  return (
    <div className="space-y-2.5">
      <CollapsibleCard label="LAB OBJECTIVE" color="#7dd3fc" defaultOpen>
        <div className="text-[13px] text-attense-text leading-relaxed">{objective}</div>
      </CollapsibleCard>

      {tools.length > 0 && (
        <CollapsibleCard label="TOOLS" color="#9ae4ff">
          <div className="flex flex-wrap gap-1.5">
            {tools.map(t => (
              <span key={t} className="font-mono text-[11px] px-2 py-1 rounded"
                style={{ background: 'rgba(125,211,252,0.06)', border: '1px solid rgba(125,211,252,0.22)', color: '#9ae4ff' }}>
                {t}
              </span>
            ))}
          </div>
        </CollapsibleCard>
      )}

      <CollapsibleCard label="FREE EXPLORATION" color="#2ee39a">
        <div className="text-[12.5px] text-attense-dim leading-relaxed">
          No step-by-step guidance. Use the Terminal and ZAP panels below to explore the target at your own pace.
          When you're done, visit Reports to see a full analysis of what you found and how you could improve.
        </div>
      </CollapsibleCard>

      {hints.length > 0 && (
        <CollapsibleCard label="HINTS" color="#fbbf24" badge={`${hintsRevealed}/${hints.length}`}>
          {hints.slice(0, hintsRevealed).map((h, i) => (
            <div key={i} className="text-[12.5px] text-attense-text leading-relaxed mb-2 flex gap-2">
              <span style={{ color: '#fbbf24' }} className="shrink-0">💡</span>
              <span>{h}</span>
            </div>
          ))}
          {hintsRevealed < hints.length && (
            <button onClick={() => setHintsRevealed(v => v + 1)}
              className="w-full font-mono text-[11px] tracking-wider py-2 rounded mt-1 transition-colors"
              style={{ background: 'rgba(250,204,21,0.06)', border: '1px solid rgba(250,204,21,0.2)', color: '#fbbf24' }}
            >REVEAL HINT</button>
          )}
        </CollapsibleCard>
      )}
    </div>
  )
}

// ── Mission sidebar ──────────────────────────────────────────────────────────
function MissionSidebar({
  snapshot, module, briefing,
  elapsed, timerRunning, isDone,
  progress, mode = 'tutorial',
  variantId,
  collapsed, onToggle,
}) {
  const tasks = progress?.tasks || []
  const completedCount = (progress?.completed_tasks || []).length
  const totalTasks     = tasks.length || 3
  const pct = totalTasks > 0 ? (completedCount / totalTasks) * 100 : 0
  const isLab = mode === 'lab'

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

        {isLab && (
          <div
            className="rounded-xl p-4 mb-4"
            style={{
              background: 'rgba(125,211,252,0.035)',
              border: '1px solid rgba(125,211,252,0.18)',
            }}
          >
            <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#7dd3fc' }}>
              TARGET SCOPE
            </div>
            <code
              className="block font-mono text-[10.5px] leading-relaxed break-all"
              style={{ color: '#d7f3ff' }}
            >
              {targetUrlFor(snapshot?.module_id, mode)}
            </code>
            <div className="mt-2 text-[10.5px] leading-relaxed text-attense-dim">
              Operator tools are pinned to the in-lab target-agent service. External targets stay blocked.
            </div>
          </div>
        )}

        {/* Chosen attack variant — read-only. Picked on the Mission page. */}
        {(progress?.variant_name || variantId) && (
          <div
            className="rounded-xl p-3 mb-4 flex items-center gap-2"
            style={{
              background: 'rgba(125,211,252,0.03)',
              border: '1px solid rgba(125,211,252,0.16)',
            }}
          >
            <span className="font-mono text-[8.5px] tracking-[0.22em]" style={{ color: '#7dd3fc' }}>
              VARIANT
            </span>
            <span className="text-[12px] font-semibold text-attense-text truncate">
              {progress?.variant_name || variantId}
            </span>
            {progress?.variant_difficulty && (
              <span className="ml-auto font-mono text-[8.5px] font-bold tracking-[0.14em] px-1.5 py-0.5 rounded uppercase"
                style={{ color: '#9ae4ff', background: 'rgba(125,211,252,0.08)', border: '1px solid rgba(125,211,252,0.25)' }}>
                {progress.variant_difficulty}
              </span>
            )}
          </div>
        )}

        {isLab ? (
          <LabModePanel moduleId={snapshot?.module_id} briefing={briefing} />
        ) : (
          <div
            className="rounded-xl p-4"
            style={{
              background: 'rgba(46,227,154,0.04)',
              border: '1px solid rgba(46,227,154,0.18)',
            }}
          >
            <div className="font-mono text-[9px] tracking-[0.28em] mb-2" style={{ color: '#2ee39a' }}>
              GUIDED WALKTHROUGH
            </div>
            <div className="text-[11px] text-attense-dim leading-relaxed">
              Follow the numbered steps in the panel on the right →. Each step explains
              what the technique is and how to perform it. As you act on the target,
              steps tick off automatically.
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

// ── Walkthrough section block (WHAT / HOW / LOOK FOR) ───────────────────────
function sectionText(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join('\n')
  return value == null ? '' : String(value)
}

function WSection({ label, color, mono, children }) {
  const text = sectionText(children)
  if (!text.trim()) return null
  return (
    <div className="mb-4">
      <div className="font-mono text-[11px] tracking-[0.16em] mb-1.5" style={{ color }}>
        {label}
      </div>
      {mono ? (
        <div
          className="text-[14px] leading-relaxed font-mono rounded-lg px-3.5 py-3 whitespace-pre-wrap break-words"
          style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#e8eef7' }}
        >
          {text}
        </div>
      ) : (
        <div className="text-[15px] leading-relaxed whitespace-pre-line" style={{ color: '#d6ddee' }}>
          {text}
        </div>
      )}
    </div>
  )
}

// ── A single TryHackMe-style walkthrough task ───────────────────────────────
function WalkthroughTask({ index, task, isOpen, onToggle, missionStarted }) {
  const complete = !!task.complete
  const matchCount = task.match_count ?? 0
  const minCount   = task.min_count ?? 1
  return (
    <div
      className="rounded-xl overflow-hidden mb-2 transition-colors"
      style={{
        border: `1px solid ${complete ? 'rgba(46,227,154,0.32)' : isOpen ? 'rgba(255,21,53,0.32)' : 'rgba(255,255,255,0.08)'}`,
        background: complete ? 'rgba(46,227,154,0.045)' : isOpen ? 'rgba(255,21,53,0.03)' : 'rgba(255,255,255,0.02)',
      }}
    >
      <button onClick={onToggle} className="w-full flex items-center gap-3 px-3.5 py-3 text-left">
        <span
          className="shrink-0 grid place-items-center rounded-full transition-all"
          style={{
            width: 22, height: 22,
            border: `2px solid ${complete ? '#2ee39a' : 'rgba(255,255,255,0.2)'}`,
            background: complete ? '#2ee39a' : 'transparent',
          }}
        >
          {complete ? (
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#04130c" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 6L9 17l-5-5" />
            </svg>
          ) : (
            <span className="font-mono text-[10px]" style={{ color: '#8b93ad' }}>{index + 1}</span>
          )}
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[8px] tracking-[0.22em] mb-0.5" style={{ color: complete ? '#2ee39a' : '#7a8194' }}>
            TASK {index + 1}{complete ? ' · COMPLETE' : ''}
          </div>
          <div className="text-[12.5px] font-semibold leading-snug text-attense-text">
            {task.title}
          </div>
        </div>
        <span className="text-attense-dim text-sm transition-transform shrink-0" style={{ transform: isOpen ? 'rotate(180deg)' : '' }}>
          ▾
        </span>
      </button>

      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="px-3.5 pb-3.5 pt-2.5" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
              <WSection label="WHAT IS THIS" color="#7dd3fc">{task.what}</WSection>
              <WSection label="HOW IT'S DONE" color="#ff6b81" mono>{task.how}</WSection>
              <WSection label="WHAT TO LOOK FOR" color="#9be8c5">{task.look_for}</WSection>

              {/* live auto-tracking status */}
              <div
                className="mt-1 flex items-center gap-2 rounded-lg px-2.5 py-1.5 font-mono text-[9.5px]"
                style={{
                  background: complete ? 'rgba(46,227,154,0.07)' : 'rgba(255,255,255,0.025)',
                  border: `1px solid ${complete ? 'rgba(46,227,154,0.25)' : 'rgba(255,255,255,0.07)'}`,
                }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: complete ? '#2ee39a' : missionStarted ? '#fbbf24' : '#4a5280' }}
                />
                <span style={{ color: complete ? '#2ee39a' : '#9aa0c0' }}>
                  {complete
                    ? 'Detected — step complete'
                    : missionStarted
                      ? `Auto-tracking… ${matchCount}/${minCount} detected`
                      : 'Press START, then act on the target'}
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Guided walkthrough (overview + progress + task sections) ─────────────────
function GuidedWalkthrough({ progress, missionStarted, briefing }) {
  const tasks = progress?.tasks || []
  const completedCount = (progress?.completed_tasks || []).length
  const total = tasks.length
  const pct = total > 0 ? Math.round((completedCount / total) * 100) : 0
  const overview = progress?.variant_overview
    || briefing?.objective || briefing?.background || ''

  // Auto-open the first incomplete task; collapse all when finished.
  const firstIncomplete = tasks.findIndex(t => !t.complete)
  const [openTask, setOpenTask] = useState(0)
  const [userTouched, setUserTouched] = useState(false)
  useEffect(() => {
    if (!userTouched) setOpenTask(firstIncomplete)
  }, [firstIncomplete, userTouched])

  return (
    <div className="mb-4">
      {/* Overview — what this attack is */}
      {overview && (
        <div
          className="rounded-xl p-4 mb-3"
          style={{
            background: 'linear-gradient(135deg, rgba(255,21,53,0.05) 0%, rgba(139,47,255,0.03) 100%)',
            border: '1px solid rgba(255,21,53,0.18)',
          }}
        >
          <div className="flex items-center gap-2 mb-2">
            <div className="font-mono text-[9px] tracking-[0.26em]" style={{ color: '#ff6b81' }}>
              {progress?.variant_name ? progress.variant_name.toUpperCase() : 'OVERVIEW'}
            </div>
            {progress?.variant_difficulty && (
              <span className="ml-auto font-mono text-[8px] font-bold tracking-[0.14em] px-1.5 py-0.5 rounded uppercase"
                style={{ color: '#ff9aab', background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)' }}>
                {progress.variant_difficulty}
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-attense-text leading-relaxed">{overview}</div>
        </div>
      )}

      {/* Progress bar — TryHackMe room completion */}
      {total > 0 && (
        <div className="rounded-xl p-3.5 mb-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-[9px] tracking-[0.28em] text-attense-dim">WALKTHROUGH</span>
            <span className="font-mono text-[10px] tabular-nums" style={{ color: pct === 100 ? '#2ee39a' : '#cfd6e8' }}>
              {completedCount}/{total} · {pct}%
            </span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
            <motion.div
              className="h-full rounded-full"
              animate={{ width: pct + '%' }}
              transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
              style={{
                background: pct === 100 ? '#2ee39a' : 'linear-gradient(90deg,#ff1535,#ff6b00)',
                boxShadow: pct > 0 && pct < 100 ? '0 0 6px rgba(255,21,53,0.5)' : 'none',
              }}
            />
          </div>
        </div>
      )}

      {/* Task sections */}
      {total > 0 ? (
        tasks.map((t, i) => (
          <WalkthroughTask
            key={i}
            index={i}
            task={t}
            isOpen={openTask === i}
            onToggle={() => { setUserTouched(true); setOpenTask(openTask === i ? -1 : i) }}
            missionStarted={missionStarted}
          />
        ))
      ) : (
        <div className="rounded-xl p-4 text-center" style={{ background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.08)' }}>
          <div className="font-mono text-[10px] text-attense-dim leading-relaxed">
            {missionStarted ? 'Loading walkthrough…' : 'Press START to load the guided walkthrough.'}
          </div>
        </div>
      )}
    </div>
  )
}

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

        {/* Guided walkthrough — TryHackMe-style task sections (tutorial mode) */}
        {!isLab && !activeMutation && (
          <GuidedWalkthrough
            progress={progress}
            missionStarted={missionStarted}
            briefing={briefing}
          />
        )}

        {/* Objective — Lab mode and Mutation runs keep the classic objective card */}
        {(isLab || activeMutation) && (
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
        )}

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

// ── MITRE technique string parser ───────────────────────────────────────────
// "T1110.003 · Brute Force: Password Spraying" → {id, name, url}
const FALLBACK_DATABASE_REFS = {
  brute_force: [
    { kind: 'OWASP', label: 'OWASP Brute Force', url: 'https://owasp.org/www-community/attacks/Brute_force_attack' },
    { kind: 'CWE', label: 'CWE-307 Excessive Authentication Attempts', url: 'https://cwe.mitre.org/data/definitions/307.html' },
  ],
  xss: [
    { kind: 'OWASP', label: 'OWASP XSS', url: 'https://owasp.org/www-community/attacks/xss/' },
    { kind: 'CWE', label: 'CWE-79 Cross-site Scripting', url: 'https://cwe.mitre.org/data/definitions/79.html' },
  ],
  cmd_injection: [
    { kind: 'OWASP', label: 'OWASP Command Injection', url: 'https://owasp.org/www-community/attacks/Command_Injection' },
    { kind: 'CWE', label: 'CWE-78 OS Command Injection', url: 'https://cwe.mitre.org/data/definitions/78.html' },
  ],
  dir_traversal: [
    { kind: 'OWASP', label: 'OWASP Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
    { kind: 'CWE', label: 'CWE-22 Path Traversal', url: 'https://cwe.mitre.org/data/definitions/22.html' },
  ],
  file_upload: [
    { kind: 'OWASP', label: 'OWASP File Upload', url: 'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload' },
    { kind: 'CWE', label: 'CWE-434 Unrestricted Upload', url: 'https://cwe.mitre.org/data/definitions/434.html' },
  ],
  csrf: [
    { kind: 'OWASP', label: 'OWASP CSRF', url: 'https://owasp.org/www-community/attacks/csrf' },
    { kind: 'CWE', label: 'CWE-352 CSRF', url: 'https://cwe.mitre.org/data/definitions/352.html' },
  ],
  recon: [
    { kind: 'OWASP', label: 'OWASP WSTG Information Gathering', url: 'https://owasp.org/www-project-web-security-testing-guide/' },
    { kind: 'MITRE', label: 'ATT&CK Reconnaissance', url: 'https://attack.mitre.org/tactics/TA0043/' },
  ],
}

const FALLBACK_PHASES = {
  recon: ['Reconnaissance', 'Discovery', 'Enumeration', 'Hidden clue'],
  brute_force: ['Credential access', 'Account discovery', 'Password guessing', 'Valid accounts'],
  xss: ['Input discovery', 'Context testing', 'Script execution', 'Defense mapping'],
  cmd_injection: ['Input discovery', 'Shell syntax', 'Execution proof', 'Defense mapping'],
  dir_traversal: ['Input discovery', 'Path escape', 'Sensitive collection', 'Bypass testing'],
  file_upload: ['Upload baseline', 'Filename policy', 'Payload delivery', 'Storage exposure'],
  csrf: ['Session setup', 'Token inspection', 'Forged request', 'Impact proof'],
}

function fallbackPhase(moduleId, index) {
  const phases = FALLBACK_PHASES[moduleId] || ['Attack path']
  return phases[index] || phases[phases.length - 1]
}

function buildFallbackWalkthrough(moduleId, snapshot, variantId) {
  const briefing = briefingFor(moduleId)
  const steps = tutorialStepsFor(moduleId)
  const refs = FALLBACK_DATABASE_REFS[moduleId] || []
  return {
    module_id: moduleId,
    variant_id: variantId || null,
    variant_name: null,
    difficulty: null,
    overview: briefing?.objective || briefing?.background || snapshot?.module_name || 'Guided lesson content.',
    reference: refs[0] || null,
    database_refs: refs,
    defensive_insight: briefing?.defenseBreakdown?.summary || briefing?.realWorldImpact || null,
    sections: steps.map((step, index) => ({
      title: step.title || `Section ${index + 1}`,
      phase: fallbackPhase(moduleId, index),
      what: step.concept || step.what,
      how: [step.why, step.tryIt, step.observe].filter(Boolean).join('\n\n'),
      look_for: step.lookFor || step.look_for,
      checkpoint: step.observe || step.tryIt,
      mitre: null,
      database_refs: refs,
    })),
  }
}

function externalArrow() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3" />
    </svg>
  )
}

function SourceLink({ source }) {
  if (!source?.url) return null
  return (
    <a
      href={source.url}
      target="_blank"
      rel="noreferrer"
      className="flex items-center justify-between gap-2 rounded-lg px-3 py-2.5 transition-colors"
      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#dfe5f2' }}
    >
      <span className="min-w-0">
        <span className="block font-mono text-[10px] tracking-[0.16em]" style={{ color: '#7dd3fc' }}>{source.kind || 'REF'}</span>
        <span className="block text-[13px] leading-snug truncate">{source.label || source.url}</span>
      </span>
      <span className="shrink-0" style={{ color: '#7dd3fc' }}>{externalArrow()}</span>
    </a>
  )
}

function parseMitre(str) {
  if (!str) return null
  const raw = String(str).trim()
  const robustMatch = raw.match(/^(T\d{4}(?:\.\d{3})?)\s*(?:\W+)?\s*(.*)$/)
  if (robustMatch) {
    return {
      id: robustMatch[1],
      name: (robustMatch[2] || '').trim(),
      url: `https://attack.mitre.org/techniques/${robustMatch[1].replace('.', '/')}/`,
    }
  }
  const match = raw.match(/^(T\d{4}(?:\.\d{3})?)\s*(?:[·آ\-–—:]+)?\s*(.*)$/)
  if (match) {
    return {
      id: match[1],
      name: (match[2] || '').trim(),
      url: `https://attack.mitre.org/techniques/${match[1].replace('.', '/')}/`,
    }
  }
  const parts = String(str).split('·')
  const id = (parts[0] || '').trim()
  const name = parts.slice(1).join('·').trim()
  if (!id) return null
  return { id, name, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` }
}

// ── A single Guided-Room task section (TryHackMe-style) ─────────────────────
function GuidedSection({ index, section, isOpen, onToggle, done, onToggleDone }) {
  const m = parseMitre(section.mitre)
  const refs = Array.isArray(section.database_refs) ? section.database_refs : []
  return (
    <div
      className="rounded-xl overflow-hidden mb-3 transition-colors"
      style={{
        border: `1px solid ${done ? 'rgba(46,227,154,0.32)' : isOpen ? 'rgba(255,21,53,0.3)' : 'rgba(255,255,255,0.12)'}`,
        background: done ? 'rgba(46,227,154,0.05)' : isOpen ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.045)',
      }}
    >
      <button onClick={onToggle} className="w-full flex items-center gap-3.5 px-5 py-4 text-left">
        <span
          className="shrink-0 grid place-items-center rounded-full transition-all"
          style={{
            width: 26, height: 26,
            border: `2px solid ${done ? '#2ee39a' : 'rgba(255,255,255,0.2)'}`,
            background: done ? '#2ee39a' : 'transparent',
          }}
        >
          {done ? (
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#04130c" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 6L9 17l-5-5" />
            </svg>
          ) : (
            <span className="font-mono text-[11px]" style={{ color: '#8b93ad' }}>{index + 1}</span>
          )}
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[10px] tracking-[0.22em] mb-1" style={{ color: done ? '#2ee39a' : '#8b93ad' }}>
            TASK {index + 1}{done ? ' · COMPLETE' : ''}
          </div>
          <div className="text-[18px] font-semibold leading-snug text-attense-text">{section.title}</div>
          {section.phase && (
            <div className="mt-1 font-mono text-[11px] tracking-[0.16em]" style={{ color: '#7dd3fc' }}>
              {section.phase}
            </div>
          )}
        </div>
        {m && (
          <span className="hidden md:inline-flex shrink-0 font-mono text-[9px] font-semibold px-2 py-1 rounded"
            style={{ background: 'rgba(255,21,53,0.06)', border: '1px solid rgba(255,21,53,0.28)', color: '#ff6b81' }}>
            {m.id}
          </span>
        )}
        <span className="text-attense-dim text-sm transition-transform shrink-0" style={{ transform: isOpen ? 'rotate(180deg)' : '' }}>▾</span>
      </button>

      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
              {m && (
                <a href={m.url} target="_blank" rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg px-3 py-1.5 mb-3.5 transition-colors"
                  style={{ background: 'rgba(255,21,53,0.05)', border: '1px solid rgba(255,21,53,0.25)' }}
                  title="Open this technique on attack.mitre.org">
                  <span className="font-mono text-[11px] tracking-[0.16em]" style={{ color: '#ff9aab' }}>MITRE ATT&CK</span>
                  <span className="font-mono text-[13px] font-bold" style={{ color: '#ff6b81' }}>{m.id}</span>
                  <span className="text-[13px]" style={{ color: '#d6ddee' }}>{m.name}</span>
                  <span className="text-[12px]" style={{ color: '#ff6b81' }}>↗</span>
                </a>
              )}
              <WSection label="WHAT IS THIS" color="#7dd3fc">{section.what}</WSection>
              <WSection label="HOW IT'S DONE" color="#ff6b81" mono>{section.how}</WSection>
              <WSection label="WHAT TO LOOK FOR" color="#9be8c5">{section.look_for}</WSection>
              <WSection label="CHECKPOINT" color="#fbbf24">{section.checkpoint}</WSection>

              {(m || refs.length > 0) && (
                <div
                  className="rounded-xl p-3.5 mb-3"
                  style={{ background: 'rgba(255,255,255,0.035)', border: '1px solid rgba(255,255,255,0.1)' }}
                >
                  <div className="font-mono text-[11px] tracking-[0.2em] text-attense-muted mb-2.5">
                    SOURCES AND DATABASES
                  </div>
                  <div className="grid gap-2 md:grid-cols-2">
                    {m && (
                      <SourceLink
                        source={{
                          kind: 'MITRE',
                          label: `${m.id}${m.name ? ` ${m.name}` : ''}`,
                          url: m.url,
                        }}
                      />
                    )}
                    {refs.map((source, i) => <SourceLink key={`${source.url || source.label}-${i}`} source={source} />)}
                  </div>
                </div>
              )}

              <button
                onClick={onToggleDone}
                className="mt-1 w-full font-mono text-[12px] font-bold tracking-[0.18em] py-3 rounded-lg transition-all"
                style={{
                  background: done ? 'rgba(46,227,154,0.08)' : 'linear-gradient(135deg,#2ee39a,#0fb877)',
                  color: done ? '#2ee39a' : '#04130c',
                  border: done ? '1px solid rgba(46,227,154,0.3)' : '1px solid transparent',
                }}
              >
                {done ? '✓ COMPLETED · UNDO' : 'MARK COMPLETE ✓'}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Guided Room — full-width TryHackMe-style learning room ───────────────────
// No left/right panels, no target iframe, no START. Just the attack explained
// section by section, grounded in MITRE ATT&CK and OWASP references.
function GuidedRoom({ snapshot, variantId }) {
  const moduleId = snapshot?.module_id
  const vId = variantId || snapshot?.variant_id || null

  const [wt, setWt] = useState(null)
  const [loading, setLoading] = useState(true)
  const [openIdx, setOpenIdx] = useState(0)
  const [doneSet, setDoneSet] = useState(() => new Set())

  const storeKey = `attense_guided_done_${moduleId}_${vId || 'default'}`

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.walkthrough(moduleId, vId)
      .then(r => {
        if (!cancelled) {
          setWt(r?.sections?.length ? r : buildFallbackWalkthrough(moduleId, snapshot, vId))
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setWt(buildFallbackWalkthrough(moduleId, snapshot, vId))
          setLoading(false)
        }
      })
    return () => { cancelled = true }
  }, [moduleId, vId, snapshot?.module_name])

  useEffect(() => {
    try { setDoneSet(new Set(JSON.parse(localStorage.getItem(storeKey) || '[]'))) }
    catch { setDoneSet(new Set()) }
  }, [storeKey])

  const toggleDone = (i) => setDoneSet(prev => {
    const n = new Set(prev)
    n.has(i) ? n.delete(i) : n.add(i)
    try { localStorage.setItem(storeKey, JSON.stringify([...n])) } catch { /* ignore */ }
    // auto-advance to the next section when completing one
    if (!prev.has(i)) setOpenIdx(i + 1)
    return n
  })

  const sections = wt?.sections || []
  const total = sections.length
  const doneCount = sections.reduce((acc, _s, i) => acc + (doneSet.has(i) ? 1 : 0), 0)
  const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0

  // unique MITRE technique chips for the header
  const headerTechs = []
  const seen = new Set()
  sections.forEach(s => {
    const m = parseMitre(s.mitre)
    if (m && !seen.has(m.id)) { seen.add(m.id); headerTechs.push(m) }
  })

  const icon = CATEGORY_ICON?.[snapshot?.category] || CATEGORY_ICON?.[snapshot?.module_category] || '▪'

  return (
    <div className="flex-1 min-h-0 overflow-y-auto">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {loading ? (
          <div className="py-16 text-center font-mono text-[11px] tracking-widest text-attense-dim">
            LOADING WALKTHROUGH…
          </div>
        ) : (
          <>
            {/* Room header */}
            <section className="relative rounded-2xl border border-attense-border overflow-hidden mb-6"
              style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div className="absolute inset-0 pointer-events-none opacity-[0.07] bg-grid bg-[length:30px_30px]" />
              <div className="absolute top-0 right-0 w-56 h-56 rounded-full bg-attense-red/5 blur-3xl pointer-events-none" />
              <div className="relative p-6">
                <div className="flex items-start gap-4">
                  <div className="w-14 h-14 rounded-xl border grid place-items-center text-2xl shrink-0"
                    style={{ borderColor: 'rgba(255,21,53,0.45)', background: 'rgba(255,21,53,0.06)', color: '#ff4060' }}>
                    {icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="font-mono text-[9px] tracking-[0.26em] text-attense-dim">
                        {snapshot?.scenario_id || '—'}
                      </span>
                      {wt?.variant_name && (
                        <>
                          <span className="text-attense-dim">·</span>
                          <span className="font-mono text-[9px] tracking-[0.18em]" style={{ color: '#7dd3fc' }}>
                            {wt.variant_name.toUpperCase()}
                          </span>
                        </>
                      )}
                      {wt?.difficulty && (
                        <span className="font-mono text-[8px] font-bold tracking-[0.14em] px-1.5 py-0.5 rounded uppercase"
                          style={{ color: '#ff9aab', background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)' }}>
                          {wt.difficulty}
                        </span>
                      )}
                    </div>
                    <h1 className="text-[22px] font-bold tracking-tight text-attense-text mb-2">
                      {snapshot?.module_name}
                    </h1>
                    {wt?.overview && (
                      <p className="text-[15px] text-attense-muted leading-relaxed">{wt.overview}</p>
                    )}
                  </div>
                </div>

                {/* MITRE technique chips */}
                {headerTechs.length > 0 && (
                  <div className="mt-4">
                    <div className="font-mono text-[8.5px] tracking-[0.26em] text-attense-dim mb-2">MITRE ATT&CK TECHNIQUES</div>
                    <div className="flex flex-wrap gap-2">
                      {headerTechs.map(m => (
                        <a key={m.id} href={m.url} target="_blank" rel="noreferrer" title={m.name}
                          className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 font-mono text-[10px] transition-colors"
                          style={{ background: 'rgba(255,21,53,0.05)', border: '1px solid rgba(255,21,53,0.28)', color: '#e6e8ee' }}>
                          <span className="font-bold" style={{ color: '#ff6b81' }}>{m.id}</span>
                          <span className="text-attense-muted truncate max-w-[180px]">{m.name}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {Array.isArray(wt?.database_refs) && wt.database_refs.length > 0 && (
                  <div className="mt-4">
                    <div className="font-mono text-[8.5px] tracking-[0.26em] text-attense-dim mb-2">ONLINE REFERENCES</div>
                    <div className="grid gap-2 md:grid-cols-3">
                      {wt.database_refs.slice(0, 3).map((ref, i) => (
                        <SourceLink key={`${ref.url || ref.label}-${i}`} source={ref} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Reading progress */}
                {total > 0 && (
                  <div className="mt-5">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-[8.5px] tracking-[0.26em] text-attense-dim">WALKTHROUGH PROGRESS</span>
                      <span className="font-mono text-[10px] tabular-nums" style={{ color: pct === 100 ? '#2ee39a' : '#cfd6e8' }}>
                        {doneCount}/{total} · {pct}%
                      </span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                      <motion.div className="h-full rounded-full" animate={{ width: pct + '%' }}
                        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                        style={{ background: pct === 100 ? '#2ee39a' : 'linear-gradient(90deg,#ff1535,#ff6b00)' }} />
                    </div>
                  </div>
                )}

                {wt?.reference && (
                  <a href={wt.reference.url} target="_blank" rel="noreferrer"
                    className="inline-flex items-center gap-1.5 mt-4 font-mono text-[10px] transition-colors"
                    style={{ color: '#7dd3fc' }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3" />
                    </svg>
                    {wt.reference.label} ↗
                  </a>
                )}
              </div>
            </section>

            {/* Section list */}
            <div className="flex items-end justify-between mb-3">
              <div className="font-mono text-[11px] tracking-[0.3em] text-attense-muted">ATTACK WALKTHROUGH</div>
              <div className="font-mono text-[11px] text-attense-muted">{total} SECTION{total === 1 ? '' : 'S'}</div>
            </div>

            {total > 0 ? (
              sections.map((s, i) => (
                <GuidedSection
                  key={i}
                  index={i}
                  section={s}
                  isOpen={openIdx === i}
                  onToggle={() => setOpenIdx(openIdx === i ? -1 : i)}
                  done={doneSet.has(i)}
                  onToggleDone={() => toggleDone(i)}
                />
              ))
            ) : (
              <div className="rounded-xl p-6 text-center font-mono text-[11px] text-attense-dim"
                style={{ background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.08)' }}>
                No walkthrough content available for this variant.
              </div>
            )}

            {/* Defensive insight */}
            {wt?.defensive_insight && (
              <div className="rounded-xl p-5 mt-4"
                style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.22)' }}>
                <div className="font-mono text-[9px] tracking-[0.26em] mb-2" style={{ color: '#7dd3fc' }}>
                  HOW TO DEFEND
                </div>
                <div className="text-[12px] text-attense-text leading-relaxed">{wt.defensive_insight}</div>
              </div>
            )}

            {/* Hand-off to operator mode */}
            <div className="rounded-xl p-5 mt-4 text-center"
              style={{ background: 'rgba(255,21,53,0.03)', border: '1px solid rgba(255,21,53,0.16)' }}>
              <div className="text-[12.5px] font-semibold text-attense-text mb-1">Ready to try it for real?</div>
              <div className="text-[11.5px] text-attense-muted leading-relaxed">
                Switch to <span style={{ color: '#7dd3fc' }} className="font-semibold">OPERATOR MODE</span> above to
                launch the live target and perform this attack hands-on — your actions are tracked automatically.
              </div>
            </div>

            <div className="h-10" />
          </>
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
  // Guided Mode = a full-width TryHackMe-style learning room (no target, no
  // panels, no START). Operator Mode (and mutation runs) = the hands-on lab.
  const guided = mode === 'tutorial' && !isMutationRun

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

        {/* Action buttons — Operator mode only (Guided is a reading room) */}
        {!replay && !guided && !missionStarted && (
          <button onClick={handleStart}
            className="font-mono text-[10.5px] font-bold tracking-[0.14em] px-5 py-2 rounded-lg transition-all duration-150 shrink-0"
            style={{ background: 'linear-gradient(135deg,#ff1535,#cc0020)', color: 'white', boxShadow: '0 0 14px rgba(255,21,53,0.35)' }}
          >START ▸</button>
        )}
        {!replay && !guided && missionStarted && !isDone && (
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

      {/* Body: Guided Mode = full-width room · Operator Mode = 3-column lab */}
      {guided ? (
        <GuidedRoom snapshot={snapshot} variantId={variantId} />
      ) : (
      <>
      <div className="flex-1 min-h-0 flex overflow-hidden">
        <MissionSidebar
          snapshot={snapshot} module={module} briefing={briefing}
          elapsed={elapsed} timerRunning={missionStarted && !isDone}
          isDone={isDone} progress={progress} mode={mode}
          variantId={variantId}
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
        {/* Right panel kept only for mutation runs (live MUTATION OBJECTIVE flip card).
            Plain operator mode uses the single left panel above. */}
        {isMutationRun && (
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
        )}
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
      </>
      )}
    </div>
  )
}
