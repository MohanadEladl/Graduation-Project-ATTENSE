import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'

/**
 * MissionReport — post-mission coaching report.
 *
 * Sections (rendered with staggered fadeUp):
 *   1. Header — grade, score, duration, variant, mode
 *   2. AI Coaching summary (or rules-based fallback)
 *   3. Task Results grid
 *   4. What You Did Right
 *   5. What You Missed (with how-to-fix)
 *   6. Ideal Approach (numbered, copyable commands)
 *   7. Vulnerability Deep Dive
 *   8. Defensive Controls
 *   9. Action Replay timeline
 */

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
  transition: { delay, duration: 0.5, ease: [0.22, 1, 0.36, 1] },
})

const GRADE_COLORS = {
  S: { fg: '#facc15', bg: 'rgba(250,204,21,0.06)',  bd: 'rgba(250,204,21,0.45)' },
  A: { fg: '#00c8ff', bg: 'rgba(0,200,255,0.06)',   bd: 'rgba(0,200,255,0.45)' },
  B: { fg: '#2ee39a', bg: 'rgba(46,227,154,0.06)',  bd: 'rgba(46,227,154,0.45)' },
  C: { fg: '#fb923c', bg: 'rgba(251,146,60,0.06)',  bd: 'rgba(251,146,60,0.45)' },
  F: { fg: '#ff4060', bg: 'rgba(255,21,53,0.06)',   bd: 'rgba(255,21,53,0.45)' },
}

const CHANNEL_COLOR = {
  browser:  { fg: '#fb923c', bd: 'rgba(251,146,60,0.3)',  bg: 'rgba(251,146,60,0.06)' },
  terminal: { fg: '#7dd3fc', bd: 'rgba(125,211,252,0.3)', bg: 'rgba(125,211,252,0.06)' },
  evidence: { fg: '#2ee39a', bd: 'rgba(46,227,154,0.3)',  bg: 'rgba(46,227,154,0.06)' },
}

const ADAPT_GRADE_COLORS = {
  S: { fg: '#facc15', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.4)' },
  A: { fg: '#00c8ff', bg: 'rgba(0,200,255,0.06)',  bd: 'rgba(0,200,255,0.4)'  },
  B: { fg: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.4)' },
  C: { fg: '#fb923c', bg: 'rgba(251,146,60,0.06)', bd: 'rgba(251,146,60,0.4)' },
  F: { fg: '#ff4060', bg: 'rgba(255,21,53,0.06)',  bd: 'rgba(255,21,53,0.4)'  },
}

function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    try {
      navigator.clipboard?.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch { /* ignore */ }
  }
  return (
    <div className="relative my-1">
      <pre
        className="font-mono text-[11px] rounded leading-relaxed whitespace-pre-wrap overflow-x-auto"
        style={{
          background: 'rgba(0,0,0,0.45)',
          border: '1px solid rgba(255,255,255,0.06)',
          color: code.trim().startsWith('#') ? '#7a8699' : '#a3e635',
          padding: '10px 56px 10px 12px',
        }}
      >{code}</pre>
      <button
        onClick={copy}
        title="Copy command"
        className="absolute top-1.5 right-1.5 font-mono text-[8.5px] tracking-[0.1em] px-2 py-1 rounded"
        style={{
          background: copied ? 'rgba(46,227,154,0.12)' : 'rgba(255,255,255,0.04)',
          border: `1px solid ${copied ? 'rgba(46,227,154,0.4)' : 'rgba(255,255,255,0.08)'}`,
          color:   copied ? '#2ee39a' : '#94a3b8',
        }}
      >{copied ? '✓ COPIED' : 'COPY'}</button>
    </div>
  )
}

function GradeBadge({ grade, score }) {
  const c = GRADE_COLORS[grade] || GRADE_COLORS.C
  return (
    <div className="flex flex-col items-center" style={{ minWidth: 130 }}>
      <motion.div
        className="rounded-2xl flex items-center justify-center font-bold"
        style={{
          width: 110, height: 110,
          background: c.bg, border: `2px solid ${c.bd}`,
          color: c.fg,
          fontSize: 64, lineHeight: 1,
          textShadow: `0 0 28px ${c.fg}88`,
          fontFamily: "'Rajdhani', sans-serif",
        }}
        initial={{ scale: 0.5, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 0.25, duration: 0.55, ease: 'backOut' }}
      >
        {grade}
      </motion.div>
      <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim mt-2">SCORE</div>
      <div className="font-mono font-bold tabular-nums" style={{ fontSize: 18, color: c.fg }}>
        {score} / 100
      </div>
    </div>
  )
}

function HeroStat({ label, value, mono = true }) {
  return (
    <div className="rounded-lg px-4 py-3" style={{
      background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
    }}>
      <div className="font-mono text-[9px] tracking-[0.24em] text-attense-dim mb-1">{label}</div>
      <div className={(mono ? 'font-mono ' : 'font-sans font-semibold ') + 'text-[13.5px] text-attense-text truncate'}>
        {value || '—'}
      </div>
    </div>
  )
}

function fmtDuration(secs) {
  if (secs == null) return '—'
  if (secs < 60) return `${secs}s`
  return `${Math.floor(secs / 60)}m ${secs % 60}s`
}

function fmtRel(delta) {
  if (delta == null) return '—'
  if (delta < 60) return `+${delta.toFixed(1)}s`
  return `+${Math.floor(delta / 60)}m${Math.round(delta % 60).toString().padStart(2, '0')}s`
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

  const coachingNote = score >= 90
    ? 'Excellent — you pivoted every time the environment shifted. This is the core of real red-teaming: staying effective when the target fights back.'
    : score >= 70
    ? 'Good adaptation. Review any shifts you missed and drill the alternative technique — in the field, a stalled attack is a failed attack.'
    : score >= 40
    ? 'Partial adaptation. When a mutation fires, stop and re-enumerate before pushing forward with the same payload. Identify what changed first.'
    : 'The mutations stopped your progress. Focus your next attempt on recognising when a technique has stopped working — the first 30 seconds after a shift are critical.'

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

              {/* Activity count + picker attribution */}
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
          {coachingNote}
        </div>
      </div>
    </motion.section>
  )
}

export default function MissionReport() {
  const { sid } = useParams()
  const navigate = useNavigate()
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [regenerating, setRegenerating] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.sessions.getReport(sid)
      .then(r => { if (!cancelled) { setReport(r); setLoading(false) } })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [sid])

  const regen = async () => {
    setRegenerating(true)
    try {
      const r = await api.sessions.regenReport(sid)
      setReport(r)
    } catch (e) { setError(e.message) }
    finally { setRegenerating(false) }
  }

  if (loading) return (
    <div className="h-full flex items-center justify-center font-mono text-[11px] tracking-widest text-attense-dim">
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
        style={{ width: 16, height: 16, marginRight: 10,
                 border: '2px solid rgba(255,21,53,0.3)', borderTopColor: '#ff1535', borderRadius: '50%' }}
      />
      GENERATING REPORT…
    </div>
  )

  if (error) return (
    <div className="p-6 max-w-2xl mx-auto">
      <div className="rounded-lg p-4 font-mono text-[11px]"
        style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
        {error}
      </div>
      <Link to="/" className="inline-block mt-4 font-mono text-[11px] text-attense-muted hover:text-attense-red">← Back</Link>
    </div>
  )

  if (!report) return null

  const c = GRADE_COLORS[report.grade] || GRADE_COLORS.C

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '24px 32px 48px' }}>

      {/* Top toolbar */}
      <div className="flex items-center gap-3 mb-6 flex-wrap">
        <button onClick={() => navigate('/reports')}
          className="font-mono text-[10px] tracking-[0.18em] text-attense-dim hover:text-attense-red transition-colors">
          ← BACK TO REPORTS
        </button>
        <div className="flex-1" />
        <button onClick={() => navigate(`/workspace/${sid}?replay=1`)}
          className="font-mono text-[10px] tracking-[0.18em] px-3 py-2 rounded-lg"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
          REVIEW SESSION
        </button>
        <button onClick={regen} disabled={regenerating}
          className="font-mono text-[10px] tracking-[0.18em] px-3 py-2 rounded-lg"
          style={{
            background: 'rgba(125,211,252,0.06)', border: '1px solid rgba(125,211,252,0.25)',
            color: '#7dd3fc', cursor: regenerating ? 'wait' : 'pointer',
          }}>
          {regenerating ? 'REGENERATING…' : '↻ REGENERATE'}
        </button>
      </div>

      {/* ── HEADER ── */}
      <motion.div {...fadeUp(0)} className="rounded-2xl p-6 mb-6"
        style={{
          background: 'linear-gradient(135deg, rgba(7,9,15,0.5) 0%, rgba(7,9,15,0.85) 100%)',
          border: `1px solid ${c.bd}`,
          boxShadow: `0 0 60px ${c.fg}11`,
        }}>
        <div className="flex items-start gap-6 flex-wrap">
          <GradeBadge grade={report.grade} score={report.score} />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[9px] tracking-[0.32em] mb-1" style={{ color: c.fg }}>
              MISSION REPORT
            </div>
            <h1 style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontSize: 32, fontWeight: 700, letterSpacing: '-0.005em',
              color: '#edf0f8', lineHeight: 1.1, marginBottom: 6,
            }}>
              {report.module_name}
            </h1>
            <div className="flex gap-2 flex-wrap mb-4">
              {report.variant_name && (
                <span className="font-mono text-[9.5px] tracking-[0.18em] px-2.5 py-1 rounded"
                  style={{ background: 'rgba(139,47,255,0.08)', border: '1px solid rgba(139,47,255,0.3)', color: '#c4a8ed' }}>
                  {report.variant_name}
                </span>
              )}
              <span className="font-mono text-[9.5px] tracking-[0.18em] px-2.5 py-1 rounded"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                {(report.mode || 'tutorial').toUpperCase()} MODE
              </span>
              <span className="font-mono text-[9.5px] tracking-[0.18em] px-2.5 py-1 rounded"
                style={{ background: c.bg, border: `1px solid ${c.bd}`, color: c.fg }}>
                {report.success ? 'SUCCESS' : 'INCOMPLETE'}
              </span>
            </div>
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
          </div>
        </div>
      </motion.div>


      {/* ── TASK RESULTS ── */}
      <motion.section {...fadeUp(0.1)} className="mb-5">
        <SectionTitle title="Task Results" subtitle="What the evidence engine credited" />
        <div className="grid md:grid-cols-2 gap-3">
          {report.task_results?.map((t, i) => (
            <div key={i} className="rounded-lg p-4"
              style={{
                background: t.completed ? 'rgba(46,227,154,0.04)' : 'rgba(255,21,53,0.04)',
                border: `1px solid ${t.completed ? 'rgba(46,227,154,0.25)' : 'rgba(255,21,53,0.22)'}`,
              }}>
              <div className="flex items-start gap-2.5">
                <div className="shrink-0 rounded-full w-6 h-6 flex items-center justify-center font-bold"
                  style={{
                    background: t.completed ? 'rgba(46,227,154,0.15)' : 'rgba(255,21,53,0.1)',
                    color:      t.completed ? '#2ee39a' : '#ff4060',
                    fontSize: 12,
                  }}>{t.completed ? '✓' : '✗'}</div>
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold mb-1" style={{ color: '#e6e8ee' }}>{t.title}</div>
                  <div className="text-[11px]" style={{ color: '#9aa0c0' }}>{t.feedback}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.section>

      {/* ── WHAT YOU DID RIGHT ── */}
      <motion.section {...fadeUp(0.15)} className="mb-5">
        <SectionTitle title="What You Did Right" subtitle="Wins worth keeping" color="#2ee39a" />
        {(report.what_you_did_right || []).length === 0 ? (
          <Empty text="No completed steps yet. Try the ideal approach below and re-attempt."/>
        ) : (
          <div className="grid md:grid-cols-2 gap-3">
            {report.what_you_did_right.map((x, i) => (
              <div key={i} className="rounded-lg p-4"
                style={{ background: 'rgba(46,227,154,0.04)', border: '1px solid rgba(46,227,154,0.2)' }}>
                <div className="text-[13px] font-semibold mb-1" style={{ color: '#9be8c5' }}>✓ {x.title}</div>
                <div className="text-[11.5px] leading-relaxed" style={{ color: '#a0b0c8' }}>{x.detail}</div>
              </div>
            ))}
          </div>
        )}
      </motion.section>

      {/* ── WHAT YOU MISSED ── */}
      <motion.section {...fadeUp(0.2)} className="mb-5">
        <SectionTitle title="What You Missed" subtitle="Gaps to close next attempt" color="#fb923c" />
        {(report.what_you_missed || []).length === 0 ? (
          <Empty text="✨ Perfect execution — nothing missed."/>
        ) : (
          <div className="space-y-3">
            {report.what_you_missed.map((x, i) => (
              <div key={i} className="rounded-lg p-4"
                style={{ background: 'rgba(251,146,60,0.04)', border: '1px solid rgba(251,146,60,0.22)' }}>
                <div className="text-[13px] font-semibold mb-1" style={{ color: '#fbb88a' }}>✗ {x.title}</div>
                <div className="text-[11.5px] leading-relaxed mb-2" style={{ color: '#a0b0c8' }}>{x.detail}</div>
                {x.how_to_fix && (
                  <div className="rounded p-2.5"
                    style={{ background: 'rgba(125,211,252,0.05)', border: '1px solid rgba(125,211,252,0.18)' }}>
                    <span className="font-mono text-[8.5px] tracking-[0.2em]" style={{ color: '#7dd3fc' }}>HOW TO FIX</span>
                    <div className="text-[11.5px] mt-1" style={{ color: '#c9d4e8' }}>{x.how_to_fix}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </motion.section>

      {/* ── IDEAL APPROACH ── */}
      <motion.section {...fadeUp(0.25)} className="mb-5">
        <SectionTitle title="Ideal Approach" subtitle="Copy these commands and run them step-by-step" color="#7dd3fc" />
        <div className="space-y-2">
          {(report.ideal_approach || []).map((s, i) => (
            <div key={i} className="rounded-lg p-3"
              style={{ background: 'rgba(125,211,252,0.025)', border: '1px solid rgba(125,211,252,0.18)' }}>
              <div className="flex items-baseline gap-2 mb-1">
                <span className="font-mono text-[10px] font-bold" style={{ color: '#7dd3fc' }}>
                  Step {s.step}
                </span>
                {s.why && (
                  <span className="text-[11px]" style={{ color: '#9aa0c0' }}>{s.why}</span>
                )}
              </div>
              <CodeBlock code={s.command} />
            </div>
          ))}
        </div>
      </motion.section>

      {/* ── VULNERABILITY DEEP DIVE ── */}
      {report.vulnerability_explained && (
        <motion.section {...fadeUp(0.3)} className="mb-5">
          <SectionTitle title="Vulnerability Deep Dive" subtitle="What this attack means in the real world" color="#ff4060" />
          <div className="rounded-xl p-5"
            style={{ background: 'rgba(255,21,53,0.04)', border: '1px solid rgba(255,21,53,0.22)' }}>
            <div className="flex items-baseline gap-3 mb-3">
              <div className="text-[18px] font-semibold" style={{ color: '#edf0f8' }}>
                {report.vulnerability_explained.name}
              </div>
              <span className="font-mono text-[9.5px] tracking-[0.18em] px-2 py-0.5 rounded"
                style={{ background: 'rgba(255,21,53,0.1)', border: '1px solid rgba(255,21,53,0.3)', color: '#ff4060' }}>
                {report.vulnerability_explained.cvss_category}
              </span>
            </div>
            <div className="space-y-3">
              {[
                ['WHAT IT IS',          report.vulnerability_explained.what_it_is],
                ['WHY IT MATTERS',      report.vulnerability_explained.why_it_matters],
                ['REAL-WORLD EXAMPLE',  report.vulnerability_explained.real_world_example],
              ].map(([label, val]) => (
                <div key={label}>
                  <div className="font-mono text-[8.5px] tracking-[0.24em] mb-1" style={{ color: '#7a8699' }}>{label}</div>
                  <div className="text-[12.5px] leading-relaxed" style={{ color: '#c9d4e8' }}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        </motion.section>
      )}

      {/* ── DEFENSIVE CONTROLS ── */}
      {(report.defensive_controls || []).length > 0 && (
        <motion.section {...fadeUp(0.35)} className="mb-5">
          <SectionTitle title="Defensive Controls" subtitle="How blue teams shut this down" color="#7dd3fc" />
          <div className="grid md:grid-cols-2 gap-3">
            {report.defensive_controls.map((d, i) => (
              <div key={i} className="rounded-lg p-4"
                style={{ background: 'rgba(125,211,252,0.03)', border: '1px solid rgba(125,211,252,0.18)' }}>
                <div className="text-[13px] font-semibold mb-1" style={{ color: '#a4d4ff' }}>🛡 {d.control}</div>
                <div className="text-[11.5px] leading-relaxed" style={{ color: '#a0b0c8' }}>{d.implementation}</div>
              </div>
            ))}
          </div>
        </motion.section>
      )}

      {/* ── ACTION REPLAY ── */}
      {(report.evidence_timeline || []).length > 0 && (
        <motion.section {...fadeUp(0.4)} className="mb-5">
          <SectionTitle title="Action Replay" subtitle={`${report.evidence_timeline.length} events captured`} />
          <div className="rounded-xl overflow-hidden"
            style={{ background: 'rgba(8,10,17,0.5)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="overflow-y-auto" style={{ maxHeight: 460 }}>
              {report.evidence_timeline.map((e, i) => {
                const cc = CHANNEL_COLOR[e.channel] || CHANNEL_COLOR.evidence
                return (
                  <div key={i} className="flex items-start gap-3 px-4 py-2.5"
                    style={{ borderBottom: i < report.evidence_timeline.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                    <span className="shrink-0 font-mono text-[10px] tabular-nums w-14" style={{ color: '#4a5280' }}>
                      {fmtRel(e.delta_s)}
                    </span>
                    <span className="shrink-0 font-mono text-[8.5px] tracking-[0.16em] px-1.5 py-0.5 rounded"
                      style={{ background: cc.bg, border: `1px solid ${cc.bd}`, color: cc.fg, minWidth: 64, textAlign: 'center' }}>
                      {(e.channel || '?').toUpperCase()}
                    </span>
                    <span className="shrink-0 font-mono text-[10px]" style={{ color: '#7a8699', minWidth: 130 }}>
                      {e.kind}
                    </span>
                    <span className="text-[11.5px] flex-1 min-w-0 truncate" style={{ color: '#c9d4e8' }}>
                      {e.description}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </motion.section>
      )}

      {/* ── MUTATION TIMELINE ── */}
      {(report.mutation_timeline || []).length > 0 && (
        <MutationTimelineSection report={report} />
      )}

      {/* Re-attempt CTA */}
      <motion.div {...fadeUp(0.45)} className="flex justify-center gap-3 flex-wrap mt-8">
        <button onClick={() => navigate(`/workspace/${sid}?retry=1`)}
          className="font-mono font-bold text-white"
          style={{
            fontSize: 11, letterSpacing: '0.12em', padding: '12px 30px', borderRadius: 10,
            background: 'linear-gradient(135deg,#ff1535,#cc0020)',
            boxShadow: '0 0 22px rgba(255,21,53,0.4)',
          }}>
          ⚡ RE-ATTEMPT THIS MISSION
        </button>
        <button onClick={() => navigate(`/modules/${report.module_id}`)}
          className="font-mono"
          style={{
            fontSize: 11, letterSpacing: '0.12em', padding: '12px 24px', borderRadius: 10,
            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
            color: '#94a3b8',
          }}>
          TRY ANOTHER VARIANT
        </button>
      </motion.div>
    </div>
  )
}

function SectionTitle({ title, subtitle, color = '#94a3b8' }) {
  return (
    <div className="mb-3 flex items-baseline gap-3 flex-wrap">
      <h2 style={{
        fontFamily: "'Rajdhani', sans-serif", fontSize: 19, fontWeight: 700,
        letterSpacing: '0.02em', color, margin: 0,
      }}>{title}</h2>
      <span className="text-[11px] text-attense-dim">{subtitle}</span>
    </div>
  )
}

function Empty({ text }) {
  return (
    <div className="rounded-lg px-4 py-6 text-center"
      style={{ background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.08)' }}>
      <div className="text-[11.5px]" style={{ color: '#7a8699' }}>{text}</div>
    </div>
  )
}
