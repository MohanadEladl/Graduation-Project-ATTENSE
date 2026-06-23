/**
 * AttackReport.jsx — Red-team attack debrief page.
 * Route: /attack-report/:sid
 * Only accessible after execute() has run on the session.
 */
import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { api } from '../api/client.js'

// ── Animation helper ─────────────────────────────────────────────────────────
const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.32, delay, ease: [0.22, 1, 0.36, 1] },
})

// ── Severity colours ─────────────────────────────────────────────────────────
const SEV_CFG = {
  critical: { color: '#f87171', bg: 'rgba(248,113,113,0.08)', bd: 'rgba(248,113,113,0.3)' },
  high:     { color: '#fb923c', bg: 'rgba(251,146,60,0.08)',  bd: 'rgba(251,146,60,0.3)'  },
  medium:   { color: '#facc15', bg: 'rgba(250,204,21,0.08)',  bd: 'rgba(250,204,21,0.3)'  },
  low:      { color: '#7dd3fc', bg: 'rgba(125,211,252,0.08)', bd: 'rgba(125,211,252,0.3)' },
  info:     { color: '#a3a8b8', bg: 'rgba(163,168,184,0.06)', bd: 'rgba(163,168,184,0.18)' },
}

function sevCfg(s) { return SEV_CFG[s?.toLowerCase()] || SEV_CFG.info }

function fmtMs(ms) {
  if (!ms) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

// ── Atoms ────────────────────────────────────────────────────────────────────
function SectionTitle({ children, color = '#9ba3b8' }) {
  return (
    <div className="font-mono text-[9px] tracking-[0.32em] mb-3" style={{ color }}>
      {children}
    </div>
  )
}

function Card({ children, style, className = '' }) {
  return (
    <div
      className={`rounded-xl p-4 ${className}`}
      style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', ...style }}
    >
      {children}
    </div>
  )
}

// ── Sections ─────────────────────────────────────────────────────────────────

function AttackHeader({ report }) {
  const sev = sevCfg(report.severity)
  const succeeded = report.goal_achieved
  return (
    <div
      className="shrink-0 flex flex-wrap items-center gap-4 px-6 py-4"
      style={{ background: 'rgba(0,0,0,0.5)', borderBottom: '1px solid rgba(255,255,255,0.07)' }}
    >
      <Link
        to="/"
        className="font-mono text-[9.5px] tracking-[0.22em] text-attense-dim hover:text-attense-red transition-colors"
      >
        ← DASHBOARD
      </Link>

      <div className="flex items-center gap-2 min-w-0">
        <span className="text-[14px] font-semibold text-attense-text truncate">
          {report.module_name}
        </span>
        <span
          className="font-mono text-[8.5px] tracking-[0.14em] px-2 py-0.5 rounded"
          style={{ color: sev.color, background: sev.bg, border: `1px solid ${sev.bd}` }}
        >
          {report.severity?.toUpperCase()}
        </span>
        <span
          className="font-mono text-[8px] tracking-[0.14em] px-2 py-0.5 rounded"
          style={{ color: '#7a8194', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          {report.scenario_id}
        </span>
      </div>

      <div className="flex-1" />

      {/* Goal badge */}
      <span
        className="font-mono text-[9px] tracking-[0.18em] px-3 py-1.5 rounded-lg"
        style={report.state === 'error'
          ? { color: '#f87171', background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.3)' }
          : succeeded
            ? { color: '#2ee39a', background: 'rgba(46,227,154,0.08)', border: '1px solid rgba(46,227,154,0.3)' }
            : { color: '#fb923c', background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.3)' }
        }
      >
        {report.state === 'error' ? 'ATTACK ERRORED' : succeeded ? 'OBJECTIVE MET' : 'OBJECTIVE NOT MET'}
      </span>

      {/* Steps ratio */}
      <div className="font-mono text-[11px] text-attense-dim">
        <strong style={{ color: succeeded ? '#2ee39a' : '#fb923c' }}>{report.successful_steps}</strong>
        <span style={{ color: '#4a5363' }}> / {report.total_steps} probes</span>
      </div>
    </div>
  )
}

function SummaryCard({ report }) {
  const succeeded = report.goal_achieved
  return (
    <motion.section {...fadeUp(0.05)}>
      <SectionTitle>ATTACK SUMMARY</SectionTitle>
      <Card>
        <div className="text-[13px] font-semibold text-attense-text leading-relaxed mb-3">
          {report.summary || report.description}
        </div>
        {report.error && (
          <div
            className="rounded-lg px-3 py-2 mb-3 font-mono text-[11px]"
            style={{ background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.25)', color: '#f87171' }}
          >
            {report.error}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-attense-dim mt-1">
          <span>Target: <strong className="text-attense-text">{report.target}</strong></span>
          <span>Category: <strong className="text-attense-text">{report.category}</strong></span>
          <span>Duration: <strong className="text-attense-text">{fmtMs(report.duration_ms)}</strong></span>
          {report.elapsed && (
            <span>Elapsed: <strong className="text-attense-text">{report.elapsed}</strong></span>
          )}
        </div>

        {/* Steps progress bar */}
        {report.total_steps > 0 && (
          <div className="mt-3">
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
              <motion.div
                className="h-full rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${(report.successful_steps / report.total_steps) * 100}%` }}
                transition={{ duration: 0.9, delay: 0.25, ease: 'easeOut' }}
                style={{
                  background: succeeded
                    ? 'linear-gradient(90deg, #2ee39a88, #2ee39a)'
                    : 'linear-gradient(90deg, #fb923c88, #fb923c)',
                }}
              />
            </div>
            <div className="flex justify-between mt-1 font-mono text-[9px] text-attense-dim">
              <span>0</span>
              <span>{report.successful_steps} / {report.total_steps} steps succeeded</span>
            </div>
          </div>
        )}
      </Card>
    </motion.section>
  )
}

function StepsSection({ report }) {
  if (!report.steps?.length) return null
  return (
    <motion.section {...fadeUp(0.1)}>
      <SectionTitle>ATTACK STEPS</SectionTitle>
      <div className="space-y-2">
        {report.steps.map((step, i) => (
          <div
            key={i}
            className="flex items-start gap-3 rounded-xl px-4 py-3"
            style={{
              background: step.success ? 'rgba(46,227,154,0.03)' : 'rgba(248,113,113,0.03)',
              border: `1px solid ${step.success ? 'rgba(46,227,154,0.18)' : 'rgba(248,113,113,0.18)'}`,
            }}
          >
            {/* Step index */}
            <span
              className="shrink-0 font-mono text-[10px] font-bold flex items-center justify-center rounded mt-0.5"
              style={{
                width: 24, height: 24, minWidth: 24,
                background: step.success ? 'rgba(46,227,154,0.1)' : 'rgba(248,113,113,0.1)',
                border: `1px solid ${step.success ? 'rgba(46,227,154,0.3)' : 'rgba(248,113,113,0.3)'}`,
                color: step.success ? '#2ee39a' : '#f87171',
              }}
            >
              {i + 1}
            </span>

            <div className="flex-1 min-w-0">
              {/* Label + URL */}
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span
                  className="text-[12px] font-semibold"
                  style={{ color: step.success ? '#2ee39a' : '#f87171' }}
                >
                  {step.label}
                </span>
                {step.url && (
                  <span className="font-mono text-[9px] text-attense-dim truncate max-w-[260px]">
                    {step.url}
                  </span>
                )}
              </div>

              {/* Detail */}
              {step.detail && (
                <div className="text-[11px] text-attense-dim leading-relaxed">
                  {step.detail}
                </div>
              )}
            </div>

            {/* Status code + latency */}
            <div className="shrink-0 flex flex-col items-end gap-1">
              {step.status_code != null && (
                <span
                  className="font-mono text-[9px] px-1.5 py-0.5 rounded"
                  style={{
                    background: step.status_code < 400 ? 'rgba(46,227,154,0.08)' : 'rgba(248,113,113,0.08)',
                    border: `1px solid ${step.status_code < 400 ? 'rgba(46,227,154,0.25)' : 'rgba(248,113,113,0.25)'}`,
                    color: step.status_code < 400 ? '#2ee39a' : '#f87171',
                  }}
                >
                  {step.status_code}
                </span>
              )}
              {step.latency_ms > 0 && (
                <span className="font-mono text-[9px] text-attense-dim">
                  {fmtMs(step.latency_ms)}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </motion.section>
  )
}

function LogSection({ logs }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  if (!logs?.length) return null

  return (
    <motion.section {...fadeUp(0.15)}>
      <SectionTitle>TERMINAL OUTPUT</SectionTitle>
      <div
        className="rounded-xl overflow-hidden"
        style={{ border: '1px solid rgba(255,255,255,0.08)' }}
      >
        {/* Title bar */}
        <div
          className="flex items-center gap-1.5 px-3 py-2"
          style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
        >
          {['#f87171', '#facc15', '#2ee39a'].map(c => (
            <div key={c} className="w-2.5 h-2.5 rounded-full" style={{ background: c, opacity: 0.6 }} />
          ))}
          <span className="font-mono text-[9px] text-attense-dim ml-2">attense-attackbox</span>
        </div>
        {/* Scrollable log */}
        <div
          className="overflow-y-auto px-4 py-3 space-y-0.5"
          style={{ background: '#060810', maxHeight: 420 }}
        >
          {logs.map((line, i) => {
            const color = line.startsWith('[+]') ? '#2ee39a'
              : line.startsWith('[!]') || line.startsWith('[-]') ? '#f87171'
              : line.startsWith('[*]') ? '#7dd3fc'
              : line.startsWith('[>]') ? '#fbbf24'
              : '#9ba3b8'
            return (
              <div key={i} className="font-mono text-[10.5px] leading-relaxed whitespace-pre-wrap break-all" style={{ color }}>
                {line || ' '}
              </div>
            )
          })}
          <div ref={bottomRef} />
        </div>
      </div>
    </motion.section>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AttackReport() {
  const { sid } = useParams()
  const [report, setReport]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  useEffect(() => {
    if (!sid) return
    setLoading(true)
    api.sessions.getAttackReport(sid)
      .then(r => { setReport(r); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [sid])

  if (loading) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4" style={{ background: '#07090f' }}>
        <div
          className="w-10 h-10 rounded-full border-2 border-t-transparent animate-spin"
          style={{ borderColor: 'rgba(255,64,96,0.5)', borderTopColor: 'transparent' }}
        />
        <div className="font-mono text-[10px] tracking-[0.3em] text-attense-dim">LOADING ATTACK REPORT…</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 p-8" style={{ background: '#07090f' }}>
        <div
          className="rounded-xl p-4 max-w-md w-full font-mono text-[11px]"
          style={{ background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.25)', color: '#f87171' }}
        >
          {error.includes('409') || error.includes('not been executed')
            ? 'No attack has been executed for this session yet. Run the attack first, then view the report.'
            : error}
        </div>
        <Link to="/" className="font-mono text-[10px] tracking-[0.2em] text-attense-dim hover:text-attense-red">
          ← BACK
        </Link>
      </div>
    )
  }

  if (!report) return null

  return (
    <div className="h-full flex flex-col overflow-hidden" style={{ background: '#07090f' }}>
      <AttackHeader report={report} />

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-6 py-6 space-y-8">
          <SummaryCard report={report} />
          <StepsSection report={report} />
          <LogSection logs={report.logs} />

          {/* Footer */}
          <motion.div {...fadeUp(0.2)} className="pb-8 flex items-center gap-2">
            <Link
              to={`/workspace/${sid}`}
              className="font-mono text-[10px] tracking-[0.14em] px-4 py-2 rounded-lg transition-colors"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.1)', color: '#7a8194' }}
            >
              ← BACK TO WORKSPACE
            </Link>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
