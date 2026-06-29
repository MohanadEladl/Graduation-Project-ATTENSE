import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { SeverityBadge } from '../components/SeverityBadge.jsx'

const RATING_STYLES = {
  excellent: { color: '#2ee39a', bg: 'rgba(46,227,154,0.08)',  bd: 'rgba(46,227,154,0.3)'  },
  good:      { color: '#7dd3fc', bg: 'rgba(125,211,252,0.08)', bd: 'rgba(125,211,252,0.3)' },
  basic:     { color: '#fbbf24', bg: 'rgba(250,204,21,0.08)',  bd: 'rgba(250,204,21,0.3)'  },
  incomplete:{ color: '#f87171', bg: 'rgba(248,113,113,0.08)', bd: 'rgba(248,113,113,0.3)' },
}

function LabAnalysisSection({ sid }) {
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading]   = useState(false)
  const [loaded, setLoaded]     = useState(false)

  const load = async () => {
    if (loaded) return
    setLoading(true)
    try {
      const r = await api.sessions.labAnalysis(sid)
      setAnalysis(r)
    } catch {
      setAnalysis({ error: 'Could not load analysis.' })
    }
    setLoading(false)
    setLoaded(true)
  }

  if (!loaded) {
    return (
      <button
        onClick={load}
        disabled={loading}
        className="w-full font-mono text-[10px] tracking-[0.14em] py-2 rounded-lg mt-3 transition-colors"
        style={{
          background: 'rgba(125,211,252,0.05)',
          border: '1px solid rgba(125,211,252,0.22)',
          color: loading ? '#4a5280' : '#7dd3fc',
          cursor: loading ? 'wait' : 'pointer',
        }}
      >
        {loading ? 'LOADING ANALYSIS…' : '▸ VIEW LAB ANALYSIS'}
      </button>
    )
  }

  if (analysis?.error) {
    return (
      <div className="mt-3 font-mono text-[10.5px] text-attense-dim">{analysis.error}</div>
    )
  }

  if (!analysis) return null

  const rs = RATING_STYLES[analysis.rating] || RATING_STYLES.incomplete

  return (
    <div className="mt-4 space-y-3">
      {/* Rating header */}
      <div className="flex items-center gap-3">
        <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim">LAB ANALYSIS</div>
        <span
          className="font-mono text-[9px] tracking-[0.16em] px-2 py-0.5 rounded font-bold"
          style={{ color: rs.color, background: rs.bg, border: `1px solid ${rs.bd}` }}
        >
          {(analysis.rating || 'unknown').toUpperCase()}
        </span>
        {analysis.evidence_count > 0 && (
          <span className="font-mono text-[9px] text-attense-dim">
            {analysis.evidence_count} evidence event{analysis.evidence_count !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {analysis.rating_reason && (
        <p className="text-[11.5px] text-attense-muted leading-relaxed">{analysis.rating_reason}</p>
      )}

      {/* What worked */}
      {analysis.what_worked?.length > 0 && (
        <div className="rounded-lg p-3"
          style={{ background: 'rgba(46,227,154,0.04)', border: '1px solid rgba(46,227,154,0.18)' }}>
          <div className="font-mono text-[9px] tracking-[0.22em] mb-2" style={{ color: '#2ee39a' }}>
            WHAT WORKED
          </div>
          <ul className="space-y-1">
            {analysis.what_worked.map((item, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-relaxed" style={{ color: '#a8d8c0' }}>
                <span className="shrink-0" style={{ color: '#2ee39a' }}>✓</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* What was missed */}
      {analysis.what_missed?.length > 0 && (
        <div className="rounded-lg p-3"
          style={{ background: 'rgba(250,204,21,0.04)', border: '1px solid rgba(250,204,21,0.18)' }}>
          <div className="font-mono text-[9px] tracking-[0.22em] mb-2" style={{ color: '#fbbf24' }}>
            WHAT WAS MISSED
          </div>
          <ul className="space-y-1">
            {analysis.what_missed.map((item, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-relaxed" style={{ color: '#d4b96a' }}>
                <span className="shrink-0" style={{ color: '#fbbf24' }}>◌</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Better approach */}
      {analysis.better_approach?.length > 0 && (
        <div className="rounded-lg p-3"
          style={{ background: 'rgba(125,211,252,0.04)', border: '1px solid rgba(125,211,252,0.18)' }}>
          <div className="font-mono text-[9px] tracking-[0.22em] mb-2" style={{ color: '#7dd3fc' }}>
            BETTER APPROACH
          </div>
          <ul className="space-y-1">
            {analysis.better_approach.map((item, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-relaxed" style={{ color: '#a0c4e0' }}>
                <span className="shrink-0" style={{ color: '#7dd3fc' }}>→</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default function Reports() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  useEffect(() => {
    api.sessions.list().catch(() => [])
      .then(s => {
        const done = (Array.isArray(s) ? s : []).filter(
          x => x.learning_success || x.learning_state === 'completed' || x.state === 'completed'
        )
        setSessions(done.sort((a, b) => (b.learning_completed_at || b.created_at || 0) - (a.learning_completed_at || a.created_at || 0)))
        setLoading(false)
      })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="mb-5">
        <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Reports</h1>
        <p className="font-mono text-[11px] text-attense-dim mt-1">
          Completed lab mission reports · {sessions.length} available
        </p>
      </div>

      {error && (
        <div className="rounded-lg p-4 font-mono text-[11px] mb-4"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {loading && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING…</div>
      )}

      {!loading && sessions.length === 0 && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">
          No completed missions yet. Complete a lab mission to generate a report.
        </div>
      )}

      <div className="flex flex-col gap-3">
        {sessions.map(s => {
          const r = s.result || {}
          const done  = s.learning_completed_tasks?.length ?? s.completed_steps?.length ?? r.successful_steps ?? 0
          const total = s.learning_total_tasks || s.total_steps || r.total_steps || 0
          const durSecs = s.learning_duration_s
          const dur = durSecs != null
            ? (durSecs < 60 ? `${durSecs}s` : `${Math.floor(durSecs / 60)}m ${durSecs % 60}s`)
            : (r.duration_ms ? `${Math.round(r.duration_ms / 1000)}s` : '—')
          const date = (s.learning_completed_at || s.created_at)
            ? new Date((s.learning_completed_at || s.created_at) * 1000).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })
            : '—'
          const isLab = s.mode === 'lab'

          return (
            <div key={s.session_id}
              className="glass-card rounded-xl overflow-hidden transition-all duration-150 cursor-pointer"
              style={{ padding: '18px 22px' }}
              onClick={() => navigate(`/report/${s.session_id}`)}
              onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(125,211,252,0.35)'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'}
            >
              {/* Top row */}
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-mono text-[10px] font-bold text-attense-red">
                    {s.session_id?.slice(0, 12)}…
                  </span>
                  <SeverityBadge severity={s.severity} />
                  <span className="font-mono text-[10px] text-attense-dim">
                    {s.module_name || s.module_id}
                  </span>
                  <span className="font-mono text-[10px] text-attense-dim">· {s.scenario_id}</span>
                  {isLab && (
                    <span className="font-mono text-[9px] tracking-[0.14em] px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(125,211,252,0.08)', border: '1px solid rgba(125,211,252,0.25)', color: '#7dd3fc' }}>
                      LAB
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono text-[10px] text-attense-dim">{date}</span>
                  <a
                    href={`/api/sessions/${s.session_id}/logs?format=ndjson`}
                    onClick={e => e.stopPropagation()}
                    className="font-mono text-[9.5px] font-bold tracking-[0.1em] px-2.5 py-1 rounded-md transition-colors"
                    style={{ background: 'rgba(139,47,255,0.1)', border: '1px solid rgba(139,47,255,0.25)', color: '#a060ff' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(139,47,255,0.18)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'rgba(139,47,255,0.1)'}
                  >EXPORT</a>
                  <button
                    onClick={e => { e.stopPropagation(); navigate(`/workspace/${s.session_id}?replay=1`) }}
                    className="font-mono text-[9.5px] font-bold tracking-[0.1em] px-2.5 py-1 rounded-md transition-colors"
                    style={{ background: 'rgba(0,200,255,0.06)', border: '1px solid rgba(0,200,255,0.2)', color: '#00c8ff' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,200,255,0.12)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'rgba(0,200,255,0.06)'}
                  >REPLAY</button>
                  <button
                    onClick={e => { e.stopPropagation(); navigate(`/report/${s.session_id}`) }}
                    className="font-mono text-[9.5px] font-bold tracking-[0.1em] px-2.5 py-1 rounded-md transition-colors"
                    style={{ background: 'rgba(46,227,154,0.08)', border: '1px solid rgba(46,227,154,0.3)', color: '#2ee39a' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(46,227,154,0.16)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'rgba(46,227,154,0.08)'}
                  >VIEW REPORT →</button>
                </div>
              </div>

              {/* Summary */}
              {r.summary && (
                <p className="text-[12px] text-attense-muted leading-relaxed mb-4">{r.summary}</p>
              )}
              {r.error && (
                <p className="font-mono text-[11px] mb-4" style={{ color: '#ff4060' }}>{r.error}</p>
              )}

              {/* Stats row */}
              <div className="flex gap-3">
                {[
                  { label: 'STEPS',    value: `${done}/${total}`, color: '#e8ecf4' },
                  { label: 'PASSED',   value: done,               color: '#2ee39a' },
                  { label: 'FAILED',   value: total - done,       color: (total - done) > 0 ? '#ff4060' : '#3a4060' },
                  { label: 'DURATION', value: dur,                color: '#e8ecf4' },
                ].map(stat => (
                  <div key={stat.label}
                    className="rounded-lg px-4 py-3 flex-1"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}
                  >
                    <div className="font-mono text-[8.5px] tracking-[0.18em] text-attense-dim mb-1">{stat.label}</div>
                    <div className="font-mono text-[18px] font-bold" style={{ color: stat.color }}>{stat.value}</div>
                  </div>
                ))}
              </div>

              {/* Lab analysis — only for lab-mode sessions */}
              {isLab && <LabAnalysisSection sid={s.session_id} />}
            </div>
          )
        })}
      </div>
    </div>
  )
}
