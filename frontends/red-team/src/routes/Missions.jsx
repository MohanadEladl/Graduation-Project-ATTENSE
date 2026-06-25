import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { SeverityBadge } from '../components/SeverityBadge.jsx'

export default function Missions() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [filter,   setFilter]   = useState('all')

  useEffect(() => {
    let cancelled = false
    api.sessions.list().catch(() => []).then(s => {
      if (!cancelled) { setSessions(Array.isArray(s) ? s : []); setLoading(false) }
    }).catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [])

  const filters = ['all', 'running', 'completed', 'idle', 'error']
  const filtered = filter === 'all' ? sessions : sessions.filter(s => s.state === filter)
  const sorted = [...filtered].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="flex justify-between items-start mb-5">
        <div>
          <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Sessions</h1>
          <p className="font-mono text-[11px] text-attense-dim mt-1">
            {sessions.length} total · {sessions.filter(s => s.state === 'running').length} active
          </p>
        </div>
        <button
          onClick={() => navigate('/modules')}
          className="font-mono text-[11px] font-bold tracking-[0.08em] px-4 py-2 rounded-lg text-white"
          style={{ background: 'linear-gradient(135deg,#ff1535,#cc0020)', boxShadow: '0 0 14px rgba(255,21,53,0.3)' }}
        >
          ⚡ NEW MISSION
        </button>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1.5 mb-4">
        {filters.map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className="font-mono text-[10px] tracking-[0.12em] px-3 py-1.5 rounded-md capitalize transition-all"
            style={{
              background: filter === f ? 'rgba(255,21,53,0.12)' : 'transparent',
              border: `1px solid ${filter === f ? 'rgba(255,21,53,0.3)' : 'rgba(255,255,255,0.07)'}`,
              color: filter === f ? '#ff4060' : '#4a5280',
            }}
          >{f}</button>
        ))}
      </div>

      {/* Table header */}
      <div
        className="grid font-mono text-[9px] tracking-[0.16em] text-attense-dim px-4 py-2 uppercase mb-1"
        style={{ gridTemplateColumns: '1fr 120px 80px 140px 80px 70px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}
      >
        <span>Session / Module</span><span>Scenario</span><span>Severity</span>
        <span>Progress</span><span>State</span><span></span>
      </div>

      {loading && <div className="py-12 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING…</div>}
      {error   && (
        <div className="rounded-lg p-4 font-mono text-[11px]"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {!loading && !error && sorted.map(s => {
        const isRunning   = s.state === 'running'
        const isCompleted = s.state === 'completed'
        const done  = s.completed_steps?.length ?? 0
        const total = s.total_steps ?? 0
        const pct   = total > 0 ? Math.round((done / total) * 100) : 0

        return (
          <div key={s.session_id}
            className="grid items-center px-4 py-3 rounded-lg mb-1.5 cursor-pointer transition-all"
            style={{
              gridTemplateColumns: '1fr 120px 80px 140px 80px 70px',
              background: 'rgba(255,255,255,0.018)',
              border: '1px solid rgba(255,255,255,0.06)',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.018)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)' }}
          >
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: isRunning ? '#ff1535' : isCompleted ? '#00c8ff' : '#2a2e45', boxShadow: isRunning ? '0 0 5px #ff1535' : 'none', animation: isRunning ? 'pulse-glow 1.5s infinite' : 'none' }} />
                <span className="font-mono text-[9.5px] text-attense-red truncate">{s.session_id?.slice(0,12)}…</span>
              </div>
              <div className="text-[12.5px] font-medium text-attense-text">{s.module_name || s.module_id}</div>
            </div>
            <span className="font-mono text-[10px] text-attense-dim">{s.scenario_id || '—'}</span>
            <div><SeverityBadge severity={s.severity} /></div>
            <div className="flex items-center gap-2 pr-4">
              <div className="flex-1 h-[3px] rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <div className="h-full rounded-full transition-all"
                  style={{ width: pct + '%', background: isRunning ? 'linear-gradient(90deg,#ff1535,#ff6b00)' : isCompleted ? '#00c8ff' : '#2a2e45' }} />
              </div>
              <span className="font-mono text-[9.5px] text-attense-dim whitespace-nowrap">{pct}%</span>
            </div>
            <span
              className="font-mono text-[9px] font-bold tracking-[0.1em] px-2 py-0.5 rounded w-fit"
              style={{
                color: isRunning ? '#ff4060' : isCompleted ? '#00c8ff' : '#4a5280',
                background: isRunning ? 'rgba(255,21,53,0.1)' : isCompleted ? 'rgba(0,200,255,0.08)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${isRunning ? 'rgba(255,21,53,0.3)' : isCompleted ? 'rgba(0,200,255,0.2)' : 'rgba(255,255,255,0.08)'}`,
              }}
            >{(s.state || 'idle').toUpperCase()}</span>
            <button
              onClick={() => navigate(`/workspace/${s.session_id}`)}
              className="font-mono text-[10px] font-bold tracking-[0.1em] px-3 py-1.5 rounded-md transition-colors"
              style={{ background: 'rgba(139,47,255,0.1)', border: '1px solid rgba(139,47,255,0.25)', color: '#a060ff' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(139,47,255,0.18)'}
              onMouseLeave={e => e.currentTarget.style.background = 'rgba(139,47,255,0.1)'}
            >OPEN →</button>
          </div>
        )
      })}

      {!loading && !error && sorted.length === 0 && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">No sessions for filter: {filter}</div>
      )}
    </div>
  )
}
