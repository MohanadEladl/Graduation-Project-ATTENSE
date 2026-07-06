import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { CategoryIcon } from '../components/SeverityBadge.jsx'
import {
  ChevronRight, Zap, CheckCircle2, Loader2, Circle, Clock, Trophy,
} from 'lucide-react'

const SEV_COLOR = { critical:'#ff1535', high:'#ff6b00', medium:'#f5c400', low:'#00c8ff', info:'#8b8faa' }
const SEV_DIFFICULTY = { critical:'Expert', high:'Hard', medium:'Medium', low:'Easy', info:'Fundamental' }

// A mission is COMPLETE when its goal event fired (learning_success) OR the
// attack run finished (state === 'completed' — instructor/demo/auto execution
// that ran the module end to end). Otherwise it is ACTIVE once started, else
// IDLE. Both completion signals come straight from the backend session record.
function missionStatus(s) {
  if (s.learning_success || s.state === 'completed') return 'completed'
  if (s.state === 'running' || s.mission_started_at) return 'active'
  return 'idle'
}

const STATUS_META = {
  completed: { label: 'Complete',    color: '#2ee39a', Icon: CheckCircle2 },
  active:    { label: 'In progress', color: '#ff4060', Icon: Loader2 },
  idle:      { label: 'Idle',        color: '#6b7390', Icon: Circle },
}

function relTime(ts) {
  if (!ts) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function fmtDuration(sec) {
  if (!sec && sec !== 0) return null
  const m = Math.floor(sec / 60), s = sec % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

export default function Missions() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState([])
  const [catMap,   setCatMap]   = useState({})
  const [variantMap, setVariantMap] = useState({})  // module_id → { variant_id → {name,difficulty} }
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [filter,   setFilter]   = useState('all')

  useEffect(() => {
    let cancelled = false

    // Full load: sessions + module categories + variant names.
    async function loadAll() {
      const [s, mods] = await Promise.all([
        api.sessions.list().catch(() => []),
        api.modules().catch(() => []),
      ])
      if (cancelled) return
      const list = Array.isArray(s) ? s : []
      setSessions(list)
      const map = {}
      for (const m of (Array.isArray(mods) ? mods : [])) map[m.module_id] = m.category
      setCatMap(map)

      // Resolve variant names for each module that has a launched session.
      const moduleIds = [...new Set(list.map(x => x.module_id).filter(Boolean))]
      const lists = await Promise.all(moduleIds.map(mid =>
        api.variants(mid).then(r => r?.variants || r || []).catch(() => [])))
      if (cancelled) return
      const vmap = {}
      moduleIds.forEach((mid, i) => {
        vmap[mid] = {}
        for (const v of (Array.isArray(lists[i]) ? lists[i] : [])) vmap[mid][v.variant_id] = v
      })
      setVariantMap(vmap)
      setError(null)
      setLoading(false)
    }

    loadAll().catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })

    // Keep mission status live against the backend: re-poll the (cheap) session
    // list so a mission that completes elsewhere flips to Complete without a
    // manual reload. Also refresh when the tab regains focus.
    async function refreshSessions() {
      try {
        const s = await api.sessions.list()
        if (!cancelled && Array.isArray(s)) { setSessions(s); setError(null) }
      } catch { /* transient backend blip — keep last good state */ }
    }
    const interval = setInterval(refreshSessions, 5000)
    window.addEventListener('focus', refreshSessions)
    return () => {
      cancelled = true
      clearInterval(interval)
      window.removeEventListener('focus', refreshSessions)
    }
  }, [])

  const withStatus = sessions.map(s => ({ ...s, _status: missionStatus(s) }))
  const counts = {
    all:       withStatus.length,
    completed: withStatus.filter(s => s._status === 'completed').length,
    active:    withStatus.filter(s => s._status === 'active').length,
    idle:      withStatus.filter(s => s._status === 'idle').length,
  }
  const filtered = filter === 'all' ? withStatus : withStatus.filter(s => s._status === filter)
  const sorted = [...filtered].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
  const completionPct = counts.all > 0 ? Math.round((counts.completed / counts.all) * 100) : 0

  const FILTERS = [
    { key: 'all',       label: 'All' },
    { key: 'active',    label: 'In progress' },
    { key: 'completed', label: 'Complete' },
    { key: 'idle',      label: 'Idle' },
  ]

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      {/* Header */}
      <div className="flex flex-wrap justify-between items-end gap-4 mb-5">
        <div>
          <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Missions</h1>
          <p className="font-mono text-[11px] text-attense-dim mt-1">
            {counts.all} launched · {counts.active} in progress · {counts.completed} complete
          </p>
        </div>
        <button
          onClick={() => navigate('/modules')}
          className="inline-flex items-center gap-2 font-mono text-[10.5px] font-bold tracking-[0.14em] px-4 py-2 rounded-lg transition-all duration-150"
          style={{ background: 'linear-gradient(135deg,#ff1535,#cc0020)', color: 'white', boxShadow: '0 0 14px rgba(255,21,53,0.3)' }}
        >
          <Zap className="w-3.5 h-3.5" /> NEW MISSION
        </button>
      </div>

      {/* Completion summary bar — aggregate of all missions, not per-task progress */}
      {counts.all > 0 && (
        <div
          className="flex items-center gap-4 rounded-xl px-4 py-3 mb-5"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}
        >
          <Trophy size={16} style={{ color: completionPct === 100 ? '#2ee39a' : '#f5c400' }} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-mono text-[9px] tracking-[0.24em] text-attense-dim">MISSIONS COMPLETE</span>
              <span className="font-mono text-[10px] tabular-nums" style={{ color: completionPct === 100 ? '#2ee39a' : '#cfd6e8' }}>
                {counts.completed}/{counts.all} · {completionPct}%
              </span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div className="h-full rounded-full transition-all duration-700"
                style={{ width: completionPct + '%', background: completionPct === 100 ? '#2ee39a' : 'linear-gradient(90deg,#ff1535,#ff6b00)' }} />
            </div>
          </div>
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex flex-wrap gap-1.5 mb-5">
        {FILTERS.map(f => {
          const active = filter === f.key
          return (
            <button key={f.key} onClick={() => setFilter(f.key)}
              className="inline-flex items-center gap-2 font-mono text-[10px] tracking-[0.1em] px-3 py-1.5 rounded-lg transition-colors"
              style={{
                background: active ? 'rgba(255,21,53,0.1)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${active ? 'rgba(255,21,53,0.4)' : 'rgba(255,255,255,0.08)'}`,
                color: active ? '#ff6b81' : '#8b93a7',
              }}>
              {f.label}
              <span className="tabular-nums" style={{ opacity: 0.7 }}>{counts[f.key] ?? 0}</span>
            </button>
          )
        })}
      </div>

      {loading && <div className="py-14 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING MISSIONS…</div>}
      {error && (
        <div className="rounded-lg p-4 font-mono text-[11px]"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {!loading && !error && sorted.length > 0 && (
        <div className="grid gap-5" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(300px, 100%), 1fr))' }}>
          {sorted.map(s => {
            const color      = SEV_COLOR[s.severity]      || '#8b8faa'
            const variant    = variantMap[s.module_id]?.[s.variant_id]
            const variantName = variant?.name
            const difficulty = variant?.difficulty || SEV_DIFFICULTY[s.severity] || 'Fundamental'
            const status     = s._status
            const meta       = STATUS_META[status]
            const StatusIcon = meta.Icon
            const complete   = status === 'completed'
            const category   = catMap[s.module_id]
            const duration   = fmtDuration(s.learning_duration_s)

            return (
              <button
                key={s.session_id}
                onClick={() => navigate(`/workspace/${s.session_id}`)}
                className="group relative flex flex-col text-left rounded-2xl overflow-hidden transition-all duration-200 hover:-translate-y-1 focus:outline-none focus:ring-2 focus:ring-attense-red/40"
                style={{
                  background: '#0c0f16',
                  border: `1px solid ${complete ? 'rgba(46,227,154,0.35)' : 'rgba(255,255,255,0.07)'}`,
                }}
              >
                {/* Cover */}
                <div
                  className="relative flex items-center justify-center overflow-hidden"
                  style={{
                    aspectRatio: '16 / 9',
                    background: `radial-gradient(120% 90% at 50% 0%, ${(complete ? '#2ee39a' : color)}12, transparent 60%), #0a0d14`,
                  }}
                >
                  <div className="absolute inset-0 bg-grid opacity-60 transition-opacity duration-300 group-hover:opacity-100" style={{ backgroundSize: '22px 22px' }} />

                  {/* difficulty badge (top-left) */}
                  <span className="absolute top-3 left-3 z-10 inline-flex items-center rounded-md px-2 py-1 font-mono text-[9px] font-bold uppercase tracking-[0.18em]"
                    style={{ background: color + '1f', color, border: `1px solid ${color}40` }}>
                    {difficulty}
                  </span>

                  {/* status pill (top-right) */}
                  <span className="absolute top-3 right-3 z-10 inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-[9px] font-bold uppercase tracking-[0.14em]"
                    style={{ background: meta.color + '1f', color: meta.color, border: `1px solid ${meta.color}45` }}>
                    <StatusIcon size={11} strokeWidth={2.4} className={status === 'active' ? 'animate-spin' : ''} style={status === 'active' ? { animationDuration: '2s' } : undefined} />
                    {meta.label}
                  </span>

                  {/* glowing category icon */}
                  <div className="relative z-[1] flex items-center justify-center rounded-2xl transition-transform duration-300 group-hover:scale-110"
                    style={{
                      width: 78, height: 78,
                      background: `radial-gradient(circle at 50% 40%, ${(complete ? '#2ee39a' : color)}26, ${(complete ? '#2ee39a' : color)}08 70%)`,
                      color: complete ? '#2ee39a' : color,
                      filter: `drop-shadow(0 0 18px ${(complete ? '#2ee39a' : color)}55)`,
                    }}>
                    <CategoryIcon category={category} size={36} strokeWidth={1.4} />
                  </div>
                </div>

                {/* Body */}
                <div className="flex flex-col flex-1" style={{ padding: '14px 18px 14px' }}>
                  <div className="font-mono text-[9px] tracking-[0.2em] text-attense-dim uppercase mb-1">
                    {s.scenario_id || category || 'Mission'}
                  </div>
                  <div className="text-[15px] font-bold leading-snug text-attense-text transition-colors group-hover:text-white">
                    {s.module_name || s.module_id}
                  </div>
                  {/* Variant — distinguishes two runs of the same module. */}
                  {variantName && (
                    <span className="inline-flex items-center gap-1.5 self-start mt-2 rounded-md px-2 py-0.5 font-mono text-[9.5px] font-semibold"
                      style={{ background: color + '14', color, border: `1px solid ${color}33` }}>
                      <span style={{ opacity: 0.7 }}>▸</span> {variantName}
                    </span>
                  )}

                  {/* footer meta */}
                  <div className="flex items-center gap-3 mt-auto pt-4 border-t border-white/[0.06]">
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-attense-dim">
                      <Clock size={11} strokeWidth={2} /> {relTime(s.created_at)}
                    </span>
                    {complete && duration && (
                      <>
                        <span className="text-attense-border">|</span>
                        <span className="inline-flex items-center gap-1 font-mono text-[10px]" style={{ color: '#2ee39a' }}>
                          {duration}
                        </span>
                      </>
                    )}
                    <ChevronRight size={18} strokeWidth={2.5}
                      className="ml-auto transition-all duration-200 group-hover:translate-x-1"
                      style={{ color: complete ? '#2ee39a' : color }} />
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      )}

      {!loading && !error && sorted.length === 0 && (
        <div className="py-14 text-center">
          <div className="font-mono text-[11px] text-attense-dim mb-3">
            {filter === 'all' ? 'No missions launched yet.' : `No ${filter} missions.`}
          </div>
          {filter === 'all' && (
            <button onClick={() => navigate('/modules')}
              className="inline-flex items-center gap-2 font-mono text-[10.5px] font-bold tracking-[0.14em] px-4 py-2 rounded-lg"
              style={{ background: 'linear-gradient(135deg,#ff1535,#cc0020)', color: 'white' }}>
              <Zap className="w-3.5 h-3.5" /> LAUNCH YOUR FIRST MISSION
            </button>
          )}
        </div>
      )}
    </div>
  )
}
