import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { CategoryIcon } from '../components/SeverityBadge.jsx'
import { ChevronRight, BarChart3, Layers, GraduationCap, BookOpen } from 'lucide-react'

export default function Modules() {
  const navigate  = useNavigate()
  const [modules, setModules]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [error,   setError]     = useState(null)
  const [launching, setLaunching] = useState(null)
  const [query,   setQuery]     = useState('')
  const [category, setCategory] = useState('ALL')

  useEffect(() => {
    api.modules()
      .then(m => { setModules(m); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  const visible = modules.filter(m => {
    const q = query.trim().toLowerCase()
    if (category !== 'ALL' && m.category !== category) return false
    if (!q) return true
    return m.name?.toLowerCase().includes(q) || m.module_id?.toLowerCase().includes(q)
  })

  const launch = (mod) => {
    navigate(`/mission/${mod.module_id}`)
  }

  const SEV_COLOR = { critical:'#ff1535', high:'#ff6b00', medium:'#f5c400', low:'#00c8ff', info:'#8b8faa' }
  const SEV_DIFFICULTY = { critical:'Expert', high:'Hard', medium:'Medium', low:'Easy', info:'Fundamental' }
  const SEV_TIER = { critical:'Tier IV', high:'Tier III', medium:'Tier II', low:'Tier I', info:'Tier 0' }

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="mb-6">
        <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Lab Modules</h1>
        <p className="font-mono text-[11px] text-attense-dim mt-1">
          {modules.length} modules loaded · choose a lab to start learning
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search modules…"
          className="ml-auto font-mono text-[11.5px] text-attense-text rounded-lg px-3 py-1.5"
          style={{
            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
            outline: 'none', width: 220,
          }}
          onFocus={e => e.target.style.borderColor = 'rgba(255,21,53,0.4)'}
          onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
        />
      </div>

      {error && (
        <div className="rounded-lg p-4 font-mono text-[11px] mb-4"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {loading ? (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING MODULES…</div>
      ) : (
        <div className="grid gap-5" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(290px, 100%), 1fr))' }}>
          {visible.map(m => {
            const color      = SEV_COLOR[m.severity]      || '#8b8faa'
            const difficulty = SEV_DIFFICULTY[m.severity] || 'Fundamental'
            const tier       = SEV_TIER[m.severity]       || 'Tier 0'
            const steps      = m.steps?.length ?? 0
            return (
              <button
                key={m.module_id}
                onClick={() => launch(m)}
                className="group flex flex-col text-left rounded-2xl border border-white/[0.07] overflow-hidden transition-all duration-200 hover:border-white/[0.16] hover:-translate-y-1 focus:outline-none focus:ring-2 focus:ring-attense-red/40"
                style={{ background: '#0c0f16' }}
              >
                {/* Illustration / cover */}
                <div
                  className="relative flex items-center justify-center overflow-hidden"
                  style={{
                    aspectRatio: '16 / 10',
                    background: `radial-gradient(120% 90% at 50% 0%, ${color}10, transparent 60%), #0a0d14`,
                  }}
                >
                  {/* circuit grid */}
                  <div
                    className="absolute inset-0 bg-grid opacity-60 transition-opacity duration-300 group-hover:opacity-100"
                    style={{ backgroundSize: '22px 22px' }}
                  />
                  {/* status badge */}
                  <span
                    className="absolute top-3 left-3 z-10 inline-flex items-center rounded-md px-2 py-1 font-mono text-[9px] font-bold uppercase tracking-[0.18em]"
                    style={{ background: color + '1f', color, border: `1px solid ${color}40` }}
                  >
                    {difficulty}
                  </span>
                  {/* glowing category icon */}
                  <div
                    className="relative z-[1] flex items-center justify-center rounded-2xl transition-transform duration-300 group-hover:scale-110"
                    style={{
                      width: 86, height: 86,
                      background: `radial-gradient(circle at 50% 40%, ${color}26, ${color}08 70%)`,
                      color,
                      filter: `drop-shadow(0 0 18px ${color}55)`,
                    }}
                  >
                    <CategoryIcon category={m.category} size={40} strokeWidth={1.4} />
                  </div>
                </div>

                {/* Body */}
                <div className="flex flex-col flex-1" style={{ padding: '16px 18px 14px' }}>
                  {/* tag row */}
                  <div className="flex items-center gap-4 mb-2">
                    <span className="inline-flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em]" style={{ color }}>
                      <BookOpen size={12} strokeWidth={2} /> Lab
                    </span>
                    <span className="inline-flex items-center gap-1.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-attense-muted">
                      <GraduationCap size={12} strokeWidth={2} /> {m.category}
                    </span>
                  </div>

                  {/* title */}
                  <div className="text-[15.5px] font-bold leading-snug text-attense-text transition-colors group-hover:text-white">
                    {m.name}
                  </div>
                  <div className="font-mono text-[9px] tracking-[0.2em] text-attense-dim uppercase mt-1">{m.scenario_id}</div>

                  {/* footer meta */}
                  <div className="flex items-center gap-3 mt-auto pt-4 border-t border-white/[0.06]">
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-attense-dim">
                      <BarChart3 size={12} strokeWidth={2} /> {difficulty}
                    </span>
                    <span className="text-attense-border">|</span>
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-attense-dim">
                      {steps} steps
                    </span>
                    <span className="text-attense-border">|</span>
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-attense-dim">
                      <Layers size={12} strokeWidth={2} /> {tier}
                    </span>
                    <ChevronRight
                      size={18} strokeWidth={2.5}
                      className="ml-auto text-attense-dim transition-all duration-200 group-hover:translate-x-1"
                      style={{ color }}
                    />
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      )}

      {!loading && visible.length === 0 && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">No modules match that filter.</div>
      )}
    </div>
  )
}
