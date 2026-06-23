import { useEffect, useMemo, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { api } from '../api/client.js'
import { CATEGORY_ICON } from '../components/SeverityBadge.jsx'

const DIFF_COLOR = { Easy: '#2ee39a', Medium: '#facc15', Hard: '#ff4060' }
const DIFF_MIN   = { Easy: 8, Medium: 12, Hard: 18 }

function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return r ? `${parseInt(r[1], 16)},${parseInt(r[2], 16)},${parseInt(r[3], 16)}` : '255,255,255'
}

export default function Mission() {
  const { moduleId } = useParams()
  const navigate = useNavigate()
  const [module, setModule] = useState(null)
  const [variants, setVariants] = useState([])
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [launching, setLaunching] = useState(null)   // variant_id currently launching

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.modules(),
      api.variants(moduleId).catch(() => ({ variants: [] })),
      api.sessions.list(moduleId).catch(() => []),
    ])
      .then(([mods, varResp, sess]) => {
        if (cancelled) return
        const m = mods.find(x => x.module_id === moduleId)
        if (!m) setError(`Unknown mission: ${moduleId}`)
        else setModule(m)
        setVariants(varResp?.variants || [])
        setSessions(sess || [])
        setLoading(false)
      })
      .catch(err => { if (!cancelled) { setError(err.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [moduleId])

  // Most recent non-errored session for a given variant (per-variant resume).
  const resumableFor = useMemo(() => {
    const rank = (s) => s.state === 'running' ? 3 : s.state === 'completed' ? 2 : s.state === 'idle' ? 1 : 0
    return (variantId) => {
      const candidates = (sessions || [])
        .filter(s => s.state !== 'error')
        .filter(s => (s.variant_id || null) === (variantId || null))
        .sort((a, b) => rank(b) - rank(a) || (b.created_at || 0) - (a.created_at || 0))
      return candidates[0] || null
    }
  }, [sessions])

  const launch = async (variant) => {
    if (!module || launching) return
    const vid = variant?.variant_id || null
    // If there's an existing session for this exact variant, resume it instead.
    const existing = resumableFor(vid)
    if (existing?.session_id) {
      navigate(`/workspace/${existing.session_id}`)
      return
    }
    setLaunching(vid || '__default__')
    try {
      const session = await api.sessions.create(module.module_id)
      if (vid) {
        try { await api.sessions.setVariant(session.session_id, vid) } catch { /* non-fatal */ }
      }
      navigate(`/workspace/${session.session_id}`)
    } catch (e) {
      setError(e.message)
      setLaunching(null)
    }
  }

  if (loading) {
    return <div className="p-12 text-center text-attense-muted font-mono text-xs tracking-widest">LOADING MISSION…</div>
  }
  if (error) {
    return (
      <div className="p-6 max-w-3xl mx-auto">
        <div className="rounded border border-attense-red/40 bg-attense-red/10 text-attense-red font-mono text-xs p-4">
          {error}
        </div>
        <Link to="/" className="inline-block mt-4 text-attense-muted hover:text-attense-red font-mono text-xs">
          ← Back to missions
        </Link>
      </div>
    )
  }
  if (!module) return null

  const icon = CATEGORY_ICON[module.category] || '▪'

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl px-6 py-8">
        <Link to="/" className="inline-flex items-center gap-1 text-[11px] font-mono text-attense-muted hover:text-attense-red transition-colors mb-5">
          ← ALL MISSIONS
        </Link>

        {/* Hero */}
        <section className="relative rounded-xl border border-attense-border bg-attense-panel/60 overflow-hidden mb-8">
          <div className="absolute inset-0 pointer-events-none opacity-[0.08] bg-grid bg-[length:32px_32px]" />
          <div className="absolute top-0 right-0 w-56 h-56 rounded-full bg-attense-red/5 blur-3xl pointer-events-none" />

          <div className="relative p-7">
            <div className="flex items-center gap-5">
              <div className="w-16 h-16 rounded-lg border border-attense-red/50 bg-attense-bg grid place-items-center text-attense-red text-3xl shadow-glow-red shrink-0">
                {icon}
              </div>
              <h1 className="text-[26px] font-semibold tracking-tight text-attense-text">
                {module.name}
              </h1>
            </div>

            {/* Stats row */}
            <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3">
              <Stat label="ATTACK VARIANTS" value={variants.length || 1} />
              <Stat label="TARGET PAGE" value={module.lab?.target_path || '/'} mono />
              <Stat label="SEVERITY" value={(module.severity || 'info').toUpperCase()} />
              <Stat label="CATEGORY" value={(module.category || 'unknown').toUpperCase()} />
            </div>
          </div>
        </section>

        {/* Variant labs */}
        <section>
          <div className="flex items-end justify-between mb-4">
            <div>
              <div className="text-[10px] font-mono tracking-[0.32em] text-attense-muted mb-1">
                CHOOSE YOUR ATTACK
              </div>
              <h2 className="text-[18px] font-semibold text-attense-text">
                Each variant is its own hands-on lab.
              </h2>
            </div>
            <div className="text-[10.5px] font-mono text-attense-dim">
              {variants.length || 1} LAB{(variants.length || 1) === 1 ? '' : 'S'}
            </div>
          </div>

          {variants.length > 0 ? (
            <div className="grid gap-3 md:grid-cols-2">
              {variants.map((v, idx) => (
                <VariantCard
                  key={v.variant_id}
                  index={idx}
                  variant={v}
                  resumable={resumableFor(v.variant_id)}
                  launching={launching === v.variant_id}
                  onLaunch={() => launch(v)}
                />
              ))}
            </div>
          ) : (
            // Module with no variants — single lab fallback.
            <button
              onClick={() => launch(null)}
              disabled={launching}
              className="w-full rounded-lg border border-attense-border bg-attense-panel/40 hover:border-attense-red/40
                         px-5 py-6 text-left transition-colors disabled:opacity-60"
            >
              <div className="text-[14px] font-semibold text-attense-text mb-1">Start the lab</div>
              <div className="text-[12px] text-attense-muted">
                {launching ? 'Launching…' : 'Open the sandboxed environment and begin the attack.'}
              </div>
            </button>
          )}
        </section>

        <div className="h-12" />
      </div>
    </div>
  )
}

function VariantCard({ index, variant, resumable, launching, onLaunch }) {
  const col = DIFF_COLOR[variant.difficulty] || '#8b8faa'
  const est = DIFF_MIN[variant.difficulty] || 10
  const done = resumable?.completed_steps?.length ?? 0
  const total = resumable?.total_steps ?? 0
  const state = (resumable?.state || '').toUpperCase()

  return (
    <motion.button
      onClick={onLaunch}
      disabled={launching}
      whileHover={{ y: -3 }}
      whileTap={{ scale: 0.99 }}
      className="group relative text-left rounded-xl overflow-hidden disabled:opacity-70 disabled:cursor-wait"
      style={{
        background: '#0c0f16',
        border: `1px solid ${resumable ? col + '44' : 'rgba(255,255,255,0.07)'}`,
      }}
    >
      {/* difficulty accent bar */}
      <span className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: col }} />
      {/* soft glow on hover */}
      <span
        className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity"
        style={{ background: `rgba(${hexToRgb(col)},0.16)` }}
      />

      <div className="relative p-5 pl-6">
        <div className="flex items-center gap-3 mb-2">
          <span
            className="grid place-items-center w-7 h-7 rounded-md font-mono text-[12px] font-bold shrink-0"
            style={{ background: `${col}1a`, border: `1px solid ${col}40`, color: col }}
          >
            {index + 1}
          </span>
          <span className="text-[15px] font-semibold text-attense-text group-hover:text-white transition-colors">
            {variant.name}
          </span>
          <span
            className="ml-auto font-mono text-[8.5px] font-bold tracking-[0.18em] px-2 py-0.5 rounded uppercase"
            style={{ background: `${col}14`, border: `1px solid ${col}40`, color: col }}
          >
            {variant.difficulty || 'MED'}
          </span>
        </div>

        {/* the small, simple meaning of this variation */}
        <p className="text-[12.5px] leading-relaxed text-attense-muted min-h-[34px]">
          {variant.description}
        </p>

        <div className="mt-4 pt-3 border-t border-white/[0.06] flex items-center gap-3">
          <span className="font-mono text-[10px] text-attense-dim">~{est} MIN</span>
          {resumable && total > 0 && (
            <>
              <span className="text-attense-border">·</span>
              <span className="font-mono text-[10px]" style={{ color: col }}>
                {done}/{total} · {state}
              </span>
            </>
          )}
          <span
            className="ml-auto font-mono text-[11px] font-semibold tracking-[0.16em] inline-flex items-center gap-1.5 transition-transform group-hover:translate-x-1"
            style={{ color: col }}
          >
            {launching ? 'LAUNCHING…' : resumable ? 'RESUME →' : 'START LAB →'}
          </span>
        </div>
      </div>
    </motion.button>
  )
}

function Stat({ label, value, mono }) {
  return (
    <div className="rounded-md border border-attense-border bg-attense-bg/40 px-4 py-3">
      <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-1">{label}</div>
      <div className={(mono ? 'font-mono ' : 'font-sans font-semibold ') + 'text-[14px] text-attense-text truncate'}>
        {value}
      </div>
    </div>
  )
}
