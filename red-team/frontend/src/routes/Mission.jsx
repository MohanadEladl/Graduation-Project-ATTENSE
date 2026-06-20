import { useEffect, useState } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { SeverityBadge, CATEGORY_ICON } from '../components/SeverityBadge.jsx'
import { TaskAccordion } from '../components/TaskAccordion.jsx'
import { briefingFor } from '../data/missionBriefings.js'

export default function Mission() {
  const { moduleId } = useParams()
  const navigate = useNavigate()
  const [module, setModule] = useState(null)
  const [target, setTarget] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [launching, setLaunching] = useState(false)
  const [resumable, setResumable] = useState(null)

  const startLab = async () => {
    if (!module || launching) return
    setLaunching(true)
    try {
      const session = await api.sessions.create(module.module_id)
      navigate(`/workspace/${session.session_id}`)
    } catch (e) {
      setError(e.message)
      setLaunching(false)
    }
  }

  const resume = () => {
    if (resumable?.session_id) navigate(`/workspace/${resumable.session_id}`)
  }

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.modules(),
      api.target().catch(() => null),
      api.sessions.list(moduleId).catch(() => []),
    ])
      .then(([mods, tgt, sessions]) => {
        if (cancelled) return
        const m = mods.find(x => x.module_id === moduleId)
        if (!m) setError(`Unknown mission: ${moduleId}`)
        else setModule(m)
        setTarget(tgt)
        // Resume the most recent non-errored session for this module.
        const rank = (s) => s.state === 'running' ? 3 : s.state === 'completed' ? 2 : s.state === 'idle' ? 1 : 0
        const candidates = (sessions || [])
          .filter(s => s.state !== 'error')
          .sort((a, b) => rank(b) - rank(a) || (b.created_at || 0) - (a.created_at || 0))
        setResumable(candidates[0] || null)
        setLoading(false)
      })
      .catch(err => { if (!cancelled) { setError(err.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [moduleId])

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
  const briefing = briefingFor(module.module_id)

  // Prefer module.lab.learner_steps (from the Python module) → richest guidance.
  // Fall back to briefing.steps (from missionBriefings.js) → still learner-oriented.
  // Last resort: module.steps (engine steps) → internal/technical.
  const labSteps = module.lab?.learner_steps
  let stepsForAccordion
  if (Array.isArray(labSteps) && labSteps.length > 0) {
    stepsForAccordion = labSteps.map(s => ({
      title: s.action || s.title || 'Step',
      hint:  '', // keep accordion clean — the expected outcome is in 'expected'
      command: s.command || '',
      technique: s.technique || '',
      expected: s.expected || '',
    }))
  } else {
    stepsForAccordion = (briefing.steps || []).map(s => ({
      title: s,
      hint: '',
      expected: '',
    }))
  }
  if (stepsForAccordion.length === 0) stepsForAccordion = module.steps || []
  const stepCount = stepsForAccordion.length
  const estMinutes = Math.max(5, stepCount * 3)

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
            <div className="flex items-start gap-5">
              <div className="w-16 h-16 rounded-lg border border-attense-red/50 bg-attense-bg grid place-items-center text-attense-red text-3xl shadow-glow-red shrink-0">
                {icon}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] font-mono tracking-[0.28em] text-attense-muted">
                    {module.scenario_id || '—'}
                  </span>
                  <span className="text-attense-dim">·</span>
                  <span className="text-[10px] font-mono tracking-[0.28em] text-attense-muted">
                    {(module.category || 'UNKNOWN').toUpperCase()}
                  </span>
                </div>
                <h1 className="text-[26px] font-semibold tracking-tight text-attense-text mb-2">
                  {module.name}
                </h1>
                <p className="text-[13.5px] text-attense-muted leading-relaxed max-w-2xl">
                  {module.description}
                </p>

                {/* MITRE ATT&CK technique chips */}
                {Array.isArray(module.mitre?.techniques) && module.mitre.techniques.length > 0 && (
                  <div className="mt-4">
                    <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-2">
                      MITRE ATT&CK
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {module.mitre.techniques.map(t => (
                        <a
                          key={t.id}
                          href={`https://attack.mitre.org/techniques/${(t.id || '').replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer"
                          title={t.tactic ? `${t.tactic} — ${t.name}` : t.name}
                          className="inline-flex items-center gap-1.5 rounded-md border border-attense-red/30 bg-attense-red/5 px-2.5 py-1
                                     font-mono text-[10px] text-attense-text hover:border-attense-red/60 hover:bg-attense-red/10 transition-colors"
                        >
                          <span className="font-semibold text-attense-red">{t.id}</span>
                          <span className="text-attense-muted truncate max-w-[180px]">{t.name}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <SeverityBadge severity={module.severity} className="shrink-0" />
            </div>

            {/* Stats row */}
            <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3">
              <Stat label="TASKS" value={stepCount} />
              <Stat label="EST. TIME" value={`${estMinutes} min`} />
              <Stat label="TARGET PAGE" value={module.lab?.target_path || '/'} mono />
              <Stat label="SEVERITY" value={(module.severity || 'info').toUpperCase()} />
            </div>

            {/* CTA */}
            <div className="mt-6 flex items-center gap-3">
              {resumable ? (
                <>
                  <button
                    onClick={resume}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md
                               bg-attense-red text-white font-mono text-[12px] tracking-[0.2em] font-semibold
                               hover:bg-attense-redSoft transition-colors shadow-glow-red"
                  >
                    RESUME MISSION →
                  </button>
                  <span className="text-[10px] font-mono text-attense-dim tracking-wider">
                    {(resumable.completed_steps?.length ?? 0)}/{resumable.total_steps} steps · {(resumable.state || 'idle').toUpperCase()}
                  </span>
                  <button
                    onClick={startLab}
                    disabled={launching}
                    className="ml-2 inline-flex items-center gap-2 px-3 py-2 rounded-md border border-attense-border
                               text-attense-muted font-mono text-[10.5px] tracking-[0.2em]
                               hover:border-attense-red/40 hover:text-attense-text transition-colors
                               disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {launching ? 'LAUNCHING…' : 'NEW SESSION'}
                  </button>
                </>
              ) : (
                <button
                  onClick={startLab}
                  disabled={launching}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md
                             bg-attense-red text-white font-mono text-[12px] tracking-[0.2em] font-semibold
                             hover:bg-attense-redSoft transition-colors shadow-glow-red
                             disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {launching ? 'LAUNCHING…' : 'START LAB →'}
                </button>
              )}
              <span className="ml-auto text-[10px] font-mono text-attense-dim tracking-wider">
                SANDBOXED LAB · NO EXTERNAL ACCESS
              </span>
            </div>
          </div>
        </section>

        {/* Tasks */}
        <section>
          <div className="flex items-end justify-between mb-4">
            <div>
              <div className="text-[10px] font-mono tracking-[0.32em] text-attense-muted mb-1">
                TUTORIAL STEPS
              </div>
              <h2 className="text-[18px] font-semibold text-attense-text">
                Interact with the vulnerable app.
              </h2>
            </div>
            <div className="text-[10.5px] font-mono text-attense-dim">
              {stepCount} STEP{stepCount === 1 ? '' : 'S'}
            </div>
          </div>

          <TaskAccordion steps={stepsForAccordion} />
        </section>

        <div className="h-12" />
      </div>
    </div>
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
