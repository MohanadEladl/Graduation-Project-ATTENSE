import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client.js'
import { StatCard } from '../components/StatCard.jsx'

function Field({ label, value, set, placeholder, type = 'text', disabled }) {
  return (
    <div className="mb-4">
      <label className="font-mono text-[10px] tracking-[0.14em] text-attense-dim block mb-1.5">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => set(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full font-mono text-[12px] text-attense-text rounded-lg px-3 py-2.5 disabled:opacity-40"
        style={{
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.1)',
          outline: 'none',
        }}
        onFocus={e => e.target.style.borderColor = 'rgba(255,21,53,0.45)'}
        onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
      />
    </div>
  )
}

function Toggle({ label, value, set, disabled }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <span className="font-mono text-[11px] text-attense-dim">{label}</span>
      <div
        onClick={() => !disabled && set(!value)}
        className="relative transition-all duration-200"
        style={{
          width: 36, height: 20, borderRadius: 10,
          background: value ? '#ff1535' : 'rgba(255,255,255,0.08)',
          cursor: disabled ? 'not-allowed' : 'pointer',
          boxShadow: value ? '0 0 8px rgba(255,21,53,0.4)' : 'none',
        }}
      >
        <div style={{
          position: 'absolute', top: 3,
          left: value ? 18 : 3,
          width: 14, height: 14, borderRadius: '50%',
          background: 'white',
          transition: 'left 0.2s',
        }} />
      </div>
    </div>
  )
}

export default function Settings() {
  const [target, setTargetState] = useState({ host: 'target-agent', port: 80, timeout: 10, use_https: false })
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)

  // Lab overview data
  const [modules,  setModules]  = useState([])
  const [sessions, setSessions] = useState([])

  useEffect(() => {
    api.target().then(t => {
      if (t) setTargetState(t)
      setLoading(false)
    }).catch(() => setLoading(false))

    // Fetch lab stats
    Promise.all([
      api.modules().catch(() => []),
      api.sessions.list().catch(() => []),
    ]).then(([m, s]) => {
      setModules(Array.isArray(m) ? m : [])
      setSessions(Array.isArray(s) ? s : [])
    })
  }, [])

  const completed = sessions.filter(s => s.learning_success)
  const running   = sessions.filter(s => s.mission_started_at && !s.learning_success)

  const todayStart = useMemo(() => {
    const d = new Date(); d.setHours(0,0,0,0); return d.getTime() / 1000
  }, [])

  const completedToday = completed.filter(s => {
    const t = s.learning_completed_at || s.created_at || 0
    return t >= todayStart
  }).length

  const successRate = useMemo(() => {
    const started = sessions.filter(s => s.mission_started_at || s.learning_progress_percent > 0)
    if (!started.length) return 0
    return Math.round(started.reduce((n, s) => n + (s.learning_progress_percent || 0), 0) / started.length)
  }, [sessions])

  const save = async () => {
    setSaving(true); setError(null)
    try {
      localStorage.setItem('attense_target', JSON.stringify(target))
      await new Promise(r => setTimeout(r, 400))
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const panel = (title, children) => (
    <div
      className="glass-card rounded-xl mb-5 overflow-hidden"
      style={{ padding: '18px 22px' }}
    >
      <div className="font-mono text-[9.5px] tracking-[0.22em] font-bold mb-4"
        style={{ color: '#ff4060' }}>
        {title}
      </div>
      {children}
    </div>
  )

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="mb-6">
        <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Settings</h1>
        <p className="font-mono text-[11px] text-attense-dim mt-1">Target configuration & preferences</p>
      </div>

      <div className="max-w-lg">
        {/* ── Lab Overview ── */}
        <div
          className="glass-card rounded-xl mb-5 overflow-hidden"
          style={{ padding: '18px 22px' }}
        >
          <div className="font-mono text-[9.5px] tracking-[0.22em] font-bold mb-4"
            style={{ color: '#ff4060' }}>
            LAB OVERVIEW
          </div>
          <div className="grid grid-cols-2 gap-3">
            <StatCard
              label="Active Missions"
              numericValue={running.length}
              suffix=""
              sub={`${running.length} module${running.length === 1 ? '' : 's'} running`}
              color="#ff1535"
              index={0}
              icon={
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
              }
            />
            <StatCard
              label="Completed Today"
              numericValue={completedToday}
              suffix=""
              sub="missions finished"
              color="#00c8ff"
              index={1}
              icon={
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              }
            />
            <StatCard
              label="Lab Modules"
              numericValue={modules.length}
              suffix=""
              sub="scenarios loaded"
              color="#8b2fff"
              index={2}
              icon={
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>
                </svg>
              }
            />
            <StatCard
              label="Success Rate"
              numericValue={successRate}
              suffix="%"
              sub="steps passed"
              color="#f5c400"
              index={3}
              icon={
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                </svg>
              }
            />
          </div>
        </div>

        {loading ? (
          <div className="py-10 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING…</div>
        ) : (
          <>
            {panel('TARGET CONFIG', <>
              <Field
                label="HOST"
                value={target.host}
                set={v => setTargetState(p => ({ ...p, host: v }))}
                placeholder="target-agent"
                disabled={saving}
              />
              <Field
                label="PORT"
                value={String(target.port)}
                set={v => setTargetState(p => ({ ...p, port: Number(v.replace(/\D/g, '')) || 80 }))}
                placeholder="80"
                type="text"
                disabled={saving}
              />
              <Field
                label="TIMEOUT (seconds)"
                value={String(target.timeout ?? 10)}
                set={v => setTargetState(p => ({ ...p, timeout: Number(v.replace(/\D/g, '')) || 10 }))}
                placeholder="10"
                disabled={saving}
              />
              <Toggle
                label="Use HTTPS"
                value={target.use_https ?? false}
                set={v => setTargetState(p => ({ ...p, use_https: v }))}
                disabled={saving}
              />
            </>)}

            {panel('INTERFACE', <>
              <div className="mb-3">
                <div className="font-mono text-[10px] tracking-[0.14em] text-attense-dim mb-2">API BASE URL</div>
                <div className="font-mono text-[11.5px] text-attense-muted px-3 py-2 rounded-lg"
                  style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                  {window.location.origin}
                </div>
              </div>
              <div className="font-mono text-[10px] text-attense-dim leading-relaxed">
                Vite proxies <span className="text-attense-muted">/api</span> and{' '}
                <span className="text-attense-muted">/ws</span> to the backend in dev mode.
                In production nginx handles routing.
              </div>
            </>)}

            {error && (
              <div className="rounded-lg px-4 py-3 font-mono text-[11px] mb-4"
                style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
                {error}
              </div>
            )}

            <button
              onClick={save}
              disabled={saving}
              className="w-full font-mono text-[11px] font-bold tracking-[0.1em] py-2.5 rounded-lg transition-all"
              style={{
                background: saved
                  ? 'rgba(46,227,154,0.1)'
                  : saving
                    ? 'rgba(255,255,255,0.04)'
                    : 'rgba(255,21,53,0.1)',
                border: `1px solid ${saved ? 'rgba(46,227,154,0.3)' : saving ? 'rgba(255,255,255,0.08)' : 'rgba(255,21,53,0.3)'}`,
                color: saved ? '#2ee39a' : saving ? '#3a4060' : '#ff4060',
                cursor: saving ? 'not-allowed' : 'pointer',
              }}
            >
              {saving ? 'SAVING…' : saved ? '✓ SAVED' : 'SAVE CONFIG'}
            </button>
          </>
        )}
      </div>
    </div>
  )
}
