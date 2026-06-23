import { useEffect, useState } from 'react'

const STATE_STYLE = {
  idle:      { color: 'text-attense-muted',  dot: '#4a5363', label: 'IDLE' },
  running:   { color: 'text-attense-amber',  dot: '#ffa724', label: 'RUNNING' },
  completed: { color: 'text-attense-mint',   dot: '#2ee39a', label: 'COMPLETED' },
  error:     { color: 'text-attense-red',    dot: '#ff2b3a', label: 'ERROR' },
}

export function StatusPanel({ session }) {
  // Keep a ticking clock when the session is running so "elapsed" refreshes
  const [, force] = useState(0)
  useEffect(() => {
    if (!session || session.state !== 'running') return
    const id = setInterval(() => force(n => n + 1), 1000)
    return () => clearInterval(id)
  }, [session])

  if (!session) {
    return (
      <div className="px-4 py-3">
        <div className="text-[9px] font-mono tracking-[0.32em] text-attense-muted mb-2">SESSION</div>
        <div className="rounded-md border border-dashed border-attense-border/70 bg-transparent p-4 text-center">
          <div className="text-[11px] font-mono text-attense-dim">no active session</div>
          <div className="text-[10px] font-mono text-attense-dim mt-1">
            start a <span className="text-attense-red">lab mission</span> to begin
          </div>
        </div>
      </div>
    )
  }

  const st = STATE_STYLE[session.state] || STATE_STYLE.idle
  const result = session.result

  return (
    <div className="px-4 py-3 animate-fade-in">
      <div className="text-[9px] font-mono tracking-[0.32em] text-attense-muted mb-2">SESSION</div>
      <div className="rounded-md border border-attense-border bg-attense-panel/60 p-3 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[12px] font-semibold truncate">
            {session.module_name}
          </span>
          <span className={'flex items-center gap-1.5 text-[10px] font-mono tracking-widest ' + st.color}>
            <span className="dot" style={{ color: st.dot }} />
            {st.label}
          </span>
        </div>

        <div className="h-px bg-attense-border" />

        <Field k="module" v={session.module_id} />
        <Field k="started" v={session.started_at || '—'} />
        {session.stopped_at && <Field k="ended" v={session.stopped_at} />}
        <Field k="elapsed" v={session.elapsed || '—'} />

        {result && (
          <>
            <div className="h-px bg-attense-border my-2" />
            <div className="grid grid-cols-2 gap-2">
              <Stat label="steps ok" value={`${result.successful_steps}/${result.total_steps}`} />
              <Stat label="duration" value={`${Math.round(result.duration_ms)}ms`} />
            </div>
            {result.summary && (
              <div className="mt-1 pt-2 border-t border-attense-border/60">
                <div className="text-[9px] font-mono tracking-[0.32em] text-attense-muted mb-1">SUMMARY</div>
                <div className="text-[11px] font-mono text-attense-text leading-snug">
                  {result.summary}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function Field({ k, v }) {
  return (
    <div className="flex items-center justify-between text-[11px] font-mono">
      <span className="text-attense-muted uppercase tracking-wider">{k}</span>
      <span className="text-attense-text truncate max-w-[170px]" title={String(v)}>{v}</span>
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div className="rounded border border-attense-border bg-attense-bg/50 px-2.5 py-1.5">
      <div className="text-[9px] font-mono tracking-widest text-attense-muted">{label}</div>
      <div className="text-[13px] font-mono font-semibold text-attense-red">{value}</div>
    </div>
  )
}
