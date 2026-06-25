import { useEffect, useState } from 'react'
import { api } from '../api/client.js'

const SEVERITY_COLOR = {
  critical: 'text-attense-violet border-attense-violet/40',
  high:     'text-attense-red    border-attense-red/40',
  medium:   'text-attense-amber  border-attense-amber/40',
  low:      'text-attense-mint   border-attense-mint/40',
  info:     'text-attense-muted  border-attense-border',
}

const CATEGORY_ICON = {
  'Reconnaissance':    '⊕',
  'Authentication':    '✦',
  'Injection':         '⎇',
  'Web Application':   '◉',
  'File System':       '⌘',
}

export function ModuleList({ onUse, activeId }) {
  const [modules, setModules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  useEffect(() => {
    let cancelled = false
    api.modules()
      .then(m => { if (!cancelled) { setModules(m); setLoading(false) } })
      .catch(err => { if (!cancelled) { setError(err.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [])

  if (loading) {
    return (
      <div className="p-4 text-xs text-attense-muted font-mono tracking-wider">
        LOADING MODULES…
      </div>
    )
  }
  if (error) {
    return (
      <div className="p-4 text-xs text-attense-red font-mono">
        ERROR: {error}
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-1.5 p-3">
      {modules.map(m => {
        const sev   = m.severity?.toLowerCase?.() || 'info'
        const sevC  = SEVERITY_COLOR[sev] || SEVERITY_COLOR.info
        const icon  = CATEGORY_ICON[m.category] || '▪'
        const isActive = activeId === m.module_id
        return (
          <button
            key={m.module_id}
            onClick={() => onUse?.(m.module_id)}
            className={
              'group text-left relative rounded-md border px-3 py-2.5 ' +
              'bg-attense-panel/60 backdrop-blur ' +
              'transition-all duration-200 ' +
              (isActive
                ? 'border-attense-red shadow-glow-red '
                : 'border-attense-border hover:border-attense-red/50 hover:bg-attense-panel2 ')
            }
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className={'text-base leading-none ' + (isActive ? 'text-attense-red' : 'text-attense-dim group-hover:text-attense-red/70')}>
                  {icon}
                </span>
                <span className="font-mono text-[12px] font-semibold tracking-wide truncate">
                  {m.module_id}
                </span>
              </div>
              <span className={'text-[9px] uppercase tracking-[0.18em] px-1.5 py-0.5 rounded border font-mono ' + sevC}>
                {sev}
              </span>
            </div>
            <div className="mt-1 flex items-center justify-between gap-2 text-[10.5px] font-mono">
              <span className="text-attense-muted truncate">{m.name}</span>
              <span className="text-attense-dim">{m.scenario_id || '—'}</span>
            </div>
          </button>
        )
      })}
    </div>
  )
}
