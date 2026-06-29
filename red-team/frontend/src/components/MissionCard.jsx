import { Link } from 'react-router-dom'
import { SeverityBadge, CATEGORY_ICON } from './SeverityBadge.jsx'

export function MissionCard({ module, progress }) {
  const icon = CATEGORY_ICON[module.category] || '▪'
  const stepCount = module.steps?.length || 0
  const done = progress?.completed ?? 0
  const state = progress?.state
  const hasProgress = done > 0 || !!state

  return (
    <Link
      to={`/mission/${module.module_id}`}
      className="group relative block rounded-lg border border-attense-border bg-attense-panel/60
                 hover:border-attense-red/60 hover:bg-attense-panel2 hover:shadow-glow-red
                 transition-all duration-200 overflow-hidden"
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-attense-red/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

      <div className="p-5">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-md border border-attense-border bg-attense-bg
                            grid place-items-center text-attense-red text-lg
                            group-hover:border-attense-red/60 transition-colors">
              {icon}
            </div>
            <div className="min-w-0">
              <div className="font-mono text-[11px] tracking-wider text-attense-muted">
                {module.scenario_id || '—'}
              </div>
              <div className="font-sans font-semibold text-[15px] truncate text-attense-text">
                {module.name}
              </div>
            </div>
          </div>
          <SeverityBadge severity={module.severity} />
        </div>

        <p className="text-[12px] text-attense-muted leading-relaxed line-clamp-3 mb-4 min-h-[3.3em]">
          {module.description}
        </p>

        <div className="flex items-center justify-between text-[10px] font-mono tracking-[0.18em] text-attense-dim pt-3 border-t border-attense-border">
          <span>{(module.category || 'UNKNOWN').toUpperCase()}</span>
          <span className="flex items-center gap-3">
            {hasProgress && <ProgressChip done={done} total={stepCount} state={state} />}
            <span>{stepCount} TASK{stepCount === 1 ? '' : 'S'}</span>
            <span className="text-attense-red group-hover:translate-x-0.5 transition-transform">
              ENTER →
            </span>
          </span>
        </div>
      </div>
    </Link>
  )
}

function ProgressChip({ done, total, state }) {
  const full = total > 0 && done >= total
  const running = state === 'running'
  const cls = running
    ? 'text-attense-red border-attense-red/40 bg-attense-red/10'
    : full
      ? 'text-attense-mint border-attense-mint/40 bg-attense-mint/5'
      : 'text-attense-muted border-attense-border bg-attense-bg/40'
  return (
    <span className={`text-[9px] px-1.5 py-0.5 rounded border tracking-[0.14em] ${cls}`}>
      {running ? 'LIVE' : `${done}/${total || '?'}`}
    </span>
  )
}
