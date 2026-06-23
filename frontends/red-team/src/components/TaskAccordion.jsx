import { useState } from 'react'

export function TaskAccordion({ steps = [] }) {
  const [open, setOpen] = useState(() => new Set([0]))

  const toggle = (idx) => {
    setOpen(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx); else next.add(idx)
      return next
    })
  }

  if (!steps.length) {
    return (
      <div className="rounded-lg border border-attense-border bg-attense-panel/40 p-6 text-center text-attense-muted font-mono text-xs">
        This mission has no tasks yet.
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-2">
      {steps.map((step, idx) => {
        const isOpen = open.has(idx)
        return (
          <div
            key={idx}
            className={
              'rounded-lg border overflow-hidden transition-colors ' +
              (isOpen
                ? 'border-attense-red/50 bg-attense-panel'
                : 'border-attense-border bg-attense-panel/40 hover:border-attense-red/30')
            }
          >
            <button
              onClick={() => toggle(idx)}
              className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left"
            >
              <div className="flex items-center gap-4 min-w-0">
                <div className={
                  'w-7 h-7 rounded-full grid place-items-center font-mono text-[11px] font-semibold border shrink-0 ' +
                  (isOpen
                    ? 'bg-attense-red/15 border-attense-red text-attense-red'
                    : 'bg-attense-bg border-attense-border text-attense-muted')
                }>
                  {idx + 1}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono tracking-[0.22em] text-attense-muted">
                      TASK {idx + 1}
                    </span>
                    {step.technique && (
                      <span className="font-mono text-[9px] font-semibold text-attense-red bg-attense-red/10 border border-attense-red/30 rounded px-1.5 py-0.5">
                        {String(step.technique).split(' ')[0]}
                      </span>
                    )}
                  </div>
                  <div className="font-sans text-[14px] font-medium text-attense-text truncate">
                    {step.title || `Step ${idx + 1}`}
                  </div>
                </div>
              </div>
              <span className={'text-attense-muted transition-transform text-sm ' + (isOpen ? 'rotate-180' : '')}>
                ▾
              </span>
            </button>

            {isOpen && (
              <div className="px-5 pb-5 pt-1 border-t border-attense-border/60 bg-attense-bg/30">
                {step.hint && (
                  <div className="mb-3">
                    <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-1">
                      HINT
                    </div>
                    <div className="text-[12.5px] text-attense-text leading-relaxed font-mono bg-attense-bg/60 border border-attense-border rounded px-3 py-2">
                      {step.hint}
                    </div>
                  </div>
                )}

                {step.technique && (
                  <div className="mb-3">
                    <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-1">
                      MITRE TECHNIQUE
                    </div>
                    <div className="text-[12px] text-attense-text font-mono">
                      {step.technique}
                    </div>
                  </div>
                )}

                {step.command && (
                  <div className="mb-3">
                    <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-1">
                      COMMAND
                    </div>
                    <pre className="text-[12px] text-attense-mint leading-relaxed font-mono bg-attense-bg/80 border border-attense-border rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all">
{step.command}
                    </pre>
                  </div>
                )}

                {step.expected && (
                  <div className="mb-3">
                    <div className="text-[9px] font-mono tracking-[0.28em] text-attense-muted mb-1">
                      EXPECTED OUTCOME
                    </div>
                    <div className="text-[12.5px] text-attense-text leading-relaxed">
                      {step.expected}
                    </div>
                  </div>
                )}

                {!step.hint && !step.command && !step.expected && (
                  <div className="text-[12px] text-attense-muted italic">
                    No additional guidance for this task.
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
