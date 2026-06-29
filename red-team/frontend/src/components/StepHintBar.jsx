/**
 * StepHintBar — header strip rendered above the Terminal and ZAP panels.
 *
 * Shows the active Lab step (title + goal) with a SHOW COMMAND
 * toggle that reveals the literal command to run for this step, plus a
 * COPY button. Mirrors the same UX pattern used by the step cards in
 * the sidebar so the Lab panels feel consistent.
 *
 * Pass `tool="terminal" | "zap"` to filter which command to surface
 * when a step has both (the Lab-step schema in missionBriefings.js
 * sometimes uses `command` for terminal and `zapRequest` for ZAP).
 */
import { useState, useEffect } from 'react'

export default function StepHintBar({ activeStep, tool = 'terminal' }) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied]     = useState(false)

  // Hide the command again when the active step changes.
  useEffect(() => { setRevealed(false); setCopied(false) }, [activeStep?.n, activeStep?.title])

  if (!activeStep) return null

  // Pick a sensible command for this tool. Falls back across fields.
  const cmdRaw =
    (tool === 'zap' &&
      (activeStep.zapRequest || activeStep.zap_command || activeStep.zap)) ||
    activeStep.command ||
    (Array.isArray(activeStep.commands) ? activeStep.commands.join('\n') : '') ||
    ''
  const cmd = typeof cmdRaw === 'string' ? cmdRaw : String(cmdRaw)

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(cmd)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch (_) { /* ignore */ }
  }

  return (
    <div
      className="shrink-0 px-4 py-2"
      style={{
        background: 'rgba(125,211,252,0.04)',
        borderBottom: '1px solid rgba(125,211,252,0.18)',
        color: '#cfe7fb',
      }}
    >
      <div className="flex items-center gap-2">
        <span
          className="font-mono text-[9px] tracking-[0.2em] px-1.5 py-0.5 rounded shrink-0"
          style={{
            color: '#0c0f16',
            background: '#7dd3fc',
            border: '1px solid #38bdf8',
          }}
        >STEP {activeStep.n || '?'}</span>
        <span className="font-mono text-[11px] tracking-[0.04em] truncate" title={activeStep.title}>
          {activeStep.title}
        </span>
        <div className="ml-auto flex items-center gap-2 shrink-0">
          {cmd && (
            <button
              onClick={() => setRevealed(v => !v)}
              className="font-mono text-[9.5px] tracking-[0.18em] px-2 py-1 rounded transition-colors"
              style={{
                color: revealed ? '#0c0f16' : '#7dd3fc',
                background: revealed ? '#7dd3fc' : 'rgba(125,211,252,0.08)',
                border: '1px solid rgba(125,211,252,0.4)',
              }}
              title={revealed ? 'Hide command' : 'Reveal command for this step'}
            >
              {revealed ? '▴ HIDE COMMAND' : '▾ SHOW COMMAND'}
            </button>
          )}
        </div>
      </div>

      {activeStep.goal && (
        <div
          className="mt-1 font-mono text-[10px] leading-[1.5]"
          style={{ color: '#94a3b8' }}
        >
          {activeStep.goal}
        </div>
      )}

      {revealed && cmd && (
        <div className="mt-2 flex items-start gap-2">
          <pre
            className="flex-1 min-w-0 font-mono text-[11px] leading-[1.55] px-2.5 py-1.5 rounded overflow-x-auto"
            style={{
              background: '#0a0d13',
              color: '#9be8c5',
              border: '1px solid rgba(255,255,255,0.06)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >{cmd}</pre>
          <button
            onClick={onCopy}
            className="shrink-0 font-mono text-[9px] tracking-[0.18em] px-2 py-1 rounded transition-colors"
            style={{
              color: copied ? '#0c0f16' : '#9be8c5',
              background: copied ? '#9be8c5' : 'rgba(155,232,197,0.08)',
              border: '1px solid rgba(155,232,197,0.4)',
            }}
            title="Copy command to clipboard"
          >{copied ? '✓ COPIED' : 'COPY'}</button>
        </div>
      )}
    </div>
  )
}
