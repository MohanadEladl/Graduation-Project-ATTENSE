import { useEffect, useRef } from 'react'

const TAG_COLORS = {
  '[+]': 'text-attense-mint',
  '[!]': 'text-attense-red',
  '[*]': 'text-attense-muted',
  '[-]': 'text-attense-dim',
}

function colorFor(line) {
  const head = line.slice(0, 3)
  return TAG_COLORS[head] || 'text-attense-text'
}

function formatTs(ts) {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  return d.toTimeString().slice(0, 8)
}

export function LogView({ logs = [], empty = 'No activity yet.' }) {
  const hostRef = useRef(null)
  const stickRef = useRef(true)

  // Auto-scroll only while the user is already near the bottom.
  useEffect(() => {
    const el = hostRef.current
    if (!el || !stickRef.current) return
    el.scrollTop = el.scrollHeight
  }, [logs])

  const onScroll = () => {
    const el = hostRef.current
    if (!el) return
    const nearBottom = el.scrollHeight - el.clientHeight - el.scrollTop < 40
    stickRef.current = nearBottom
  }

  return (
    <div
      ref={hostRef}
      onScroll={onScroll}
      className="h-full w-full overflow-y-auto rounded-md border border-attense-border
                 bg-attense-panel/60 shadow-inset-hair font-mono text-[12.5px] leading-[1.55]
                 px-4 py-3"
    >
      {logs.length === 0 ? (
        <div className="text-attense-muted italic">{empty}</div>
      ) : (
        logs.map((entry, i) => (
          <div key={i} className="flex gap-3">
            <span className="text-attense-dim select-none shrink-0">
              {formatTs(entry.ts)}
            </span>
            <span className={'whitespace-pre ' + colorFor(entry.line)}>
              {entry.line || '\u00a0'}
            </span>
          </div>
        ))
      )}
    </div>
  )
}
