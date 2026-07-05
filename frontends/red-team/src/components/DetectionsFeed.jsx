import { useEffect, useRef } from 'react'

const SEV_STYLES = {
  critical: 'border-attense-red/60 bg-attense-red/10 text-attense-red',
  high:     'border-attense-red/50 bg-attense-red/10 text-attense-red',
  medium:   'border-attense-yellow/50 bg-attense-yellow/5 text-attense-yellow',
  low:      'border-attense-mint/40 bg-attense-mint/5 text-attense-mint',
  info:     'border-attense-border bg-attense-bg/40 text-attense-muted',
}

function fmtTime(ts) {
  if (!ts) return ''
  try { return new Date(ts).toTimeString().slice(0, 8) } catch { return '' }
}

function severityOf(ev) {
  const m = ev.metadata || {}
  return String(m.severity || '').toLowerCase() || 'info'
}

/**
 * DetectionsFeed — renders mapped Wazuh alerts, newest at top.
 *
 * Props:
 *   detections: array of StandardEvent dicts (from useDetections)
 *   status:     broker status dict (reachable, source, last_error)
 *   highlightScenario: scenario_id of the current mission — rows matching get
 *                      "YOU WERE DETECTED" highlight
 */
export function DetectionsFeed({ detections = [], status = null, highlightScenario = null }) {
  const hostRef = useRef(null)
  // Newest first in the UI; the feed reads top-to-bottom chronologically reverse.
  const items = [...detections].reverse()

  useEffect(() => {
    // Flash the top row briefly when a new detection arrives
    if (!hostRef.current) return
    hostRef.current.scrollTop = 0
  }, [items.length])

  return (
    <div className="flex flex-col h-full min-h-0">
      <FeedHeader status={status} count={detections.length} />
      <div
        ref={hostRef}
        className="flex-1 min-h-0 overflow-y-auto rounded-md border border-attense-border
                   bg-attense-panel/60 shadow-inset-hair px-3 py-2 flex flex-col gap-1.5"
      >
        {items.length === 0 ? (
          <div className="text-attense-muted font-mono text-[11.5px] italic p-2">
            {status?.reachable
              ? 'No detections yet — blue team is quiet.'
              : 'Waiting for signal-store…'}
          </div>
        ) : (
          items.map((ev, i) => {
            const matched = highlightScenario && ev.scenario_id === highlightScenario
            return <DetectionRow key={ev.event_id || i} ev={ev} matched={matched} />
          })
        )}
      </div>
    </div>
  )
}

function FeedHeader({ status, count }) {
  const ok = !!status?.reachable
  return (
    <div className="flex items-center justify-between px-1 pb-1.5">
      <div className="flex items-center gap-2">
        <span className="text-[9px] font-mono tracking-[0.32em] text-attense-muted">DETECTIONS</span>
        <span className={
          'text-[9px] font-mono tracking-[0.18em] px-1.5 py-0.5 rounded border ' +
          (ok
            ? 'text-attense-mint border-attense-mint/40 bg-attense-mint/5'
            : 'text-attense-red  border-attense-red/40  bg-attense-red/10')
        }>
          {ok ? 'WAZUH LIVE' : 'WAZUH DOWN'}
        </span>
      </div>
      <span className="text-[9.5px] font-mono text-attense-dim">{count} EVENTS</span>
    </div>
  )
}

function DetectionRow({ ev, matched }) {
  const sev = severityOf(ev)
  const sevClass = SEV_STYLES[sev] || SEV_STYLES.info
  const m = ev.metadata || {}
  return (
    <div className={
      'rounded border px-3 py-2 font-mono text-[11.5px] transition-colors ' +
      (matched
        ? 'border-attense-red/60 bg-attense-red/10 shadow-glow-red'
        : 'border-attense-border bg-attense-bg/40')
    }>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={'uppercase text-[9px] tracking-[0.18em] px-1.5 py-0.5 rounded border ' + sevClass}>
            {sev}
          </span>
          <span className="text-attense-text truncate">
            {m.description || ev.event_type}
          </span>
        </div>
        <span className="text-[10px] text-attense-dim shrink-0">
          {fmtTime(ev.timestamp)}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[10.5px] text-attense-muted">
        <span>rule <span className="text-attense-text">{m.wazuh_rule_id || '—'}</span></span>
        <span>scenario <span className="text-attense-text">{ev.scenario_id}</span></span>
        {m.source_ip && <span>src <span className="text-attense-text">{m.source_ip}</span></span>}
        {ev.target_id && <span>tgt <span className="text-attense-text">{ev.target_id}</span></span>}
        {matched && (
          <span className="ml-auto text-attense-red tracking-[0.22em]">
            ▶ YOU WERE DETECTED
          </span>
        )}
      </div>
    </div>
  )
}
