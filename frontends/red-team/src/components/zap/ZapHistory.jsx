/**
 * ZapHistory — Burp-Proxy-History-style table. Every row has three clearly
 * visible actions: Inspect · Repeater · Fuzzer (no invisible row-clicking).
 */
import { SOURCE_LABELS, statusColor } from './zapUtils.js'

function RowButton({ label, title, onClick, tone = '#7dd3fc' }) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="shrink-0 font-mono text-[8.5px] tracking-[0.1em] px-1.5 py-0.5 rounded transition-opacity"
      style={{ color: tone, border: `1px solid ${tone}55` }}
    >{label}</button>
  )
}

export default function ZapHistory({ messages, isOperatorMode, onInspect, onRepeater, onFuzzer }) {
  return (
    <div>
      {isOperatorMode && (
        <div
          className="font-mono text-[10px] leading-relaxed rounded-md px-3 py-2 mb-3 flex items-start gap-2"
          style={{ background: 'rgba(46,227,154,0.06)', border: '1px solid rgba(46,227,154,0.25)', color: '#2ee39a' }}
        >
          <span aria-hidden>●</span>
          <span>Operator browser traffic is proxied through ZAP and appears here.
            Use Repeater and Fuzzer to replay or test requests.</span>
        </div>
      )}

      {!messages.length ? (
        <div className="font-mono text-[11px] text-attense-dim">
          <div className="mb-1 text-attense-text font-semibold">ZAP is running.</div>
          <div>No requests captured yet. Browse the target in Operator Mode, or use
            Repeater / Fuzzer — every request is recorded here.</div>
        </div>
      ) : (
        <>
          <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim mb-2">
            ZAP PROXY HISTORY ({messages.length} requests)
          </div>
          <div className="rounded-lg overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex items-center gap-3 px-3 py-1.5 font-mono text-[9px] tracking-[0.16em]"
              style={{ background: 'rgba(255,255,255,0.03)', color: '#5a6680' }}>
              <span className="w-16 shrink-0">SOURCE</span>
              <span className="w-12 shrink-0">METHOD</span>
              <span className="flex-1">PATH</span>
              <span className="w-10 text-right shrink-0">CODE</span>
              <span className="w-12 text-right shrink-0">LEN</span>
              <span className="w-[190px] shrink-0 text-right">ACTIONS</span>
            </div>
            <div style={{ maxHeight: 'calc(100vh - 320px)', minHeight: 120, overflow: 'auto' }}>
              {messages.slice().reverse().map((m, i) => (
                <div
                  key={m.id ?? i}
                  className="group flex items-center gap-3 px-3 py-1.5 font-mono text-[10.5px] hover:bg-white/[0.03]"
                  style={{ borderTop: '1px solid rgba(255,255,255,0.04)', color: '#c8d0e8' }}
                >
                  <span className="w-16 shrink-0 text-[8px] uppercase tracking-[0.12em]"
                    style={{ color: m.source === 'browser' ? '#2ee39a' : '#8a92a8' }}>
                    {SOURCE_LABELS[m.source] || m.source || '—'}
                  </span>
                  <span className="w-12 shrink-0 font-semibold"
                    style={{ color: m.method === 'POST' ? '#fbbf24' : '#7dd3fc' }}>{m.method}</span>
                  <span className="flex-1 truncate text-attense-dim" title={m.full_url || m.url}>
                    {m.path || m.url}
                  </span>
                  <span className="w-10 text-right shrink-0" style={{ color: statusColor(m.status_code || m.response_status) }}>
                    {m.status_code || m.response_status}
                  </span>
                  <span className="w-12 text-right shrink-0 text-[#5a6680]">{m.response_length}</span>
                  <div className="w-[190px] shrink-0 flex items-center justify-end gap-1.5">
                    <RowButton label="Inspect"  title="Open in Request Inspector" onClick={() => onInspect(m)} />
                    <RowButton label="Repeater" title="Send to Repeater" onClick={() => onRepeater(m)} tone="#c9a5ff" />
                    <RowButton label="Fuzzer"   title="Send to Fuzzer" onClick={() => onFuzzer(m)} tone="#2ee39a" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
