/**
 * ZapInspector — Burp-like request/response inspector. Shows method, full URL,
 * normalized path, request headers + body, response status/headers/body/length,
 * and metadata (source, timestamp, session, module).
 */
import { SOURCE_LABELS, statusColor } from './zapUtils.js'

function Field({ label, value, mono = true }) {
  return (
    <div className="flex gap-2 py-0.5">
      <span className="shrink-0 w-28" style={{ color: '#7dd3fc' }}>{label}</span>
      <span className={`flex-1 break-all ${mono ? 'font-mono' : ''}`} style={{ color: '#c8d0e8' }}>
        {value === undefined || value === null || value === '' ? '—' : String(value)}
      </span>
    </div>
  )
}

function Block({ label, text, empty = '—' }) {
  return (
    <div className="mb-3">
      <div className="font-mono text-[9px] tracking-[0.24em] mb-1" style={{ color: '#5a6680' }}>{label}</div>
      <pre className="font-mono text-[10.5px] rounded p-2 m-0"
        style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
          color: '#c8d0e8', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          maxHeight: 220, overflow: 'auto',
        }}>
        {text && String(text).length ? text : empty}
      </pre>
    </div>
  )
}

export default function ZapInspector({ message, onSendToRepeater, onSendToFuzzer }) {
  if (!message) {
    return (
      <div className="font-mono text-[11px] text-attense-dim">
        Select a request from Proxy History and click <span className="text-attense-text">Inspect</span> to view it here.
      </div>
    )
  }
  const m = message
  const ts = m.timestamp ? new Date(m.timestamp * 1000).toLocaleString() : '—'
  return (
    <div className="font-mono text-[10.5px]">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[9px] tracking-[0.3em] text-attense-dim">REQUEST INSPECTOR</div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => onSendToRepeater?.(m)} className="text-[8.5px] tracking-[0.1em] px-2 py-1 rounded"
            style={{ color: '#c9a5ff', border: '1px solid #c9a5ff55' }}>→ REPEATER</button>
          <button onClick={() => onSendToFuzzer?.(m)} className="text-[8.5px] tracking-[0.1em] px-2 py-1 rounded"
            style={{ color: '#2ee39a', border: '1px solid #2ee39a55' }}>→ FUZZER</button>
        </div>
      </div>

      {/* Request */}
      <div className="rounded-lg p-3 mb-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="text-[9px] tracking-[0.24em] mb-2" style={{ color: '#7dd3fc' }}>REQUEST</div>
        <Field label="Method" value={m.method} />
        <Field label="Full URL" value={m.full_url || m.url} />
        <Field label="Path" value={m.path} />
        <div className="mt-2" />
        <Block label="REQUEST HEADERS" text={m.request_headers} empty="(none captured)" />
        <Block label="REQUEST BODY" text={m.request_body} empty="(empty body)" />
      </div>

      {/* Response */}
      <div className="rounded-lg p-3 mb-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="text-[9px] tracking-[0.24em] mb-2" style={{ color: '#7dd3fc' }}>RESPONSE</div>
        <div className="flex gap-2 py-0.5">
          <span className="shrink-0 w-28" style={{ color: '#7dd3fc' }}>Status</span>
          <span className="font-semibold" style={{ color: statusColor(m.status_code || m.response_status) }}>
            {m.status_code || m.response_status || '—'}
          </span>
        </div>
        <Field label="Response length" value={`${m.response_length ?? 0} bytes`} />
        <div className="mt-2" />
        <Block label="RESPONSE HEADERS" text={m.response_headers} empty="(none captured)" />
        <Block label="RESPONSE BODY" text={m.response_body} empty="(empty / not captured)" />
      </div>

      {/* Metadata */}
      <div className="rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="text-[9px] tracking-[0.24em] mb-2" style={{ color: '#7dd3fc' }}>METADATA</div>
        <Field label="Source" value={SOURCE_LABELS[m.source] || m.source} />
        <Field label="Timestamp" value={ts} />
        <Field label="Session ID" value={m.session_id} />
        <Field label="Module ID" value={m.module_id} />
      </div>
    </div>
  )
}
