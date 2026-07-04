/**
 * ZapRepeater — replay/edit a single request against the local target and see
 * the full response. Populated by "Send to Repeater" from history.
 */
import { statusColor } from './zapUtils.js'

export default function ZapRepeater({ c }) {
  const r = c.repResult
  const parsed = r?.status === 'ok' ? r : null
  return (
    <div className="font-mono">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[9px] tracking-[0.3em] text-attense-dim">REPEATER · target-agent only</div>
        <button
          onClick={() => c.sendToFuzzer({ method: c.repMethod, path: c.repPath, request_body: c.repBody })}
          className="text-[8.5px] tracking-[0.12em] px-2 py-1 rounded"
          style={{ color: '#2ee39a', border: '1px solid #2ee39a55' }}
          title="Send this request to the Fuzzer"
        >→ SEND TO FUZZER</button>
      </div>

      <div className="flex items-center gap-2 mb-2">
        <select value={c.repMethod} onChange={e => c.setRepMethod(e.target.value)}
          className="text-[11px] px-2 py-1.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8', outline: 'none' }}>
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <div className="flex-1 flex items-center rounded overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.1)' }}>
          <span className="text-[10px] px-2 py-1.5 shrink-0" style={{ color: '#5a6680', background: 'rgba(255,255,255,0.02)' }}>http://target-agent</span>
          <input value={c.repPath} onChange={e => c.setRepPath(e.target.value)}
            className="flex-1 text-[11px] px-2 py-1.5 bg-transparent outline-none" style={{ color: '#d0d8e8' }}
            placeholder={c.defaultAuthPath} />
        </div>
        <button onClick={c.runRepeater} disabled={c.repLoading}
          className="text-[10px] font-bold tracking-[0.12em] px-4 py-1.5 rounded-md"
          style={{ background: c.repLoading ? 'rgba(125,211,252,0.06)' : 'rgba(125,211,252,0.12)', border: '1px solid rgba(125,211,252,0.35)', color: '#7dd3fc', cursor: c.repLoading ? 'wait' : 'pointer' }}>
          {c.repLoading ? 'SENDING…' : 'SEND'}
        </button>
      </div>

      <div className="text-[9px] tracking-[0.2em] mb-1" style={{ color: '#5a6680' }}>REQUEST HEADERS (one per line, Key: Value)</div>
      <textarea value={c.repHeaders} onChange={e => c.setRepHeaders(e.target.value)} rows={2}
        className="w-full text-[11px] px-3 py-2 rounded mb-2 resize-y"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#d0d8e8', outline: 'none' }}
        placeholder="Content-Type: application/x-www-form-urlencoded" />

      {(c.repMethod === 'POST' || c.repMethod === 'PUT' || c.repMethod === 'PATCH') && (
        <>
          <div className="text-[9px] tracking-[0.2em] mb-1" style={{ color: '#5a6680' }}>REQUEST BODY</div>
          <textarea value={c.repBody} onChange={e => c.setRepBody(e.target.value)} rows={3}
            className="w-full text-[11px] px-3 py-2 rounded mb-3 resize-y"
            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#d0d8e8', outline: 'none' }}
            placeholder="username=admin&password=wrong" />
        </>
      )}

      {r && (
        <div className="rounded-lg p-3 mt-2" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#c8d0e8' }}>
          <div className="text-[9px] tracking-[0.3em] text-attense-dim mb-2">RESPONSE</div>
          {r.status === 'ok' ? (
            <>
              <div className="text-[11px] mb-2">
                <span style={{ color: '#7dd3fc' }}>Status: </span>
                <span className="font-semibold" style={{ color: statusColor(r.response_status) }}>{r.response_status}</span>
                <span className="text-attense-dim"> · {r.response_length} bytes</span>
              </div>
              <div className="text-[9px] tracking-[0.2em] mb-1" style={{ color: '#5a6680' }}>RESPONSE HEADERS</div>
              <pre className="text-[10px] m-0 mb-2" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 120, overflow: 'auto' }}>{r.response_headers || '—'}</pre>
              <div className="text-[9px] tracking-[0.2em] mb-1" style={{ color: '#5a6680' }}>RESPONSE BODY</div>
              <pre className="text-[10px] m-0" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 200, overflow: 'auto' }}>{r.response_body || '—'}</pre>
            </>
          ) : (
            <div className="text-[10.5px]" style={{ color: r.status === 'blocked' ? '#fbbf24' : '#f87171' }}>
              {r.status === 'blocked' ? 'Blocked: ' : 'Error: '}{r.detail || 'unknown'}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
