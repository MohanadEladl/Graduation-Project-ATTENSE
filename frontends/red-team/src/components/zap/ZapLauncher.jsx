/**
 * ZapLauncher — compact card shown in the Red Team workspace where the embedded
 * ZAP panel used to live. Instead of squeezing all of ZAP into the browser
 * column, it opens a dedicated desktop-style ZAP Workspace in a separate window,
 * still bound to the active Red Team session.
 */
import { useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { STATUS_STYLES } from './zapUtils.js'

export default function ZapLauncher({ sessionId, moduleId, mode = 'operator', minimized, onToggleMinimize }) {
  const [status, setStatus] = useState('checking')
  const [zapVersion, setZapVersion] = useState('')

  useEffect(() => {
    let alive = true
    const check = () => api.zap.status()
      .then(r => { if (alive) { setStatus(r.status || 'error'); setZapVersion(r.version || '') } })
      .catch(() => alive && setStatus('offline'))
    check()
    const iv = setInterval(check, 15000)
    return () => { alive = false; clearInterval(iv) }
  }, [])

  const openWorkspace = () => {
    const q = new URLSearchParams({
      session_id: sessionId || '',
      module_id:  moduleId || '',
      mode:       mode || 'operator',
    }).toString()
    // Reuse the SAME window on every click instead of stacking new ones. The
    // named target ('attense_zap_workspace') already targets one window, but the
    // old `noopener` flag defeated that — noopener makes the browser ignore the
    // name and open a fresh window each time. Without it, a re-click redirects
    // the existing window to the latest URL; focus() brings it to the front.
    const win = window.open(
      `/zap-workspace?${q}`,
      'attense_zap_workspace',
      'width=1280,height=860',
    )
    win?.focus()
  }

  const s = STATUS_STYLES[status] || STATUS_STYLES.error

  return (
    <div className="h-full w-full flex flex-col overflow-hidden"
      style={{ background: '#0a0d13', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
      <div className="shrink-0 flex items-center justify-between px-4 py-2"
        style={{ background: 'rgba(0,0,0,0.45)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="flex items-center gap-2.5">
          <span className="font-mono text-[10px] tracking-[0.22em] text-attense-text">OWASP ZAP · LOCAL PROXY</span>
          <span className="font-mono text-[8.5px] tracking-[0.2em] px-1.5 py-0.5 rounded"
            style={{ color: s.color, background: s.bg, border: `1px solid ${s.bd}` }}>{status.toUpperCase()}</span>
          {zapVersion && <span className="font-mono text-[8.5px] text-attense-dim">v{zapVersion}</span>}
        </div>
        <button onClick={() => onToggleMinimize?.()}
          className="text-attense-dim hover:text-attense-text transition-colors px-1.5 py-0.5 rounded flex items-center"
          style={{ border: '1px solid rgba(255,255,255,0.08)' }} title={minimized ? 'Maximize' : 'Minimize'}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            {minimized ? <path d="M18 15l-6-6-6 6" /> : <path d="M6 9l6 6 6-6" />}
          </svg>
        </button>
      </div>

      <div className="flex-1 min-h-0 flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl p-6 text-center"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(125,211,252,0.18)' }}>
          <div className="mx-auto mb-3 w-12 h-12 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(125,211,252,0.1)', border: '1px solid rgba(125,211,252,0.3)' }}>
            <span className="font-mono text-[18px]" style={{ color: '#7dd3fc' }}>⚡</span>
          </div>
          <div className="font-mono text-[13px] text-attense-text font-semibold mb-1">ZAP Desktop Workspace</div>
          <div className="font-mono text-[10.5px] text-attense-dim leading-relaxed mb-4">
            ZAP now opens as a separate desktop-style tool — a wider Burp-like window with
            Proxy History, Inspector, Repeater and Fuzzer — while staying connected to this
            Red Team session. Operator browser traffic is proxied through ZAP and appears there.
          </div>
          <button onClick={openWorkspace}
            className="font-mono text-[11px] font-bold tracking-[0.14em] px-5 py-2.5 rounded-md"
            style={{ background: 'rgba(125,211,252,0.14)', border: '1px solid rgba(125,211,252,0.4)', color: '#7dd3fc' }}>
            OPEN ZAP WORKSPACE →
          </button>
          <div className="font-mono text-[9px] text-attense-dim mt-3">
            Opens in a new window · session {sessionId ? sessionId.slice(0, 8) : '—'} · {mode}
          </div>
        </div>
      </div>
    </div>
  )
}
