/**
 * ZapPanel — Lab Mode OWASP ZAP panel with real status.
 *
 * Connects to the local ZAP proxy via the backend API.
 * Shows proxy history, request inspector, and repeater tabs.
 * All requests are scoped to the local target-agent only.
 */
import { useEffect, useState } from 'react'
import { api } from '../api/client.js'

const STATUS_STYLES = {
  running: { color: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.25)' },
  offline: { color: '#fbbf24', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.25)' },
  error:   { color: '#f87171', bg: 'rgba(248,113,113,0.06)', bd: 'rgba(248,113,113,0.25)' },
  checking:{ color: '#7dd3fc', bg: 'rgba(125,211,252,0.06)', bd: 'rgba(125,211,252,0.25)' },
}

const TABS = [
  { id: 'history',   label: 'Proxy History' },
  { id: 'inspector', label: 'Request Inspector' },
  { id: 'repeater',  label: 'Repeater' },
]

export default function ZapPanel({ minimized, onToggleMinimize }) {
  const [status, setStatus] = useState('checking')
  const [zapVersion, setZapVersion] = useState('')
  const [activeTab, setActiveTab] = useState('history')
  const [messages, setMessages] = useState([])
  const [selectedMsg, setSelectedMsg] = useState(null)

  // Repeater state
  const [repMethod, setRepMethod] = useState('GET')
  const [repPath, setRepPath] = useState('/')
  const [repBody, setRepBody] = useState('')
  const [repResult, setRepResult] = useState(null)
  const [repLoading, setRepLoading] = useState(false)

  // Check status on mount + every 15s
  useEffect(() => {
    const check = () => {
      api.zap.status()
        .then(r => {
          setStatus(r.status || 'error')
          setZapVersion(r.version || '')
        })
        .catch(() => setStatus('offline'))
    }
    check()
    const iv = setInterval(check, 15000)
    return () => clearInterval(iv)
  }, [])

  // Fetch history when tab is active and ZAP is running
  useEffect(() => {
    if (activeTab !== 'history' || status !== 'running') return
    api.zap.history(50)
      .then(r => setMessages(r.messages || []))
      .catch(() => setMessages([]))
    const iv = setInterval(() => {
      api.zap.history(50)
        .then(r => setMessages(r.messages || []))
        .catch(() => {})
    }, 8000)
    return () => clearInterval(iv)
  }, [activeTab, status])

  const handleSendRepeater = async () => {
    setRepLoading(true)
    try {
      const r = await api.zap.repeater(repMethod, repPath, null, repBody || null)
      setRepResult(r)
    } catch (e) {
      setRepResult({ status: 'error', detail: e.message })
    }
    setRepLoading(false)
  }

  const s = STATUS_STYLES[status] || STATUS_STYLES.error

  return (
    <div
      className="h-full w-full flex flex-col overflow-hidden"
      style={{ background: '#0a0d13', borderTop: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Header */}
      <div
        className="shrink-0 flex items-center justify-between px-4 py-2"
        style={{ background: 'rgba(0,0,0,0.45)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center gap-2.5">
          <span className="font-mono text-[10px] tracking-[0.22em] text-attense-text">
            OWASP ZAP · LOCAL PROXY
          </span>
          <span
            className="font-mono text-[8.5px] tracking-[0.20em] px-1.5 py-0.5 rounded"
            style={{ color: s.color, background: s.bg, border: `1px solid ${s.bd}` }}
          >
            {status.toUpperCase()}
          </span>
          {zapVersion && (
            <span className="font-mono text-[8.5px] text-attense-dim">
              v{zapVersion}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9px] tracking-[0.2em] text-attense-dim">
            local-only · target-agent
          </span>
          <button
            onClick={() => onToggleMinimize?.()}
            className="text-attense-dim hover:text-attense-text transition-colors px-1.5 py-0.5 rounded flex items-center"
            style={{ border: '1px solid rgba(255,255,255,0.08)' }}
            title={minimized ? 'Maximize panel' : 'Minimize panel'}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              {minimized
                ? <path d="M18 15l-6-6-6 6"/>
                : <path d="M6 9l6 6 6-6"/>
              }
            </svg>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div
        className="shrink-0 flex items-center gap-0 px-3 pt-2"
        style={{ background: 'rgba(0,0,0,0.30)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        {TABS.map(t => {
          const active = activeTab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className="font-mono text-[10px] tracking-[0.16em] px-3 py-1.5 rounded-t-md transition-colors"
              style={{
                background: active ? 'rgba(125,211,252,0.08)' : 'transparent',
                color: active ? '#7dd3fc' : '#7a8194',
                border: active ? '1px solid rgba(125,211,252,0.25)' : '1px solid transparent',
                borderBottom: 'none',
                marginRight: 4,
                cursor: 'pointer',
              }}
            >
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Body */}
      <div
        className="flex-1 min-h-0 overflow-y-auto px-5 py-4"
        style={{ background: '#0a0d13' }}
      >
        {status !== 'running' ? (
          <div className="max-w-2xl">
            <div className="rounded-lg px-4 py-3" style={{
              background: 'rgba(250,204,21,0.06)',
              border: '1px solid rgba(250,204,21,0.2)',
              color: '#fbbf24',
            }}>
              <div className="font-mono text-[11px] font-semibold mb-1">
                ZAP is {status === 'checking' ? 'connecting…' : 'offline'}
              </div>
              <div className="font-mono text-[10.5px] text-attense-dim">
                The OWASP ZAP proxy container needs to be running. Start it with:
                <code className="block mt-1 text-attense-text">docker compose up zap</code>
              </div>
            </div>
          </div>
        ) : activeTab === 'history' ? (
          <HistoryTab messages={messages} onSelect={m => { setSelectedMsg(m); setActiveTab('inspector') }} />
        ) : activeTab === 'inspector' ? (
          <InspectorTab message={selectedMsg} />
        ) : (
          <RepeaterTab
            method={repMethod} path={repPath} body={repBody}
            onMethodChange={setRepMethod} onPathChange={setRepPath} onBodyChange={setRepBody}
            onSend={handleSendRepeater} loading={repLoading} result={repResult}
          />
        )}
      </div>
    </div>
  )
}

/* ── Sub-components ──────────────────────────────────────────────────────── */

function HistoryTab({ messages, onSelect }) {
  if (!messages.length) {
    return (
      <div className="font-mono text-[11px] text-attense-dim">
        <div className="mb-2 text-attense-text font-semibold">ZAP is running.</div>
        <div>No proxy history yet. Browse the target in the Lab Browser to generate traffic,</div>
        <div>or use the Repeater tab to send requests.</div>
      </div>
    )
  }
  return (
    <div>
      <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim mb-2">
        PROXY HISTORY ({messages.length} requests)
      </div>
      <div className="space-y-px">
        {messages.map((m, i) => (
          <button
            key={m.id || i}
            onClick={() => onSelect(m)}
            className="w-full text-left flex items-center gap-3 px-3 py-1.5 rounded transition-colors font-mono text-[10.5px] hover:bg-white/[0.03]"
            style={{ color: '#c8d0e8' }}
          >
            <span className="w-12 shrink-0 font-semibold" style={{
              color: m.method === 'POST' ? '#fbbf24' : '#7dd3fc'
            }}>{m.method}</span>
            <span className="flex-1 truncate text-attense-dim">{m.url}</span>
            <span className="w-10 text-right shrink-0" style={{
              color: (m.status_code + '').startsWith('2') ? '#2ee39a'
                : (m.status_code + '').startsWith('4') ? '#fbbf24' : '#f87171'
            }}>{m.status_code}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

function InspectorTab({ message }) {
  if (!message) {
    return (
      <div className="font-mono text-[11px] text-attense-dim">
        Select a request from Proxy History to inspect it.
      </div>
    )
  }
  return (
    <div>
      <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim mb-2">
        REQUEST INSPECTOR
      </div>
      <div className="rounded-lg p-3 font-mono text-[10.5px] leading-relaxed"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#c8d0e8' }}>
        <div><span style={{ color: '#7dd3fc' }}>Method:</span> {message.method}</div>
        <div><span style={{ color: '#7dd3fc' }}>URL:</span> {message.url}</div>
        <div><span style={{ color: '#7dd3fc' }}>Status:</span> {message.status_code}</div>
        <div><span style={{ color: '#7dd3fc' }}>Response size:</span> {message.response_length} bytes</div>
      </div>
    </div>
  )
}

function RepeaterTab({ method, path, body, onMethodChange, onPathChange, onBodyChange, onSend, loading, result }) {
  return (
    <div>
      <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim mb-3">
        REPEATER · target-agent only
      </div>
      <div className="flex items-center gap-2 mb-3">
        <select
          value={method}
          onChange={e => onMethodChange(e.target.value)}
          className="font-mono text-[11px] px-2 py-1.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8', outline: 'none' }}
        >
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <div className="flex-1 flex items-center gap-0 rounded overflow-hidden"
          style={{ border: '1px solid rgba(255,255,255,0.1)' }}>
          <span className="font-mono text-[10px] px-2 py-1.5 shrink-0" style={{ color: '#5a6680', background: 'rgba(255,255,255,0.02)' }}>
            http://target-agent
          </span>
          <input
            value={path}
            onChange={e => onPathChange(e.target.value)}
            className="flex-1 font-mono text-[11px] px-2 py-1.5 bg-transparent outline-none"
            style={{ color: '#d0d8e8' }}
            placeholder="/auth/login"
          />
        </div>
        <button
          onClick={onSend}
          disabled={loading}
          className="font-mono text-[10px] font-bold tracking-[0.12em] px-4 py-1.5 rounded-md transition-all"
          style={{
            background: loading ? 'rgba(125,211,252,0.06)' : 'rgba(125,211,252,0.12)',
            border: '1px solid rgba(125,211,252,0.35)',
            color: '#7dd3fc',
            cursor: loading ? 'wait' : 'pointer',
          }}
        >{loading ? 'SENDING…' : 'SEND'}</button>
      </div>
      {(method === 'POST' || method === 'PUT' || method === 'PATCH') && (
        <textarea
          value={body}
          onChange={e => onBodyChange(e.target.value)}
          rows={3}
          className="w-full font-mono text-[11px] px-3 py-2 rounded mb-3 resize-y"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#d0d8e8', outline: 'none' }}
          placeholder="Request body..."
        />
      )}
      {result && (
        <div className="rounded-lg p-3 font-mono text-[10.5px] leading-relaxed mt-2"
          style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#c8d0e8' }}>
          <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim mb-2">RESPONSE</div>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 200, overflow: 'auto' }}>
            {result.status === 'ok' ? JSON.stringify(result.response, null, 2) : `Error: ${result.detail || 'unknown'}`}
          </pre>
        </div>
      )}
    </div>
  )
}
