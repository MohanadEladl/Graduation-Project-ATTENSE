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
  { id: 'fuzzer',    label: 'Fuzzer' },
]

// Preset payload lists for the Fuzzer — mirrors the wordlists a beginner would
// reach for in Burp Intruder, but built-in so there's no file to manage.
const FUZZER_PRESETS = {
  passwords: {
    label: 'Common passwords',
    items: ['password', '123456', 'admin', 'letmein', 'password123',
            'lab2024', 'qwerty', 'welcome', 'changeme', 'guest'],
  },
  usernames: {
    label: 'Common usernames',
    items: ['admin', 'operator', 'guest', 'root', 'user', 'test',
            'alice', 'bob', 'service'],
  },
  leaked: {
    label: 'Leaked mini-list',
    items: ['123456', 'password', '12345678', 'qwerty', 'abc123',
            'monkey', 'letmein', 'dragon', 'password123', 'iloveyou'],
  },
}

// Put a § payload marker on the last field value of a form body, so "Send to
// Fuzzer" arrives with a sensible default position (e.g. user=x&password=§).
function markLastValue(body) {
  if (!body || body.includes('§')) return body
  const idx = body.lastIndexOf('=')
  return idx === -1 ? body + '§' : body.slice(0, idx + 1) + '§'
}

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

  // Fuzzer (Intruder-style) state
  const [fuzMethod, setFuzMethod] = useState('POST')
  const [fuzPath, setFuzPath] = useState('/auth/login')
  const [fuzBody, setFuzBody] = useState('')
  const [fuzPreset, setFuzPreset] = useState('none')
  const [fuzList, setFuzList] = useState('')
  const [fuzResult, setFuzResult] = useState(null)
  const [fuzLoading, setFuzLoading] = useState(false)
  const [fuzSort, setFuzSort] = useState('order')   // 'order' | 'status' | 'length'
  const [fuzGrep, setFuzGrep] = useState('')        // Burp "Grep - Match" string

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

  const handleSelectPreset = (key) => {
    setFuzPreset(key)
    if (FUZZER_PRESETS[key]) setFuzList(FUZZER_PRESETS[key].items.join('\n'))
  }

  // "Send to Fuzzer" (mirrors Burp's "Send to Intruder"). Marks the last field
  // value with § as a sensible default payload position.
  const handleSendToFuzzer = (method, path, body) => {
    setFuzMethod(method || 'POST')
    setFuzPath(path || '/')
    setFuzBody(markLastValue(body || ''))
    setFuzResult(null)
    setActiveTab('fuzzer')
  }

  const handleRunFuzzer = async () => {
    setFuzLoading(true)
    setFuzResult(null)
    setFuzSort('order')
    try {
      const payloads = fuzList.split('\n').map(s => s.trim()).filter(Boolean)
      const r = await api.zap.fuzzer(fuzMethod, fuzPath, fuzBody, payloads, '§', fuzGrep || null)
      setFuzResult(r)
    } catch (e) {
      setFuzResult({ status: 'error', detail: e.message })
    }
    setFuzLoading(false)
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
          <HistoryTab
            messages={messages}
            onSelect={m => { setSelectedMsg(m); setActiveTab('inspector') }}
            onSendToFuzzer={m => handleSendToFuzzer(m.method, m.url, m.method === 'POST' ? '' : '')}
          />
        ) : activeTab === 'inspector' ? (
          <InspectorTab message={selectedMsg} />
        ) : activeTab === 'repeater' ? (
          <RepeaterTab
            method={repMethod} path={repPath} body={repBody}
            onMethodChange={setRepMethod} onPathChange={setRepPath} onBodyChange={setRepBody}
            onSend={handleSendRepeater} loading={repLoading} result={repResult}
            onSendToFuzzer={() => handleSendToFuzzer(repMethod, repPath, repBody)}
          />
        ) : (
          <FuzzerTab
            method={fuzMethod} path={fuzPath} body={fuzBody}
            preset={fuzPreset} list={fuzList} sort={fuzSort} grep={fuzGrep}
            onMethodChange={setFuzMethod} onPathChange={setFuzPath} onBodyChange={setFuzBody}
            onSelectPreset={handleSelectPreset} onListChange={setFuzList}
            onSort={setFuzSort} onGrepChange={setFuzGrep}
            onRun={handleRunFuzzer} loading={fuzLoading} result={fuzResult}
          />
        )}
      </div>
    </div>
  )
}

/* ── Sub-components ──────────────────────────────────────────────────────── */

function HistoryTab({ messages, onSelect, onSendToFuzzer }) {
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
        PROXY HISTORY ({messages.length} requests) · hover a row to send it to the Fuzzer
      </div>
      <div className="space-y-px">
        {messages.map((m, i) => (
          <div
            key={m.id || i}
            className="group w-full flex items-center gap-3 px-3 py-1.5 rounded transition-colors font-mono text-[10.5px] hover:bg-white/[0.03]"
            style={{ color: '#c8d0e8' }}
          >
            <button onClick={() => onSelect(m)} className="flex-1 min-w-0 text-left flex items-center gap-3">
              <span className="w-12 shrink-0 font-semibold" style={{
                color: m.method === 'POST' ? '#fbbf24' : '#7dd3fc'
              }}>{m.method}</span>
              <span className="flex-1 truncate text-attense-dim">{m.url}</span>
              <span className="w-10 text-right shrink-0" style={{
                color: (m.status_code + '').startsWith('2') ? '#2ee39a'
                  : (m.status_code + '').startsWith('4') ? '#fbbf24' : '#f87171'
              }}>{m.status_code}</span>
            </button>
            <button
              onClick={() => onSendToFuzzer?.(m)}
              className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity font-mono text-[8.5px] tracking-[0.1em] px-1.5 py-0.5 rounded"
              style={{ color: '#7dd3fc', border: '1px solid rgba(125,211,252,0.3)' }}
              title="Send to Fuzzer"
            >→ FUZZER</button>
          </div>
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

function RepeaterTab({ method, path, body, onMethodChange, onPathChange, onBodyChange, onSend, loading, result, onSendToFuzzer }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim">
          REPEATER · target-agent only
        </div>
        <button
          onClick={onSendToFuzzer}
          className="font-mono text-[8.5px] tracking-[0.12em] px-2 py-1 rounded"
          style={{ color: '#7dd3fc', border: '1px solid rgba(125,211,252,0.3)' }}
          title="Send this request to the Fuzzer"
        >→ SEND TO FUZZER</button>
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

function FuzzerTab({
  method, path, body, preset, list, sort, grep,
  onMethodChange, onPathChange, onBodyChange,
  onSelectPreset, onListChange, onSort, onGrepChange, onRun, loading, result,
}) {
  const rows = result?.status === 'ok' ? (result.results || []) : []
  const count = list.split('\n').map(s => s.trim()).filter(Boolean).length
  const markerOk = body.includes('§')
  const grepUsed = Boolean(result?.grep)

  // Sortable results (Burp lets you sort by Status or Length to surface the
  // outlier). 'order' keeps request order.
  const sorted = [...rows]
  if (sort === 'status') sorted.sort((a, b) => (a.status_code + '').localeCompare(b.status_code + ''))
  else if (sort === 'length') sorted.sort((a, b) => a.length - b.length)

  const hasStatusHit = rows.some(r => r.status_hit)
  const hasGrepHit = rows.some(r => r.grep_hit)

  const SectionLabel = ({ n, children }) => (
    <div className="font-mono text-[9px] tracking-[0.28em] mb-2 flex items-center gap-2" style={{ color: '#7dd3fc' }}>
      <span className="rounded-full w-4 h-4 inline-flex items-center justify-center text-[8px]"
        style={{ background: 'rgba(125,211,252,0.12)', border: '1px solid rgba(125,211,252,0.35)' }}>{n}</span>
      {children}
    </div>
  )

  const Header = ({ col, label, w }) => (
    <button
      onClick={() => onSort?.(sort === col ? 'order' : col)}
      className={`${w} text-right font-mono text-[9px] tracking-[0.16em]`}
      style={{ color: sort === col ? '#7dd3fc' : '#5a6680', cursor: 'pointer' }}
      title="Click to sort"
    >{label}{sort === col ? ' ▲' : ''}</button>
  )

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="font-mono text-[9px] tracking-[0.3em] text-attense-dim">
          FUZZER · target-agent only
        </div>
        <span className="font-mono text-[8.5px] tracking-[0.18em] px-2 py-0.5 rounded"
          style={{ color: '#c9a5ff', background: 'rgba(168,120,255,0.08)', border: '1px solid rgba(168,120,255,0.3)' }}>
          ATTACK TYPE · SNIPER
        </span>
      </div>

      {/* ── 1 · POSITIONS ── */}
      <SectionLabel n="1">POSITIONS · mark the value to attack with §</SectionLabel>
      <div className="flex items-center gap-2 mb-2">
        <select
          value={method}
          onChange={e => onMethodChange(e.target.value)}
          className="font-mono text-[11px] px-2 py-1.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8', outline: 'none' }}
        >
          {['POST', 'GET', 'PUT', 'PATCH'].map(m => <option key={m} value={m}>{m}</option>)}
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
      </div>
      <textarea
        value={body}
        onChange={e => onBodyChange(e.target.value)}
        rows={2}
        className="w-full font-mono text-[11px] px-3 py-2 rounded mb-1 resize-y"
        style={{
          background: 'rgba(255,255,255,0.02)',
          border: `1px solid ${markerOk ? 'rgba(255,255,255,0.08)' : 'rgba(248,113,113,0.4)'}`,
          color: '#d0d8e8', outline: 'none',
        }}
        placeholder="username=§&password=x"
      />
      {!markerOk && (
        <div className="font-mono text-[9.5px] mb-2" style={{ color: '#f87171' }}>
          Add a § where the payload should go, e.g. username=§
        </div>
      )}

      {/* ── 2 · PAYLOADS ── */}
      <div className="mt-4"><SectionLabel n="2">PAYLOADS · simple list</SectionLabel></div>
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        {Object.entries(FUZZER_PRESETS).map(([key, p]) => (
          <button
            key={key}
            onClick={() => onSelectPreset(key)}
            className="font-mono text-[9px] tracking-[0.1em] px-2 py-1 rounded transition-colors"
            style={{
              background: preset === key ? 'rgba(125,211,252,0.12)' : 'rgba(255,255,255,0.03)',
              color: preset === key ? '#7dd3fc' : '#8a92a8',
              border: `1px solid ${preset === key ? 'rgba(125,211,252,0.35)' : 'rgba(255,255,255,0.08)'}`,
              cursor: 'pointer',
            }}
          >{p.label}</button>
        ))}
      </div>
      <textarea
        value={list}
        onChange={e => onListChange(e.target.value)}
        rows={4}
        className="w-full font-mono text-[11px] px-3 py-2 rounded mb-3 resize-y"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#d0d8e8', outline: 'none' }}
        placeholder="one payload per line"
      />

      {/* Grep - Match (Burp Intruder). For username enumeration, matching a
          string in the response is far more reliable than eyeballing Length. */}
      <div className="flex items-center gap-2 mb-3">
        <span className="font-mono text-[9px] tracking-[0.16em] shrink-0" style={{ color: '#5a6680' }}>GREP · MATCH</span>
        <input
          value={grep}
          onChange={e => onGrepChange(e.target.value)}
          className="flex-1 font-mono text-[11px] px-2 py-1.5 rounded bg-transparent outline-none"
          style={{ border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8' }}
          placeholder="optional — a string to match in responses"
        />
      </div>

      <button
        onClick={onRun}
        disabled={loading || !markerOk}
        className="font-mono text-[10px] font-bold tracking-[0.12em] px-4 py-2 rounded-md transition-all"
        style={{
          background: (loading || !markerOk) ? 'rgba(125,211,252,0.06)' : 'rgba(125,211,252,0.12)',
          border: '1px solid rgba(125,211,252,0.35)',
          color: '#7dd3fc',
          cursor: (loading || !markerOk) ? 'not-allowed' : 'pointer',
        }}
      >{loading ? `ATTACKING ${count} PAYLOADS…` : `START ATTACK · ${count} payloads`}</button>

      {/* ── 3 · RESULTS ── */}
      {result?.status === 'error' && (
        <div className="font-mono text-[10.5px] mt-3" style={{ color: '#f87171' }}>
          Error: {result.detail || 'unknown'}
        </div>
      )}
      {rows.length > 0 && (
        <div className="mt-5">
          <SectionLabel n="3">RESULTS · sort by Status or Length to find the outlier</SectionLabel>
          <div className="rounded-lg overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex items-center px-3 py-1.5"
              style={{ background: 'rgba(255,255,255,0.03)' }}>
              <span className="flex-1 font-mono text-[9px] tracking-[0.16em]" style={{ color: '#5a6680' }}>PAYLOAD</span>
              <Header col="status" label="STATUS" w="w-16" />
              <Header col="length" label="LENGTH" w="w-20" />
              {grepUsed && <span className="w-16 text-right font-mono text-[9px] tracking-[0.16em]" style={{ color: '#5a6680' }}>MATCH</span>}
            </div>
            <div style={{ maxHeight: 220, overflow: 'auto' }}>
              {sorted.map((row, i) => (
                <div
                  key={i}
                  className="flex items-center font-mono text-[10.5px] px-3 py-1.5"
                  style={{
                    background: row.hit ? 'rgba(46,227,154,0.10)' : 'transparent',
                    borderTop: '1px solid rgba(255,255,255,0.04)',
                    color: row.hit ? '#2ee39a' : '#c8d0e8',
                  }}
                >
                  <span className="flex-1 truncate">{row.hit ? '★ ' : ''}{row.payload}</span>
                  <span className="w-16 text-right font-semibold" style={{
                    color: row.status_hit ? '#2ee39a'
                      : (row.status_code + '').startsWith('2') ? '#7dd3fc'
                      : (row.status_code + '').startsWith('4') ? '#fbbf24' : '#f87171'
                  }}>{row.status_code}</span>
                  <span className="w-20 text-right" style={{ color: '#5a6680' }}>{row.length}</span>
                  {grepUsed && (
                    <span className="w-16 text-right font-semibold" style={{ color: row.grep_match ? '#2ee39a' : '#5a6680' }}>
                      {row.grep_match ? '✓' : '·'}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
          {hasStatusHit && (
            <div className="font-mono text-[10px] mt-2" style={{ color: '#2ee39a' }}>
              ★ The 302 row is a valid login — that payload is the password. Confirm it in the Repeater tab.
            </div>
          )}
          {grepUsed && hasGrepHit && !hasStatusHit && (
            <div className="font-mono text-[10px] mt-2" style={{ color: '#2ee39a' }}>
              ★ Every response is 401, but the ✓ rows contain "{result.grep}" — those usernames exist
              (invalid ones respond differently). Pick one and brute its password.
            </div>
          )}
          {grepUsed && !hasGrepHit && !hasStatusHit && (
            <div className="font-mono text-[10px] mt-2" style={{ color: '#fbbf24' }}>
              No response matched "{result.grep}". Try a different wordlist or grep string.
            </div>
          )}
          {!grepUsed && !hasStatusHit && (
            <div className="font-mono text-[10px] mt-2" style={{ color: '#fbbf24' }}>
              No status outlier. For username enumeration, add a GREP match string that only valid responses contain
              (length alone is unreliable here — the app reflects the username).
            </div>
          )}
        </div>
      )}
    </div>
  )
}
