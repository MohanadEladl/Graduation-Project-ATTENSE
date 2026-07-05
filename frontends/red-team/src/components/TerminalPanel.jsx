/**
 * TerminalPanel — Lab Mode terminal with real AttackBox integration.
 *
 * Connects to the local ATTENSE AttackBox container via the backend API.
 * Commands are executed inside the attackbox container and restricted to
 * the local target-agent only — no external hosts allowed.
 */
import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'

const STATUS_STYLES = {
  running: { color: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.25)' },
  stopped: { color: '#fbbf24', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.25)' },
  offline: { color: '#fbbf24', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.25)' },
  error:   { color: '#f87171', bg: 'rgba(248,113,113,0.06)', bd: 'rgba(248,113,113,0.25)' },
  checking:{ color: '#7dd3fc', bg: 'rgba(125,211,252,0.06)', bd: 'rgba(125,211,252,0.25)' },
}

const TOOLS = ['nmap', 'hydra', 'curl', 'ffuf', 'gobuster', 'jq', 'python3', 'nc']

const WELCOME_LINES = [
  { tag: 'info',    text: '┌─────────────────────────────────────────────┐' },
  { tag: 'info',    text: '│  ATTENSE AttackBox — Local Lab Console      │' },
  { tag: 'info',    text: '└─────────────────────────────────────────────┘' },
  { tag: 'dim',     text: '' },
  { tag: 'success', text: '  Approved target: http://target-agent' },
  { tag: 'dim',     text: `  Available tools: ${TOOLS.join(', ')}` },
  { tag: 'dim',     text: '  Wordlists: /wordlists/ (also /opt/wordlists/)' },
  { tag: 'dim',     text: '  Type a command and press Enter. External targets are blocked.' },
  { tag: 'dim',     text: '' },
]

export default function TerminalPanel({ minimized, onToggleMinimize }) {
  const [status, setStatus] = useState('checking')
  const [statusDetail, setStatusDetail] = useState('')
  const [lines, setLines] = useState(WELCOME_LINES)
  const [cmd, setCmd] = useState('')
  const [running, setRunning] = useState(false)
  const [history, setHistory] = useState([])
  const [histIdx, setHistIdx] = useState(-1)
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  // Check status on mount + every 15s
  useEffect(() => {
    const check = () => {
      api.attackbox.status()
        .then(r => { setStatus(r.status || 'error'); setStatusDetail(r.detail || '') })
        .catch(() => { setStatus('offline'); setStatusDetail('Backend unavailable') })
    }
    check()
    const iv = setInterval(check, 15000)
    return () => clearInterval(iv)
  }, [])

  // Auto-scroll
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [lines])

  const addLine = (tag, text) => setLines(prev => [...prev, { tag, text }])

  const handleExec = async () => {
    const trimmed = cmd.trim()
    if (!trimmed || running) return

    addLine('cmd', `lab@attense:~/lab$ ${trimmed}`)
    setHistory(h => [trimmed, ...h.slice(0, 50)])
    setHistIdx(-1)
    setCmd('')
    setRunning(true)

    try {
      const result = await api.attackbox.exec(trimmed)
      if (result.status === 'blocked') {
        addLine('error', `⛔ ${result.output}`)
      } else if (result.status === 'ok') {
        if (result.output) {
          result.output.split('\n').forEach(l => addLine('output', l))
        }
        if (result.exit_code && result.exit_code !== 0) {
          addLine('dim', `(exit code: ${result.exit_code})`)
        }
      } else if (result.status === 'timeout') {
        addLine('error', `⏱ ${result.output}`)
      } else {
        addLine('error', `Error: ${result.output || result.detail || 'unknown error'}`)
      }
    } catch (e) {
      addLine('error', `Network error: ${e.message}`)
    }
    setRunning(false)
    inputRef.current?.focus()
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleExec()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (history.length > 0) {
        const next = Math.min(histIdx + 1, history.length - 1)
        setHistIdx(next)
        setCmd(history[next])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histIdx > 0) {
        setHistIdx(histIdx - 1)
        setCmd(history[histIdx - 1])
      } else {
        setHistIdx(-1)
        setCmd('')
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setLines(WELCOME_LINES)
    }
  }

  const s = STATUS_STYLES[status] || STATUS_STYLES.error

  const LINE_COLORS = {
    info:    '#9ae4ff',
    dim:     '#5a6680',
    cmd:     '#c8d0e8',
    output:  '#d0d8e8',
    error:   '#f87171',
    success: '#2ee39a',
    blocked: '#fbbf24',
  }

  return (
    <div
      className="h-full w-full flex flex-col overflow-hidden"
      style={{ background: '#0a0d13', borderTop: '1px solid rgba(255,255,255,0.06)' }}
      onClick={() => inputRef.current?.focus()}
    >
      {/* Header bar */}
      <div
        className="shrink-0 flex items-center justify-between px-4 py-2"
        style={{ background: 'rgba(0,0,0,0.45)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center gap-2.5">
          <span className="flex gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: '#ff5b66' }} />
            <span className="w-2 h-2 rounded-full" style={{ background: '#ffa724' }} />
            <span className="w-2 h-2 rounded-full" style={{ background: '#2ee39a' }} />
          </span>
          <span className="font-mono text-[10px] tracking-[0.22em] text-attense-text">
            ATTENSE ATTACKBOX
          </span>
          <span
            className="font-mono text-[8.5px] tracking-[0.20em] px-1.5 py-0.5 rounded"
            style={{ color: s.color, background: s.bg, border: `1px solid ${s.bd}` }}
          >
            {status.toUpperCase()}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9px] tracking-[0.2em] text-attense-dim">
            local-only · target-agent
          </span>
          <button
            onClick={(e) => { e.stopPropagation(); setLines(WELCOME_LINES) }}
            className="font-mono text-[9px] tracking-[0.14em] text-attense-dim hover:text-attense-text transition-colors px-1.5 py-0.5 rounded"
            style={{ border: '1px solid rgba(255,255,255,0.08)' }}
            title="Clear terminal (Ctrl+L)"
          >CLEAR</button>
          <button
            onClick={(e) => { e.stopPropagation(); onToggleMinimize?.() }}
            className="text-attense-dim hover:text-attense-text transition-colors px-1.5 py-0.5 rounded flex items-center"
            style={{ border: '1px solid rgba(255,255,255,0.08)' }}
            title={minimized ? 'Maximize terminal' : 'Minimize terminal'}
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

      {/* Terminal output */}
      <div
        ref={scrollRef}
        className="flex-1 min-h-0 overflow-y-auto px-4 py-3 font-mono text-[11.5px] leading-[1.55]"
        style={{ background: '#0a0d13' }}
      >
        {lines.map((l, i) => (
          <div key={i} style={{ color: LINE_COLORS[l.tag] || '#d0d8e8', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {l.text}
          </div>
        ))}

        {status !== 'running' && (
          <div className="mt-3 rounded px-3 py-2" style={{
            background: 'rgba(248,113,113,0.06)',
            border: '1px solid rgba(248,113,113,0.2)',
            color: '#f87171',
          }}>
            AttackBox backend unavailable.{statusDetail ? ` ${statusDetail}` : ''}
          </div>
        )}

        {/* Input line */}
        {status === 'running' && (
          <div className="mt-1 flex items-center gap-0">
            <span style={{ color: '#7dd3fc' }}>lab@attense</span>
            <span style={{ color: '#5a6680' }}>:</span>
            <span style={{ color: '#9be8c5' }}>~/lab</span>
            <span style={{ color: '#5a6680' }}>$ </span>
            <input
              ref={inputRef}
              value={cmd}
              onChange={e => setCmd(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={running}
              className="flex-1 bg-transparent outline-none font-mono text-[11.5px]"
              style={{ color: '#d0d8e8', caretColor: '#ff2b3a' }}
              placeholder={running ? 'running…' : 'type a command…'}
              autoFocus
            />
            {running && (
              <span className="inline-block w-2 h-3.5 ml-1" style={{
                background: '#ff2b3a', animation: 'blink 1s steps(1) infinite',
              }} />
            )}
          </div>
        )}
      </div>

      <style>{`@keyframes blink{50%{opacity:0}}`}</style>
    </div>
  )
}
