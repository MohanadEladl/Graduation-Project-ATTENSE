/**
 * LabToolsStrip - Terminal / ZAP selector shown only in Lab Mode.
 * Shows real status badges (Running / Offline / Error) instead of static labels.
 */
import { useEffect, useState } from 'react'
import { api } from '../api/client.js'

const STATUS_DOT = {
  running:  '#2ee39a',
  offline:  '#fbbf24',
  stopped:  '#fbbf24',
  error:    '#f87171',
  checking: '#7dd3fc',
}

export default function LabToolsStrip({ selectedTool, onSelect }) {
  const [termStatus, setTermStatus] = useState('checking')
  const [zapStatus, setZapStatus] = useState('checking')

  useEffect(() => {
    const check = () => {
      api.attackbox.status()
        .then(r => setTermStatus(r.status || 'error'))
        .catch(() => setTermStatus('offline'))
      api.zap.status()
        .then(r => setZapStatus(r.status || 'error'))
        .catch(() => setZapStatus('offline'))
    }
    check()
    const iv = setInterval(check, 15000)
    return () => clearInterval(iv)
  }, [])

  const tools = [
    {
      id: 'terminal',
      label: 'Terminal',
      status: termStatus,
      icon: (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="4 17 10 11 4 5"/>
          <line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
      ),
    },
    {
      id: 'zap',
      label: 'ZAP',
      status: zapStatus,
      icon: (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
        </svg>
      ),
    },
  ]

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[9px] tracking-[0.28em] text-attense-dim mr-1">
        LAB TOOLS
      </span>
      {tools.map(t => {
        const active = selectedTool === t.id
        const dotColor = STATUS_DOT[t.status] || STATUS_DOT.error
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onSelect?.(t.id)}
            className="font-mono text-[10px] font-semibold tracking-[0.16em] px-3.5 py-2 rounded-md transition-colors flex items-center gap-1.5"
            style={{
              background: active
                ? 'rgba(125,211,252,0.12)'
                : 'rgba(255,255,255,0.03)',
              color: active ? '#7dd3fc' : '#a8b0cc',
              border: `1px solid ${active ? 'rgba(125,211,252,0.45)' : 'rgba(255,255,255,0.10)'}`,
              cursor: 'pointer',
            }}
            aria-pressed={active}
          >
            {t.icon}
            {t.label.toUpperCase()}
            <span
              className="w-1.5 h-1.5 rounded-full shrink-0 ml-0.5"
              style={{ background: dotColor, boxShadow: `0 0 4px ${dotColor}` }}
              title={`${t.label}: ${t.status}`}
            />
          </button>
        )
      })}
    </div>
  )
}
