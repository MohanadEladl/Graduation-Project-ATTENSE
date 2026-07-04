/**
 * ZapWorkspace — standalone desktop-style ZAP tool, opened in its own window
 * (window.open) from the Red Team workspace but still bound to the active Red
 * Team session via ?session_id=&module_id=&mode= query params. Every request it
 * makes carries those, so evidence/reports stay linked to the mission.
 *
 * Strictly local: all traffic is scoped to target-agent (backend-enforced).
 */
import { useSearchParams } from 'react-router-dom'
import { useZapController } from '../components/zap/useZapController.js'
import { STATUS_STYLES } from '../components/zap/zapUtils.js'
import ZapHistory from '../components/zap/ZapHistory.jsx'
import ZapInspector from '../components/zap/ZapInspector.jsx'
import ZapRepeater from '../components/zap/ZapRepeater.jsx'
import ZapFuzzer from '../components/zap/ZapFuzzer.jsx'

const TABS = [
  { id: 'history',   label: 'Proxy History' },
  { id: 'inspector', label: 'Inspector' },
  { id: 'repeater',  label: 'Repeater' },
  { id: 'fuzzer',    label: 'Fuzzer' },
  { id: 'help',      label: 'Notes / Help' },
]

function ConnField({ label, value, color = '#c8d0e8' }) {
  return (
    <div className="flex flex-col">
      <span className="font-mono text-[8px] tracking-[0.22em] text-attense-dim">{label}</span>
      <span className="font-mono text-[11px]" style={{ color }}>{value || '—'}</span>
    </div>
  )
}

export default function ZapWorkspace() {
  const [params] = useSearchParams()
  const sessionId = params.get('session_id') || ''
  const moduleId  = params.get('module_id') || ''
  const mode      = params.get('mode') || 'operator'

  // Live-ish history: poll every 3s while this window is open.
  const c = useZapController({ sessionId, moduleId, mode, pollMs: 3000 })
  const s = STATUS_STYLES[c.status] || STATUS_STYLES.error

  return (
    <div className="min-h-screen w-full flex flex-col" style={{ background: '#0a0d13', color: '#c8d0e8' }}>
      {/* Top connection bar */}
      <div className="shrink-0 flex items-center justify-between gap-6 px-6 py-3"
        style={{ background: 'rgba(0,0,0,0.5)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[12px] font-bold tracking-[0.2em]" style={{ color: '#7dd3fc' }}>OWASP ZAP</span>
          <span className="font-mono text-[8.5px] tracking-[0.2em] px-1.5 py-0.5 rounded"
            style={{ color: s.color, background: s.bg, border: `1px solid ${s.bd}` }}>{c.status.toUpperCase()}</span>
          {c.zapVersion && <span className="font-mono text-[8.5px] text-attense-dim">v{c.zapVersion}</span>}
        </div>
        <div className="flex items-center gap-6">
          <ConnField label="SESSION" value={sessionId} color="#7dd3fc" />
          <ConnField label="MODULE" value={moduleId} />
          <ConnField label="MODE" value={mode} />
          <ConnField label="TARGET" value="target-agent (local only)" color="#2ee39a" />
          <button onClick={c.refreshHistory}
            className="font-mono text-[10px] tracking-[0.12em] px-3 py-1.5 rounded-md"
            style={{ background: 'rgba(125,211,252,0.12)', border: '1px solid rgba(125,211,252,0.35)', color: '#7dd3fc' }}>
            ⟳ REFRESH
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="shrink-0 flex items-center gap-1 px-6 pt-2"
        style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        {TABS.map(t => {
          const active = c.activeTab === t.id
          return (
            <button key={t.id} onClick={() => c.setActiveTab(t.id)}
              className="font-mono text-[10.5px] tracking-[0.16em] px-4 py-2 rounded-t-md"
              style={{
                background: active ? 'rgba(125,211,252,0.08)' : 'transparent',
                color: active ? '#7dd3fc' : '#7a8194',
                border: active ? '1px solid rgba(125,211,252,0.25)' : '1px solid transparent',
                borderBottom: 'none',
              }}>{t.label}</button>
          )
        })}
      </div>

      {/* Body */}
      <div className="flex-1 min-h-0 overflow-y-auto px-6 py-5" style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
        {c.status !== 'running' ? (
          <div className="max-w-2xl rounded-lg px-4 py-3"
            style={{ background: 'rgba(250,204,21,0.06)', border: '1px solid rgba(250,204,21,0.2)', color: '#fbbf24' }}>
            <div className="font-mono text-[11px] font-semibold mb-1">
              ZAP is {c.status === 'checking' ? 'connecting…' : 'offline'}
            </div>
            <div className="font-mono text-[10.5px] text-attense-dim">
              The OWASP ZAP container must be running. Start it with
              <code className="block mt-1 text-attense-text">docker compose up zap</code>
            </div>
          </div>
        ) : c.activeTab === 'history' ? (
          <ZapHistory messages={c.messages} isOperatorMode={c.isOperatorMode}
            onInspect={c.sendToInspector} onRepeater={c.sendToRepeater} onFuzzer={c.sendToFuzzer} />
        ) : c.activeTab === 'inspector' ? (
          <ZapInspector message={c.selectedMsg} onSendToRepeater={c.sendToRepeater} onSendToFuzzer={c.sendToFuzzer} />
        ) : c.activeTab === 'repeater' ? (
          <ZapRepeater c={c} />
        ) : c.activeTab === 'fuzzer' ? (
          <ZapFuzzer c={c} />
        ) : (
          <HelpTab />
        )}
      </div>
    </div>
  )
}

function HelpTab() {
  return (
    <div className="font-mono text-[11px] leading-relaxed max-w-2xl" style={{ color: '#c8d0e8' }}>
      <div className="text-[9px] tracking-[0.3em] text-attense-dim mb-2">NOTES / HELP</div>
      <ul className="space-y-2 list-disc pl-5">
        <li><b>Proxy History</b> records every request — Operator browser traffic (proxied through ZAP), plus your Repeater and Fuzzer requests.</li>
        <li>Each history row has <b>Inspect</b>, <b>Send to Repeater</b> and <b>Send to Fuzzer</b> buttons.</li>
        <li><b>Repeater</b> replays one editable request. <b>Fuzzer</b> replaces a § marker with each payload (Sniper).</li>
        <li>Operator missions complete from approved local tools: <b>Repeater / Fuzzer / validator-safe AttackBox</b> against <code>/op/...</code> routes. Browsing is useful for capture and visibility, but exploit completion must come from those tools.</li>
        <li>All traffic is local-only — <b>target-agent</b> is the only allowed host. External URLs are blocked.</li>
      </ul>
    </div>
  )
}
