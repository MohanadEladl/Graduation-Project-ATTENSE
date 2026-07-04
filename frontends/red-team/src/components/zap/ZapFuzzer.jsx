/**
 * ZapFuzzer — Burp-Intruder-style sniper fuzzer. Mark a value with §, pick a
 * payload list, replay each through ZAP against the local target, read the
 * status/length/grep outlier. Populated by "Send to Fuzzer" (body preserved).
 */
import { FUZZER_PRESETS, statusColor } from './zapUtils.js'

const SectionLabel = ({ n, children }) => (
  <div className="font-mono text-[9px] tracking-[0.28em] mb-2 flex items-center gap-2" style={{ color: '#7dd3fc' }}>
    <span className="rounded-full w-4 h-4 inline-flex items-center justify-center text-[8px]"
      style={{ background: 'rgba(125,211,252,0.12)', border: '1px solid rgba(125,211,252,0.35)' }}>{n}</span>
    {children}
  </div>
)

export default function ZapFuzzer({ c }) {
  const result = c.fuzResult
  const rows = result?.status === 'ok' ? (result.results || []) : []
  const count = c.fuzList.split('\n').map(s => s.trim()).filter(Boolean).length
  const markerOk = c.fuzBody.includes('§')
  const grepUsed = Boolean(result?.grep)

  const sorted = [...rows]
  if (c.fuzSort === 'status') sorted.sort((a, b) => (a.status_code + '').localeCompare(b.status_code + ''))
  else if (c.fuzSort === 'length') sorted.sort((a, b) => a.length - b.length)

  const hasStatusHit = rows.some(r => r.status_hit)
  const hasGrepHit = rows.some(r => r.grep_hit)

  const Header = ({ col, label, w }) => (
    <button onClick={() => c.setFuzSort(c.fuzSort === col ? 'order' : col)}
      className={`${w} text-right font-mono text-[9px] tracking-[0.16em]`}
      style={{ color: c.fuzSort === col ? '#7dd3fc' : '#5a6680', cursor: 'pointer' }}
      title="Click to sort">{label}{c.fuzSort === col ? ' ▲' : ''}</button>
  )

  return (
    <div className="font-mono">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[9px] tracking-[0.3em] text-attense-dim">FUZZER · target-agent only</div>
        <span className="text-[8.5px] tracking-[0.18em] px-2 py-0.5 rounded"
          style={{ color: '#c9a5ff', background: 'rgba(168,120,255,0.08)', border: '1px solid rgba(168,120,255,0.3)' }}>
          ATTACK TYPE · SNIPER
        </span>
      </div>

      <SectionLabel n="1">POSITIONS · mark the value to attack with §</SectionLabel>
      <div className="flex items-center gap-2 mb-2">
        <select value={c.fuzMethod} onChange={e => c.setFuzMethod(e.target.value)}
          className="text-[11px] px-2 py-1.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8', outline: 'none' }}>
          {['POST', 'GET', 'PUT', 'PATCH'].map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <div className="flex-1 flex items-center rounded overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.1)' }}>
          <span className="text-[10px] px-2 py-1.5 shrink-0" style={{ color: '#5a6680', background: 'rgba(255,255,255,0.02)' }}>http://target-agent</span>
          <input value={c.fuzPath} onChange={e => c.setFuzPath(e.target.value)}
            className="flex-1 text-[11px] px-2 py-1.5 bg-transparent outline-none" style={{ color: '#d0d8e8' }}
            placeholder={c.defaultAuthPath} />
        </div>
      </div>
      <textarea value={c.fuzBody} onChange={e => c.setFuzBody(e.target.value)} rows={2}
        className="w-full text-[11px] px-3 py-2 rounded mb-1 resize-y"
        style={{ background: 'rgba(255,255,255,0.02)', border: `1px solid ${markerOk ? 'rgba(255,255,255,0.08)' : 'rgba(248,113,113,0.4)'}`, color: '#d0d8e8', outline: 'none' }}
        placeholder="username=admin&password=§" />
      {!markerOk && (
        <div className="text-[9.5px] mb-2" style={{ color: '#f87171' }}>
          Add a § where the payload should go, e.g. username=admin&password=§
        </div>
      )}
      {markerOk && c.fuzMarkerNote && (
        <div className="text-[9.5px] mb-2" style={{ color: '#fbbf24' }}>{c.fuzMarkerNote}</div>
      )}

      <div className="mt-4"><SectionLabel n="2">PAYLOADS · simple list</SectionLabel></div>
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        {Object.entries(FUZZER_PRESETS).map(([key, p]) => (
          <button key={key} onClick={() => c.selectPreset(key)}
            className="text-[9px] tracking-[0.1em] px-2 py-1 rounded"
            style={{
              background: c.fuzPreset === key ? 'rgba(125,211,252,0.12)' : 'rgba(255,255,255,0.03)',
              color: c.fuzPreset === key ? '#7dd3fc' : '#8a92a8',
              border: `1px solid ${c.fuzPreset === key ? 'rgba(125,211,252,0.35)' : 'rgba(255,255,255,0.08)'}`,
            }}>{p.label}</button>
        ))}
      </div>
      <textarea value={c.fuzList} onChange={e => c.setFuzList(e.target.value)} rows={4}
        className="w-full text-[11px] px-3 py-2 rounded mb-3 resize-y"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', color: '#d0d8e8', outline: 'none' }}
        placeholder="one payload per line" />

      <div className="flex items-center gap-2 mb-3">
        <span className="text-[9px] tracking-[0.16em] shrink-0" style={{ color: '#5a6680' }}>GREP · MATCH</span>
        <input value={c.fuzGrep} onChange={e => c.setFuzGrep(e.target.value)}
          className="flex-1 text-[11px] px-2 py-1.5 rounded bg-transparent outline-none"
          style={{ border: '1px solid rgba(255,255,255,0.1)', color: '#d0d8e8' }}
          placeholder="optional — a string to match in responses" />
      </div>

      <button onClick={c.runFuzzer} disabled={c.fuzLoading || !markerOk}
        className="text-[10px] font-bold tracking-[0.12em] px-4 py-2 rounded-md"
        style={{ background: (c.fuzLoading || !markerOk) ? 'rgba(125,211,252,0.06)' : 'rgba(125,211,252,0.12)', border: '1px solid rgba(125,211,252,0.35)', color: '#7dd3fc', cursor: (c.fuzLoading || !markerOk) ? 'not-allowed' : 'pointer' }}>
        {c.fuzLoading ? `ATTACKING ${count} PAYLOADS…` : `START ATTACK · ${count} payloads`}
      </button>

      {result && result.status !== 'ok' && (
        <div className="text-[10.5px] mt-3" style={{ color: result.status === 'blocked' ? '#fbbf24' : '#f87171' }}>
          {result.status === 'blocked' ? 'Blocked: ' : 'Error: '}{result.detail || 'unknown'}
        </div>
      )}
      {rows.length > 0 && (
        <div className="mt-5">
          <SectionLabel n="3">RESULTS · sort by Status or Length to find the outlier</SectionLabel>
          <div className="rounded-lg overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex items-center px-3 py-1.5" style={{ background: 'rgba(255,255,255,0.03)' }}>
              <span className="flex-1 text-[9px] tracking-[0.16em]" style={{ color: '#5a6680' }}>PAYLOAD</span>
              <Header col="status" label="STATUS" w="w-16" />
              <Header col="length" label="LENGTH" w="w-20" />
              {grepUsed && <span className="w-16 text-right text-[9px] tracking-[0.16em]" style={{ color: '#5a6680' }}>MATCH</span>}
            </div>
            <div style={{ maxHeight: 240, overflow: 'auto' }}>
              {sorted.map((row, i) => (
                <div key={i} className="flex items-center text-[10.5px] px-3 py-1.5"
                  style={{ background: row.hit ? 'rgba(46,227,154,0.10)' : 'transparent', borderTop: '1px solid rgba(255,255,255,0.04)', color: row.hit ? '#2ee39a' : '#c8d0e8' }}>
                  <span className="flex-1 truncate">{row.hit ? '★ ' : ''}{row.payload}</span>
                  <span className="w-16 text-right font-semibold" style={{ color: row.status_hit ? '#2ee39a' : statusColor(row.status_code) }}>{row.status_code}</span>
                  <span className="w-20 text-right" style={{ color: '#5a6680' }}>{row.length}</span>
                  {grepUsed && <span className="w-16 text-right font-semibold" style={{ color: row.grep_match ? '#2ee39a' : '#5a6680' }}>{row.grep_match ? '✓' : '·'}</span>}
                </div>
              ))}
            </div>
          </div>
          {hasStatusHit && (
            <div className="text-[10px] mt-2" style={{ color: '#2ee39a' }}>
              ★ The 302 row is a valid login — that payload is the password. Confirm it in the Repeater tab.
            </div>
          )}
          {grepUsed && hasGrepHit && !hasStatusHit && (
            <div className="text-[10px] mt-2" style={{ color: '#2ee39a' }}>
              ★ The ✓ rows contain "{result.grep}" — those usernames exist. Pick one and brute its password.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
