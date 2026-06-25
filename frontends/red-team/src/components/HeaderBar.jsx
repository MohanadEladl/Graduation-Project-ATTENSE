export function HeaderBar({ connected, moduleCount, target }) {
  return (
    <header className="relative flex items-center justify-between px-5 py-3 border-b border-attense-border bg-attense-panel/60 backdrop-blur-xl">
      <div className="flex items-center gap-3">
        {/* Mark */}
        <div className="relative">
          <svg width="28" height="32" viewBox="0 0 26 32" fill="none" aria-hidden="true">
            <path d="M13 0 L26 5.5 V19 C26 25.5 13 32 13 32 S0 25.5 0 19 V5.5 Z" fill="#ff2b3a" />
            <rect x="2.5" y="0.5" width="21" height="3" fill="#ffa724" opacity="0.88" />
            <path d="M13 3 L23.5 7.5 V19 C23.5 24.5 13 30 13 30 S2.5 24.5 2.5 19 V7.5 Z" fill="#1a0000" opacity="0.55" />
          </svg>
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-attense-red rounded-full animate-pulse-slow shadow-glow-red" />
        </div>

        <div>
          <div className="font-sans font-semibold tracking-[0.22em] text-[13px] leading-none text-attense-text">
            ATTENSE
          </div>
          <div className="font-mono text-[9.5px] tracking-[0.32em] text-attense-muted mt-1">
            CYBER·LAB · v3.0
          </div>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <Chip label="MODULES" value={moduleCount ?? '—'} />
        <Chip label="TARGET" value={target ? `${target.host}:${target.port}` : '—'} />
        <div className="flex items-center gap-2">
          <span
            className="dot"
            style={{ color: connected ? '#2ee39a' : '#ff2b3a' }}
          />
          <span className={'text-[10px] font-mono tracking-[0.22em] ' + (connected ? 'text-attense-mint' : 'text-attense-red')}>
            {connected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>
      </div>
    </header>
  )
}

function Chip({ label, value }) {
  return (
    <div className="hidden md:flex items-center gap-2 text-[10px] font-mono">
      <span className="text-attense-muted tracking-[0.28em]">{label}</span>
      <span className="text-attense-text tracking-wider">{value}</span>
    </div>
  )
}
