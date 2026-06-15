/**
 * ModeSwitcher — two large mode buttons placed under the mission top toolbar.
 *
 *   [ GUIDED MODE ]   [ OPERATOR MODE ]
 *
 * Guided:   rich walkthrough with explanations — browser iframe is active.
 * Operator: real pentesting via AttackBox terminal/ZAP — iframe is locked.
 *
 * Switching modes does NOT restart the mission or reset evidence.
 */
export default function ModeSwitcher({ mode, onChange }) {
  const isGuided   = mode === 'tutorial'
  const isOperator = mode === 'lab'

  const baseClass =
    'font-mono text-[11px] font-bold tracking-[0.18em] px-6 py-2.5 rounded-lg ' +
    'transition-all duration-150 flex items-center gap-2'

  const activeStyle = {
    background: 'linear-gradient(135deg,#7dd3fc,#0ea5e9)',
    color: '#0c0f16',
    border: '1px solid transparent',
    boxShadow: '0 0 14px rgba(14,165,233,0.32)',
    cursor: 'pointer',
  }

  const inactiveStyle = {
    background: 'rgba(255,255,255,0.03)',
    color: '#a8b0cc',
    border: '1px solid rgba(255,255,255,0.10)',
    cursor: 'pointer',
  }

  return (
    <div className="flex items-center gap-2.5">
      <button
        type="button"
        onClick={() => onChange?.('tutorial')}
        className={baseClass}
        style={isGuided ? activeStyle : inactiveStyle}
        aria-pressed={isGuided}
        title="Guided Mode: step-by-step walkthrough with explanations"
      >
        {/* Book icon */}
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z"/>
          <path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z"/>
        </svg>
        GUIDED MODE
      </button>
      <button
        type="button"
        onClick={() => onChange?.('lab')}
        className={baseClass}
        style={isOperator ? activeStyle : inactiveStyle}
        aria-pressed={isOperator}
        title="Operator Mode: use real tools — Terminal, curl, hydra, ZAP"
      >
        {/* Terminal icon */}
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="4 17 10 11 4 5"/>
          <line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
        OPERATOR MODE
      </button>
    </div>
  )
}
