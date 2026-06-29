import { useNavigate } from 'react-router-dom'
import {
  ChevronsUpDown,
  LayoutGrid,
  User,
  Lock,
  Home,
  LogOut,
  PanelLeft,
} from 'lucide-react'

const SECTIONS = [
  { key: 'overview', label: 'Overview', icon: LayoutGrid },
  { key: 'account', label: 'Account', icon: User },
  { key: 'security', label: 'Security', icon: Lock },
]

export default function RangeSidebar({
  section,
  onSelect,
  online = false,
  moduleCount = 0,
  collapsed = false,
  onToggle,
}) {
  const navigate = useNavigate()

  return (
    <aside
      className={`flex h-full shrink-0 flex-col overflow-hidden border-r border-[#1a2030] bg-[#0c0f16] text-[#e6e8ee] transition-[width] duration-300 ease-in-out ${
        collapsed ? 'w-14' : 'w-60'
      }`}
    >
      {/* Logo */}
      <div className="flex min-h-[48px] items-center justify-between px-3.5 py-3.5">
        <div
          className={`flex items-center gap-2 overflow-hidden transition-all duration-300 ${
            collapsed ? 'w-0 opacity-0' : 'opacity-100'
          }`}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            style={{ filter: 'drop-shadow(0 0 8px rgba(255,21,53,0.55))', flexShrink: 0 }}
          >
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535" />
          </svg>
          <span className="whitespace-nowrap text-sm font-bold tracking-tight text-white">ATTENSE</span>
        </div>

        {collapsed && (
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            style={{ filter: 'drop-shadow(0 0 8px rgba(255,21,53,0.55))', flexShrink: 0 }}
          >
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535" />
          </svg>
        )}

        <button
          onClick={onToggle}
          className="flex-shrink-0 rounded p-0.5 text-[#7a8699] transition-colors hover:bg-white/[0.06] hover:text-white"
        >
          <PanelLeft
            className={`h-4 w-4 transition-transform duration-300 ${collapsed ? 'rotate-180' : ''}`}
          />
        </button>
      </div>

      {/* Project switcher */}
      {collapsed ? (
        <div className="mx-auto mb-1 mt-1 flex justify-center">
          <span className="block h-[18px] w-[18px] rounded-full bg-gradient-to-br from-[#ff1535] to-[#8b2fff]" />
        </div>
      ) : (
        <div className="mx-2 mb-1 flex items-center gap-2 rounded-lg px-3 py-2">
          <span className="h-[18px] w-[18px] flex-shrink-0 rounded-full bg-gradient-to-br from-[#ff1535] to-[#8b2fff]" />
          <span className="text-xs text-white">Red Team</span>
          <span className="rounded bg-[#1a2030] px-1.5 py-px text-[9px] text-[#7a8699]">range</span>
          <ChevronsUpDown className="ml-auto h-3.5 w-3.5 text-[#4a5363]" />
        </div>
      )}

      {/* Settings sections */}
      <div className="mt-3.5 px-2">
        {!collapsed && (
          <div className="mb-1.5 px-2 text-[10px] tracking-wide text-[#4a5363]">Settings</div>
        )}
        {SECTIONS.map(s => {
          const Icon = s.icon
          const active = section === s.key
          return (
            <button
              key={s.key}
              onClick={() => onSelect?.(s.key)}
              title={collapsed ? s.label : undefined}
              className={`flex w-full items-center rounded-lg px-2 py-1.5 text-left text-xs transition-colors ${
                collapsed ? 'justify-center' : 'gap-2.5'
              } ${
                active
                  ? 'bg-[rgba(255,21,53,0.12)] text-white'
                  : 'text-[#7a8699] hover:bg-white/[0.04] hover:text-white'
              }`}
              style={active ? { boxShadow: 'inset 0 0 0 1px rgba(255,21,53,0.3)' } : undefined}
            >
              <Icon className={`h-[15px] w-[15px] flex-shrink-0 ${active ? 'text-[#ff1535]' : ''}`} />
              {!collapsed && s.label}
            </button>
          )
        })}
      </div>

      {/* Range health */}
      {collapsed ? (
        <div className="mx-auto mt-4">
          <span
            className="block h-2 w-2 rounded-full"
            title={online ? 'Range online' : 'Range offline'}
            style={{
              background: online ? '#2ee39a' : '#f87171',
              boxShadow: `0 0 6px ${online ? 'rgba(46,227,154,0.6)' : 'rgba(248,113,113,0.6)'}`,
            }}
          />
        </div>
      ) : (
        <div className="mx-2.5 mt-4 rounded-lg border border-[#1a2030] bg-[#10141d] p-3">
          <div className="mb-1.5 flex items-center gap-2">
            <span
              className="h-2 w-2 rounded-full"
              style={{
                background: online ? '#2ee39a' : '#f87171',
                boxShadow: `0 0 6px ${online ? 'rgba(46,227,154,0.6)' : 'rgba(248,113,113,0.6)'}`,
              }}
            />
            <h4 className="text-xs font-medium text-white">Range {online ? 'online' : 'offline'}</h4>
          </div>
          <p className="text-[11px] leading-snug text-[#7a8699]">
            {online
              ? `${moduleCount} lab module${moduleCount === 1 ? '' : 's'} loaded and ready to launch.`
              : 'Backend unreachable — start the range to see live telemetry.'}
          </p>
        </div>
      )}

      {/* Footer */}
      <div className="mt-auto border-t border-[#1a2030] p-2">
        <button
          onClick={() => navigate('/')}
          title={collapsed ? 'Back to Range' : undefined}
          className={`flex w-full items-center rounded-lg px-2 py-1.5 text-left text-xs text-[#7a8699] transition-colors hover:bg-white/[0.04] hover:text-white ${
            collapsed ? 'justify-center' : 'gap-2.5'
          }`}
        >
          <Home className="h-[15px] w-[15px]" />
          {!collapsed && 'Back to Range'}
        </button>
        <button
          onClick={() => navigate('/login')}
          title={collapsed ? 'Log out' : undefined}
          className={`flex w-full items-center rounded-lg px-2 py-1.5 text-left text-xs text-[#7a8699] transition-colors hover:bg-white/[0.04] hover:text-white ${
            collapsed ? 'justify-center' : 'gap-2.5'
          }`}
        >
          <LogOut className="h-[15px] w-[15px]" />
          {!collapsed && 'Log out'}
        </button>
      </div>
    </aside>
  )
}
