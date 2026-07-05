import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { api } from '../api/client.js'

/* ── New-UI app shell ──
   Top nav pill (mirrors HomeHero's navbar) + scrollable content.
   Replaces the old Sidebar/AppLayout chrome across every inner page. */

const NAV = [
  { to: '/missions',  label: 'Missions'  },
  { to: '/modules',   label: 'Modules'   },
  { to: '/gauntlet',  label: 'Gauntlet'  },
  { to: '/reports',   label: 'Reports'   },
  { to: '/settings',  label: 'Settings'  },
]

export function RangeLayout() {
  const navigate = useNavigate()
  const [health, setHealth] = useState({ ok: false, modules: 0 })

  // Poll /health every 5s for the online indicator
  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const h = await api.health()
        if (!cancelled) setHealth(h)
      } catch {
        if (!cancelled) setHealth({ ok: false, modules: 0 })
      }
    }
    poll()
    const t = setInterval(poll, 5000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  return (
    <div
      id="app-shell"
      className="h-full w-full flex flex-col overflow-hidden font-sans"
      style={{ background: '#07080a', position: 'relative', isolation: 'isolate' }}
    >
      {/* Subtle red glow behind app chrome */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: -1,
          pointerEvents: 'none',
          background: 'radial-gradient(60% 50% at 50% 0%, rgba(184,2,50,0.16) 0%, rgba(255,22,42,0.05) 40%, transparent 70%)',
        }}
      />

      {/* ── NAVBAR pill ── */}
      <header className="shrink-0 flex justify-center px-7 pt-6 pb-4 relative z-50">
        <motion.div
          className="relative flex w-full max-w-[1200px] items-center justify-between rounded-[18px] border border-white/[0.12] px-7 py-4"
          style={{ background: 'transparent', boxShadow: 'none' }}
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* Brand */}
          <button onClick={() => navigate('/dashboard')} className="flex items-center gap-3">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ filter: 'drop-shadow(0 0 10px rgba(255,21,53,0.55))' }}>
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535" />
            </svg>
            <span className="text-[20px] font-bold tracking-tight text-white">
              ATT<span style={{ color: '#ff1535' }}>3</span>NSE
            </span>
          </button>

          {/* Centered nav links */}
          <div className="absolute left-1/2 top-1/2 flex -translate-x-1/2 -translate-y-1/2 items-center gap-[26px]">
            {NAV.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                className="text-[15px] font-medium transition-colors hover:text-white"
                style={({ isActive }) => ({ color: isActive ? '#ffffff' : '#9aa4b4' })}
              >
                {l.label}
              </NavLink>
            ))}
          </div>
        </motion.div>
      </header>

      {/* ── Page content (full width — pages manage their own padding/height) ── */}
      <main className="flex-1 min-h-0 overflow-y-auto animate-fade-up">
        <Outlet />
      </main>
    </div>
  )
}
