import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import RaycastBackground from './RaycastBackground.jsx'

/* ── Shared new-UI homepage hero (Landing + Dashboard) ──
   Box model mirrors Raycast's .page_hero / .page_heroBackground /
   .page_heroText so the WebGL canvas gets the exact same dimensions
   (1200px wide × hero height), making the beam scale identical. */

export default function HomeHero({
  links = [],
  navCta,
  eyebrow = '',
  online = false,
  titleA = 'Detect. Contain.',
  titleB = 'Measure.',
  subtitle,
  primaryCta,
  secondaryCta,
}) {
  const navigate = useNavigate()
  const go = (to) => to && navigate(to)

  return (
    <div className="relative w-full font-sans select-none" style={{ background: '#07080a', height: '100vh', overflowY: 'auto', overflowX: 'hidden' }}>

      {/* ── NAVBAR pill ── */}
      <motion.div
        className="absolute top-6 left-0 right-0 z-50 flex justify-center px-7"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      >
        <div
          className="relative flex w-full max-w-[1200px] items-center justify-between rounded-[18px] border border-white/[0.12] px-7 py-4"
          style={{ background: 'transparent', boxShadow: 'none' }}
        >
          <button onClick={() => go(links[0]?.to)} className="flex items-center gap-3">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ filter: 'drop-shadow(0 0 10px rgba(255,21,53,0.55))' }}>
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535" />
            </svg>
            <span className="text-[20px] font-bold tracking-tight text-white">
              ATT<span style={{ color: '#ff1535' }}>3</span>NSE
            </span>
          </button>

          {/* Centered nav links */}
          <div className="absolute left-1/2 top-1/2 flex -translate-x-1/2 -translate-y-1/2 items-center gap-[26px]">
            {links.map((l) => (
              <button
                key={l.label}
                onClick={() => go(l.to)}
                className="text-[15px] font-medium transition-colors hover:text-white"
                style={{ color: '#9aa4b4' }}
              >
                {l.label}
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* ── HERO section — height defined by text padding (mirrors .page_hero) ── */}
      <section style={{ position: 'relative', width: '100%' }}>

        {/* BACKGROUND: WebGL canvas, inset:0, max-width 1200 centred (.page_heroBackground) */}
        <div style={{ position: 'absolute', top: 0, bottom: 0, left: 0, right: 0, width: '100%', maxWidth: 1200, margin: '0 auto', zIndex: 0 }}>
          <RaycastBackground style={{ width: '100%', height: '100%' }} />
          {/* Exact edge-fade overlay from .page_heroBackground:after */}
          <div
            className="pointer-events-none"
            style={{
              position: 'absolute',
              inset: 0,
              background:
                'linear-gradient(to bottom,#07080a20 0,#07080a20 90%,#07080a 100%) 100% 100% /100% 100% no-repeat,' +
                'linear-gradient(to left,#07080a00 0,#07080a 100%) 0 0 /5% 100% no-repeat,' +
                'linear-gradient(to right,#07080a00 0,#07080a 100%) 100% 0 /5% 100% no-repeat',
            }}
          />
        </div>

        {/* TEXT — padding 370/16/212, max-width 818, gap 32 (.page_heroText) */}
        <motion.div
          initial={{ opacity: 0, y: 28 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
          style={{
            position: 'relative',
            zIndex: 10,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            textAlign: 'center',
            maxWidth: 818,
            margin: '0 auto',
            padding: '370px 16px 212px',
            gap: 32,
          }}
        >
          {/* Eyebrow */}
          {eyebrow && (
            <div className="flex items-center gap-2.5">
              <span
                className="h-[7px] w-[7px] rounded-full"
                style={{
                  background: online ? '#2ee39a' : '#ff1535',
                  boxShadow: online ? '0 0 10px #2ee39a' : '0 0 10px #ff1535',
                }}
              />
              <span style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 11,
                letterSpacing: '0.30em',
                textTransform: 'uppercase',
                color: '#9aa4b4',
              }}>
                {eyebrow}
              </span>
            </div>
          )}

          {/* Headline */}
          <h1 style={{
            fontSize: 'clamp(48px, 6.2vw, 88px)',
            fontWeight: 700,
            lineHeight: 1.02,
            letterSpacing: '-0.025em',
            color: '#ffffff',
            margin: 0,
            textShadow: '0 2px 32px rgba(0,0,0,0.55)',
          }}>
            {titleA}<br />
            <span style={{ color: '#ff1535' }}>{titleB}</span>
          </h1>

          {/* Subtitle */}
          {subtitle && (
            <p style={{
              margin: 0,
              maxWidth: 540,
              fontSize: 18,
              fontWeight: 500,
              lineHeight: 1.55,
              color: 'rgba(255,255,255,0.62)',
              textShadow: '0 1px 12px rgba(0,0,0,0.65)',
              letterSpacing: '0.01em',
            }}>
              {subtitle}
            </p>
          )}

          {/* CTAs */}
          <div className="flex items-center gap-4">
            {primaryCta && (
              <motion.button
                onClick={() => go(primaryCta.to)}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                style={{
                  background: '#ff1535',
                  borderRadius: 12,
                  padding: '14px 28px',
                  fontSize: 13,
                  fontWeight: 700,
                  letterSpacing: '0.13em',
                  color: '#fff',
                  boxShadow: '0 0 24px rgba(255,21,53,0.38)',
                }}
              >
                {primaryCta.label}
              </motion.button>
            )}
            {secondaryCta && (
              <motion.button
                onClick={() => go(secondaryCta.to)}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                style={{
                  borderRadius: 12,
                  border: '1px solid rgba(255,255,255,0.14)',
                  background: 'rgba(255,255,255,0.04)',
                  padding: '14px 28px',
                  fontSize: 13,
                  fontWeight: 700,
                  letterSpacing: '0.13em',
                  color: '#c2c9d4',
                }}
              >
                {secondaryCta.label}
              </motion.button>
            )}
          </div>
        </motion.div>
      </section>
    </div>
  )
}
