import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useAnimate, stagger } from 'framer-motion'

// Cubic-bezier equivalents for GSAP power eases (from lukebaffait.fr/js/index.js)
const POWER3_OUT   = [0.215, 0.61, 0.355, 1]
const POWER3_INOUT = [0.645, 0.045, 0.355, 1]
const POWER2_OUT   = [0.25, 0.46, 0.45, 0.94]

const WORD = 'GAUNTLET'
const TEXT_GRADIENT = 'linear-gradient(180deg, #ffffff 0%, #d4dcf0 42%, #8190b0 100%)'

export default function GauntletIntro({ onDone }) {
  const [scope, animate] = useAnimate()

  useEffect(() => {
    const finish = () => onDone?.()
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) { finish(); return }

    let cancelled = false
    const fallback = setTimeout(() => { if (!cancelled) finish() }, 7000)

    const run = async () => {
      if (cancelled) return

      // ── Set initial states instantly ──
      await animate([
        ['.gi-char',      { y: '110%' },               { duration: 0 }],
        ['#gi-dot',       { opacity: 0 },              { duration: 0, at: 0 }],
        ['#gi-panel-dark',{ y: '100%' },               { duration: 0, at: 0 }],
        ['#gi-panel-red', { y: '100%' },               { duration: 0, at: 0 }],
        ['#gi-wordmark',  { scale: 1, y: '0%', opacity: 1 }, { duration: 0, at: 0 }],
      ])

      // 0.2s initial delay
      await new Promise(r => setTimeout(r, 200))

      // ── 1. Letters roll up, staggered from center ──
      await animate('.gi-char', { y: '0%' }, {
        duration: 0.4,
        ease: POWER3_OUT,
        delay: stagger(0.025, { from: 'center' }),
      })

      // ── 2. Red dot accent fades in ──
      await animate('#gi-dot', { opacity: 1 }, { duration: 0.25, ease: POWER2_OUT })

      // ── 3. Pause ──
      await new Promise(r => setTimeout(r, 300))

      // ── 4. Wordmark scales up and moves to bottom (the cinematic move) ──
      //    On the real site the wordmark grows to fill the viewport width and
      //    lands near the bottom — the panels sweep in to cover it mid-motion.
      const vh = window.innerHeight
      const vw = window.innerWidth
      // Target: fill viewport width. Estimate wordmark natural width from fontSize.
      const fontSize = Math.min(104, vw * 0.09)
      const wordmarkW = WORD.length * fontSize * 1.25   // rough em-width per char
      const targetW   = vw - (vw < 768 ? 40 : 96)      // padding matches real site
      const targetScale = Math.max(1, targetW / wordmarkW)
      // Move to bottom-ish (mirrors the real site's bottomPad calc)
      const bottomPad = vw < 768 ? Math.max(vh * 0.18, 110) : 80
      const targetY   = vh / 2 - bottomPad - (fontSize * targetScale) / 2

      const wordmarkAnim = animate('#gi-wordmark',
        { scale: targetScale, y: targetY },
        { duration: 0.75, ease: POWER3_INOUT }
      )

      // Dark panel sweeps up 0.05s after wordmark move starts (matches '<+=0.05')
      await new Promise(r => setTimeout(r, 50))
      const darkUp = animate('#gi-panel-dark', { y: '0%' }, { duration: 0.45, ease: POWER3_INOUT })

      // Red panel starts 0.3s before dark panel ends (matches '-=0.3'):
      // dark ends at 0.05 + 0.45 = 0.5s → red starts at 0.5 - 0.3 = 0.2s after dark starts
      await new Promise(r => setTimeout(r, 200))
      const redUp = animate('#gi-panel-red', { y: '0%' }, { duration: 0.45, ease: POWER3_INOUT })

      // Wait for all three to settle
      await Promise.all([wordmarkAnim, darkUp, redUp])

      // ── 5. Hide only the intro bg — wordmark stays VISIBLE above the panels
      //    (gi-name is z-index 5, above panels at 3/4, so it shows on the red) ──
      await animate('#gi-bg', { opacity: 0 }, { duration: 0 })

      // ── 6. Panels wipe upward while wordmark reverses back to center ──
      await new Promise(r => setTimeout(r, 50))

      const redWipe  = animate('#gi-panel-red',  { y: '-100%' }, { duration: 0.55, ease: POWER3_INOUT })
      // Wordmark flies back to original scale/position as panels clear
      const wordmarkReverse = animate('#gi-wordmark',
        { scale: 1, y: '0%' },
        { duration: 0.6, ease: POWER3_INOUT }
      )

      // Dark starts 0.4s before red wipe ends = 0.15s after red wipe starts
      await new Promise(r => setTimeout(r, 150))
      const darkWipe = animate('#gi-panel-dark', { y: '-100%' }, { duration: 0.55, ease: POWER3_INOUT })

      await Promise.all([redWipe, darkWipe, wordmarkReverse])

      // ── 7. Fade out intro wordmark — hero's static GAUNTLET is now underneath ──
      await animate('#gi-wordmark', { opacity: 0 }, { duration: 0.2, ease: POWER2_OUT })
    }

    run()
      .then(() => { if (!cancelled) finish() })
      .catch(() => { if (!cancelled) finish() })

    return () => {
      cancelled = true
      clearTimeout(fallback)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const overlay = (
    <div ref={scope} aria-hidden="true" style={{ position: 'fixed', inset: 0, zIndex: 99999, pointerEvents: 'none' }}>

      {/* black intro backdrop */}
      <div id="gi-bg" style={{ position: 'absolute', inset: 0, background: '#0a0a0a', zIndex: 1 }} />

      {/* centered wordmark — z-index 5 keeps it ABOVE both panels (3/4) at all times */}
      <div
        id="gi-name"
        style={{ position: 'absolute', inset: 0, zIndex: 5, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      >
        <div
          id="gi-wordmark"
          style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', transformOrigin: 'center center' }}
        >
          <div style={{ display: 'flex', flexWrap: 'nowrap' }}>
            {WORD.split('').map((ch, i) => (
              <span
                key={i}
                style={{
                  display: 'inline-block', overflow: 'hidden',
                  padding: '0.15em 0.3em', margin: '-0.15em -0.3em',
                  fontFamily: "'Rajdhani', sans-serif",
                  fontSize: 'clamp(56px, 9vw, 104px)',
                  fontWeight: 700, letterSpacing: '0.12em', lineHeight: 1,
                }}
              >
                <span
                  className="gi-char"
                  style={{
                    display: 'inline-block', transform: 'translateY(110%)',
                    background: TEXT_GRADIENT,
                    WebkitBackgroundClip: 'text', backgroundClip: 'text',
                    WebkitTextFillColor: 'transparent', color: 'transparent',
                  }}
                >
                  {ch}
                </span>
              </span>
            ))}
          </div>

          {/* Red dot accent — mirrors pDot from the real site */}
          <div
            id="gi-dot"
            style={{
              width: 8, height: 8, borderRadius: '50%',
              background: '#ff1535',
              boxShadow: '0 0 14px rgba(255,21,53,0.9)',
              marginTop: 18, opacity: 0,
            }}
          />
        </div>
      </div>

      {/* transition panels */}
      <div id="gi-panel-dark" style={{ position: 'absolute', inset: 0, background: '#0a0a0a', transform: 'translateY(100%)', zIndex: 3 }} />
      <div id="gi-panel-red"  style={{ position: 'absolute', inset: 0, background: '#ff1535', transform: 'translateY(100%)', zIndex: 4 }} />
    </div>
  )

  return createPortal(overlay, document.body)
}
