import { useEffect } from 'react'

// ─────────────────────────────────────────────────────
//  useLenis — Lenis smooth scroll, integrated with GSAP
//  Call once at App root.
// ─────────────────────────────────────────────────────

export function useLenis() {
  useEffect(() => {
    let lenis = null

    async function init() {
      try {
        const [{ default: Lenis }, { gsap }, { ScrollTrigger }] = await Promise.all([
          import('lenis'),
          import('gsap'),
          import('gsap/ScrollTrigger'),
        ])
        gsap.registerPlugin(ScrollTrigger)

        lenis = new Lenis({ duration: 1.5 })
        lenis.on('scroll', ScrollTrigger.update)

        gsap.ticker.add(time => lenis.raf(time * 1000))
        gsap.ticker.lagSmoothing(0)

        document.documentElement.classList.add('lenis')
      } catch (e) {
        console.warn('Lenis/GSAP init failed:', e)
      }
    }

    init()

    return () => {
      if (lenis) {
        lenis.destroy()
        document.documentElement.classList.remove('lenis', 'lenis-smooth')
      }
    }
  }, [])
}
