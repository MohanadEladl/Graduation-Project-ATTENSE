import { useEffect, useRef } from 'react'

// ─────────────────────────────────────────────────────
//  useCaseTilt — 3D tilt effect for case cards
//  Pass a ref to the card element; the hook applies
//  GSAP-style perspective rotateX/Y on mousemove.
// ─────────────────────────────────────────────────────

const TILT_MAX  = 14  // degrees
const PERSP     = 900 // px
const EASE      = 0.1 // lerp factor per frame

export function useCaseTilt(cardRef) {
  const target = useRef({ rx: 0, ry: 0 })
  const current = useRef({ rx: 0, ry: 0 })
  const rafRef  = useRef(null)

  useEffect(() => {
    const el = cardRef.current
    if (!el) return

    function onMove(e) {
      const { left, top, width, height } = el.getBoundingClientRect()
      const cx = left + width  / 2
      const cy = top  + height / 2
      const mx = (e.clientX - cx) / (width  / 2)
      const my = (e.clientY - cy) / (height / 2)
      target.current.rx = -my * TILT_MAX
      target.current.ry =  mx * TILT_MAX
    }

    function onLeave() {
      target.current.rx = 0
      target.current.ry = 0
    }

    function loop() {
      const t = target.current
      const c = current.current
      c.rx += (t.rx - c.rx) * EASE
      c.ry += (t.ry - c.ry) * EASE
      el.style.transform = `perspective(${PERSP}px) rotateX(${c.rx.toFixed(3)}deg) rotateY(${c.ry.toFixed(3)}deg)`
      rafRef.current = requestAnimationFrame(loop)
    }

    el.addEventListener('mousemove', onMove)
    el.addEventListener('mouseleave', onLeave)
    rafRef.current = requestAnimationFrame(loop)

    return () => {
      el.removeEventListener('mousemove', onMove)
      el.removeEventListener('mouseleave', onLeave)
      cancelAnimationFrame(rafRef.current)
      el.style.transform = ''
    }
  }, [cardRef])
}
