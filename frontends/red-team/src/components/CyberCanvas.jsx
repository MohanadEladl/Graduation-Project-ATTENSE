// Animated cyber network canvas background
import { useEffect, useRef } from 'react'

export function CyberCanvas({ className = '' }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let raf
    let W, H
    const NODES = 52
    const MAX_DIST = 155
    const nodes = []

    function resize() {
      W = canvas.width  = canvas.offsetWidth
      H = canvas.height = canvas.offsetHeight
    }

    function init() {
      nodes.length = 0
      for (let i = 0; i < NODES; i++) {
        nodes.push({
          x:     Math.random() * W,
          y:     Math.random() * H,
          vx:    (Math.random() - 0.5) * 0.32,
          vy:    (Math.random() - 0.5) * 0.32,
          r:     Math.random() * 2.2 + 1,
          type:  Math.random() < 0.5 ? 0 : Math.random() < 0.5 ? 1 : 2,
          pulse: Math.random() * Math.PI * 2,
        })
      }
      // central target node
      nodes.push({ x: W / 2, y: H / 2, vx: 0, vy: 0, r: 5, type: 3, pulse: 0 })
    }

    const COLORS = [
      { line: 'rgba(255,21,53,',   dot: '#ff1535', glow: 'rgba(255,21,53,0.6)' },
      { line: 'rgba(139,47,255,',  dot: '#8b2fff', glow: 'rgba(139,47,255,0.5)' },
      { line: 'rgba(0,200,255,',   dot: '#00c8ff', glow: 'rgba(0,200,255,0.5)' },
    ]

    function draw(t) {
      ctx.clearRect(0, 0, W, H)

      // grid
      ctx.strokeStyle = 'rgba(255,255,255,0.016)'
      ctx.lineWidth = 1
      const g = 56
      for (let x = 0; x < W; x += g) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke() }
      for (let y = 0; y < H; y += g) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke() }

      // move
      for (const n of nodes) {
        if (n.type === 3) continue
        n.x += n.vx; n.y += n.vy
        if (n.x < 0 || n.x > W) n.vx *= -1
        if (n.y < 0 || n.y > H) n.vy *= -1
        n.pulse += 0.022
      }

      // edges
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j]
          const dx = a.x - b.x, dy = a.y - b.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < MAX_DIST) {
            const alpha = (1 - dist / MAX_DIST) * 0.25
            const ci = Math.min(a.type === 3 ? b.type : a.type, 2)
            ctx.beginPath()
            ctx.strokeStyle = COLORS[ci].line + alpha + ')'
            ctx.lineWidth = (1 - dist / MAX_DIST) * 1.1
            ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
          }
        }
      }

      // nodes
      for (const n of nodes) {
        const p = 0.7 + Math.sin(n.pulse) * 0.3
        if (n.type === 3) {
          // target glow
          const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, 30)
          grad.addColorStop(0, 'rgba(255,21,53,0.28)')
          grad.addColorStop(1, 'rgba(255,21,53,0)')
          ctx.beginPath(); ctx.arc(n.x, n.y, 30, 0, Math.PI * 2)
          ctx.fillStyle = grad; ctx.fill()

          ctx.beginPath(); ctx.arc(n.x, n.y, 5, 0, Math.PI * 2)
          ctx.fillStyle = '#ff1535'
          ctx.shadowBlur = 18; ctx.shadowColor = '#ff1535'; ctx.fill(); ctx.shadowBlur = 0

          for (let r = 1; r <= 3; r++) {
            ctx.beginPath()
            ctx.arc(n.x, n.y, r * 14 + Math.sin(t / 900 + r) * 3, 0, Math.PI * 2)
            ctx.strokeStyle = `rgba(255,21,53,${0.14 - r * 0.04})`
            ctx.lineWidth = 1; ctx.stroke()
          }
        } else {
          const c = COLORS[Math.min(n.type, 2)]
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r * p, 0, Math.PI * 2)
          ctx.fillStyle = c.dot
          ctx.shadowBlur = 5; ctx.shadowColor = c.glow; ctx.fill(); ctx.shadowBlur = 0
        }
      }

      raf = requestAnimationFrame(draw)
    }

    resize(); init(); raf = requestAnimationFrame(draw)

    const ro = new ResizeObserver(() => { resize(); init() })
    ro.observe(canvas)
    return () => { cancelAnimationFrame(raf); ro.disconnect() }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 w-full h-full pointer-events-none ${className}`}
    />
  )
}
