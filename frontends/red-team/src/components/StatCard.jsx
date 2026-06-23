import { useEffect, useMemo, useRef, useState } from 'react'
import { motion, animate, useInView } from 'framer-motion'

export function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return r ? `${parseInt(r[1], 16)},${parseInt(r[2], 16)},${parseInt(r[3], 16)}` : '255,255,255'
}

function AnimatedNumber({ target, suffix = '' }) {
  const [display, setDisplay] = useState(0)
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-30px' })
  useEffect(() => {
    if (!inView) return
    const ctrl = animate(0, target, {
      duration: 1.6,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: v => setDisplay(Math.round(v)),
    })
    return ctrl.stop
  }, [target, inView])
  return <span ref={ref}>{display}{suffix}</span>
}

function Sparkline({ seed, color }) {
  const bars = useMemo(() => {
    let s = (seed + 3) * 137 + 42
    return Array.from({ length: 10 }, () => {
      s = (s * 16807) % 2147483647
      return 0.14 + (s / 2147483647) * 0.86
    })
  }, [seed])
  return (
    <svg width="64" height="22" viewBox="0 0 64 22" aria-hidden="true">
      {bars.map((h, i) => (
        <motion.rect
          key={i}
          x={i * 7}
          y={22 - h * 20}
          width={5}
          height={h * 20}
          fill={color}
          rx={1.5}
          initial={{ scaleY: 0 }}
          animate={{ scaleY: 1 }}
          transition={{ delay: 0.7 + i * 0.045, duration: 0.35, ease: 'easeOut' }}
          style={{ transformOrigin: `${i * 7 + 2.5}px 22px`, opacity: 0.15 + (i / 9) * 0.55 }}
        />
      ))}
    </svg>
  )
}

export function StatCard({ label, numericValue, suffix, sub, color, icon, index }) {
  const [hov, setHov] = useState(false)

  return (
    <motion.div
      style={{ flex: 1, minWidth: 0 }}
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.18 + index * 0.08, duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      onHoverStart={() => setHov(true)}
      onHoverEnd={() => setHov(false)}
    >
      <motion.div
        className="relative rounded-xl overflow-hidden cursor-default h-full"
        style={{
          background: hov
            ? `linear-gradient(145deg, rgba(12,15,22,0.98) 0%, rgba(9,11,18,0.98) 100%)`
            : 'rgba(9,11,18,0.96)',
          backdropFilter: 'blur(18px)',
          boxShadow: hov
            ? `0 0 0 1px ${color}66, 0 0 40px ${color}22, 0 16px 40px rgba(0,0,0,0.55)`
            : `0 0 0 1px ${color}22, 0 4px 16px rgba(0,0,0,0.3)`,
          transition: 'box-shadow 0.3s ease, background 0.3s ease',
        }}
        animate={{ y: hov ? -5 : 0 }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
      >
        {/* animated top border */}
        <motion.div
          className="absolute top-0 left-0 right-0"
          style={{ height: 1.5 }}
          animate={{
            background: hov
              ? `linear-gradient(90deg, transparent 0%, ${color}cc 40%, ${color}ff 50%, ${color}cc 60%, transparent 100%)`
              : `linear-gradient(90deg, transparent, ${color}44, transparent)`,
          }}
          transition={{ duration: 0.3 }}
        />

        {/* corner accent brackets */}
        <div className="absolute top-2 left-2 w-3 h-3 pointer-events-none"
          style={{ borderTop: `1px solid ${color}44`, borderLeft: `1px solid ${color}44` }} />
        <div className="absolute top-2 right-2 w-3 h-3 pointer-events-none"
          style={{ borderTop: `1px solid ${color}44`, borderRight: `1px solid ${color}44` }} />
        <div className="absolute bottom-2 left-2 w-3 h-3 pointer-events-none"
          style={{ borderBottom: `1px solid ${color}44`, borderLeft: `1px solid ${color}44` }} />
        <div className="absolute bottom-2 right-2 w-3 h-3 pointer-events-none"
          style={{ borderBottom: `1px solid ${color}44`, borderRight: `1px solid ${color}44` }} />

        {/* ambient radial glow */}
        <motion.div
          className="absolute inset-0 pointer-events-none"
          animate={{
            background: hov
              ? `radial-gradient(ellipse 100% 90% at 80% 100%, ${color}1c, transparent 65%)`
              : `radial-gradient(ellipse 80% 70% at 80% 100%, ${color}0d, transparent 65%)`,
          }}
          transition={{ duration: 0.3 }}
        />

        <div className="relative p-5">
          {/* label + icon */}
          <div className="flex justify-between items-start mb-4">
            <span className="font-mono text-[9px] tracking-[0.3em] uppercase" style={{ color: '#28334a' }}>
              {label}
            </span>
            <motion.div
              animate={{
                opacity: hov ? 1 : 0.45,
                scale: hov ? 1.15 : 1,
                filter: hov ? `drop-shadow(0 0 6px ${color})` : 'none',
              }}
              transition={{ duration: 0.2 }}
              style={{ color }}
            >
              {icon}
            </motion.div>
          </div>

          {/* big number */}
          <div
            className="font-mono font-bold leading-none mb-1"
            style={{
              fontSize: 38,
              color: '#edf0f8',
              textShadow: hov ? `0 0 30px ${color}70` : 'none',
              transition: 'text-shadow 0.3s',
              fontVariantNumeric: 'tabular-nums',
              letterSpacing: '-0.02em',
            }}
          >
            <AnimatedNumber target={numericValue} suffix={suffix} />
          </div>

          {/* sub + sparkline */}
          <div className="flex items-end justify-between mt-3.5">
            <span className="text-[10.5px]" style={{ color: '#263040' }}>{sub}</span>
            <Sparkline seed={numericValue} color={color} />
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}
