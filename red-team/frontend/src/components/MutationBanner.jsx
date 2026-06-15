import { useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export default function MutationBanner({ mutations, onDismiss }) {
  const latest = useMemo(() => {
    if (!mutations || mutations.length === 0) return null
    return mutations[mutations.length - 1]
  }, [mutations])
  const [typed, setTyped] = useState('')

  useEffect(() => {
    if (!latest) return
    const text = latest.taunt || latest.fallback_taunt || latest.description || ''
    setTyped('')
    let i = 0
    const id = window.setInterval(() => {
      i += 1
      setTyped(text.slice(0, i))
      if (i >= text.length) window.clearInterval(id)
    }, 22)
    return () => window.clearInterval(id)
  }, [latest?.id, latest?.mutation_id])

  if (!latest) return null

  const color = latest.color || '#fb923c'

  return (
    <AnimatePresence>
      <motion.div
        key={latest.id || latest.mutation_id}
        initial={{ opacity: 0, y: 72 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 72 }}
        transition={{ duration: 0.36, ease: [0.22, 1, 0.36, 1] }}
        className="fixed bottom-5 left-1/2 z-[70] w-[min(760px,calc(100vw-32px))] -translate-x-1/2 rounded-xl px-4 py-3 shadow-2xl"
        style={{
          background: 'rgba(7,9,15,0.96)',
          border: `1px solid ${color}66`,
          boxShadow: `0 0 34px ${color}22, inset 0 0 18px ${color}0f`,
          backdropFilter: 'blur(16px)',
        }}
      >
        <div className="flex items-start gap-3">
          <div
            className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg font-mono text-[15px] font-bold"
            style={{ color, border: `1px solid ${color}66`, background: `${color}14` }}
          >
            M
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center justify-between gap-3">
              <div className="font-mono text-[9px] font-bold tracking-[0.28em]" style={{ color }}>
                MUTATION ACTIVE
              </div>
              <button
                onClick={onDismiss}
                className="shrink-0 font-mono text-[12px] text-attense-dim transition-colors hover:text-attense-text"
                aria-label="Dismiss mutation banner"
              >
                x
              </button>
            </div>
            <div className="text-[13px] font-semibold text-attense-text">{latest.label}</div>
            <div className="mt-1 font-mono text-[11px] leading-relaxed" style={{ color: '#d8e0f5' }}>
              {typed}
              <motion.span
                animate={{ opacity: [0, 1, 0] }}
                transition={{ duration: 0.75, repeat: Infinity }}
                style={{ color }}
              >
                |
              </motion.span>
            </div>
            <div className="mt-2 text-[11px] leading-relaxed text-attense-dim">
              {latest.objective || latest.description}
            </div>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
