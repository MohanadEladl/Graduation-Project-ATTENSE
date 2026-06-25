import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { api } from '../api/client.js'

/**
 * VariantPicker — lets the learner choose an attack variant for a module.
 *
 * Props:
 *   moduleId    — string  ("brute_force", etc.)
 *   value       — string  active variant_id (controlled)
 *   onChange    — fn(variant_id) called when learner picks one
 *   compact     — bool    render in a compact horizontal layout
 *
 * Fetches /api/modules/{module_id}/variants once on mount.
 */
export function VariantPicker({ moduleId, value, onChange, compact = false }) {
  const [variants, setVariants] = useState([])
  const [loading,  setLoading]  = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.variants(moduleId)
      .then(r => { if (!cancelled) { setVariants(r.variants || []); setLoading(false) } })
      .catch(() => { if (!cancelled) { setVariants([]); setLoading(false) } })
    return () => { cancelled = true }
  }, [moduleId])

  // Auto-pick first variant if nothing chosen
  useEffect(() => {
    if (!loading && variants.length && !value) onChange?.(variants[0].variant_id)
  }, [loading, variants, value, onChange])

  if (loading) {
    return (
      <div className="font-mono text-[10px] tracking-widest text-attense-dim py-2">
        LOADING VARIANTS…
      </div>
    )
  }

  if (variants.length === 0) {
    return (
      <div className="font-mono text-[10px] text-attense-dim italic py-2">
        No variants available for this module.
      </div>
    )
  }

  const diffColor = (d) => ({
    Easy:   '#2ee39a',
    Medium: '#facc15',
    Hard:   '#ff4060',
  })[d] || '#94a3b8'

  return (
    <div className="space-y-2">
      <div className="font-mono text-[9px] tracking-[0.28em] text-attense-dim mb-1">
        ATTACK VARIANT
      </div>
      <div className={compact ? 'flex gap-2 flex-wrap' : 'space-y-2'}>
        {variants.map(v => {
          const sel = value === v.variant_id
          const col = diffColor(v.difficulty)
          return (
            <motion.button
              key={v.variant_id}
              onClick={() => onChange?.(v.variant_id)}
              className="text-left rounded-lg"
              style={{
                background: sel ? `rgba(${hexToRgb(col)},0.07)` : 'rgba(255,255,255,0.018)',
                border:     `1px solid ${sel ? col + '55' : 'rgba(255,255,255,0.06)'}`,
                padding: compact ? '10px 14px' : '12px 14px',
                minWidth: compact ? 200 : 'auto',
                flex: compact ? '1 1 auto' : undefined,
                transition: 'background 0.15s, border-color 0.15s',
              }}
              whileHover={{ background: `rgba(${hexToRgb(col)},0.1)`, borderColor: col + '55' }}
              whileTap={{ scale: 0.985 }}
            >
              <div className="flex items-center gap-2 mb-1">
                <div
                  className="shrink-0 rounded-full"
                  style={{
                    width: 12, height: 12,
                    border: `2px solid ${sel ? col : 'rgba(255,255,255,0.14)'}`,
                    background: sel ? col : 'transparent',
                  }}
                />
                <span className="text-[12.5px] font-semibold" style={{ color: sel ? '#edf0f8' : '#c0c5db' }}>
                  {v.name}
                </span>
                <span className="font-mono text-[8.5px] tracking-[0.15em] px-1.5 py-0.5 rounded ml-auto"
                  style={{ background: `${col}11`, border: `1px solid ${col}33`, color: col }}>
                  {(v.difficulty || 'MED').toUpperCase()}
                </span>
              </div>
              <div className="text-[11px] leading-relaxed ml-5" style={{ color: '#7a8699' }}>
                {v.description}
              </div>
              {Array.isArray(v.techniques) && v.techniques.length > 0 && (
                <div className="mt-1.5 ml-5 flex gap-1.5 flex-wrap">
                  {v.techniques.slice(0, 4).map(t => (
                    <span key={t} className="font-mono text-[8.5px] tracking-wider"
                      style={{ color: '#3a4060' }}>
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}

function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return r ? `${parseInt(r[1],16)},${parseInt(r[2],16)},${parseInt(r[3],16)}` : '255,255,255'
}
