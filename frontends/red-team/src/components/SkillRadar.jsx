import { useState } from 'react'
import { motion } from 'framer-motion'

const NUM_AXES = 7
const CX_OFFSET = -Math.PI / 2

function axisAngle(i) {
  return CX_OFFSET + (2 * Math.PI * i) / NUM_AXES
}

function pt(cx, cy, r, score, i) {
  const a = axisAngle(i)
  return {
    x: cx + r * (score / 100) * Math.cos(a),
    y: cy + r * (score / 100) * Math.sin(a),
  }
}

function polyPath(points) {
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ') + ' Z'
}

function ringPath(cx, cy, r, frac) {
  const pts = Array.from({ length: NUM_AXES }, (_, i) => {
    const a = axisAngle(i)
    return { x: cx + r * frac * Math.cos(a), y: cy + r * frac * Math.sin(a) }
  })
  return polyPath(pts)
}

export function SkillRadar({ data = [], size = 300, onModuleClick }) {
  const [hoveredIdx, setHoveredIdx] = useState(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })

  const cx = size / 2
  const cy = size / 2
  const maxR = size / 2 - 40

  const scorePts = data.map((d, i) => pt(cx, cy, maxR, d.score || 0, i))
  const scorePath = scorePts.length === NUM_AXES ? polyPath(scorePts) : ''

  const rings = [0.25, 0.5, 0.75, 1.0]

  return (
    <div style={{ position: 'relative', display: 'inline-block', width: size, height: size }}>
      <svg width={size} height={size} style={{ display: 'block' }}>
        {/* rings */}
        {rings.map((frac) => (
          <path
            key={frac}
            d={ringPath(cx, cy, maxR, frac)}
            fill="none"
            stroke="rgba(255,255,255,0.08)"
            strokeWidth={1}
          />
        ))}

        {/* axes */}
        {data.map((_, i) => {
          const a = axisAngle(i)
          return (
            <line
              key={i}
              x1={cx}
              y1={cy}
              x2={(cx + maxR * Math.cos(a)).toFixed(2)}
              y2={(cy + maxR * Math.sin(a)).toFixed(2)}
              stroke="rgba(255,255,255,0.08)"
              strokeWidth={1}
            />
          )
        })}

        {/* score polygon */}
        {scorePath && (
          <motion.path
            d={scorePath}
            fill="rgba(255,21,53,0.15)"
            stroke="rgba(255,21,53,0.7)"
            strokeWidth={1.5}
            strokeLinejoin="round"
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            style={{ transformOrigin: `${cx}px ${cy}px` }}
          />
        )}

        {/* axis dots + dashed ring for untested */}
        {data.map((d, i) => {
          const a = axisAngle(i)
          const tipX = (cx + maxR * Math.cos(a)).toFixed(2)
          const tipY = (cy + maxR * Math.sin(a)).toFixed(2)
          const p = scorePts[i]
          return (
            <g key={i}>
              {d.score === 0 && (
                <circle
                  cx={tipX}
                  cy={tipY}
                  r={8}
                  fill="none"
                  stroke="rgba(255,21,53,0.35)"
                  strokeWidth={1}
                  strokeDasharray="3 2"
                />
              )}
              <circle
                cx={p.x.toFixed(2)}
                cy={p.y.toFixed(2)}
                r={3}
                fill={d.score > 0 ? '#ff1535' : 'rgba(255,21,53,0.3)'}
                style={{ cursor: onModuleClick ? 'pointer' : 'default' }}
                onMouseEnter={(e) => {
                  setHoveredIdx(i)
                  const rect = e.currentTarget.closest('svg').getBoundingClientRect()
                  setTooltipPos({ x: e.clientX - rect.left, y: e.clientY - rect.top })
                }}
                onMouseLeave={() => setHoveredIdx(null)}
                onClick={() => onModuleClick && onModuleClick(d.module_id)}
              />
            </g>
          )
        })}

        {/* axis labels */}
        {data.map((d, i) => {
          const a = axisAngle(i)
          const lx = cx + (maxR + 16) * Math.cos(a)
          const ly = cy + (maxR + 16) * Math.sin(a)
          const anchor = Math.cos(a) > 0.1 ? 'start' : Math.cos(a) < -0.1 ? 'end' : 'middle'
          return (
            <text
              key={i}
              x={lx.toFixed(2)}
              y={ly.toFixed(2)}
              textAnchor={anchor}
              dominantBaseline="middle"
              fontFamily="'JetBrains Mono', 'Courier New', monospace"
              fontSize={9}
              fill="#4a5280"
              style={{ cursor: onModuleClick ? 'pointer' : 'default' }}
              onClick={() => onModuleClick && onModuleClick(d.module_id)}
            >
              {d.label || d.module_id}
            </text>
          )
        })}
      </svg>

      {/* hover tooltip */}
      {hoveredIdx !== null && data[hoveredIdx] && (
        <div
          style={{
            position: 'absolute',
            left: tooltipPos.x + 10,
            top: tooltipPos.y - 10,
            background: 'rgba(8,10,17,0.96)',
            border: '1px solid rgba(255,21,53,0.3)',
            borderRadius: 8,
            padding: '8px 10px',
            pointerEvents: 'none',
            zIndex: 10,
            minWidth: 140,
          }}
        >
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#ff1535', marginBottom: 4, letterSpacing: '0.08em' }}>
            {data[hoveredIdx].label || data[hoveredIdx].module_id}
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#4a5280', marginBottom: 4 }}>
            score: {data[hoveredIdx].score ?? 0}
          </div>
          {(data[hoveredIdx].variants || []).map((v) => (
            <div key={v.variant_id} style={{ fontFamily: 'monospace', fontSize: 9, color: '#6a7898', lineHeight: 1.6 }}>
              {v.name}: {v.best_score ?? 0} ({v.best_grade ?? '—'}) ×{v.attempts ?? 0}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
