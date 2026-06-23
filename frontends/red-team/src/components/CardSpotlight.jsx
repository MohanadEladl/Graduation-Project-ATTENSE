// Ported from Aceternity UI (card-spotlight) — JSX adaptation.
// Source: https://ui.aceternity.com/components/card-spotlight
import { useMotionValue, motion, useMotionTemplate } from 'framer-motion'
import React, { useState } from 'react'
import { CanvasRevealEffect } from './CanvasRevealEffect.jsx'

const cn = (...c) => c.filter(Boolean).join(' ')

export const CardSpotlight = ({
  children,
  radius = 350,
  color = '#1a1f2e',
  dotColors = [[59, 130, 246], [139, 92, 246]],
  className,
  ...props
}) => {
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)

  function handleMouseMove({ currentTarget, clientX, clientY }) {
    const { left, top } = currentTarget.getBoundingClientRect()
    mouseX.set(clientX - left)
    mouseY.set(clientY - top)
  }

  const [isHovering, setIsHovering] = useState(false)

  return (
    <div
      className={cn(
        'group/spotlight relative rounded-xl border border-white/[0.07] bg-attense-panel overflow-hidden',
        className
      )}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
      {...props}
    >
      <motion.div
        className="pointer-events-none absolute z-0 -inset-px rounded-xl opacity-0 transition duration-300 group-hover/spotlight:opacity-100"
        style={{
          backgroundColor: color,
          maskImage: useMotionTemplate`
            radial-gradient(
              ${radius}px circle at ${mouseX}px ${mouseY}px,
              white,
              transparent 80%
            )
          `,
        }}
      >
        {isHovering && (
          <CanvasRevealEffect
            animationSpeed={5}
            containerClassName="bg-transparent absolute inset-0 pointer-events-none"
            colors={dotColors}
            dotSize={3}
          />
        )}
      </motion.div>
      {children}
    </div>
  )
}
