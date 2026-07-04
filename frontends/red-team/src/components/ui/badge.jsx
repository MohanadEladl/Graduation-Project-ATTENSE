import * as React from 'react'
import { cva } from 'class-variance-authority'
import { cn } from '../../lib/utils.js'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded font-mono text-[9px] font-bold uppercase tracking-[0.12em] px-2 py-0.5 border whitespace-nowrap',
  {
    variants: {
      tone: {
        red:     'text-attense-red    border-attense-red/30    bg-attense-red/10',
        violet:  'text-attense-violet border-attense-violet/30 bg-attense-violet/10',
        amber:   'text-attense-amber  border-attense-amber/30  bg-attense-amber/10',
        mint:    'text-attense-mint   border-attense-mint/30   bg-attense-mint/10',
        cyan:    'text-attense-cyan   border-attense-cyan/30   bg-attense-cyan/10',
        neutral: 'text-attense-dim    border-white/10          bg-white/[0.03]',
      },
    },
    defaultVariants: { tone: 'neutral' },
  }
)

const Badge = React.forwardRef(({ className, tone, ...props }, ref) => (
  <span ref={ref} className={cn(badgeVariants({ tone }), className)} {...props} />
))
Badge.displayName = 'Badge'

export { Badge, badgeVariants }
