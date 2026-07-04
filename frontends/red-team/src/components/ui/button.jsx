import * as React from 'react'
import { cva } from 'class-variance-authority'
import { cn } from '../../lib/utils.js'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg font-mono text-[11px] font-bold tracking-[0.08em] transition-all disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default:
          'text-white shadow-[0_0_14px_rgba(255,21,53,0.3)] bg-[linear-gradient(135deg,#ff1535,#cc0020)] hover:shadow-[0_0_20px_rgba(255,21,53,0.45)]',
        outline:
          'border border-white/10 text-attense-dim hover:text-attense-text hover:border-white/20 hover:bg-white/[0.03]',
        ghost:
          'text-attense-dim hover:text-attense-text hover:bg-white/[0.03]',
      },
      size: {
        default: 'h-9 px-4',
        sm:      'h-7 px-3 text-[10px]',
      },
      active: {
        true: '',
        false: '',
      },
    },
    compoundVariants: [
      {
        variant: 'outline',
        active: true,
        class: 'border-attense-red/30 bg-attense-red/[0.12] text-attense-red',
      },
    ],
    defaultVariants: { variant: 'default', size: 'default', active: false },
  }
)

const Button = React.forwardRef(({ className, variant, size, active, ...props }, ref) => (
  <button ref={ref} className={cn(buttonVariants({ variant, size, active }), className)} {...props} />
))
Button.displayName = 'Button'

export { Button, buttonVariants }
