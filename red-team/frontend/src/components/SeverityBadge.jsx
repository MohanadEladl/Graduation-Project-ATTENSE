const COLOR = {
  critical: 'text-attense-violet border-attense-violet/50 bg-attense-violet/10',
  high:     'text-attense-red    border-attense-red/50    bg-attense-red/10',
  medium:   'text-attense-amber  border-attense-amber/50  bg-attense-amber/10',
  low:      'text-attense-mint   border-attense-mint/50   bg-attense-mint/10',
  info:     'text-attense-muted  border-attense-border    bg-attense-panel2',
}

export function SeverityBadge({ severity, className = '' }) {
  const sev = (severity || 'info').toLowerCase()
  const cls = COLOR[sev] || COLOR.info
  return (
    <span className={
      'inline-flex items-center text-[9px] uppercase tracking-[0.22em] px-2 py-0.5 ' +
      'rounded border font-mono font-semibold ' + cls + ' ' + className
    }>
      {sev}
    </span>
  )
}

export const CATEGORY_ICON = {
  'Reconnaissance':  '⊕',
  'Authentication':  '✦',
  'Injection':       '⎇',
  'Web Application': '◉',
  'File System':     '⌘',
}

// Real Lucide icons (the set shadcn ships with) keyed by category.
import { Radar, KeyRound, Syringe, Globe, FolderTree, ShieldAlert } from 'lucide-react'

export const CATEGORY_LUCIDE = {
  'Reconnaissance':  Radar,
  'Authentication':  KeyRound,
  'Injection':       Syringe,
  'Web Application': Globe,
  'File System':     FolderTree,
}

export const CategoryIcon = ({ category, ...props }) => {
  const Icon = CATEGORY_LUCIDE[category] || ShieldAlert
  return <Icon {...props} />
}
