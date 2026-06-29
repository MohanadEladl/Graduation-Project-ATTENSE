/**
 * LabPanel - host for the currently-selected Lab tool. Lives directly below
 * the Lab Browser only when Lab Mode is active.
 */
import TerminalPanel from './TerminalPanel.jsx'
import ZapPanel from './ZapPanel.jsx'

export default function LabPanel({ selectedTool, activeStep, minimized, onToggleMinimize }) {
  if (selectedTool === 'zap') return <ZapPanel activeStep={activeStep} minimized={minimized} onToggleMinimize={onToggleMinimize} />
  return <TerminalPanel activeStep={activeStep} minimized={minimized} onToggleMinimize={onToggleMinimize} />
}
