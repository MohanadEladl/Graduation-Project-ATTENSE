/**
 * LabPanel - host for the currently-selected Lab tool. Lives directly below
 * the Lab Browser only when Lab Mode is active.
 */
import TerminalPanel from './TerminalPanel.jsx'
import ZapLauncher from './zap/ZapLauncher.jsx'

export default function LabPanel({
  selectedTool,
  activeStep,
  minimized,
  onToggleMinimize,
  sessionId,
  moduleId,
  mode,
}) {
  if (selectedTool === 'zap') {
    // ZAP now opens as a separate desktop-style workspace (window.open) instead
    // of being squeezed into the browser column. This is a compact launcher.
    return (
      <ZapLauncher
        minimized={minimized}
        onToggleMinimize={onToggleMinimize}
        sessionId={sessionId}
        moduleId={moduleId}
        mode={mode}
      />
    )
  }
  return (
    <TerminalPanel
      activeStep={activeStep}
      minimized={minimized}
      onToggleMinimize={onToggleMinimize}
      sessionId={sessionId}
      moduleId={moduleId}
    />
  )
}
