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
  // Both tools stay mounted at all times — only the inactive one is hidden via
  // CSS. Switching tabs used to conditionally render ONE OR THE OTHER, which
  // unmounts the non-selected component; TerminalPanel's command history lives
  // only in its own React state, so unmounting it (e.g. by switching to ZAP
  // and back) wiped it. Keeping both mounted preserves that state across tab
  // switches.
  return (
    <>
      <div style={{ display: selectedTool === 'zap' ? 'contents' : 'none' }}>
        <ZapLauncher
          minimized={minimized}
          onToggleMinimize={onToggleMinimize}
          sessionId={sessionId}
          moduleId={moduleId}
          mode={mode}
        />
      </div>
      <div style={{ display: selectedTool === 'zap' ? 'none' : 'contents' }}>
        <TerminalPanel
          activeStep={activeStep}
          minimized={minimized}
          onToggleMinimize={onToggleMinimize}
          sessionId={sessionId}
          moduleId={moduleId}
        />
      </div>
    </>
  )
}
