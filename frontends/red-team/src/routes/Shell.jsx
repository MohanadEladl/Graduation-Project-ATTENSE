import { useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useShell }      from '../hooks/useShell.js'
import { TerminalView }  from '../components/Terminal.jsx'
import { ModuleList }    from '../components/ModuleList.jsx'
import { TargetConfig }  from '../components/TargetConfig.jsx'
import { StatusPanel }   from '../components/StatusPanel.jsx'

export default function Shell() {
  const termRef = useRef(null)
  const [params, setParams] = useSearchParams()
  const autoUse = params.get('use')
  const { connected, snapshot, sendLine, onOutput, onPrompt } = useShell()

  useEffect(() => {
    const offOut = onOutput((line) => termRef.current?.writeOutput(line))
    const offP   = onPrompt((p)    => termRef.current?.setPrompt(p))
    return () => { offOut(); offP() }
  }, [onOutput, onPrompt])

  // Auto-run `use <module>` when the user arrives from a "Start Lab" click.
  // Fires once per navigation; clears the query string so refresh is a no-op.
  useEffect(() => {
    if (!autoUse || !connected) return
    const t = setTimeout(() => {
      sendLine(`use ${autoUse}`)
      termRef.current?.focus()
      setParams({}, { replace: true })
    }, 150)
    return () => clearTimeout(t)
  }, [autoUse, connected, sendLine, setParams])

  const activeModuleId = snapshot?.active_session?.module_id || null
  const target = snapshot?.target || null

  const handleUse = (moduleId) => {
    if (activeModuleId && activeModuleId !== moduleId) {
      sendLine('back')
      setTimeout(() => {
        sendLine(`use ${moduleId}`)
        termRef.current?.focus()
      }, 50)
    } else if (!activeModuleId) {
      sendLine(`use ${moduleId}`)
      termRef.current?.focus()
    } else {
      termRef.current?.focus()
    }
  }

  return (
    <div className="h-full w-full flex">
      <aside className="w-[320px] shrink-0 border-r border-attense-border bg-attense-panel/40 overflow-y-auto">
        <div className="px-4 pt-4 pb-2 text-[9px] font-mono tracking-[0.32em] text-attense-muted">
          MODULES
        </div>
        <ModuleList onUse={handleUse} activeId={activeModuleId} />

        <div className="hair mx-4 my-2" />

        <TargetConfig
          host={target?.host ?? 'target-agent'}
          port={target?.port ?? 80}
        />

        <div className="hair mx-4 my-2" />

        <StatusPanel session={snapshot?.active_session || null} />

        <div className="px-4 py-4 text-[9.5px] font-mono text-attense-dim leading-relaxed">
          <div className="tracking-[0.32em] text-attense-muted mb-1.5">HINTS</div>
          <div>• Click a module to <span className="text-attense-red">use</span> it</div>
          <div>• <span className="text-attense-red">show steps</span> before you attack</div>
          <div>• <span className="text-attense-red">start</span> runs the real HTTP probe</div>
          <div>• <span className="text-attense-red">back</span> closes the session</div>
        </div>
      </aside>

      <section className="flex-1 min-w-0 flex flex-col p-4 gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono tracking-[0.28em] text-attense-muted">SHELL</span>
            <span className="text-[10px] font-mono text-attense-dim">/ws/shell</span>
            <span className={
              'text-[9px] font-mono tracking-[0.18em] px-1.5 py-0.5 rounded border ' +
              (connected
                ? 'text-attense-mint border-attense-mint/40 bg-attense-mint/5'
                : 'text-attense-red  border-attense-red/40  bg-attense-red/5')
            }>
              {connected ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-attense-dim/60" />
            <span className="w-3 h-3 rounded-full bg-attense-dim/60" />
            <span className="w-3 h-3 rounded-full bg-attense-red/80 shadow-glow-red" />
          </div>
        </div>
        <div className="flex-1 min-h-0">
          <TerminalView ref={termRef} onSubmit={sendLine} />
        </div>
        <div className="flex items-center justify-between text-[10px] font-mono text-attense-dim">
          <span>ATTENSE Cyber Range · lab-only · do not target external hosts</span>
          <span className="flex items-center gap-3">
            <Kbd>↑↓</Kbd><span>history</span>
            <Kbd>Ctrl+C</Kbd><span>cancel line</span>
            <Kbd>Ctrl+L</Kbd><span>clear</span>
          </span>
        </div>
      </section>
    </div>
  )
}

function Kbd({ children }) {
  return (
    <kbd className="px-1.5 py-0.5 rounded border border-attense-border bg-attense-panel/70 text-attense-text font-mono text-[10px]">
      {children}
    </kbd>
  )
}
