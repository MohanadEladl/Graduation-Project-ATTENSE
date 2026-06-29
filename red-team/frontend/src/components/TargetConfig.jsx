export function TargetConfig({ host, port }) {
  return (
    <div className="px-4 py-3">
      <div className="text-[9px] font-mono tracking-[0.32em] text-attense-muted mb-2">TARGET</div>
      <div className="rounded-md border border-attense-border bg-attense-panel/60 p-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-attense-dim">Host</span>
          <span className="font-mono text-[12px] text-attense-text truncate max-w-[170px]" title={host}>
            {host}
          </span>
        </div>
        <div className="h-px bg-attense-border my-2" />
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-attense-dim">Port</span>
          <span className="font-mono text-[12px] text-attense-text">{port}</span>
        </div>
      </div>
      <div className="mt-2 text-[10px] font-mono text-attense-dim">
        change with <span className="text-attense-red">set target &lt;host&gt; &lt;port&gt;</span>
      </div>
    </div>
  )
}
