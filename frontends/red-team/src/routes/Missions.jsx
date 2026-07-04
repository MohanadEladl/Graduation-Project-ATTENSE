import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Zap, ArrowRight } from 'lucide-react'
import { api } from '../api/client.js'
import { SeverityBadge } from '../components/SeverityBadge.jsx'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table.jsx'
import { Badge } from '../components/ui/badge.jsx'
import { Button } from '../components/ui/button.jsx'

const STATE_TONE = { running: 'red', completed: 'cyan', idle: 'neutral', error: 'amber' }

const rowVariants = {
  hidden:  { opacity: 0, y: 10 },
  visible: (i) => ({ opacity: 1, y: 0, transition: { delay: i * 0.04, duration: 0.25, ease: 'easeOut' } }),
}

export default function Missions() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [filter,   setFilter]   = useState('all')

  useEffect(() => {
    let cancelled = false
    api.sessions.list().catch(() => []).then(s => {
      if (!cancelled) { setSessions(Array.isArray(s) ? s : []); setLoading(false) }
    }).catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [])

  const filters = ['all', 'running', 'completed', 'idle', 'error']
  const filtered = filter === 'all' ? sessions : sessions.filter(s => s.state === filter)
  const sorted = [...filtered].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="flex justify-between items-start mb-5">
        <div>
          <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Sessions</h1>
          <p className="font-mono text-[11px] text-attense-dim mt-1">
            {sessions.length} total · {sessions.filter(s => s.state === 'running').length} active
          </p>
        </div>
        <Button onClick={() => navigate('/modules')}>
          <Zap className="w-3.5 h-3.5" /> NEW MISSION
        </Button>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1.5 mb-4">
        {filters.map(f => (
          <Button key={f} size="sm" variant="outline" active={filter === f}
            onClick={() => setFilter(f)} className="capitalize">{f}</Button>
        ))}
      </div>

      {loading && <div className="py-12 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING…</div>}
      {error   && (
        <div className="rounded-lg p-4 font-mono text-[11px]"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          Backend offline — {error}
        </div>
      )}

      {!loading && !error && sorted.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Session / Module</TableHead>
              <TableHead>Scenario</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>State</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.map((s, i) => {
              const isRunning = s.state === 'running'
              const done  = s.completed_steps?.length ?? 0
              const total = s.total_steps ?? 0
              const pct   = total > 0 ? Math.round((done / total) * 100) : 0

              return (
                <motion.tr key={s.session_id} custom={i} initial="hidden" animate="visible" variants={rowVariants}
                  className="cursor-pointer bg-white/[0.018] border border-white/[0.06] hover:bg-white/[0.035] hover:border-white/10"
                  onClick={() => navigate(`/workspace/${s.session_id}`)}
                >
                  <TableCell>
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: isRunning ? '#ff1535' : s.state === 'completed' ? '#00c8ff' : '#2a2e45', boxShadow: isRunning ? '0 0 5px #ff1535' : 'none', animation: isRunning ? 'pulse-glow 1.5s infinite' : 'none' }} />
                      <span className="font-mono text-[9.5px] text-attense-red truncate">{s.session_id?.slice(0,12)}…</span>
                    </div>
                    <div className="text-[12.5px] font-medium text-attense-text">{s.module_name || s.module_id}</div>
                  </TableCell>
                  <TableCell className="font-mono text-[10px] text-attense-dim">{s.scenario_id || '—'}</TableCell>
                  <TableCell><SeverityBadge severity={s.severity} /></TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 pr-4">
                      <div className="flex-1 h-[3px] rounded-full overflow-hidden bg-white/[0.06]">
                        <div className="h-full rounded-full transition-all"
                          style={{ width: pct + '%', background: isRunning ? 'linear-gradient(90deg,#ff1535,#ff6b00)' : s.state === 'completed' ? '#00c8ff' : '#2a2e45' }} />
                      </div>
                      <span className="font-mono text-[9.5px] text-attense-dim whitespace-nowrap">{pct}%</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge tone={STATE_TONE[s.state] || 'neutral'}>{(s.state || 'idle').toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="ghost" className="text-attense-violet hover:text-attense-violet hover:bg-attense-violet/10"
                      onClick={e => { e.stopPropagation(); navigate(`/workspace/${s.session_id}`) }}>
                      OPEN <ArrowRight className="w-3 h-3" />
                    </Button>
                  </TableCell>
                </motion.tr>
              )
            })}
          </TableBody>
        </Table>
      )}

      {!loading && !error && sorted.length === 0 && (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">No sessions for filter: {filter}</div>
      )}
    </div>
  )
}
