import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client.js'

/**
 * useRangeStats — single source of truth for the Settings/Overview dashboard.
 *
 * Polls the live backend (sessions, modules, health, attackbox/zap status) and
 * derives every metric the dashboard renders: KPI counts, a time-bucketed
 * activity series for sparklines, mission-status distribution, a recent-session
 * list, and a computed insight string. All fetches fail soft so the dashboard
 * degrades gracefully when the backend is offline.
 *
 * @param {string} windowKey  one of WINDOWS keys ('4h' | '12h' | '24h' | '7d')
 */

export const WINDOWS = [
  { key: '4h', label: 'Last 4 hours', hours: 4 },
  { key: '12h', label: 'Last 12 hours', hours: 12 },
  { key: '24h', label: 'Last 24 hours', hours: 24 },
  { key: '7d', label: 'Last 7 days', hours: 168 },
]

const BUCKETS = 12
const POLL_MS = 8000

export function sessionPct(s) {
  const done = s.completed_steps?.length ?? 0
  const total = s.total_steps ?? 0
  return total > 0 ? Math.round((done / total) * 100) : 0
}

function changePct(curr, prev) {
  if (prev > 0) return Math.abs(Math.round(((curr - prev) / prev) * 1000) / 10)
  return curr > 0 ? 100 : 0
}

export function useRangeStats(windowKey = '12h') {
  const [sessions, setSessions] = useState([])
  const [modules, setModules] = useState([])
  const [health, setHealth] = useState({ ok: false, modules: 0 })
  const [tools, setTools] = useState({ attackbox: 'checking', zap: 'checking' })
  const [loading, setLoading] = useState(true)
  const [lastError, setLastError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      const [s, m, h, ab, zp] = await Promise.all([
        api.sessions.list().catch(() => null),
        api.modules().catch(() => null),
        api.health().catch(() => null),
        api.attackbox.status().catch(() => null),
        api.zap.status().catch(() => null),
      ])
      if (cancelled) return
      if (s) setSessions(Array.isArray(s) ? s : [])
      if (m) setModules(Array.isArray(m) ? m : [])
      setHealth(h || { ok: false, modules: 0 })
      setTools({
        attackbox: ab?.status || 'offline',
        zap: zp?.status || 'offline',
      })
      setLastError(h ? null : 'backend offline')
      setLoading(false)
    }
    poll()
    const iv = setInterval(poll, POLL_MS)
    return () => { cancelled = true; clearInterval(iv) }
  }, [])

  const win = useMemo(
    () => WINDOWS.find(w => w.key === windowKey) || WINDOWS[1],
    [windowKey],
  )

  const derived = useMemo(() => {
    const now = Date.now() / 1000
    const winSec = win.hours * 3600
    const winStart = now - winSec
    const prevStart = now - 2 * winSec
    const ts = s => Number(s.created_at) || 0
    const completedTs = s => Number(s.completed_at || s.learning_completed_at || s.created_at) || 0

    const inWindow = sessions.filter(s => ts(s) >= winStart)
    const inPrev = sessions.filter(s => ts(s) >= prevStart && ts(s) < winStart)

    const isRunning = s => s.state === 'running'
    const isCompleted = s => s.state === 'completed'

    const active = sessions.filter(isRunning).length
    const completed = sessions.filter(isCompleted).length
    const started = sessions.filter(
      s => isRunning(s) || isCompleted(s) || s.state === 'error' || sessionPct(s) > 0,
    ).length
    const successRate = started > 0 ? Math.round((completed / started) * 100) : 0

    const todayStart = (() => {
      const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime() / 1000
    })()
    const completedToday = sessions.filter(
      s => isCompleted(s) && completedTs(s) >= todayStart,
    ).length

    // Tools online out of 3 (backend, attackbox, zap)
    const onlineCount =
      (health?.ok ? 1 : 0) +
      (tools.attackbox === 'running' ? 1 : 0) +
      (tools.zap === 'running' ? 1 : 0)

    // Activity sparkline: sessions created per bucket across the window
    const series = new Array(BUCKETS).fill(0)
    const slot = winSec / BUCKETS
    for (const s of inWindow) {
      const idx = Math.min(BUCKETS - 1, Math.floor((ts(s) - winStart) / slot))
      if (idx >= 0) series[idx] += 1
    }
    const flat = new Array(BUCKETS).fill(1)

    // Status distribution
    const runningN = active
    const completedN = completed
    const idleN = Math.max(0, sessions.length - runningN - completedN)

    // Recent sessions (newest first) with computed progress
    const recent = [...sessions]
      .sort((a, b) => ts(b) - ts(a))
      .map(s => ({ ...s, pct: sessionPct(s) }))

    const counts = {
      active: {
        value: active,
        change: changePct(inWindow.filter(isRunning).length, inPrev.filter(isRunning).length),
        direction: active >= inPrev.filter(isRunning).length ? 'up' : 'down',
        spark: series,
      },
      completedToday: {
        value: completedToday,
        change: changePct(inWindow.filter(isCompleted).length, inPrev.filter(isCompleted).length),
        direction: 'up',
        spark: series,
      },
      total: {
        value: sessions.length,
        change: changePct(inWindow.length, inPrev.length),
        direction: inWindow.length >= inPrev.length ? 'up' : 'down',
        spark: series,
      },
      modules: { value: modules.length, change: null, direction: 'up', spark: flat },
      successRate: { value: `${successRate}%`, change: null, direction: 'up', spark: flat },
      toolsOnline: { value: `${onlineCount}/3`, change: null, direction: 'up', spark: flat },
    }

    // Computed insight (no LLM — instant). Returned as parts so the component
    // can bold the emphasis span without the hook needing JSX.
    const cInWin = inWindow.filter(isCompleted).length
    const winLabel = win.label.toLowerCase()
    let insight
    if (cInWin > 0) {
      insight = {
        strong: `${cInWin} mission${cInWin === 1 ? '' : 's'} completed`,
        post: ` in the ${winLabel} — ${successRate}% success rate across ${sessions.length} sessions.`,
      }
    } else if (active > 0) {
      insight = {
        strong: `${active} mission${active === 1 ? '' : 's'} running`,
        post: ` across the range right now. ${modules.length} modules available.`,
      }
    } else if (sessions.length > 0) {
      insight = {
        pre: `No missions active in the ${winLabel}. `,
        strong: `${completed} completed`,
        post: ` all-time across ${sessions.length} sessions.`,
      }
    } else {
      insight = {
        pre: 'The range is idle. ',
        strong: `${modules.length} lab modules`,
        post: ' are ready to launch.',
      }
    }

    return { counts, series, statusDist: { running: runningN, completed: completedN, idle: idleN }, recent, insight }
  }, [sessions, modules, health, tools, win])

  return {
    loading,
    online: !!health?.ok,
    moduleCount: modules.length,
    lastError,
    window: win,
    ...derived,
  }
}
