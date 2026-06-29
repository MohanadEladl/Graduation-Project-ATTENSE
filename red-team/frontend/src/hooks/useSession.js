import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api/client.js'

/**
 * useSession — connect to /ws/sessions/:sid and mirror session state.
 *
 * Options:
 *   replay: if true, skip the WebSocket and just REST-fetch the final
 *           snapshot + full log history (read-only view).
 *
 * Returns:
 *   - connected:   WebSocket open?
 *   - snapshot:    latest SessionRecord snapshot (or null)
 *   - logs:        append-only array of { ts, line } (back-filled on connect)
 *   - running:     convenience = snapshot.state === 'running'
 *   - start():     kick off the attack (server-side)
 *   - setOption(k, v): REST set (engine validates)
 *   - setTarget(host, port?): REST set
 *   - reset():     delete the session on the server (caller should navigate away)
 */
export function useSession(sid, { replay = false } = {}) {
  const [connected, setConnected] = useState(false)
  const [snapshot, setSnapshot]   = useState(null)
  const [logs, setLogs]           = useState([])
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  useEffect(() => {
    if (!sid) return
    let cancelled = false

    // Back-fill the full log history and initial snapshot before the WS opens
    // so the UI never blinks empty.
    Promise.all([api.sessions.get(sid).catch(() => null),
                 api.sessions.logs(sid).catch(() => null)])
      .then(([snap, logRes]) => {
        if (cancelled) return
        if (snap)   setSnapshot(snap)
        if (logRes) setLogs(logRes.logs || [])
      })

    // Replay mode: no WebSocket, no polling — just the REST snapshot above.
    if (replay) return () => { cancelled = true }

    const open = () => {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const ws = new WebSocket(`${proto}://${window.location.host}/ws/sessions/${sid}`)
      wsRef.current = ws

      ws.onopen = () => setConnected(true)

      ws.onmessage = (ev) => {
        let msg; try { msg = JSON.parse(ev.data) } catch { return }
        if (msg.type === 'snapshot') setSnapshot(msg.data || null)
        else if (msg.type === 'log') setLogs(prev => {
          const next = prev.concat(msg.data)
          return next.length > 3000 ? next.slice(next.length - 3000) : next
        })
      }

      ws.onclose = () => {
        setConnected(false)
        if (!cancelled) reconnectRef.current = setTimeout(open, 1500)
      }
      ws.onerror = () => { try { ws.close() } catch {} }
    }

    open()

    return () => {
      cancelled = true
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      try { wsRef.current?.close() } catch {}
    }
  }, [sid])

  const start = useCallback(() => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'start' }))
      return Promise.resolve()
    }
    // Fallback to REST if WS isn't up yet — only starts timer, no attack.
    return api.sessions.start(sid).then(setSnapshot)
  }, [sid])

  const execute = useCallback(() => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'execute' }))
      return Promise.resolve()
    }
    // Fallback to REST if WS isn't up yet.
    return api.sessions.execute(sid).then(setSnapshot)
  }, [sid])

  const setOption = useCallback((key, value) => {
    return api.sessions.setOption(sid, key, value).then(setSnapshot)
  }, [sid])

  const setTarget = useCallback((host, port) => {
    return api.sessions.setTarget(sid, host, port).then(setSnapshot)
  }, [sid])

  const reset = useCallback(() => api.sessions.remove(sid), [sid])

  const running = snapshot?.state === 'running'

  return { connected, snapshot, logs, running, start, execute, setOption, setTarget, reset }
}
