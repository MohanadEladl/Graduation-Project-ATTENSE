import { useEffect, useRef, useState } from 'react'

/**
 * useDetections — stream Wazuh detections from /ws/detections.
 *
 * Options:
 *   sinceTs:    epoch seconds; server filters the initial snapshot so the
 *               workspace only sees alerts that fired after the mission started.
 *   maxItems:   client-side cap on kept events.
 *
 * Returns:
 *   detections: [] (newest last, the feed flips for display)
 *   status:     { reachable, source, last_poll, last_error, buffered }
 *   connected:  websocket open?
 */
export function useDetections({ sinceTs = null, maxItems = 500 } = {}) {
  const [detections, setDetections] = useState([])
  const [status, setStatus]         = useState(null)
  const [connected, setConnected]   = useState(false)
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  useEffect(() => {
    let cancelled = false

    const open = () => {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const q = sinceTs ? `?since=${encodeURIComponent(sinceTs)}` : ''
      const ws = new WebSocket(`${proto}://${window.location.host}/ws/detections${q}`)
      wsRef.current = ws

      ws.onopen = () => setConnected(true)

      ws.onmessage = (ev) => {
        let msg; try { msg = JSON.parse(ev.data) } catch { return }
        if (msg.type === 'snapshot') {
          const d = msg.data || {}
          setStatus(d.status || null)
          setDetections(d.events || [])
        } else if (msg.type === 'detection') {
          setDetections(prev => {
            const next = prev.concat(msg.data)
            return next.length > maxItems ? next.slice(next.length - maxItems) : next
          })
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (!cancelled) reconnectRef.current = setTimeout(open, 2000)
      }
      ws.onerror = () => { try { ws.close() } catch {} }
    }

    open()
    return () => {
      cancelled = true
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      try { wsRef.current?.close() } catch {}
    }
  }, [sinceTs, maxItems])

  return { detections, status, connected }
}
