import { useEffect, useRef, useState, useCallback } from 'react'

/**
 * useShell — connect to /ws/shell, expose:
 *   - connected: boolean
 *   - snapshot:  { target, module_count, active_session }
 *   - sendLine(text): push a command
 *   - onOutput(cb): subscribe to output lines (returns unsubscribe)
 *   - onPrompt(cb): subscribe to prompt updates
 *   - reconnect(): force a fresh WebSocket (used as a safety net)
 *
 * Race-safe buffering: the server emits the banner + first prompt
 * immediately after ws.onopen, which can fire before the consumer's
 * useEffect has registered subscribers. To avoid dropping those early
 * messages we buffer them in outputQueue/promptQueue and flush the
 * buffer synchronously on the first subscription.
 */
export function useShell({ autoReconnect = true } = {}) {
  const [connected, setConnected] = useState(false)
  const [snapshot, setSnapshot]   = useState(null)
  const wsRef        = useRef(null)
  const outputSubs   = useRef(new Set())
  const promptSubs   = useRef(new Set())
  const outputQueue  = useRef([])
  const promptQueue  = useRef([])
  const reconnectRef = useRef(null)

  const connect = useCallback(() => {
    // Same-origin WS — works both in dev (Vite proxy) and prod (nginx proxy)
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url   = `${proto}://${window.location.host}/ws/shell`
    const ws    = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
    }

    ws.onmessage = (ev) => {
      let msg
      try { msg = JSON.parse(ev.data) } catch { return }
      switch (msg.type) {
        case 'output': {
          const data = String(msg.data ?? '')
          if (outputSubs.current.size === 0) {
            outputQueue.current.push(data)
          } else {
            outputSubs.current.forEach(fn => fn(data))
          }
          break
        }
        case 'prompt': {
          const data = String(msg.data ?? '')
          if (promptSubs.current.size === 0) {
            promptQueue.current.push(data)
          } else {
            promptSubs.current.forEach(fn => fn(data))
          }
          break
        }
        case 'snapshot':
          setSnapshot(msg.data || null)
          break
        default:
          break
      }
    }

    ws.onclose = () => {
      setConnected(false)
      if (autoReconnect) {
        reconnectRef.current = setTimeout(connect, 1500)
      }
    }

    ws.onerror = () => {
      try { ws.close() } catch {}
    }
  }, [autoReconnect])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      try { wsRef.current?.close() } catch {}
    }
  }, [connect])

  const sendLine = useCallback((line) => {
    const ws = wsRef.current
    if (!ws || ws.readyState !== WebSocket.OPEN) return false
    ws.send(JSON.stringify({ type: 'input', data: String(line) }))
    return true
  }, [])

  const onOutput = useCallback((fn) => {
    outputSubs.current.add(fn)
    // Flush any messages that arrived before a subscriber was attached.
    if (outputQueue.current.length > 0) {
      const q = outputQueue.current
      outputQueue.current = []
      q.forEach(line => { try { fn(line) } catch {} })
    }
    return () => outputSubs.current.delete(fn)
  }, [])

  const onPrompt = useCallback((fn) => {
    promptSubs.current.add(fn)
    if (promptQueue.current.length > 0) {
      const q = promptQueue.current
      promptQueue.current = []
      q.forEach(p => { try { fn(p) } catch {} })
    }
    return () => promptSubs.current.delete(fn)
  }, [])

  const reconnect = useCallback(() => {
    // Force a fresh WebSocket so the server re-emits the banner + prompt.
    // The auto-reconnect onclose handler is disabled on the outgoing socket
    // so it can't schedule a competing delayed reconnect.
    const ws = wsRef.current
    if (ws) {
      try { ws.onclose = null } catch {}
      try { ws.close() } catch {}
    }
    if (reconnectRef.current) {
      clearTimeout(reconnectRef.current)
      reconnectRef.current = null
    }
    setConnected(false)
    connect()
  }, [connect])

  return { connected, snapshot, sendLine, onOutput, onPrompt, reconnect }
}
