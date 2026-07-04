/**
 * useZapController — all ZAP panel state + handlers in one hook so the embedded
 * launcher and the standalone ZAP Workspace share identical logic (no duplicate,
 * drifting copies). Every request is scoped to the local target-agent; the
 * backend enforces that too.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../api/client.js'
import {
  FUZZER_PRESETS, insertFuzzMarker, urlToPath, toOperatorAuthPath,
  editableHeadersFromRaw, headersTextToObject, isLocalTarget,
} from './zapUtils.js'

export function useZapController({ sessionId, moduleId, mode = 'operator', pollMs = 0 }) {
  const isOperatorMode = mode === 'lab' || mode === 'operator'
  const defaultAuthPath = isOperatorMode ? '/op/auth/login' : '/auth/login'
  const context = { session_id: sessionId, module_id: moduleId }

  const [status, setStatus] = useState('checking')
  const [zapVersion, setZapVersion] = useState('')
  const [activeTab, setActiveTab] = useState('history')
  const [messages, setMessages] = useState([])
  const [selectedMsg, setSelectedMsg] = useState(null)

  // Repeater
  const [repMethod, setRepMethod] = useState('GET')
  const [repPath, setRepPath] = useState(moduleId === 'brute_force' ? defaultAuthPath : '/')
  const [repHeaders, setRepHeaders] = useState('')
  const [repBody, setRepBody] = useState('')
  const [repResult, setRepResult] = useState(null)
  const [repLoading, setRepLoading] = useState(false)

  // Fuzzer (Intruder-style)
  const [fuzMethod, setFuzMethod] = useState('POST')
  const [fuzPath, setFuzPath] = useState(defaultAuthPath)
  const [fuzBody, setFuzBody] = useState('')
  const [fuzPreset, setFuzPreset] = useState('none')
  const [fuzList, setFuzList] = useState('')
  const [fuzResult, setFuzResult] = useState(null)
  const [fuzLoading, setFuzLoading] = useState(false)
  const [fuzSort, setFuzSort] = useState('order')
  const [fuzGrep, setFuzGrep] = useState('')
  const [fuzMarkerNote, setFuzMarkerNote] = useState('')

  const opAuth = useCallback(
    (p) => toOperatorAuthPath(p || defaultAuthPath, { isOperatorMode, moduleId }),
    [defaultAuthPath, isOperatorMode, moduleId],
  )

  // ── Status polling (every 15s) ──
  useEffect(() => {
    let alive = true
    const check = () => api.zap.status()
      .then(r => { if (alive) { setStatus(r.status || 'error'); setZapVersion(r.version || '') } })
      .catch(() => alive && setStatus('offline'))
    check()
    const iv = setInterval(check, 15000)
    return () => { alive = false; clearInterval(iv) }
  }, [])

  // ── History fetch + optional live polling ──
  const refreshHistory = useCallback(() => {
    return api.zap.history(80)
      .then(r => setMessages(r.messages || []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (status !== 'running') return
    refreshHistory()
    if (!pollMs) return
    const iv = setInterval(refreshHistory, pollMs)
    return () => clearInterval(iv)
  }, [status, pollMs, refreshHistory])

  // ── History row actions ──
  const sendToInspector = useCallback((m) => {
    setSelectedMsg(m)
    setActiveTab('inspector')
  }, [])

  const sendToRepeater = useCallback((m) => {
    setRepMethod((m.method || 'GET').toUpperCase())
    setRepPath(opAuth(urlToPath(m.path || m.full_url || m.url || '/')))
    setRepHeaders(editableHeadersFromRaw(m.request_headers))
    setRepBody(m.request_body || '')
    setRepResult(null)
    setActiveTab('repeater')
  }, [opAuth])

  const sendToFuzzer = useCallback((m) => {
    const { body, auto } = insertFuzzMarker(m.request_body || '')
    setFuzMethod((m.method || 'POST').toUpperCase())
    setFuzPath(opAuth(urlToPath(m.path || m.full_url || m.url || defaultAuthPath)))
    setFuzBody(body)
    setFuzResult(null)
    setFuzMarkerNote(
      auto
        ? ''
        : 'Body preserved from the captured request. Place a § where the payload '
          + 'should be injected (e.g. password=§).',
    )
    setActiveTab('fuzzer')
  }, [opAuth, defaultAuthPath])

  // ── Repeater send ──
  const runRepeater = useCallback(async () => {
    if (!isLocalTarget(repPath)) {
      setRepResult({ status: 'blocked', detail: 'Blocked: external targets are not allowed. Approved target: target-agent.' })
      return
    }
    setRepLoading(true)
    try {
      const safePath = opAuth(repPath)
      setRepPath(safePath)
      const headersObj = headersTextToObject(repHeaders)
      const r = await api.zap.repeater(repMethod, safePath, headersObj, repBody || null, context)
      setRepResult(r)
      refreshHistory()
    } catch (e) {
      setRepResult({ status: 'error', detail: e.message })
    }
    setRepLoading(false)
  }, [repMethod, repPath, repHeaders, repBody, opAuth, context, refreshHistory])

  // ── Fuzzer ──
  const selectPreset = useCallback((key) => {
    setFuzPreset(key)
    if (FUZZER_PRESETS[key]) setFuzList(FUZZER_PRESETS[key].items.join('\n'))
  }, [])

  const runFuzzer = useCallback(async () => {
    if (!isLocalTarget(fuzPath)) {
      setFuzResult({ status: 'blocked', detail: 'Blocked: external targets are not allowed. Approved target: target-agent.' })
      return
    }
    setFuzLoading(true)
    setFuzResult(null)
    setFuzSort('order')
    try {
      const payloads = fuzList.split('\n').map(s => s.trim()).filter(Boolean)
      const safePath = opAuth(fuzPath)
      setFuzPath(safePath)
      const r = await api.zap.fuzzer(fuzMethod, safePath, fuzBody, payloads, '§', fuzGrep || null, context)
      setFuzResult(r)
      refreshHistory()
    } catch (e) {
      setFuzResult({ status: 'error', detail: e.message })
    }
    setFuzLoading(false)
  }, [fuzMethod, fuzPath, fuzBody, fuzList, fuzGrep, opAuth, context, refreshHistory])

  return {
    // meta
    isOperatorMode, defaultAuthPath, sessionId, moduleId, mode,
    status, zapVersion, activeTab, setActiveTab,
    // history
    messages, selectedMsg, refreshHistory,
    sendToInspector, sendToRepeater, sendToFuzzer,
    // repeater
    repMethod, setRepMethod, repPath, setRepPath, repHeaders, setRepHeaders,
    repBody, setRepBody, repResult, repLoading, runRepeater,
    // fuzzer
    fuzMethod, setFuzMethod, fuzPath, setFuzPath, fuzBody, setFuzBody,
    fuzPreset, fuzList, setFuzList, fuzResult, fuzLoading, fuzSort, setFuzSort,
    fuzGrep, setFuzGrep, fuzMarkerNote, selectPreset, runFuzzer,
  }
}
