/**
 * zapUtils.js — pure helpers shared by the ZAP components and the ZAP Workspace.
 * No React here — just data massaging for the Burp-like history/repeater/fuzzer.
 */

export const STATUS_STYLES = {
  running:  { color: '#2ee39a', bg: 'rgba(46,227,154,0.06)', bd: 'rgba(46,227,154,0.25)' },
  offline:  { color: '#fbbf24', bg: 'rgba(250,204,21,0.06)', bd: 'rgba(250,204,21,0.25)' },
  error:    { color: '#f87171', bg: 'rgba(248,113,113,0.06)', bd: 'rgba(248,113,113,0.25)' },
  checking: { color: '#7dd3fc', bg: 'rgba(125,211,252,0.06)', bd: 'rgba(125,211,252,0.25)' },
}

export const SOURCE_LABELS = {
  browser:      'browser',
  zap_repeater: 'repeater',
  zap_fuzzer:   'fuzzer',
}

// Built-in payload lists — mirrors the wordlists a beginner reaches for in Burp
// Intruder, but bundled so there's no file to manage. Local lab only.
export const FUZZER_PRESETS = {
  passwords: {
    label: 'Common passwords',
    items: ['password', '123456', 'admin', 'letmein', 'password123',
            'lab2024', 'qwerty', 'welcome', 'changeme', 'guest'],
  },
  usernames: {
    label: 'Common usernames',
    items: ['admin', 'operator', 'guest', 'root', 'user', 'test',
            'alice', 'bob', 'service'],
  },
  leaked: {
    label: 'Leaked mini-list',
    items: ['123456', 'password', '12345678', 'qwerty', 'abc123',
            'monkey', 'letmein', 'dragon', 'password123', 'iloveyou'],
  },
}

// Local-lab safety: refuse anything that isn't a target-agent path/URL. The
// backend enforces this too (normalize_zap_target_path); this is a friendly
// first line so the student sees the block immediately.
export function isLocalTarget(pathOrUrl) {
  const raw = (pathOrUrl || '').trim()
  if (!raw) return true
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw)
      return u.hostname === 'target-agent'
    } catch { return false }
  }
  // Bare paths are fine; reject smuggled schemes / protocol-relative hosts.
  if (raw.includes('://') || raw.startsWith('//')) return false
  return true
}

// Force operator brute-force onto the harder /op backend even if a captured
// request used the guided /auth/login path.
export function toOperatorAuthPath(path, { isOperatorMode, moduleId }) {
  const raw = path || ''
  if (!isOperatorMode || moduleId !== 'brute_force') return raw
  if (raw.includes('/op/auth/login')) return raw
  return raw
    .replace('http://target-agent/auth/login', 'http://target-agent/op/auth/login')
    .replace('https://target-agent/auth/login', 'https://target-agent/op/auth/login')
    .replace('/auth/login', '/op/auth/login')
}

// Turn a full URL from history into a backend-friendly path (keeps query).
export function urlToPath(urlOrPath) {
  const raw = (urlOrPath || '/').trim()
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw)
      return (u.pathname || '/') + (u.search || '')
    } catch { return '/' }
  }
  return raw
}

// Parse a raw request-header block (as stored in history) into an editable
// "Key: Value" string, dropping the request line and headers the backend owns.
const OWNED_HEADERS = new Set(['host', 'user-agent', 'content-length', 'accept-encoding'])
export function editableHeadersFromRaw(rawHeaders) {
  if (!rawHeaders) return ''
  const out = []
  for (const line of String(rawHeaders).split(/\r?\n/)) {
    if (!line.trim()) continue
    if (/HTTP\/\d/.test(line)) continue // request/response start line
    const i = line.indexOf(':')
    if (i === -1) continue
    const k = line.slice(0, i).trim()
    const v = line.slice(i + 1).trim()
    if (!k || OWNED_HEADERS.has(k.toLowerCase())) continue
    out.push(`${k}: ${v}`)
  }
  return out.join('\n')
}

// Parse a "Key: Value" textarea into a headers object (or null if empty).
export function headersTextToObject(text) {
  const obj = {}
  for (const line of String(text || '').split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i === -1) continue
    const k = line.slice(0, i).trim()
    const v = line.slice(i + 1).trim()
    if (k) obj[k] = v
  }
  return Object.keys(obj).length ? obj : null
}

/**
 * Insert a § payload marker into a captured request body for the Fuzzer.
 * Returns { body, auto } where auto=true means we confidently placed it (around
 * a password/last form value); auto=false means the student should verify.
 */
export function insertFuzzMarker(body) {
  const b = body || ''
  if (!b) return { body: '', auto: false }
  if (b.includes('§')) return { body: b, auto: true }
  // Prefer marking the password value in a form body.
  if (/(^|&)password=/.test(b)) {
    return { body: b.replace(/((^|&)password=)[^&]*/, '$1§'), auto: true }
  }
  // Otherwise mark the last field's value in a form-ish body.
  const lastEq = b.lastIndexOf('=')
  if (lastEq !== -1) {
    const tail = b.slice(lastEq + 1)
    if (!tail.includes('&')) {
      return { body: b.slice(0, lastEq + 1) + '§', auto: false }
    }
  }
  // Non-form body (e.g. JSON): keep it and let the student place the marker.
  return { body: b, auto: false }
}

export function statusColor(code) {
  const s = String(code || '')
  if (s.startsWith('2')) return '#2ee39a'
  if (s.startsWith('3')) return '#7dd3fc'
  if (s.startsWith('4')) return '#fbbf24'
  return '#f87171'
}
