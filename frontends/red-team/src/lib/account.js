/**
 * account.js — local operator account store.
 *
 * The range has no auth backend (the Login screen is a mock), so the operator
 * profile and password live in localStorage. Passwords are stored as a
 * SHA-256 hash via SubtleCrypto — never plaintext — but note this is local,
 * client-side state, not server-enforced authentication. If a real user API
 * is added later, swap getAccount/saveAccount/changePassword to hit it.
 */

const PROFILE_KEY = 'attense_account'
const PASSWORD_KEY = 'attense_account_pwd'
const PASSWORD_AT_KEY = 'attense_account_pwd_at'
// Session token minted by the portal login (POST /api/auth/login) and handed to
// this app via the redirect URL fragment. Used to hydrate the real operator
// identity from the control API.
const SESSION_TOKEN_KEY = 'attense_session_token'

// Backend role → the label shown in Settings → Account.
const ROLE_LABELS = {
  red_team: 'Red Team Operator',
  ciso: 'CISO',
  soc_manager: 'SOC Manager',
  soc_l1: 'SOC Analyst',
  soc_l2: 'IR Lead',
}
function roleLabel(role) {
  return ROLE_LABELS[role] || DEFAULT_ACCOUNT.role
}

const DEFAULT_ACCOUNT = {
  name: 'Operator',
  email: 'operator@attense.local',
  operatorId: 'operator_01',
  role: 'Red Team Operator',
  avatar: '', // data URL, optional
}

export function getAccount() {
  try {
    const saved = JSON.parse(localStorage.getItem(PROFILE_KEY) || '{}')
    return { ...DEFAULT_ACCOUNT, ...saved }
  } catch {
    return { ...DEFAULT_ACCOUNT }
  }
}

export function saveAccount(patch) {
  const next = { ...getAccount(), ...patch }
  localStorage.setItem(PROFILE_KEY, JSON.stringify(next))
  return next
}

export function hasPassword() {
  return !!localStorage.getItem(PASSWORD_KEY)
}

export function getPasswordMeta() {
  const at = Number(localStorage.getItem(PASSWORD_AT_KEY)) || null
  return { set: !!localStorage.getItem(PASSWORD_KEY), changedAt: at }
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Set or change the operator password.
 * If a password already exists, `current` must match it.
 * Throws Error with a user-facing message on validation failure.
 */
export async function changePassword(current, next) {
  if (!next || next.length < 8) {
    throw new Error('New password must be at least 8 characters.')
  }
  const stored = localStorage.getItem(PASSWORD_KEY)
  if (stored) {
    const currentHash = await sha256(current || '')
    if (currentHash !== stored) {
      throw new Error('Current password is incorrect.')
    }
  }
  localStorage.setItem(PASSWORD_KEY, await sha256(next))
  localStorage.setItem(PASSWORD_AT_KEY, String(Math.floor(Date.now() / 1000)))
}

/**
 * Capture a session token handed over in the URL fragment by the portal login
 * (`#session=<token>`), persist it, and strip it from the address bar so it
 * doesn't linger in history or get shared. Call once, early, on app start.
 * Returns true if a token was captured.
 */
export function captureSessionTokenFromUrl() {
  const hash = window.location.hash || ''
  const m = hash.match(/session=([^&]+)/)
  if (!m) return false
  try {
    localStorage.setItem(SESSION_TOKEN_KEY, decodeURIComponent(m[1]))
  } catch {
    return false
  }
  // Remove the fragment without reloading or adding a history entry.
  const clean = window.location.pathname + window.location.search
  window.history.replaceState(null, '', clean)
  return true
}

export function getSessionToken() {
  return localStorage.getItem(SESSION_TOKEN_KEY) || ''
}

/**
 * Hydrate the local operator profile from the logged-in portal session.
 * No-op when there is no token. On success, the real identity (display name,
 * email, role) flows into the same account store Settings → Account renders.
 * On 401 (expired/invalid) the token is cleared and the existing local
 * DEFAULT_ACCOUNT stays in place — no forced redirect.
 */
export async function hydrateFromSession() {
  const token = getSessionToken()
  if (!token) return null
  try {
    const res = await fetch('/control-api/api/auth/me', {
      headers: { 'X-Session-Token': token },
    })
    if (res.status === 401) {
      localStorage.removeItem(SESSION_TOKEN_KEY)
      return null
    }
    if (!res.ok) return null
    const me = await res.json()
    return saveAccount({
      name: me.display_name || me.username || DEFAULT_ACCOUNT.name,
      email: me.email || DEFAULT_ACCOUNT.email,
      operatorId: me.username || DEFAULT_ACCOUNT.operatorId,
      role: roleLabel(me.role),
    })
  } catch {
    // Network blip — keep whatever profile we already have.
    return null
  }
}

/**
 * Sign out: drop the portal session token and return to the portal login.
 * Leaves local profile/password state alone (a fresh login re-hydrates it).
 */
export function logout() {
  localStorage.removeItem(SESSION_TOKEN_KEY)
  window.location.href = 'http://127.0.0.1:5173/red-login.html'
}
