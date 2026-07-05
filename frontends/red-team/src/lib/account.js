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
