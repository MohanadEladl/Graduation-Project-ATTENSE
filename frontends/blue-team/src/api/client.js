export const SESSION_TOKEN_KEY = 'attense_session_token'

const controlBase = import.meta.env.VITE_CONTROL_API_URL || ''
const blueBase = import.meta.env.VITE_BLUETEAM_API_URL || ''

export function captureTokenFromUrl() {
  const params = new URLSearchParams(window.location.search)
  const token = params.get('token')
  if (!token) return
  localStorage.setItem(SESSION_TOKEN_KEY, token)
  params.delete('token')
  const query = params.toString()
  window.history.replaceState({}, '', `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`)
}

export function getToken() {
  return localStorage.getItem(SESSION_TOKEN_KEY) || ''
}

export function clearToken() {
  localStorage.removeItem(SESSION_TOKEN_KEY)
}

async function parse(response) {
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || `Request failed with ${response.status}`)
  return data
}

function controlHeaders() {
  const token = getToken()
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'X-Session-Token': token } : {}),
  }
}

function roomHeaders(roomId) {
  return {
    'Content-Type': 'application/json',
    ...(roomId ? { 'X-Room-Id': roomId } : {}),
  }
}

export const api = {
  auth: {
    login: async (username, password) => {
      const data = await fetch(`${controlBase}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      }).then(parse)
      localStorage.setItem(SESSION_TOKEN_KEY, data.token)
      return data
    },
    me: () => fetch(`${controlBase}/api/auth/me`, { headers: controlHeaders() }).then(parse),
  },
  rooms: {
    list: () => fetch(`${controlBase}/api/rooms`, { headers: controlHeaders() }).then(parse),
    get: (roomId) => fetch(`${controlBase}/api/rooms/${encodeURIComponent(roomId)}`, { headers: controlHeaders() }).then(parse),
    blueStart: (roomId) => fetch(`${controlBase}/api/rooms/${encodeURIComponent(roomId)}/blue-start`, {
      method: 'POST',
      headers: controlHeaders(),
    }).then(parse),
  },
  blue: {
    investigate: (roomId, payload) => fetch(`${blueBase}/blueteam/investigate-alert`, {
      method: 'POST',
      headers: roomHeaders(roomId),
      body: JSON.stringify(payload),
    }).then(parse),
    deny: (roomId, payload) => fetch(`${blueBase}/blueteam/deny-alert`, {
      method: 'POST',
      headers: roomHeaders(roomId),
      body: JSON.stringify(payload),
    }).then(parse),
    confirm: (roomId, payload) => fetch(`${blueBase}/blueteam/confirm-incident`, {
      method: 'POST',
      headers: roomHeaders(roomId),
      body: JSON.stringify(payload),
    }).then(parse),
    initiateContainment: (roomId, payload) => fetch(`${blueBase}/blueteam/initiate-containment`, {
      method: 'POST',
      headers: roomHeaders(roomId),
      body: JSON.stringify(payload),
    }).then(parse),
    completeContainment: (roomId, payload) => fetch(`${blueBase}/blueteam/complete-containment`, {
      method: 'POST',
      headers: roomHeaders(roomId),
      body: JSON.stringify(payload),
    }).then(parse),
  },
}
