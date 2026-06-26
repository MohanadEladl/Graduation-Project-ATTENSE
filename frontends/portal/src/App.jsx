import { useCallback, useEffect, useState } from 'react'
import './styles/portal.css'

// In local development the Vite proxy forwards /api/* to the control API,
// avoiding a browser cross-origin request. Deployments can override this with
// VITE_API_BASE_URL.
const defaultApiUrl = import.meta.env.VITE_API_BASE_URL || window.location.origin

const DESTINATIONS = {
  ciso: { title: 'CISO oversight', description: 'Review and confirm companies, then monitor the exercise estate.', url: null },
  soc_manager: { title: 'SOC manager workspace', description: 'Create and operate exercise rooms, then work cases in TheHive.', url: 'http://localhost:9000' },
  soc_l1: { title: 'SOC analyst workspace', description: 'Investigate assigned cases in TheHive.', url: 'http://localhost:9000' },
  soc_l2: { title: 'SOC analyst workspace', description: 'Investigate and contain assigned incidents in TheHive.', url: 'http://localhost:9000' },
  red_team: { title: 'Red Team workspace', description: 'Select a joined room and execute the assigned attack exercises.', url: 'http://localhost:3000' },
}

async function apiRequest(apiUrl, path, options = {}) {
  const response = await fetch(`${apiUrl.replace(/\/$/, '')}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`)
  return body
}

export default function App() {
  const [apiUrl, setApiUrl] = useState(defaultApiUrl)
  const [screen, setScreen] = useState('login')
  const [session, setSession] = useState(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [workspaceData, setWorkspaceData] = useState(null)

  const loadWorkspace = useCallback(async (token) => {
    const me = await apiRequest(apiUrl, '/api/auth/me', { headers: { 'X-Session-Token': token } })
    setSession({ token, ...me })
    const path = me.role === 'ciso' ? '/api/company' : '/api/rooms'
    const data = await apiRequest(apiUrl, path, { headers: { 'X-Session-Token': token } }).catch(() => null)
    setWorkspaceData(data)
    setScreen('workspace')
  }, [apiUrl])

  useEffect(() => {
    const token = localStorage.getItem('attense_session_token')
    if (token) loadWorkspace(token).catch(() => localStorage.removeItem('attense_session_token'))
  }, [loadWorkspace])

  async function submitLogin(event) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setBusy(true); setMessage('')
    try {
      const response = await apiRequest(apiUrl, '/api/auth/login', {
        method: 'POST', body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
      })
      localStorage.setItem('attense_session_token', response.token)
      await loadWorkspace(response.token)
    } catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }

  async function submitRegistration(event, path, fields) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setBusy(true); setMessage('')
    try {
      await apiRequest(apiUrl, path, { method: 'POST', body: JSON.stringify(Object.fromEntries(fields.map((field) => [field, form.get(field)]))) })
      setMessage('Registration submitted. A CISO must confirm the company before the SOC manager can create rooms.')
      setScreen('login')
    } catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }

  async function logout() {
    await apiRequest(apiUrl, '/api/auth/logout', { method: 'POST', body: JSON.stringify({ token: session.token }) }).catch(() => {})
    localStorage.removeItem('attense_session_token')
    setSession(null); setWorkspaceData(null); setScreen('login')
  }

  const destination = session && DESTINATIONS[session.role]

  return (
    <main className="portal-page">
      <section className="portal-card">
        <header className="portal-header">
          <div><p>ATTENSE</p><h1>Cyber Range Portal</h1></div>
          <label>Control API<input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} spellCheck="false" /></label>
        </header>

        {message && <p className="portal-message" role="alert">{message}</p>}

        {screen === 'login' && <>
          <form className="portal-form" onSubmit={submitLogin}>
            <h2>Sign in</h2>
            <label>Username<input name="username" required autoComplete="username" /></label>
            <label>Password<input name="password" required type="password" autoComplete="current-password" /></label>
            <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
          </form>
          <div className="portal-options"><button onClick={() => setScreen('company')}>Register company</button><button onClick={() => setScreen('ciso')}>Bootstrap first CISO</button></div>
        </>}

        {screen === 'company' && <form className="portal-form" onSubmit={(event) => submitRegistration(event, '/api/company/register-with-manager', ['company_name', 'manager_username', 'manager_email', 'manager_password'])}>
          <h2>Register a company</h2>
          <label>Company name<input name="company_name" required /></label>
          <label>SOC manager username<input name="manager_username" required /></label>
          <label>SOC manager email<input name="manager_email" type="email" required /></label>
          <label>SOC manager password<input name="manager_password" type="password" required /></label>
          <button disabled={busy}>{busy ? 'Submitting…' : 'Register company'}</button><button type="button" className="secondary" onClick={() => setScreen('login')}>Back</button>
        </form>}

        {screen === 'ciso' && <form className="portal-form" onSubmit={(event) => submitRegistration(event, '/api/auth/bootstrap-ciso', ['username', 'email', 'password'])}>
          <h2>Bootstrap CISO</h2><p>This works only until the first CISO account exists.</p>
          <label>Username<input name="username" required /></label><label>Email<input name="email" type="email" required /></label><label>Password<input name="password" type="password" required /></label>
          <button disabled={busy}>{busy ? 'Creating…' : 'Create CISO account'}</button><button type="button" className="secondary" onClick={() => setScreen('login')}>Back</button>
        </form>}

        {screen === 'workspace' && session && <section className="workspace">
          <p className="portal-eyebrow">Signed in as {session.username}</p><h2>{destination?.title || session.role}</h2><p>{destination?.description || 'No workspace mapping is configured for this role.'}</p>
          {session.role === 'red_team' && <p className="workspace-note">{session.room_id ? `Joined room: ${session.room_id}` : 'Join a room before starting an attack exercise.'}</p>}
          {session.role === 'ciso' && <p className="workspace-note">Companies visible: {Array.isArray(workspaceData) ? workspaceData.length : 'unavailable'}</p>}
          {session.role.startsWith('soc_') && <p className="workspace-note">Rooms visible: {Array.isArray(workspaceData) ? workspaceData.length : 'unavailable'}</p>}
          {destination?.url && <a className="workspace-link" href={destination.url} target="_blank" rel="noreferrer">Open workspace</a>}
          <button className="secondary" onClick={logout}>Sign out</button>
        </section>}
      </section>
    </main>
  )
}
