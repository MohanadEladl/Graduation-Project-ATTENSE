import { useEffect, useMemo, useState } from 'react'
import { api, captureTokenFromUrl, clearToken, getToken } from './api/client.js'

const defaultAction = {
  alert_id: 'alert-001',
  target_id: 'target-agent',
  target_type: 'host',
  severity: 'high',
  strategy: 'isolate_host',
  notes: '',
}

const defaultPermissions = {
  ciso: ['view_all_companies', 'view_all_reports', 'manage_permissions'],
  soc_manager: ['create_rooms', 'start_blue_team', 'manage_hive_keys', 'investigate_alerts', 'confirm_incidents', 'start_containment', 'complete_containment', 'review_reports'],
  soc_l1: ['investigate_alerts', 'confirm_incidents', 'start_containment'],
  soc_l2: ['complete_containment', 'review_reports'],
  red_team: ['join_rooms', 'create_attacks'],
}

const permissionLabels = {
  view_all_companies: 'View all companies',
  view_all_reports: 'View all reports',
  manage_permissions: 'Manage permissions',
  create_rooms: 'Create rooms',
  start_blue_team: 'Start blue exercise',
  manage_hive_keys: 'Manage Hive keys',
  investigate_alerts: 'Investigate alerts',
  confirm_incidents: 'Confirm incidents',
  start_containment: 'Start containment',
  complete_containment: 'Complete containment',
  review_reports: 'Review reports',
  join_rooms: 'Join rooms',
  create_attacks: 'Create attacks',
}

function pickIncident(room) {
  return room?.incident_id || room?.incidents?.[0] || room?.incidents_detail?.[0]?.incident_id || ''
}

function statusText(room) {
  if (!room) return 'No room selected'
  if (room.portal_demo) return 'Portal demo room ready'
  if (room.blue_started_at) return 'Blue timer running'
  if (room.packaged_at || room.attack_completed_at) return 'Packaged and waiting'
  if (room.prefired_at) return 'Attack pre-fired'
  return room.status || 'Ready'
}


function readInvitations() {
  try {
    return JSON.parse(localStorage.getItem('attense_blue_invitations') || '[]')
  } catch (_) {
    return []
  }
}

function readPermissionStore() {
  try {
    const raw = localStorage.getItem('attense_permission_store')
    if (!raw) return defaultPermissions
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : defaultPermissions
  } catch (_) {
    return defaultPermissions
  }
}

function writePermissionStore(store) {
  localStorage.setItem('attense_permission_store', JSON.stringify(store))
}

function AdminPanel({ permissions, onGrant, onRevoke }) {
  const roles = Object.keys(defaultPermissions)
  const actions = Object.keys(permissionLabels)
  const [role, setRole] = useState('soc_manager')
  const [action, setAction] = useState('create_rooms')

  return (
    <section className="panel admin-panel">
      <div className="admin-head">
        <div>
          <p className="eyebrow">Admin permissions</p>
          <h2>Grant or revoke access</h2>
        </div>
        <div className="admin-chip">Local mock backed</div>
      </div>

      <div className="admin-form">
        <label className="field">
          Role
          <select value={role} onChange={(event) => setRole(event.target.value)}>
            {roles.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label className="field">
          Permission
          <select value={action} onChange={(event) => setAction(event.target.value)}>
            {actions.map((item) => <option key={item} value={item}>{permissionLabels[item]}</option>)}
          </select>
        </label>
      </div>

      <div className="admin-actions">
        <button className="primary" type="button" onClick={() => onGrant(role, action)}>Grant</button>
        <button type="button" onClick={() => onRevoke(role, action)}>Revoke</button>
      </div>

      <div className="admin-grid">
        {roles.map((item) => (
          <article key={item} className="admin-role-card">
            <div className="admin-role-head">
              <strong>{item}</strong>
              <span>{permissions[item]?.length || 0} permissions</span>
            </div>
            <div className="perm-list">
              {(permissions[item] || []).length > 0 ? (
                permissions[item].map((perm) => (
                  <span key={perm} className="perm-pill">{permissionLabels[perm] || perm}</span>
                ))
              ) : (
                <span className="muted">No permissions granted.</span>
              )}
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}

function NotificationsDrawer({ open, invitations, onClose }) {
  return (
    <>
      <div className={open ? 'drawer-backdrop open' : 'drawer-backdrop'} onClick={onClose} aria-hidden={!open} />
      <aside className={open ? 'notif-drawer open' : 'notif-drawer'} aria-hidden={!open}>
        <div className="drawer-head">
          <div className="drawer-title">
            <p className="eyebrow">Notifications</p>
            <h2>{invitations.length ? `${invitations.length} invitation${invitations.length === 1 ? '' : 's'}` : 'No invitations'}</h2>
          </div>
          <button className="drawer-close" type="button" onClick={onClose}>Close</button>
        </div>
        <div className="drawer-body">
          {!invitations.length && <div className="empty">No invitations yet.</div>}
          {invitations.length > 0 && (
            <div className="invite-list">
              {invitations.map((invite) => (
                <article className="invite" key={invite.id}>
                  <div>
                    <h3>{invite.email}</h3>
                    <p>{invite.roomName} - Invite {invite.code} - {invite.createdAt}</p>
                  </div>
                  <span className="badge">Pending</span>
                </article>
              ))}
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
function portalRoomFromUrl() {
  const params = new URLSearchParams(window.location.search)
  const roomId = params.get('portalRoom')
  if (!roomId) return null
  return {
    room_id: roomId,
    scenario_id: params.get('scenario') || 'phishing',
    status: 'Portal demo',
    portal_demo: true,
    created_at: new Date().toISOString(),
    incidents_detail: [{
      incident_id: `${roomId}-INC`,
      status: 'READY',
      report: {
        scenario_id: params.get('scenario') || 'phishing',
        metrics: {},
      },
    }],
    portal_name: params.get('roomName') || roomId,
    portal_mode: params.get('mode') || 'team',
    hive_launch_url: params.get('hiveUrl') || 'http://127.0.0.1:9000/',
  }
}
function LoginPanel({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api.auth.login(username.trim(), password)
      await onLogin()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="login-shell">
      <form className="login-card" onSubmit={submit}>
        <img src="/assets/ATTENSELOGO.png" alt="ATTENSE" />
        <p className="eyebrow">Blue Team access</p>
        <h1>Enter the response room</h1>
        <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
        <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
        {error && <p className="error">{error}</p>}
        <button disabled={loading}>{loading ? 'Authenticating...' : 'Continue'}</button>
      </form>
    </main>
  )
}

function RoomList({ rooms, activeRoomId, onSelect, invitations, onOpenNotifications, user }) {
  return (
    <aside className="sidebar">
      <div className="brand"><img src="/assets/ATTENSELOGO.png" alt="" /><span>ATTENSE</span></div>
      <p className="eyebrow">Blue Team rooms</p>
      <div className="room-list">
        {rooms.map((room) => (
          <button
            key={room.room_id}
            className={room.room_id === activeRoomId ? 'room active' : 'room'}
            onClick={() => onSelect(room.room_id)}
          >
            <span>{room.room_id}</span>
            <small>{statusText(room)}</small>
          </button>
        ))}
        {!rooms.length && <p className="muted">No rooms available for this account.</p>}
      </div>
      <div className="sidebar-footer">
        <button className="notif-trigger sidebar-notif" type="button" onClick={onOpenNotifications}>
          <span className="notif-trigger-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M15 17h5l-1.4-1.4A2 2 0 0 1 18 14.2V11a6 6 0 0 0-4-5.7V4a2 2 0 1 0-4 0v1.3A6 6 0 0 0 6 11v3.2a2 2 0 0 1-.6 1.4L4 17h5" />
              <path d="M9 17a3 3 0 0 0 6 0" />
            </svg>
            Invitations
          </span>
          {invitations.length > 0 && <span className="notif-count">{invitations.length}</span>}
        </button>
        <div className="sidebar-user">
          <div className="sidebar-avatar">{(user?.username || 'B').slice(0, 1).toUpperCase()}</div>
          <div className="sidebar-user-copy">
            <strong>{user?.username || 'Blue operator'}</strong>
            <span>{user?.role || 'SOC Analyst'}</span>
          </div>
          <span className="status-dot" />
        </div>
      </div>
    </aside>
  )
}

function Field({ label, value, onChange, options }) {
  if (options) {
    return (
      <label className="field">{label}
        <select value={value} onChange={(event) => onChange(event.target.value)}>
          {options.map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
      </label>
    )
  }
  return (
    <label className="field">{label}
      <input value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  )
}

function Timeline({ room }) {
  const rows = [
    ['Created', room?.created_at],
    ['Pre-fired', room?.prefired_at],
    ['Attack started', room?.attack_started_at],
    ['Attack completed', room?.attack_completed_at],
    ['Packaged', room?.packaged_at],
    ['Blue entered', room?.blue_started_at],
  ]
  return (
    <section className="panel timeline">
      <h2>Deferred timeline</h2>
      {rows.map(([label, value]) => (
        <div className="time-row" key={label}>
          <span>{label}</span>
          <strong>{value ? new Date(value).toLocaleString() : 'Pending'}</strong>
        </div>
      ))}
    </section>
  )
}

function IncidentSummary({ room }) {
  const details = room?.incidents_detail || []
  return (
    <section className="panel incident-panel">
      <h2>Incident package</h2>
      {!details.length && <p className="muted">No incident report is packaged yet.</p>}
      {details.map((item) => (
        <article key={item.incident_id} className="incident-card">
          <div>
            <p className="eyebrow">{item.status}</p>
            <h3>{item.incident_id}</h3>
          </div>
          <dl>
            <div><dt>Scenario</dt><dd>{item.report?.scenario_id || room.scenario_id || 'Unknown'}</dd></div>
            <div><dt>TTD</dt><dd>{item.report?.metrics?.ttd_seconds ?? 'Pending'}</dd></div>
            <div><dt>TTC</dt><dd>{item.report?.metrics?.ttc_seconds ?? 'Pending'}</dd></div>
          </dl>
        </article>
      ))}
    </section>
  )
}

function ActionPanel({ user, room, onResult }) {
  const [form, setForm] = useState(defaultAction)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const incidentId = pickIncident(room)
  const scenarioId = room?.scenario_id || 'default-scenario'
  const analystId = user?.username || 'analyst-1'

  const payload = useMemo(() => ({
    incident_id: incidentId,
    scenario_id: scenarioId,
    analyst_id: analystId,
    alert_id: form.alert_id,
    target_id: form.target_id,
    target_type: form.target_type,
    severity: form.severity,
    strategy: form.strategy,
    notes: form.notes || undefined,
  }), [analystId, form, incidentId, scenarioId])

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }))
  }

  async function run(name, request) {
    setBusy(name)
    setError('')
    try {
      const result = await request()
      onResult(result)
    } catch (err) {
      setError(err.message || 'Action failed')
    } finally {
      setBusy('')
    }
  }

  const disabled = !room || !incidentId || busy

  return (
    <section className="panel action-panel">
      <h2>Analyst actions</h2>
      <div className="form-grid">
        <Field label="Alert ID" value={form.alert_id} onChange={(value) => update('alert_id', value)} />
        <Field label="Target ID" value={form.target_id} onChange={(value) => update('target_id', value)} />
        <Field label="Target type" value={form.target_type} onChange={(value) => update('target_type', value)} options={['host', 'service', 'account']} />
        <Field label="Severity" value={form.severity} onChange={(value) => update('severity', value)} options={['low', 'medium', 'high', 'critical']} />
        <Field label="Strategy" value={form.strategy} onChange={(value) => update('strategy', value)} options={['isolate_host', 'kill_process', 'block_request', 'lock_account', 'block_path']} />
        <Field label="Notes" value={form.notes} onChange={(value) => update('notes', value)} />
      </div>
      {error && <p className="error">{error}</p>}
      <div className="action-grid">
        <button disabled={disabled} onClick={() => run('Investigate', () => api.blue.investigate(room.room_id, payload))}>{busy === 'Investigate' ? 'Working...' : 'Investigate'}</button>
        <button disabled={disabled} onClick={() => run('Confirm', () => api.blue.confirm(room.room_id, payload))}>Confirm incident</button>
        <button disabled={disabled} onClick={() => run('Deny', () => api.blue.deny(room.room_id, payload))}>Deny alert</button>
        <button disabled={disabled} onClick={() => run('Contain', () => api.blue.initiateContainment(room.room_id, payload))}>Start containment</button>
        <button disabled={disabled} onClick={() => run('Complete', () => api.blue.completeContainment(room.room_id, payload))}>Complete containment</button>
      </div>
    </section>
  )
}

export default function App() {
  const [user, setUser] = useState(null)
  const [rooms, setRooms] = useState([])
  const [activeRoomId, setActiveRoomId] = useState('')
  const [activeRoom, setActiveRoom] = useState(null)
  const [result, setResult] = useState(null)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [invitations, setInvitations] = useState(() => readInvitations())
  const [permissionStore, setPermissionStore] = useState(() => readPermissionStore())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function loadInitial() {
    setLoading(true)
    setError('')
    try {
      const me = await api.auth.me()
      setUser(me)
      const listed = await api.rooms.list()
      setRooms(listed)
      const first = activeRoomId || listed[0]?.room_id || ''
      setActiveRoomId(first)
      if (first) setActiveRoom(await api.rooms.get(first))
    } catch (err) {
      setError(err.message || 'Unable to load Blue Team workspace')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const syncInvitations = () => setInvitations(readInvitations())
    syncInvitations()
    window.addEventListener('storage', syncInvitations)
    return () => window.removeEventListener('storage', syncInvitations)
  }, [])

  useEffect(() => {
    const syncPermissions = () => setPermissionStore(readPermissionStore())
    syncPermissions()
    window.addEventListener('storage', syncPermissions)
    return () => window.removeEventListener('storage', syncPermissions)
  }, [])

  useEffect(() => {
    const portalRoom = portalRoomFromUrl()
    if (portalRoom) {
      setUser({ username: 'portal-blue-user', role: 'Blue Team' })
      setRooms([portalRoom])
      setActiveRoomId(portalRoom.room_id)
      setActiveRoom(portalRoom)
      setLoading(false)
      return
    }
    captureTokenFromUrl()
    if (!getToken()) {
      setLoading(false)
      return
    }
    loadInitial()
  }, [])

  async function selectRoom(roomId) {
    setActiveRoomId(roomId)
    setActiveRoom(await api.rooms.get(roomId))
  }

  async function startBlue() {
    if (!activeRoomId) return
    if (activeRoom?.portal_demo) {
      window.location.href = activeRoom?.hive_launch_url || activeRoom?.hiveLaunchUrl || 'http://127.0.0.1:9000/'
      return
    }
    setError('')
    try {
      const room = await api.rooms.blueStart(activeRoomId)
      setActiveRoom(room)
      setRooms((current) => current.map((item) => item.room_id === activeRoomId ? { ...item, ...room } : item))
    } catch (err) {
      setError(err.message || 'Could not start Blue Team timer')
    }
  }

  async function refresh() {
    if (!activeRoomId) return loadInitial()
    const room = await api.rooms.get(activeRoomId)
    setActiveRoom(room)
  }

  function grantPermission(role, action) {
    setPermissionStore((current) => {
      const next = { ...current, [role]: Array.from(new Set([...(current[role] || []), action])) }
      writePermissionStore(next)
      return next
    })
  }

  function revokePermission(role, action) {
    setPermissionStore((current) => {
      const next = { ...current, [role]: (current[role] || []).filter((item) => item !== action) }
      writePermissionStore(next)
      return next
    })
  }

  function logout() {
    clearToken()
    setUser(null)
    setRooms([])
    setActiveRoom(null)
    setNotificationsOpen(false)
  }

  if (!getToken() && !user && !loading) return <LoginPanel onLogin={loadInitial} />

  return (
    <div className="app-shell">
            <RoomList
        rooms={rooms}
        activeRoomId={activeRoomId}
        onSelect={selectRoom}
        invitations={invitations}
        onOpenNotifications={() => setNotificationsOpen(true)}
        user={user}
      />
      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">{user?.role || 'Blue Team'}</p>
            <h1>{activeRoom?.room_id || 'Response console'}</h1>
            <p className="muted">{statusText(activeRoom)}</p>
          </div>
          <div className="top-actions">
            <button onClick={refresh}>Refresh</button>
            <button className="notif-trigger" type="button" onClick={() => setNotificationsOpen(true)}>
              Notifications
              {invitations.length > 0 && <span className="notif-count">{invitations.length}</span>}
            </button>
            <button className="primary" onClick={startBlue} disabled={!activeRoomId || activeRoom?.blue_started_at}>Enter TheHive</button>
            <button onClick={logout}>Logout</button>
          </div>
        </header>
        {loading && <section className="panel"><p className="muted">Loading workspace...</p></section>}
        {error && <p className="error banner">{error}</p>}
        {!loading && activeRoom && (
          <div className="grid">
            <Timeline room={activeRoom} />
            <IncidentSummary room={activeRoom} />
            <ActionPanel user={user} room={activeRoom} onResult={setResult} />
            <section className="panel result-panel">
              <h2>Last action</h2>
              {result ? <pre>{JSON.stringify(result, null, 2)}</pre> : <p className="muted">No analyst action submitted yet.</p>}
            </section>
          </div>
        )}
        {(user?.role === 'ciso' || user?.role === 'admin') && (
          <AdminPanel permissions={permissionStore} onGrant={grantPermission} onRevoke={revokePermission} />
        )}
      </main>
      <NotificationsDrawer open={notificationsOpen} invitations={invitations} onClose={() => setNotificationsOpen(false)} />
    </div>
  )
}
