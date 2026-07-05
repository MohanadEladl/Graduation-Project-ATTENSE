import { useEffect, useState } from 'react'
import { api, captureTokenFromUrl, clearToken, getToken } from './api/client.js'
import './styles.css'

const roleNames = {
 ciso: 'CISO',
 soc_manager: 'SOC Manager',
 soc_l1: 'SOC Analyst',
 soc_l2: 'SOC Analyst',
 soc: 'SOC Analyst',
}

const scenarioNames = {
 phishing: 'Phishing Campaign',
 ransomware: 'Ransomware Outbreak',
 insider: 'Insider Threat Simulation',
 web: 'Zero-Day Exploitation',
}

const fallbackRooms = [
 { room_id: 'RM-001', scenario_id: 'ransomware', room_name: 'Ransomware Outbreak', status: 'Active', portal_demo: true, hive_launch_url: 'http://127.0.0.1:9000/', desc: 'Contain a live ransomware infection spreading across network endpoints in real-time. Isolate, investigate, and eradicate.' },
 { room_id: 'RM-002', scenario_id: 'apt', room_name: 'APT Infiltration', status: 'Active', portal_demo: true, hive_launch_url: 'http://127.0.0.1:9000/', desc: 'Hunt and expel a persistent threat actor embedded deep in your infrastructure. Lateral movement in progress.' },
 { room_id: 'RM-003', scenario_id: 'supply-chain', room_name: 'Supply Chain Attack', status: 'Active', portal_demo: true, hive_launch_url: 'http://127.0.0.1:9000/', desc: 'Investigate compromised software updates affecting critical production systems. Trace the attack vector to its origin.' },
 { room_id: 'RM-004', scenario_id: 'phishing', room_name: 'Phishing Campaign', status: 'Pending', desc: 'Detect and respond to a coordinated multi-vector phishing campaign targeting all staff. Awaiting activation.' },
 { room_id: 'RM-005', scenario_id: 'web', room_name: 'Zero-Day Exploitation', status: 'Pending', desc: 'Respond to active exploitation of an unpatched critical vulnerability in production infrastructure.' },
 { room_id: 'RM-006', scenario_id: 'insider', room_name: 'Insider Threat Simulation', status: 'Closed', desc: 'Retrospective analysis of a malicious insider data exfiltration incident. Review mode only.' },
]

const analystSeed = [
 { id: 1, name: 'Jane Smith', avatar: 'J', role: 'SOC Analyst', score: 91, grade: 'A', ttd: '4m 22s', ttc: '12m 08s', ttr: '18m 45s', det: 94, con: 82, rec: 87, narrative: 'Exceptional response with outstanding threat isolation speed. Isolated the affected host within minutes, preventing lateral spread to 4 additional endpoints. Detection time was 38% faster than team average. Containment strategy reflected deep knowledge of network segmentation. Minor delay in eradication phase - recommend reviewing rollback procedures before next exercise.' },
 { id: 2, name: 'Marcus Chen', avatar: 'M', role: 'IR Lead', score: 88, grade: 'A-', ttd: '5m 10s', ttc: '10m 22s', ttr: '22m 17s', det: 88, con: 91, rec: 84, narrative: 'Strong leadership during incident response. Coordinated team actions effectively and maintained clear stakeholder communication throughout. Containment was the standout skill. Detection time slightly above average; tuning alert thresholds recommended.' },
 { id: 3, name: 'Sara Okonkwo', avatar: 'S', role: 'Threat Hunter', score: 79, grade: 'B+', ttd: '6m 55s', ttc: '16m 40s', ttr: '25m 10s', det: 82, con: 74, rec: 78, narrative: 'Strong threat hunting instincts surfaced two compromised hosts missed in initial triage. Detection time needs improvement. Overall a solid performance with clear areas to build on.' },
 { id: 4, name: 'Raj Patel', avatar: 'R', role: 'SOC Analyst', score: 74, grade: 'B', ttd: '8m 12s', ttc: '18m 55s', ttr: '28m 30s', det: 76, con: 70, rec: 74, narrative: 'Adequate performance with correct escalation procedures followed. Incident classification was accurate, but detection time was below team average.' },
 { id: 5, name: 'Lena Fischer', avatar: 'L', role: 'SOC Analyst', score: 68, grade: 'C+', ttd: '9m 44s', ttc: '22m 03s', ttr: '34m 18s', det: 65, con: 68, rec: 72, narrative: 'Performance shows clear areas for growth. Initial difficulty classifying the ransomware event severity caused delayed escalation.' },
 { id: 6, name: 'Tom Bradley', avatar: 'T', role: 'IR Lead', score: 84, grade: 'B+', ttd: '5m 58s', ttc: '13m 20s', ttr: '21m 05s', det: 86, con: 80, rec: 85, narrative: 'Strong all-around performance with excellent incident timeline management. Good detection accuracy with appropriate severity classification.' },
]

function readJson(key, fallback) {
 try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)) } catch (_) { return fallback }
}

function readProfile() {
 return readJson('attense_blue_profile', {})
}

function roomName(room) {
 return room?.portal_name || room?.room_name || room?.name || room?.scenario_name || room?.room_id || 'Response room'
}

function roomScenario(room) {
 const key = room?.scenario_id || room?.scenario || room?.incidents_detail?.[0]?.report?.scenario_id || 'phishing'
 return scenarioNames[key] || roomName(room) || key
}

function roomDate(room) {
 const value = room?.created_at || room?.createdAt || room?.blue_started_at || new Date().toISOString()
 return new Date(value).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })
}

function roomStatus(room) {
 if (!room) return 'Pending'
 if (room.portal_demo || room.blue_started_at || String(room.status || '').toLowerCase() === 'active') return 'Active'
 if (room.packaged_at || room.attack_completed_at || room.prefired_at || String(room.status || '').toLowerCase() === 'pending') return 'Pending'
 if (String(room.status || '').toLowerCase() === 'closed') return 'Closed'
 return room.status || 'Pending'
}

function roomDescription(room) {
 return room?.desc || room?.description || room?.metadata?.description || 'Respond to the active incident, review the evidence, and complete the exercise objectives with your team.'
}

function roomScore(room, offset = 0) {
 const seed = String(roomName(room) + '-' + (room?.room_id || '')).length + offset
 return Math.max(68, Math.min(98, 78 + (seed % 18)))
}

function formatSeconds(seconds) {
 const total = Number(seconds)
 if (!Number.isFinite(total)) return String(seconds)
 const mins = Math.floor(total / 60)
 const secs = total % 60
 const hours = Math.floor(mins / 60)
 const remMin = mins % 60
 if (hours > 0) return `${hours}h ${remMin}m`
 if (mins > 0) return `${mins}m ${secs}s`
 return `${secs}s`
}

function formatDuration(value) {
 if (value == null) return '--'
 if (typeof value === 'string') return value
 if (typeof value === 'number') return formatSeconds(value)
 if (typeof value === 'object') {
 if ('total_seconds' in value && typeof value.total_seconds === 'number') return formatSeconds(value.total_seconds)
 if ('seconds' in value) {
 const days = Number(value.days || 0)
 const seconds = Number(value.seconds || 0)
 const micros = Number(value.microseconds || 0)
 return formatSeconds(days * 86400 + seconds + micros / 1e6)
 }
 return String(value)
 }
 return String(value)
}

function normalizeReport(report) {
 const normalized = { ...(report || {}) }
 const metrics = report?.metrics || {}
 if (normalized.ttd == null && metrics.ttd_seconds != null) normalized.ttd = metrics.ttd_seconds
 if (normalized.ttc == null && metrics.ttc_seconds != null) normalized.ttc = metrics.ttc_seconds
 if (normalized.detection_time == null && metrics.detection_time != null) normalized.detection_time = metrics.detection_time
 if (normalized.containment_time == null && metrics.containment_time != null) normalized.containment_time = metrics.containment_time
 return normalized
}

function reportFromRoom(room) {
 return normalizeReport(room?.incidents_detail?.[0]?.report || {})
}

function reportScore(report) {
 if (report == null) return null
 if (typeof report.final_score === 'number') return report.final_score
 if (typeof report.score === 'number') return report.score
 return null
}

function hasReportData(report) {
 if (!report || typeof report !== 'object') return false
 return (
 report?.outcome != null ||
 report?.ttd != null ||
 report?.ttc != null ||
 report?.final_score != null ||
 report?.score != null ||
 (report.metrics && (report.metrics.ttd_seconds != null || report.metrics.ttc_seconds != null))
 )
}

function roomOutcome(room) {
 const report = reportFromRoom(room)
 return report?.outcome || room?.outcome || roomStatus(room)
}

function gradeFor(score) {
 if (score >= 90) return 'A'
 if (score >= 85) return 'A-'
 if (score >= 80) return 'B+'
 if (score >= 74) return 'B'
 if (score >= 68) return 'C+'
 return 'C'
}

function scoreColor(score) {
 if (score >= 90) return '#43d39f'
 if (score >= 80) return '#53b8ff'
 if (score >= 70) return '#f2b95b'
 return '#ef5350'
}

function portalRoomFromUrl() {
 const params = new URLSearchParams(window.location.search)
 const roomId = params.get('portalRoom')
 if (!roomId) return null
 const scenario = params.get('scenario') || 'phishing'
 const name = params.get('roomName') || roomId
 return {
 room_id: roomId,
 room_name: name,
 portal_name: name,
 scenario_id: scenario,
 status: 'Active',
 portal_demo: true,
 created_at: new Date().toISOString(),
 portal_mode: params.get('mode') || 'team',
 hive_launch_url: params.get('hiveUrl') || 'http://127.0.0.1:9000/',
 incidents_detail: [{
 incident_id: roomId + '-INC',
 status: 'READY',
 report: {
 scenario_id: scenario,
 ttd: Number(params.get('ttd') || params.get('ttd_seconds') || 320),
 ttc: Number(params.get('ttc') || params.get('ttc_seconds') || 740),
 metrics: { ttd_seconds: Number(params.get('ttd') || params.get('ttd_seconds') || 320), ttc_seconds: Number(params.get('ttc') || params.get('ttc_seconds') || 740) },
 },
 }],
 }
}

function buildNotifications(rooms, showFallback) {
 const shownRooms = rooms.length ? rooms : (showFallback ? fallbackRooms : [])
 const items = []
 shownRooms.forEach((room, index) => {
 const status = roomStatus(room)
 if (status === 'Active') {
 items.push({
 id: `room-${room.room_id || index}`,
 tone: 'blue',
 title: 'Room ready for investigation',
 body: `${roomName(room)} is active. Open the room to continue response work in TheHive.`,
 meta: roomDate(room),
 room,
 action: 'Open Room',
 })
 } else if (status === 'Pending') {
 items.push({
 id: `pending-${room.room_id || index}`,
 tone: 'yellow',
 title: 'Room waiting for activation',
 body: `${roomName(room)} is staged and will be available when a SOC Manager starts it.`,
 meta: roomDate(room),
 room,
 action: 'View Lobby',
 })
 }
 const report = reportFromRoom(room)
 if (hasReportData(report)) {
 items.push({
 id: `report-${room.room_id || index}`,
 tone: 'green',
 title: 'Report available',
 body: `${roomScenario(room)} has report data ready for review.`,
 meta: roomOutcome(room),
 room,
 action: 'View Report',
 })
 }
 })
 items.unshift({
 id: 'hive-connector',
 tone: 'purple',
 title: 'TheHive connector online',
 body: 'Blue Team rooms launch into TheHive for case handling. ATTENSE records room and report state locally.',
 meta: 'System',
 room: shownRooms[0] || null,
 action: 'System Notice',
 })
 return items.slice(0, 12)
}
function hiveUrlForRoom(room) {
 return room?.hive_launch_url || room?.hiveLaunchUrl || room?.metadata?.hive_launch_url || 'http://127.0.0.1:9000/'
}

function openHiveForRoom(room) {
 const hiveWindow = window.open(hiveUrlForRoom(room), '_blank', 'noopener,noreferrer')
 if (!hiveWindow) {
 window.location.href = hiveUrlForRoom(room)
 }
}
function Icon({ name, active }) {
 const stroke = active ? '#4a86e8' : '#6f7689'
 if (name === 'dashboard') return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></svg>
 if (name === 'rooms') return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>
 if (name === 'notifications') return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></svg>
 return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>
}

function Sidebar({ view, setView, user, logout }) {
 const role = roleNames[user?.role] || user?.role || 'SOC Analyst'
 const username = user?.username || user?.name || 'Blue Team'
 return (
 <aside className="dc-sidebar">
 <div className="dc-brand-block">
 <div className="dc-brand-row"><img src="/assets/ATTENSELOGO.png" alt="" /><span>ATTENSE</span></div>
 <div className="dc-brand-sub">Blue Team Portal</div>
 </div>
 <nav className="dc-nav">
 {[
 ['dashboard', 'Dashboard'],
 ['rooms', 'Rooms'],
 ['reports', 'Reports'],
 ['notifications', 'Notifications'],
 ].map(([key, label]) => (
 <button className={view === key ? 'active' : ''} key={key} type="button" onClick={() => setView(key)}>
 <Icon name={key} active={view === key} /><span>{label}</span>
 </button>
 ))}
 <div className="dc-nav-rule" />
 <button type="button" onClick={() => window.history.back()}><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#6f7689" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6" /></svg><span>Go Back</span></button>
 </nav>
 <div className="dc-sidebar-bottom">
 <div className="dc-user-card">
 <div className="dc-avatar">{username.slice(0, 1).toUpperCase()}</div>
 <div><strong>{username}</strong><span>{role}</span></div>
 <i />
 </div>
 <button className="dc-logout" type="button" onClick={logout}>Reset session</button>
 </div>
 </aside>
 )
}

function StatTile({ tone, value, label, detail }) {
 return <article className={'dc-stat dc-stat-' + tone}><b /><strong>{value}</strong><span>{label}</span><p>{detail}</p></article>
}

function DashboardView({ user, rooms, setView, selectRoom, showFallback }) {
 const shownRooms = rooms.length ? rooms : (showFallback ? fallbackRooms : [])
 const reports = shownRooms.slice(0, 5).map((room, index) => {
 const report = reportFromRoom(room)
 const score = reportScore(report) ?? 0
 return {
 room,
 id: 'RPT-' + String(2847 - index * 6),
 scenario: roomScenario(room),
 date: roomDate(room),
 score,
 grade: gradeFor(score),
 verdict: report?.verdict,
 outcome: report?.outcome || roomOutcome(room),
 }
 })
 const average = Math.round(reports.reduce((sum, item) => sum + item.score, 0) / Math.max(reports.length, 1))
 const best = Math.max(...reports.map((item) => item.score), 0)
 const name = 'Blue Team'
 const today = new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: '2-digit', year: 'numeric' })
 return (
 <main className="dc-main">
 <section className="dc-header">
 <div><p>Good morning - {today}</p><h1>Blue Team <span>Dashboard.</span></h1><div className="dc-chips"><em>SOC Analyst</em><em className="online">Online</em></div></div>
 <button type="button" onClick={() => setView('rooms')} className="dc-primary-link">Enter a New Room</button>
 </section>
 <section className="dc-stats-grid">
 <StatTile tone="purple" value={average + '%'} label="Overall Avg Score" detail={'Across ' + shownRooms.length + ' rooms'} />
 <StatTile tone="blue" value={shownRooms.length} label="Rooms Completed" detail="+2 this month" />
 <StatTile tone="green" value="#4" label="Team Rank" detail="Out of 14 analysts" />
 <StatTile tone="red" value={best} label="Best Score" detail={reports[0]?.scenario || 'Ransomware Outbreak'} />
 </section>
 <section className="dc-table-card">
 <header><div><h2>Recent History</h2><p>All completed exercises</p></div><button type="button" onClick={() => setView('reports')}>View all reports</button></header>
 <div className="dc-history-head"><span>Scenario</span><span>Date</span><span>Score</span><span>Grade</span><span>Action</span></div>
 {reports.length ? reports.map((report) => <div className="dc-history-row" key={report.id}><div><strong>{report.scenario}</strong><small>{report.id}</small></div><span>{report.date}</span><b style={{ color: scoreColor(report.score) }}>{report.score}</b><i style={{ color: scoreColor(report.score), borderColor: scoreColor(report.score) + '40', background: scoreColor(report.score) + '18' }}>{report.grade}</i><button type="button" onClick={() => { selectRoom(report.room.room_id); setView('reports') }}>View Report</button></div>) : <div className="dc-empty">No reports available yet.</div>}
 </section>
 <section className="dc-room-banner"><div><p>Start Training</p><h2>Ready for your next exercise?</h2><span>Browse available rooms and jump into a live scenario. Three rooms are currently active and accepting analysts.</span></div><button type="button" onClick={() => setView('rooms')}>Browse Rooms</button></section>
 </main>
 )
}

function RoomsView({ rooms, activeRoomId, enterRoom, endRoom, openRoomInHive, selectRoom, setView, showFallback }) {
 const shownRooms = rooms.length ? rooms : (showFallback ? fallbackRooms : [])
 const activeCount = shownRooms.filter((room) => roomStatus(room) === 'Active').length
 function viewReport(room) {
 selectRoom(room.room_id)
 setView('reports')
 }
 return (
 <main className="dc-main">
 <section className="dc-header room-header"><div><p>Training Rooms</p><h1>Room Lobby</h1><span>Browse available incident response scenarios. Enter any active room to begin your training exercise.</span></div><div className="dc-active-now"><strong>{activeCount} Active Now</strong><small>{shownRooms.length} rooms total</small></div></section>
 <section className="dc-room-grid">
 {shownRooms.length ? shownRooms.map((room) => {
 const status = roomStatus(room)
 const active = status === 'Active'
 const pending = status === 'Pending'
 const closed = status === 'Closed'
 return <article className={'dc-room-card ' + status.toLowerCase()} key={room.room_id || room.id} data-selected={room.room_id === activeRoomId}><div className="dc-room-top"><span><i />{status}</span><small>{room.room_id || room.id}</small></div><h3>{roomName(room)}</h3><p>{roomDescription(room)}</p><div className="dc-room-actions">{active && <button type="button" onClick={() => enterRoom(room)}>Enter Room</button>}{closed && <button type="button" onClick={() => openRoomInHive(room)}>Open in TheHive</button>}{pending && <button type="button" disabled>Not Yet Active</button>}<button type="button" className="ghost" onClick={() => viewReport(room)}>View Report</button>{active && <button className="danger" type="button" onClick={() => endRoom(room)}>End Incident & Report</button>}</div></article>
 }) : <div className="dc-empty">No rooms are available yet.</div>}
 </section>
 <section className="dc-note">Pending rooms open when activated by a SOC Manager. Closed rooms stay open for retrospective review - reopen them in TheHive or view their report anytime.</section>
 </main>
 )
}

function SkillBar({ label, value, tone }) {
 return <div className="dc-skill"><div><span>{label}</span><b>{value}%</b></div><i><em className={tone} style={{ width: value + '%' }} /></i></div>
}

function ReportView({ user, room }) {
 const [mode, setMode] = useState((user?.role === 'soc_manager' || user?.role === 'ciso') ? 'manager' : 'analyst')
 const [expanded, setExpanded] = useState(null)
 if (!room) {
 return (
 <main className="dc-main">
 <section className="dc-empty">No active room selected. Choose a room from the lobby or authenticate with a valid session.</section>
 </main>
 )
 }
 const activeRoom = room
 const report = reportFromRoom(activeRoom)
 const hasReport = hasReportData(report)
 if (!hasReport) {
 return (
 <main className="dc-main">
 <section className="dc-empty">
 <h2>{roomName(activeRoom)}</h2>
 <p>No incident report is available for this room yet.</p>
 <p>Either the room has not started or the backend has not generated report data.</p>
 </section>
 </main>
 )
 }
 const actualScore = reportScore(report) ?? 0
 const analystRows = [{
 id: activeRoom.room_id || activeRoom.id || 'report-1',
 name: roomName(activeRoom),
 avatar: roomName(activeRoom).slice(0, 1).toUpperCase(),
 role: roleNames[user?.role] || user?.role || 'SOC Analyst',
 score: actualScore,
 grade: gradeFor(actualScore),
 ttd: formatDuration(report?.ttd),
 ttc: formatDuration(report?.ttc),
 ttr: formatDuration(report?.ttc),
 det: report?.ttd != null ? Math.max(40, Math.min(98, 100 - Math.round(Number(report.ttd) / 6))) : 72,
 con: report?.ttc != null ? Math.max(40, Math.min(98, 100 - Math.round(Number(report.ttc) / 5))) : 68,
 rec: report?.ttc != null ? Math.max(40, Math.min(95, 100 - Math.round(Number(report.ttc) / 8))) : 70,
 narrative: report?.outcome ? `Live incident outcome: ${report.outcome}` : 'This room report is pending or unavailable.',
 }]
 const scores = analystRows.map((item) => item.score)
 const teamAvg = Math.round(scores.reduce((sum, item) => sum + item, 0) / Math.max(scores.length, 1))
 return (
 <main className="dc-main">
 <section className="dc-report-header"><div><p>Post-Incident Report</p><h1>{roomScenario(activeRoom)}</h1><div className="dc-report-badges"><span>{roomDate(activeRoom)}</span><span>{roomOutcome(activeRoom)}</span></div></div><div className="dc-toggle"><button className={mode === 'analyst' ? 'active' : ''} onClick={() => setMode('analyst')}>Analyst View</button><button className={mode === 'manager' ? 'active manager' : ''} onClick={() => setMode('manager')}>SOC Manager</button></div></section>
 {mode === 'analyst' && <section className="dc-analyst-report"><div className="dc-score-card"><div className="dc-score-ring"><svg viewBox="0 0 140 140"><defs><linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#4a86e8" /><stop offset="100%" stopColor="#43d39f" /></linearGradient></defs><circle cx="70" cy="70" r="52" /><circle cx="70" cy="70" r="52" pathLength="100" style={{ strokeDasharray: 100, strokeDashoffset: 100 - actualScore }} /></svg><div><strong>{actualScore}</strong><span>/100</span></div></div><p>Final Grade</p><b style={{ color: scoreColor(actualScore), borderColor: scoreColor(actualScore) + '40', background: scoreColor(actualScore) + '18' }}>{gradeFor(actualScore)}</b></div><div className="dc-report-side"><div className="dc-metric-grid"><article><span>Time to Detect</span><strong>{formatDuration(report?.ttd)}</strong><p>TTD</p></article><article><span>Time to Contain</span><strong>{formatDuration(report?.ttc)}</strong><p>TTC</p></article><article><span>Time to Respond</span><strong>{formatDuration(report?.ttc)}</strong><p>TTR</p></article></div><div className="dc-skills"><h2>Skill Breakdown</h2><SkillBar label="Detection" value={analystRows[0].det} tone="green" /><SkillBar label="Containment" value={analystRows[0].con} tone="blue" /><SkillBar label="Recovery" value={analystRows[0].rec} tone="purple" /></div></div><div className="dc-ai-feedback"><h2>Incident Outcome</h2><p>{report?.outcome ? `The incident received outcome: ${report.outcome}.` : analystRows[0].narrative}</p></div></section>}
 {mode === 'manager' && <section className="dc-manager-report"><div className="dc-team-stats"><article><span>Team Avg Score</span><strong>{teamAvg}</strong><p>/ 100 points</p></article><article><span>Best Score</span><strong>{Math.max(...scores)}</strong><p>{roomName(activeRoom)}</p></article><article><span>Lowest Score</span><strong>{Math.min(...scores)}</strong><p>Review needed</p></article><article><span>Analysts</span><strong>{analystRows.length}</strong><p>Report rows</p></article></div><div className="dc-analyst-table"><header><h2>Incident Summary</h2><p>Report derived from active room data</p></header><div className="dc-analyst-head"><span>Report</span><span>Role</span><span>Score</span><span>TTD</span><span>TTC</span><span>TTR</span><span /></div>{analystRows.map((analyst) => <div key={analyst.id}><button className="dc-analyst-row" type="button" onClick={() => setExpanded(expanded === analyst.id ? null : analyst.id)}><div><i>{analyst.avatar}</i><strong>{analyst.name}</strong></div><span>{analyst.role}</span><b style={{ color: scoreColor(analyst.score) }}>{analyst.score}</b><span>{analyst.ttd}</span><span>{analyst.ttc}</span><span>{analyst.ttr}</span><em>{expanded === analyst.id ? 'up' : 'down'}</em></button>{expanded === analyst.id && <div className="dc-expanded"><div className="dc-mini-score"><strong>{analyst.score}</strong><span style={{ color: scoreColor(analyst.score), borderColor: scoreColor(analyst.score) + '40', background: scoreColor(analyst.score) + '18' }}>{analyst.grade}</span></div><div><div className="dc-metric-grid small"><article><span>TTD</span><strong>{analyst.ttd}</strong></article><article><span>TTC</span><strong>{analyst.ttc}</strong></article><article><span>TTR</span><strong>{analyst.ttr}</strong></article></div><div className="dc-skills compact"><SkillBar label="Detection" value={analyst.det} tone="green" /><SkillBar label="Containment" value={analyst.con} tone="blue" /><SkillBar label="Recovery" value={analyst.rec} tone="purple" /></div><p>{analyst.narrative}</p></div></div>}</div>)}</div></section>}
 </main>
 )
}
function NotificationsView({ rooms, showFallback, setView, selectRoom, enterRoom }) {
 const notifications = buildNotifications(rooms, showFallback)
 const activeCount = notifications.filter((item) => item.tone === 'blue').length
 const reportCount = notifications.filter((item) => item.tone === 'green').length
 const pendingCount = notifications.filter((item) => item.tone === 'yellow').length
 function act(item) {
 if (!item.room) return
 if (item.action === 'Open Room') {
 enterRoom(item.room)
 return
 }
 if (item.action === 'View Report') {
 selectRoom(item.room.room_id)
 setView('reports')
 return
 }
 setView('rooms')
 }
 return (
 <main className="dc-main">
 <section className="dc-header notification-header">
 <div><p>Notification Center</p><h1>Blue Team <span>Notifications.</span></h1><span>Operational updates from rooms, reports, and TheHive handoff status.</span></div>
 <button type="button" onClick={() => setView('rooms')} className="dc-primary-link">Open Room Lobby</button>
 </section>
 <section className="dc-notification-stats">
 <article><span>Active Rooms</span><strong>{activeCount}</strong><p>Ready for TheHive</p></article>
 <article><span>Reports</span><strong>{reportCount}</strong><p>Available to review</p></article>
 <article><span>Pending</span><strong>{pendingCount}</strong><p>Waiting activation</p></article>
 </section>
 <section className="dc-notification-list">
 {notifications.map((item) => (
 <article className={'dc-notification-card ' + item.tone} key={item.id}>
 <i />
 <div>
 <header><h3>{item.title}</h3><span>{item.meta}</span></header>
 <p>{item.body}</p>
 </div>
 <button type="button" disabled={!item.room || item.action === 'System Notice'} onClick={() => act(item)}>{item.action}</button>
 </article>
 ))}
 </section>
 </main>
 )
}

function EntryModal({ room, busy, onConfirm, onCancel }) {
 const [mode, setMode] = useState('solo')
 const [emails, setEmails] = useState('')
 function submit() {
 const teammates = mode === 'team'
 ? emails.split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean)
 : []
 onConfirm(mode, teammates)
 }
 return (
 <div className="dc-overlay" role="dialog" aria-modal="true">
 <div className="dc-entry-card">
 <header><h2>Enter {roomName(room)}</h2><p>Respond alone, or bring your team into the same incident.</p></header>
 <div className="dc-entry-modes">
 <button type="button" className={mode === 'solo' ? 'active' : ''} onClick={() => setMode('solo')}><strong>Solo</strong><span>Just me</span></button>
 <button type="button" className={mode === 'team' ? 'active' : ''} onClick={() => setMode('team')}><strong>With a team</strong><span>Invite analysts</span></button>
 </div>
 {mode === 'team' && (
 <label className="dc-entry-emails">
 <span>Teammate emails</span>
 <textarea placeholder="analyst1@corp.com, analyst2@corp.com" value={emails} onChange={(event) => setEmails(event.target.value)} />
 <small>They'll get an in-app invite to join this room. TheHive opens once everyone is in.</small>
 </label>
 )}
 <div className="dc-entry-actions">
 <button type="button" className="ghost" onClick={onCancel} disabled={busy}>Cancel</button>
 <button type="button" onClick={submit} disabled={busy || (mode === 'team' && !emails.trim())}>{busy ? 'Entering...' : 'Enter Room'}</button>
 </div>
 </div>
 </div>
 )
}

function LobbyOverlay({ room, onEnterHive, onClose }) {
 const [lobby, setLobby] = useState(null)
 useEffect(() => {
 let alive = true
 async function tick() {
 try { const next = await api.rooms.lobby(room.room_id); if (alive) setLobby(next) } catch (_) { /* transient */ }
 }
 tick()
 const id = setInterval(tick, 4000)
 return () => { alive = false; clearInterval(id) }
 }, [room.room_id])
 const members = lobby?.members || []
 const allJoined = lobby ? lobby.all_joined : false
 return (
 <div className="dc-overlay" role="dialog" aria-modal="true">
 <div className="dc-lobby-card">
 <header><h2>{roomName(room)} - Team Lobby</h2><p>Waiting for your team to join. TheHive opens for everyone once all analysts confirm.</p></header>
 <ul className="dc-lobby-members">
 {members.length ? members.map((member) => (
 <li key={member.id} className={member.status === 'joined' ? 'joined' : 'pending'}>
 <i>{String(member.id).slice(0, 1).toUpperCase()}</i>
 <div><strong>{member.id}</strong><span>{member.role}</span></div>
 <em>{member.status === 'joined' ? 'Joined' : 'Pending'}</em>
 </li>
 )) : <li className="pending"><div><strong>Loading team status...</strong></div></li>}
 </ul>
 <div className="dc-entry-actions">
 <button type="button" className="ghost" onClick={onClose}>Close</button>
 <button type="button" onClick={() => onEnterHive(room)}>{allJoined ? 'Enter TheHive' : 'Start without waiting'}</button>
 </div>
 </div>
 </div>
 )
}

function HiveOverlay({ room, onFinish, onClose }) {
 // TheHive is opened in a real browser tab (first-party) rather than an iframe:
 // browsers block TheHive's login cookie when it is set from inside a
 // cross-origin frame, so an embedded login silently fails. This panel stays in
 // the app as the credentials + return-to-report control surface.
 const url = hiveUrlForRoom(room)
 const creds = room?.thehive || {}
 const [copied, setCopied] = useState('')
 const [opened, setOpened] = useState(false)
 function copy(label, value) {
 try { navigator.clipboard?.writeText(value); setCopied(label); setTimeout(() => setCopied(''), 1500) } catch (_) { /* ignore */ }
 }
 function open() {
 window.open(url, 'attense_thehive', 'noopener,noreferrer')
 setOpened(true)
 }
 return (
 <div className="dc-overlay" role="dialog" aria-modal="true">
 <div className="dc-hive-launch">
 <header><h2>TheHive - {roomName(room)}</h2><p>Investigate this incident in TheHive (opens in a new tab). When you're done, come back here and finish the incident to see your report.</p></header>
 {creds.login && creds.password ? (
 <div className="dc-hive-cred-box">
 <label>Username<code>{creds.login}</code><button type="button" onClick={() => copy('login', creds.login)}>{copied === 'login' ? 'Copied' : 'Copy'}</button></label>
 <label>Password<code>{creds.password}</code><button type="button" onClick={() => copy('password', creds.password)}>{copied === 'password' ? 'Copied' : 'Copy'}</button></label>
 </div>
 ) : null}
 <div className="dc-hive-launch-actions">
 <button type="button" onClick={open}>{opened ? 'Reopen TheHive ↗' : 'Open TheHive ↗'}</button>
 <button type="button" className="finish" onClick={onFinish}>Finish Incident &amp; View Report</button>
 <button type="button" className="ghost" onClick={onClose}>Close (keep investigating)</button>
 </div>
 </div>
 </div>
 )
}

function HiveSessionBar({ room, onReopen, onFinish }) {
 // Shown while a TheHive investigation is in progress but the launch panel is
 // dismissed, so the analyst always has a way back to TheHive and the report.
 return (
 <div className="dc-hive-session-bar">
 <div className="dc-hive-session-info"><i /><div><strong>Investigating {roomName(room)}</strong><span>TheHive session in progress</span></div></div>
 <div className="dc-hive-session-actions">
 <button type="button" onClick={onReopen}>Return to TheHive</button>
 <button type="button" className="finish" onClick={onFinish}>Finish Incident &amp; View Report</button>
 </div>
 </div>
 )
}

function InvitesBanner({ invites, onAccept }) {
 if (!invites.length) return null
 return (
 <div className="dc-invites-banner">
 {invites.map((room) => (
 <div className="dc-invite" key={room.room_id}>
 <div><strong>Team invite</strong><span>You've been invited to {roomName(room)}. Join your team to respond in TheHive.</span></div>
 <button type="button" onClick={() => onAccept(room)}>Join Room</button>
 </div>
 ))}
 </div>
 )
}

export default function App() {
 const [view, setView] = useState('dashboard')
 const [user, setUser] = useState(null)
 const [rooms, setRooms] = useState([])
 const [activeRoomId, setActiveRoomId] = useState('')
 const [activeRoom, setActiveRoom] = useState(null)
 const [loading, setLoading] = useState(true)
 const [error, setError] = useState('')
 const [entryModalRoom, setEntryModalRoom] = useState(null)
 const [lobbyRoom, setLobbyRoom] = useState(null)
 const [hiveRoom, setHiveRoom] = useState(null)
 const [hiveMinimized, setHiveMinimized] = useState(false)
 const [invites, setInvites] = useState([])
 const [entering, setEntering] = useState(false)

 async function loadInitial(initialRoomId) {
 setLoading(true); setError('')
 try {
 const me = await api.auth.me()
 setUser(me)
 const listed = await api.rooms.list()
 setRooms(listed)
 api.rooms.invites().then(setInvites).catch(() => {})
 const selected = initialRoomId || activeRoomId || listed[0]?.room_id || ''
 setActiveRoomId(selected)
 if (selected) {
 setActiveRoom(await api.rooms.get(selected))
 } else {
 setActiveRoom(null)
 }
 return { listed, selected }
 } catch (err) {
 clearToken()
 setUser({ role: 'soc_l1' })
 setRooms([])
 setActiveRoomId('')
 setActiveRoom(null)
 return { listed: [], selected: '' }
 } finally {
 setLoading(false)
 }
 }

 useEffect(() => {
 captureTokenFromUrl()
 const params = new URLSearchParams(window.location.search)
 const requestedView = params.get('view')
 const requestedIncident = params.get('incidentId')
 if (requestedView === 'reports') setView('reports')
 const portalRoom = portalRoomFromUrl()
 const token = getToken()
 if (token) {
 loadInitial(portalRoom?.room_id).then(async ({ listed }) => {
 if (requestedIncident) {
 const matched = listed.find((room) => room.incident_id === requestedIncident || (room.incidents || []).includes(requestedIncident))
 if (matched) {
 selectRoom(matched.room_id)
 setView('reports')
 }
 }
 if (!portalRoom) return
 const found = listed.some((room) => room.room_id === portalRoom.room_id)
 if (found) return
 try {
 const remoteRoom = await api.rooms.get(portalRoom.room_id)
 setRooms((current) => [remoteRoom, ...current.filter((room) => room.room_id !== portalRoom.room_id)])
 setActiveRoomId(remoteRoom.room_id)
 setActiveRoom(remoteRoom)
 return
 } catch (err) {
 setRooms((current) => [portalRoom, ...current])
 setActiveRoomId(portalRoom.room_id)
 setActiveRoom(portalRoom)
 }
 })
 return
 }
 if (portalRoom) {
 const profile = readProfile()
 setUser({ role: profile.role || localStorage.getItem('attense_blue_role') || 'soc_l1' })
 setRooms([portalRoom])
 setActiveRoomId(portalRoom.room_id)
 setActiveRoom(portalRoom)
 setLoading(false)
 return
 }
 setUser({ role: 'soc_l1' })
 setRooms([])
 setActiveRoomId('')
 setActiveRoom(null)
 setLoading(false)
 }, [])

 // Poll for room and invitation changes: there is no server push, so an
 // invited analyst learns about a new room (and the creator sees teammates
 // arrive) by this periodic refresh.
 useEffect(() => {
 if (!getToken()) return undefined
 const id = setInterval(async () => {
 const [listed, inv] = await Promise.all([
 api.rooms.list().catch(() => null),
 api.rooms.invites().catch(() => null),
 ])
 if (listed) setRooms((current) => mergeRooms(current, listed))
 if (inv) setInvites(inv)
 }, 8000)
 return () => clearInterval(id)
 }, [])

 async function selectRoom(roomId) {
 const cached = rooms.find((room) => room.room_id === roomId) || fallbackRooms.find((room) => room.room_id === roomId)
 setActiveRoomId(roomId)
 const token = getToken()
 if (!cached) {
 setActiveRoom(null)
 return
 }
 if (!token) {
 setActiveRoom(cached)
 return
 }
 if (cached.portal_demo) {
 try {
 const remoteRoom = await api.rooms.get(roomId)
 setRooms((current) => [remoteRoom, ...current.filter((room) => room.room_id !== roomId)])
 setActiveRoom(remoteRoom)
 return
 } catch (err) {
 setActiveRoom(cached)
 return
 }
 }
 setActiveRoom(await api.rooms.get(roomId))
 }

 function mergeRooms(current, listed) {
 const extras = current.filter((room) => room.portal_demo && !listed.some((item) => item.room_id === room.room_id))
 return [...extras, ...listed]
 }

 // Re-push the room's stored detections into TheHive whenever we open it, so
 // the alerts appear even for a past/closed room whose original delivery never
 // happened. Fire-and-forget and idempotent (the backend forces re-delivery and
 // TheHive dedups by sourceRef, so no duplicate alerts).
 function resyncAlerts(room) {
 if (!room || !getToken() || room.portal_demo) return
 api.rooms.replayAlerts(room.room_id).catch(() => {})
 }

 async function startHiveSession(room) {
 resyncAlerts(room)
 // Make sure the launch panel has the shared TheHive login to show. Rooms that
 // come straight from the list (e.g. a closed room opened for re-view) carry no
 // credentials; GET /rooms/{id} returns the shared-analyst login + password for
 // Blue Team users, so fetch the full room when the creds are missing - without
 // it the user opens TheHive with a blank sign-in and can't log in.
 let full = room
 if (getToken() && !room.portal_demo && !(room.thehive && room.thehive.login)) {
 try { full = await api.rooms.get(room.room_id) } catch (_) { full = room }
 }
 setHiveRoom(full)
 setHiveMinimized(false)
 }

 // Open TheHive for a room without going through the enter flow - used for
 // closed/past rooms that can't be re-entered but whose alerts we still re-push.
 function openRoomInHive(room) {
 setError('')
 setActiveRoomId(room.room_id)
 setActiveRoom(room)
 startHiveSession(room)
 }

 function enterRoom(room) {
 setError('')
 setActiveRoomId(room.room_id)
 // Demo/no-session rooms have no backend to enter; open TheHive directly.
 if (!getToken() || room.portal_demo) {
 setActiveRoom(room)
 startHiveSession(room)
 return
 }
 setEntryModalRoom(room)
 }

 async function confirmEnter(mode, teammates) {
 const room = entryModalRoom
 if (!room) return
 setEntering(true); setError('')
 try {
 const started = await api.rooms.enter(room.room_id, { mode, teammates })
 setEntryModalRoom(null)
 setActiveRoomId(room.room_id)
 setActiveRoom(started)
 setRooms((current) => current.map((item) => item.room_id === room.room_id ? { ...item, ...started } : item))
 if (mode === 'team' && teammates.length) {
 setLobbyRoom(started)
 } else {
 startHiveSession(started)
 }
 } catch (err) {
 setError(err.message || 'Could not enter the room')
 } finally {
 setEntering(false)
 }
 }

 async function acceptInvite(room) {
 setError('')
 try {
 const joined = await api.rooms.accept(room.room_id)
 setInvites((current) => current.filter((item) => item.room_id !== room.room_id))
 setActiveRoomId(room.room_id)
 setActiveRoom(joined)
 setRooms((current) => current.some((item) => item.room_id === room.room_id)
 ? current.map((item) => item.room_id === room.room_id ? { ...item, ...joined } : item)
 : [joined, ...current])
 setLobbyRoom(joined)
 } catch (err) {
 setError(err.message || 'Could not join the room')
 }
 }

 function openHive(room) {
 setLobbyRoom(null)
 startHiveSession(room)
 }

 function backToReport() {
 const room = hiveRoom
 setHiveRoom(null)
 setHiveMinimized(false)
 if (room) {
 selectRoom(room.room_id)
 setView('reports')
 }
 }

 async function finishFromHive() {
 const room = hiveRoom
 setHiveRoom(null)
 setHiveMinimized(false)
 // Ends the incident (generates the report) and switches to the report view.
 if (room) await endRoom(room)
 }

 async function endRoom(room) {
 setError('')
 setActiveRoomId(room.room_id)
 try {
 let ended = room.portal_demo ? { ...room, status: 'closed', closed_at: new Date().toISOString() } : await api.rooms.end(room.room_id)
 if (getToken() && !room.portal_demo) {
 try { ended = await api.rooms.get(room.room_id) } catch (_) {}
 }
 setActiveRoom(ended)
 setRooms((current) => current.map((item) => item.room_id === room.room_id ? { ...item, ...ended } : item))
 setView('reports')
 } catch (err) {
 setError(err.message || 'Could not end the incident')
 }
 }

 function logout() {
 clearToken(); setUser(null); setRooms([]); setActiveRoom(null); setActiveRoomId('')
 }

 return (
 <div className="dc-shell">
 <Sidebar view={view} setView={setView} user={user} logout={logout} />
 <InvitesBanner invites={invites} onAccept={acceptInvite} />
 {loading && <main className="dc-main"><section className="dc-loading">Loading workspace...</section></main>}
 {error && !loading && <main className="dc-main"><section className="dc-error-panel">{error}</section></main>}
 {!loading && !error && view === 'dashboard' && <DashboardView user={user} rooms={rooms} setView={setView} selectRoom={selectRoom} showFallback={false} />}
 {!loading && !error && view === 'rooms' && <RoomsView rooms={rooms} activeRoomId={activeRoomId} enterRoom={enterRoom} endRoom={endRoom} openRoomInHive={openRoomInHive} selectRoom={selectRoom} setView={setView} showFallback={false} />}
 {!loading && !error && view === 'reports' && <ReportView user={user} room={activeRoom} />}
 {!loading && !error && view === 'notifications' && <NotificationsView rooms={rooms} showFallback={false} setView={setView} selectRoom={selectRoom} enterRoom={enterRoom} />}
 {entryModalRoom && <EntryModal room={entryModalRoom} busy={entering} onConfirm={confirmEnter} onCancel={() => setEntryModalRoom(null)} />}
 {lobbyRoom && <LobbyOverlay room={lobbyRoom} onEnterHive={openHive} onClose={() => setLobbyRoom(null)} />}
 {hiveRoom && !hiveMinimized && <HiveOverlay room={hiveRoom} onFinish={finishFromHive} onClose={() => setHiveMinimized(true)} />}
 {hiveRoom && hiveMinimized && <HiveSessionBar room={hiveRoom} onReopen={() => setHiveMinimized(false)} onFinish={finishFromHive} />}
 </div>
 )
}