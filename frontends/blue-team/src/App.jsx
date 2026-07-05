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
 const s = String(room.status || '').toLowerCase()
 if (room.portal_demo || room.blue_started_at || s === 'active' || s === 'blue_active') return 'Active'
 if (room.packaged_at || room.attack_completed_at || room.prefired_at || s === 'pending' || s === 'packaged') return 'Pending'
 if (s === 'closed') return 'Closed'
 return 'Pending'
}

function roomDescription(room) {
 return room?.desc || room?.description || room?.metadata?.description || 'Respond to the active incident, review the evidence, and complete the exercise objectives with your team.'
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

function formatTs(ts) {
 if (!ts) return '--'
 try { return new Date(ts).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) } catch (_) { return String(ts) }
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

function RoomsView({ rooms, activeRoomId, enterRoom, endRoom, showFallback }) {
 const shownRooms = rooms.length ? rooms : (showFallback ? fallbackRooms : [])
 const activeCount = shownRooms.filter((room) => roomStatus(room) === 'Active').length
 return (
 <main className="dc-main">
 <section className="dc-header room-header"><div><p>Training Rooms</p><h1>Room Lobby</h1><span>Browse available incident response scenarios. Enter any active room to begin your training exercise.</span></div><div className="dc-active-now"><strong>{activeCount} Active Now</strong><small>{shownRooms.length} rooms total</small></div></section>
 <section className="dc-room-grid">
 {shownRooms.length ? shownRooms.map((room) => {
 const status = roomStatus(room)
 const active = status === 'Active'
 const pending = status === 'Pending'
 return <article className={'dc-room-card ' + status.toLowerCase()} key={room.room_id || room.id} data-selected={room.room_id === activeRoomId}><div className="dc-room-top"><span><i />{status}</span><small>{room.room_id || room.id}</small></div><h3>{roomName(room)}</h3><p>{roomDescription(room)}</p><div className="dc-room-actions"><button type="button" disabled={!active} onClick={() => enterRoom(room)}>{active ? 'Enter Room' : pending ? 'Not Yet Active' : 'Room Closed'}</button>{active && <button className="danger" type="button" onClick={() => endRoom(room)}>End Incident & Report</button>}</div></article>
 }) : <div className="dc-empty">No rooms are available yet.</div>}
 </section>
 <section className="dc-note">Pending rooms open when activated by a SOC Manager. Closed rooms are available for retrospective review only.</section>
 </main>
 )
}

function SkillBar({ label, value, tone }) {
 return <div className="dc-skill"><div><span>{label}</span><b>{value}%</b></div><i><em className={tone} style={{ width: value + '%' }} /></i></div>
}

const VERDICT_LABEL = { excellent: 'A', acceptable: 'B', needs_review: 'C', failed: 'F' }
const VERDICT_COLOR = { excellent: '#43d39f', acceptable: '#53b8ff', needs_review: '#f2b95b', failed: '#ef5350' }

function ruleStatusLabel(status) {
 if (status === 'triggered') return { text: 'FAIL', color: '#ef5350' }
 if (status === 'passed') return { text: 'PASS', color: '#43d39f' }
 return { text: 'N/A', color: '#888' }
}

function ReportView({ user, room }) {
 const defaultMode = (user?.role === 'soc_manager' || user?.role === 'ciso') ? 'manager' : 'analyst'
 const [mode, setMode] = useState(defaultMode)
 const [expanded, setExpanded] = useState(null)
 const [scoredReport, setScoredReport] = useState(null)
 const [markdown, setMarkdown] = useState(null)
 const [markdownError, setMarkdownError] = useState(null)
 const [memberMarkdowns, setMemberMarkdowns] = useState({})
 const [loadingReport, setLoadingReport] = useState(false)
 const [loadingMd, setLoadingMd] = useState(false)
 const [reportError, setReportError] = useState(null)
 const [reportPending, setReportPending] = useState(false)

 const incidentId = room?.incidents_detail?.[0]?.incident_id

 useEffect(() => {
  setMode(defaultMode)
  setExpanded(null)
  setScoredReport(null)
  setMarkdown(null)
  setMarkdownError(null)
  setMemberMarkdowns({})
  setReportError(null)
  setReportPending(false)
 }, [incidentId])

 function fetchReport() {
  if (!incidentId) return
  setLoadingReport(true)
  setReportError(null)
  setReportPending(false)
  api.incidents.getReport(incidentId)
   .then((r) => { setScoredReport(r); setLoadingReport(false) })
   .catch((e) => {
    if (e.status === 425) { setReportPending(true) }
    else { setReportError(e.message) }
    setLoadingReport(false)
   })
 }

 useEffect(() => { fetchReport() }, [incidentId])

 function loadMarkdown(force = false) {
  if (!incidentId || loadingMd || markdown || (!force && markdownError)) return
  setLoadingMd(true)
  api.incidents.getMarkdown(incidentId)
   .then((md) => { setMarkdown(md); setLoadingMd(false) })
   .catch((e) => { setMarkdownError(e.message || 'Could not load AI report.'); setLoadingMd(false) })
 }

 function loadMemberMarkdown(memberId) {
  if (!incidentId || memberMarkdowns[memberId]) return
  api.incidents.getMemberMarkdown(incidentId, memberId)
   .then((md) => setMemberMarkdowns((prev) => ({ ...prev, [memberId]: md })))
   .catch(() => setMemberMarkdowns((prev) => ({ ...prev, [memberId]: 'Could not load.' })))
 }

 if (!room) {
  return (
   <main className="dc-main">
    <section className="dc-empty">No active room selected. Choose a room from the lobby or authenticate with a valid session.</section>
   </main>
  )
 }

 const basicReport = reportFromRoom(room)
 const report = scoredReport || basicReport
 const hasReport = loadingReport || hasReportData(basicReport) || !!scoredReport

 if (!hasReport) {
  return (
   <main className="dc-main">
    <section className="dc-empty">
     <h2>{roomName(room)}</h2>
     <p>No incident report is available for this room yet.</p>
     <p>Either the room has not started or the backend has not generated report data.</p>
    </section>
   </main>
  )
 }

 const finalScore = scoredReport?.final_score ?? reportScore(basicReport) ?? 0
 const verdict = scoredReport?.verdict
 const verdictColor = VERDICT_COLOR[verdict] || scoreColor(finalScore)
 const verdictLabel = VERDICT_LABEL[verdict] || gradeFor(finalScore)
 const ttdSec = scoredReport?.ttd ?? report?.ttd
 const ttcSec = scoredReport?.ttc ?? report?.ttc
 const scoringRules = scoredReport?.scoring_rules || []
 const memberScores = scoredReport?.member_scores || {}
 const memberIds = Object.keys(memberScores)
 const mitre = scoredReport?.mitre_attack || {}

 const contributions = {}
 ;(scoredReport?.analyst_contributions || []).forEach((c) => { contributions[c.analyst_id] = c })
 const roomTiming = scoredReport?.room_timing || {}
 const difficultyBonus = scoredReport?.response_difficulty_bonus
 const ttcActual = scoredReport?.ttc_actual_sec
 const scoringStartedAt = scoredReport?.scoring_started_at

 const analystRows = memberIds.length > 0
  ? memberIds.map((mid) => {
   const m = memberScores[mid]
   const mColor = VERDICT_COLOR[m.verdict] || scoreColor(m.final_score)
   const contrib = contributions[mid]
   const memberTtd = contrib?.first_action_offset_sec != null
    ? contrib.first_action_offset_sec
    : ttdSec
   return {
    id: mid,
    name: mid,
    avatar: mid.slice(0, 1).toUpperCase(),
    role: 'SOC Analyst',
    score: m.final_score,
    grade: VERDICT_LABEL[m.verdict] || gradeFor(m.final_score),
    gradeColor: mColor,
    ttd: formatDuration(memberTtd),
    ttc: formatDuration(ttcSec),
    ttr: formatDuration(ttcSec),
    verdict: m.verdict,
    rules: m.scoring_rules || [],
   }
  })
  : [{
   id: room.room_id || 'report-1',
   name: roomName(room),
   avatar: roomName(room).slice(0, 1).toUpperCase(),
   role: roleNames[user?.role] || user?.role || 'SOC Analyst',
   score: finalScore,
   grade: verdictLabel,
   gradeColor: verdictColor,
   ttd: formatDuration(ttdSec),
   ttc: formatDuration(ttcSec),
   ttr: formatDuration(ttcSec),
   verdict,
   rules: scoringRules,
  }]

 const scores = analystRows.map((item) => item.score)
 const teamAvg = scoredReport?.final_score ?? Math.round(scores.reduce((sum, v) => sum + v, 0) / Math.max(scores.length, 1))

 function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
 }

 function downloadWord() {
  if (!incidentId) return
  api.incidents.getWord(incidentId)
   .then((blob) => downloadBlob(blob, `report_${incidentId.slice(0, 8)}.docx`))
   .catch((e) => alert('Could not download Word report: ' + e.message))
 }

 return (
  <main className="dc-main">
   <section className="dc-report-header">
    <div>
     <p>Post-Incident Report</p>
     <h1>{roomScenario(room)}</h1>
     <div className="dc-report-badges"><span>{roomDate(room)}</span><span>{roomOutcome(room)}</span>{verdict && <span style={{ color: verdictColor }}>{verdict}</span>}</div>
    </div>
    <div className="dc-toggle">
     <button className={mode === 'analyst' ? 'active' : ''} onClick={() => setMode('analyst')}>Analyst View</button>
     <button className={mode === 'manager' ? 'active manager' : ''} onClick={() => setMode('manager')}>SOC Manager</button>
     <button className={mode === 'ai' ? 'active' : ''} onClick={() => { setMode('ai'); loadMarkdown() }}>AI Report</button>
     {scoredReport && <button onClick={downloadWord} style={{ background: '#1a3a5c', color: '#fff', border: 'none', borderRadius: 6, padding: '6px 14px', cursor: 'pointer', fontSize: '0.85em' }}>Download .docx</button>}
    </div>
   </section>

   {loadingReport && <section className="dc-empty"><p>Loading scored report…</p></section>}
   {reportPending && (
    <section className="dc-empty">
     <p style={{ fontWeight: 600 }}>Exercise in progress</p>
     <p style={{ opacity: 0.7 }}>The scored report will be available once the exercise ends. End the incident to generate the report.</p>
    </section>
   )}
   {reportError && !reportPending && (
    <section className="dc-empty">
     <p style={{ color: '#ef5350' }}>Could not load scored report: {reportError}</p>
     <button type="button" onClick={fetchReport} style={{ marginTop: 8, cursor: 'pointer' }}>Retry</button>
    </section>
   )}

   {mode === 'analyst' && (
    <section className="dc-analyst-report">
     <div className="dc-score-card">
      <div className="dc-score-ring">
       <svg viewBox="0 0 140 140">
        <defs><linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#4a86e8" /><stop offset="100%" stopColor="#43d39f" /></linearGradient></defs>
        <circle cx="70" cy="70" r="52" />
        <circle cx="70" cy="70" r="52" pathLength="100" style={{ strokeDasharray: 100, strokeDashoffset: 100 - (finalScore ?? 0) }} />
       </svg>
       <div><strong>{finalScore ?? '—'}</strong><span>/100</span></div>
      </div>
      <p>Final Grade</p>
      <b style={{ color: verdictColor, borderColor: verdictColor + '40', background: verdictColor + '18' }}>{verdictLabel}</b>
     </div>
     <div className="dc-report-side">
      <div className="dc-metric-grid">
       <article><span>Time to Detect</span><strong>{formatDuration(ttdSec)}</strong><p>TTD</p></article>
       <article><span>Time to Contain</span><strong>{formatDuration(ttcSec)}</strong><p>TTC (threshold)</p></article>
       {ttcActual != null && <article><span>Actual TTC</span><strong>{formatDuration(ttcActual)}</strong><p>Measured</p></article>}
       <article><span>Penalty</span><strong>{scoredReport?.penalty_total ?? '—'} pts</strong><p>Deductions</p></article>
       {difficultyBonus != null && <article><span>Difficulty Bonus</span><strong>+{Math.round(difficultyBonus * 10) / 10} pts</strong><p>Complexity reward</p></article>}
      </div>
      {scoringRules.length > 0 && (
       <div className="dc-skills">
        <h2>Score Breakdown</h2>
        {scoringRules.map((r) => {
         const s = ruleStatusLabel(r.status)
         return (
          <div key={r.rule_id} className="dc-skill">
           <div>
            <span>{r.rule_id}: {r.description}</span>
            <b style={{ color: s.color }}>{s.text}{r.status === 'triggered' ? ` -${Math.abs(r.penalty_points)}pts` : ''}</b>
           </div>
           {r.evidence?.length > 0 && (
            <div style={{ marginTop: 3 }}>
             {r.evidence.map((ev, i) => <small key={i} style={{ opacity: 0.65, display: 'block' }}>{ev}</small>)}
            </div>
           )}
          </div>
         )
        })}
       </div>
      )}
      {(mitre.primary?.length > 0 || mitre.related?.length > 0) && (
       <div className="dc-skills">
        <h2>MITRE ATT&amp;CK</h2>
        {mitre.primary?.map((t) => (
         <div key={t.technique_id} className="dc-skill">
          <div><span>{t.technique_id} — {t.technique_name}</span><b>{t.tactic}</b></div>
          {t.source && <small style={{ opacity: 0.5, marginTop: 2, display: 'block', wordBreak: 'break-all' }}>{t.source}</small>}
         </div>
        ))}
        {mitre.related?.map((t) => (
         <div key={t.technique_id} className="dc-skill" style={{ opacity: 0.8 }}>
          <div><span>{t.technique_id} — {t.technique_name}</span><b style={{ opacity: 0.7 }}>{t.tactic}</b></div>
          {t.source && <small style={{ opacity: 0.5, marginTop: 2, display: 'block', wordBreak: 'break-all' }}>{t.source}</small>}
         </div>
        ))}
        {mitre.mapping_note && (
         <p style={{ fontSize: '0.78em', opacity: 0.6, marginTop: 6, padding: '0 2px' }}>{mitre.mapping_note}</p>
        )}
       </div>
      )}
      {scoredReport?.response_framework?.name && (
       <div className="dc-skills">
        <h2>Response Framework</h2>
        <div className="dc-skill"><div><span>{scoredReport.response_framework.name}</span></div></div>
        {scoredReport.response_framework.note && (
         <p style={{ fontSize: '0.78em', opacity: 0.6, marginTop: 4, padding: '0 2px' }}>{scoredReport.response_framework.note}</p>
        )}
        {scoredReport.response_framework.source && (
         <p style={{ fontSize: '0.75em', opacity: 0.45, marginTop: 3, padding: '0 2px', wordBreak: 'break-all' }}>{scoredReport.response_framework.source}</p>
        )}
       </div>
      )}
      {(scoredReport?.start_time || scoredReport?.detection_time || scoredReport?.containment_time || roomTiming.attack_started_at || scoringStartedAt) && (
       <div className="dc-skills">
        <h2>Timeline</h2>
        {roomTiming.attack_started_at && <div className="dc-skill"><div><span>Attack Started</span><b>{formatTs(roomTiming.attack_started_at)}</b></div></div>}
        {scoredReport?.start_time && <div className="dc-skill"><div><span>Incident Start</span><b>{formatTs(scoredReport.start_time)}</b></div></div>}
        {roomTiming.blue_started_at && <div className="dc-skill"><div><span>Blue Team Entered</span><b>{formatTs(roomTiming.blue_started_at)}</b></div></div>}
        {scoredReport?.detection_time && <div className="dc-skill"><div><span>Detection</span><b>{formatTs(scoredReport.detection_time)}</b></div></div>}
        {scoringStartedAt && <div className="dc-skill"><div><span>Scoring Started</span><b>{formatTs(scoringStartedAt)}</b></div></div>}
        {scoredReport?.containment_time && <div className="dc-skill"><div><span>Containment</span><b>{formatTs(scoredReport.containment_time)}</b></div></div>}
        {scoredReport?.end_time && <div className="dc-skill"><div><span>Incident End</span><b>{formatTs(scoredReport.end_time)}</b></div></div>}
        {roomTiming.exercise_mode && <div className="dc-skill"><div><span>Exercise Mode</span><b>{roomTiming.exercise_mode}</b></div></div>}
       </div>
      )}
     </div>
     <div className="dc-ai-feedback">
      <h2>Incident Outcome</h2>
      <p>{scoredReport?.status || report?.outcome || 'Outcome pending.'}</p>
      <small style={{ opacity: 0.55, fontSize: '0.78em' }}>Incident status</small>
      {scoredReport?.outcome && (
       <p style={{ marginTop: 8 }}>{scoredReport.outcome}</p>
      )}
      {scoredReport?.outcome && (
       <small style={{ opacity: 0.55, fontSize: '0.78em' }}>Exercise result</small>
      )}
      {scoredReport?.team_score_basis === 'average_of_members' && (
       <p style={{ fontSize: '0.85em', opacity: 0.7 }}>Team score is the average of {memberIds.length} analyst score(s).</p>
      )}
     </div>
    </section>
   )}

   {mode === 'manager' && (
    <section className="dc-manager-report">
     <div className="dc-team-stats">
      <article><span>Team Score</span><strong>{teamAvg ?? '—'}</strong><p>/ 100 points</p></article>
      <article><span>Verdict</span><strong style={{ color: verdictColor }}>{verdict || '—'}</strong><p>Score band</p></article>
      <article><span>Analysts</span><strong>{analystRows.length}</strong><p>Report rows</p></article>
      <article><span>Penalty</span><strong>{scoredReport?.penalty_total ?? '—'}</strong><p>Points deducted</p></article>
     </div>
     <div className="dc-analyst-table">
      <header><h2>Per-Analyst Breakdown</h2><p>{memberIds.length > 0 ? 'Individual scores from the scoring engine' : 'Report derived from active room data'}</p></header>
      <div className="dc-analyst-head"><span>Analyst</span><span>Role</span><span>Score</span><span>TTD</span><span>TTC</span><span>Verdict</span><span /></div>
      {analystRows.map((analyst) => (
       <div key={analyst.id}>
        <button className="dc-analyst-row" type="button" onClick={() => { setExpanded(expanded === analyst.id ? null : analyst.id); loadMemberMarkdown(analyst.id) }}>
         <div><i>{analyst.avatar}</i><strong>{analyst.name}</strong></div>
         <span>{analyst.role}</span>
         <b style={{ color: analyst.gradeColor }}>{analyst.score ?? '—'}</b>
         <span>{analyst.ttd}</span>
         <span>{analyst.ttc}</span>
         <span style={{ color: analyst.gradeColor }}>{analyst.verdict || analyst.grade}</span>
         <em>{expanded === analyst.id ? '▲' : '▼'}</em>
        </button>
        {expanded === analyst.id && (
         <div className="dc-expanded">
          <div className="dc-mini-score">
           <strong>{analyst.score ?? '—'}</strong>
           <span style={{ color: analyst.gradeColor, borderColor: analyst.gradeColor + '40', background: analyst.gradeColor + '18' }}>{analyst.grade}</span>
           {memberScores[analyst.id]?.penalty_total != null && (
            <span style={{ fontSize: '0.8em', opacity: 0.7 }}>Penalty: {memberScores[analyst.id].penalty_total} pts</span>
           )}
          </div>
          {contributions[analyst.id] != null && (
           <p style={{ fontSize: '0.82em', opacity: 0.7, margin: '4px 0 6px' }}>
            Actions: <strong>{contributions[analyst.id].event_count ?? 0}</strong>
            {contributions[analyst.id].event_types && Object.keys(contributions[analyst.id].event_types).length > 0 && (
             <span style={{ marginLeft: 6 }}>({Object.entries(contributions[analyst.id].event_types).map(([k, v]) => `${k}: ${v}`).join(', ')})</span>
            )}
            {contributions[analyst.id].first_action_offset_sec != null && (
             <span style={{ marginLeft: 6, opacity: 0.8 }}>· First action at +{Math.round(contributions[analyst.id].first_action_offset_sec)}s</span>
            )}
           </p>
          )}
          {analyst.rules.length > 0 && (
           <div className="dc-skills compact">
            {analyst.rules.map((r) => {
             const s = ruleStatusLabel(r.status)
             return (
              <div key={r.rule_id} className="dc-skill">
               <div><span>{r.rule_id}: {r.description}</span><b style={{ color: s.color }}>{s.text}{r.status === 'triggered' ? ` -${Math.abs(r.penalty_points)}pts` : ''}</b></div>
               {r.evidence?.length > 0 && (
                <div style={{ marginTop: 2 }}>
                 {r.evidence.map((ev, i) => <small key={i} style={{ opacity: 0.6, display: 'block' }}>{ev}</small>)}
                </div>
               )}
              </div>
             )
            })}
           </div>
          )}
          {memberMarkdowns[analyst.id] && (
           <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.8em', opacity: 0.85, marginTop: 8 }}>{memberMarkdowns[analyst.id]}</pre>
          )}
         </div>
        )}
       </div>
      ))}
     </div>
    </section>
   )}

   {mode === 'ai' && (
    <section className="dc-ai-feedback" style={{ padding: '1.5rem' }}>
     <h2>AI Incident Report</h2>
     {loadingMd && <p>Generating report…</p>}
     {markdownError && (
      <p style={{ color: '#ef5350' }}>
       {markdownError}
       <button type="button" onClick={() => { setMarkdownError(null); loadMarkdown(true) }} style={{ marginLeft: 12, cursor: 'pointer' }}>Retry</button>
      </p>
     )}
     {markdown && <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.85em', lineHeight: 1.6 }}>{markdown}</pre>}
    </section>
   )}
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
 <button type="button" onClick={open}>{opened ? 'Reopen TheHive â†—' : 'Open TheHive â†—'}</button>
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
 <div className="dc-hive-bar">
 <div><i /><strong>Investigating {roomName(room)}</strong><span>TheHive session in progress</span></div>
 <div className="dc-hive-bar-actions">
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
 setActiveRoomId(matched.room_id)
 try {
 const full = await api.rooms.get(matched.room_id)
 setActiveRoom(full)
 } catch (_) {
 setActiveRoom(matched)
 }
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

 function startHiveSession(room) {
 setHiveRoom(room)
 setHiveMinimized(false)
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
 {!loading && !error && view === 'rooms' && <RoomsView rooms={rooms} activeRoomId={activeRoomId} enterRoom={enterRoom} endRoom={endRoom} showFallback={false} />}
 {!loading && !error && view === 'reports' && <ReportView user={user} room={activeRoom} />}
 {!loading && !error && view === 'notifications' && <NotificationsView rooms={rooms} showFallback={false} setView={setView} selectRoom={selectRoom} enterRoom={enterRoom} />}
 {entryModalRoom && <EntryModal room={entryModalRoom} busy={entering} onConfirm={confirmEnter} onCancel={() => setEntryModalRoom(null)} />}
 {lobbyRoom && <LobbyOverlay room={lobbyRoom} onEnterHive={openHive} onClose={() => setLobbyRoom(null)} />}
 {hiveRoom && !hiveMinimized && <HiveOverlay room={hiveRoom} onFinish={finishFromHive} onClose={() => setHiveMinimized(true)} />}
 {hiveRoom && hiveMinimized && <HiveSessionBar room={hiveRoom} onReopen={() => setHiveMinimized(false)} onFinish={finishFromHive} />}
 </div>
 )
}