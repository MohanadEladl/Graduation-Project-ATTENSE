import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { SESSION_TOKEN_KEY } from './api/client.js'
import { RangeLayout }   from './components/RangeLayout.jsx'
import Login             from './routes/Login.jsx'
import WhoAreYou         from './routes/WhoAreYou.jsx'
import Dashboard         from './routes/Dashboard.jsx'
import Missions          from './routes/Missions.jsx'
import Modules           from './routes/Modules.jsx'
import Mission           from './routes/Mission.jsx'
import Workspace         from './routes/Workspace.jsx'
import RoomSelect        from './routes/RoomSelect.jsx'
import Shell             from './routes/Shell.jsx'
import Detections        from './routes/Detections.jsx'
import Reports           from './routes/Reports.jsx'
import Settings          from './routes/Settings.jsx'
import MissionReport     from './routes/MissionReport.jsx'
import AttackReport      from './routes/AttackReport.jsx'
import Gauntlet          from './routes/Gauntlet.jsx'
import ShapeshiftTest    from './routes/ShapeshiftTest.jsx'

// Captures ?token=<attense-app session token> from the URL (handed off by
// the portal after login — see red-team/backend/identity.py for how the
// backend validates it), persists it, then strips it from the address bar
// so it doesn't linger in browser history / get leaked via Referer.
function useSessionTokenFromUrl() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    if (!token) return

    localStorage.setItem(SESSION_TOKEN_KEY, token)
    params.delete('token')
    const rest = params.toString()
    const cleanUrl = window.location.pathname + (rest ? `?${rest}` : '') + window.location.hash
    window.history.replaceState({}, '', cleanUrl)
  }, [])
}

export default function App() {
  useSessionTokenFromUrl()
  return (
    <BrowserRouter>
      <Routes>

        {/* ── Main red-team dashboard — the attack home (full screen, own nav) ── */}
        <Route path="/"          element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />

        {/* ── Optional auxiliary screens ── */}
        <Route path="/login"     element={<Login />} />
        <Route path="/select"    element={<WhoAreYou />} />

        {/* ── Authenticated app (new-UI top nav, no sidebar) ── */}
        <Route element={<RangeLayout />}>
          <Route path="/rooms"                  element={<RoomSelect />}     />
          <Route path="/missions"              element={<Missions />}       />
          <Route path="/modules"               element={<Modules />}        />
          <Route path="/mission/:moduleId"     element={<Mission />}        />
          <Route path="/workspace/:sid"        element={<Workspace />}      />
          <Route path="/shell"                 element={<Shell />}          />
          <Route path="/detections"            element={<Detections />}     />
          <Route path="/reports"               element={<Reports />}        />
          <Route path="/settings"              element={<Settings />}       />
          <Route path="/report/:sid"           element={<MissionReport />}  />
          <Route path="/attack-report/:sid"    element={<AttackReport />}   />
          <Route path="/gauntlet"              element={<Gauntlet />}       />
          <Route path="/shapeshift-test"       element={<ShapeshiftTest />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
