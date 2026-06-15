import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { RangeLayout }   from './components/RangeLayout.jsx'
import Login             from './routes/Login.jsx'
import WhoAreYou         from './routes/WhoAreYou.jsx'
import Dashboard         from './routes/Dashboard.jsx'
import Missions          from './routes/Missions.jsx'
import Modules           from './routes/Modules.jsx'
import Mission           from './routes/Mission.jsx'
import Workspace         from './routes/Workspace.jsx'
import Shell             from './routes/Shell.jsx'
import Detections        from './routes/Detections.jsx'
import Reports           from './routes/Reports.jsx'
import Settings          from './routes/Settings.jsx'
import MissionReport     from './routes/MissionReport.jsx'
import AttackReport      from './routes/AttackReport.jsx'
import Gauntlet          from './routes/Gauntlet.jsx'
import ShapeshiftTest    from './routes/ShapeshiftTest.jsx'

export default function App() {
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
