import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import HomeHero from '../components/HomeHero.jsx'
import { api } from '../api/client.js'

export default function Dashboard() {
  const navigate = useNavigate()
  // Red-team operators must join a room before attacking anything — without
  // one, attack events fall back to the env-var INCIDENT_ID instead of a
  // real exercise. Other roles (or a backend that's unreachable) skip straight
  // to the dashboard; this is a soft gate, not an auth check.
  const [checked, setChecked] = useState(false)

  useEffect(() => {
    let cancelled = false
    api.auth.me()
      .then(me => {
        if (cancelled) return
        if (me.role === 'red_team' && !me.room_id) {
          navigate('/rooms', { replace: true })
        } else {
          setChecked(true)
        }
      })
      .catch(() => { if (!cancelled) setChecked(true) })
    return () => { cancelled = true }
  }, [navigate])

  if (!checked) return null

  return (
    <HomeHero
      links={[
        { label: 'Missions',  to: '/missions' },
        { label: 'Modules',   to: '/modules' },
        { label: 'Gauntlet',  to: '/gauntlet' },
        { label: 'Reports',   to: '/reports' },
        { label: 'Settings',  to: '/settings' },
      ]}
      navCta={{ label: 'LAUNCH MISSION', to: '/missions' }}
      online
      titleA="Break. Learn."
      titleB="Master."
      subtitle={<>Your offensive security playground.<br />Exploit live targets and sharpen real attack skills.</>}
      primaryCta={{ label: '⚡ LAUNCH MISSION', to: '/missions' }}
      secondaryCta={{ label: 'VIEW MODULES', to: '/modules' }}
    />
  )
}
