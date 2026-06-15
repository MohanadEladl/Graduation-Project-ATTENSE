import HomeHero from '../components/HomeHero.jsx'

export default function Dashboard() {
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
