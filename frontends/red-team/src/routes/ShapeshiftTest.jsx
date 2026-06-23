import { useState } from 'react'
import ShapeshiftOverlay from '../components/ShapeshiftOverlay.jsx'

const TEST_EVENTS = [
  { id: 'test-bf',  color: '#ff6b00', label: 'Rate Limiter',     taunt: 'Slow your tools or burn through your wordlist blind.' },
  { id: 'test-xss', color: '#2ee39a', label: 'CSP Header',       taunt: 'Inline scripts are dead. Find a bypass or go home.' },
  { id: 'test-ci',  color: '#8b2fff', label: 'Pipe Filtered',    taunt: 'Your | just became a decoration. Adapt.' },
  { id: 'test-red', color: '#ff1535', label: 'Account Lockout',  taunt: 'Five strikes and you\'re locked out for 60 seconds.' },
]

export default function ShapeshiftTest() {
  const [event, setEvent] = useState(null)
  const [fired, setFired] = useState([])

  const fire = (ev) => {
    setEvent({ ...ev, id: ev.id + '-' + Date.now() })
  }

  const handleDone = () => setEvent(null)

  return (
    <div style={{ minHeight: '100vh', background: '#07090f', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 24, padding: 40 }}>
      <div style={{ fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.3em', color: '#3a4560', marginBottom: 8 }}>SHAPESHIFT OVERLAY — TEST HARNESS</div>
      <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 28, fontWeight: 700, color: '#f0f4ff', letterSpacing: '0.06em', marginBottom: 24 }}>Fire a test mutation</div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
        {TEST_EVENTS.map(ev => (
          <button
            key={ev.id}
            onClick={() => fire(ev)}
            style={{
              padding: '14px 28px', borderRadius: 12, cursor: 'pointer', textAlign: 'left',
              border: `1px solid ${ev.color}55`,
              background: `${ev.color}0e`,
              fontFamily: 'monospace', fontSize: 11, letterSpacing: '0.1em',
              color: ev.color,
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 4 }}>{ev.label}</div>
            <div style={{ fontSize: 9, color: ev.color + '88', letterSpacing: '0.06em' }}>color: {ev.color}</div>
          </button>
        ))}
      </div>

      <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#2a3450', marginTop: 8 }}>
        Click a button to play the 3-beat animation. Sound is OFF (toggle in real workspace).
      </div>

      <ShapeshiftOverlay
        event={event}
        soundEnabled={false}
        onReveal={() => {}}
        onDone={handleDone}
      />
    </div>
  )
}
