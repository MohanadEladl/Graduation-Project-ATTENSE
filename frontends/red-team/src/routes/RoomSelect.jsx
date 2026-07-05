import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'

const STATUS_COLOR = { created: '#f5c400', active: '#00c8ff', closed: '#8b8faa' }

export default function RoomSelect() {
  const navigate = useNavigate()
  const [rooms, setRooms] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [joining, setJoining] = useState(null)

  useEffect(() => {
    api.rooms.list()
      .then(r => { setRooms(Array.isArray(r) ? r : []); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  const join = async (room) => {
    setJoining(room.room_id)
    setError(null)
    try {
      await api.rooms.join(room.room_id)
      navigate('/dashboard', { replace: true })
    } catch (e) {
      setError(e.message || 'Failed to join room')
      setJoining(null)
    }
  }

  const joinable = rooms.filter(r => r.status !== 'closed')

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '26px 30px' }}>
      <div className="mb-6">
        <h1 className="text-[21px] font-bold tracking-tight text-attense-text">Join an Exercise Room</h1>
        <p className="font-mono text-[11px] text-attense-dim mt-1">
          Pick the room your SOC manager spun up — your attacks will be scored against its incident.
        </p>
      </div>

      {error && (
        <div className="rounded-lg p-4 font-mono text-[11px] mb-4"
          style={{ background: 'rgba(255,21,53,0.08)', border: '1px solid rgba(255,21,53,0.25)', color: '#ff4060' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim tracking-widest">LOADING ROOMS…</div>
      ) : joinable.length === 0 ? (
        <div className="py-14 text-center font-mono text-[11px] text-attense-dim">
          No open rooms yet — ask your SOC manager to create one.
        </div>
      ) : (
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(300px, 100%), 1fr))' }}>
          {joinable.map(room => (
            <div key={room.room_id} className="rounded-2xl border border-white/[0.07] p-5" style={{ background: '#0c0f16' }}>
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-[9px] tracking-[0.2em] uppercase font-bold"
                  style={{ color: STATUS_COLOR[room.status] || '#8b8faa' }}>
                  {room.status}
                </span>
                <span className="font-mono text-[9px] text-attense-dim">{room.room_id.slice(0, 8)}</span>
              </div>
              <div className="text-[14px] font-bold text-attense-text mb-1">{room.scenario_id}</div>
              <button
                onClick={() => join(room)}
                disabled={joining === room.room_id}
                className="mt-3 w-full py-2.5 rounded-lg bg-attense-red text-white font-bold text-[12px] tracking-widest hover:bg-red-600 transition-all disabled:opacity-50"
              >
                {joining === room.room_id ? 'JOINING…' : 'JOIN ROOM'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
