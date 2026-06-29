/**
 * Detections route is retired. Left as a stub so deep links don't 404.
 * The backend /ws/detections WebSocket still exists and still works, but
 * the frontend no longer surfaces any detection UI anywhere.
 */
import { Link } from 'react-router-dom'

export default function Detections() {
  return (
    <div className="h-full flex items-center justify-center p-8">
      <div
        className="rounded-xl max-w-md text-center"
        style={{
          padding: '32px 36px',
          background: 'rgba(255,255,255,0.025)',
          border: '1px solid rgba(255,255,255,0.07)',
        }}
      >
        <div className="font-mono text-[9px] tracking-[0.32em] text-attense-dim mb-3">DETECTIONS</div>
        <h2 className="text-[18px] font-semibold text-attense-text mb-2">Feature retired</h2>
        <p className="text-[12px] text-attense-dim leading-relaxed mb-5">
          Wazuh detection feed is disabled in this build. Focus on exploring
          lab missions and tracking your progress instead.
        </p>
        <Link
          to="/"
          className="inline-block font-mono text-[10.5px] tracking-[0.16em] px-4 py-2 rounded-lg text-attense-muted transition-colors"
          style={{ border: '1px solid rgba(255,255,255,0.1)' }}
        >
          ← BACK TO DASHBOARD
        </Link>
      </div>
    </div>
  )
}
