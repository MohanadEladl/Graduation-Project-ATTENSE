import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'

export default function WhoAreYou() {
  const navigate = useNavigate()
  const [hovered, setHovered] = useState(null) // 'student' | 'firm'

  return (
    <div className="relative min-h-screen bg-attense-bg overflow-hidden font-sans flex flex-col">

      {/* back */}
      <button onClick={() => navigate('/login')}
        className="absolute top-6 left-8 z-20 font-mono text-[11px] tracking-widest text-attense-dim hover:text-attense-text transition-colors">
        ← BACK
      </button>

      {/* wordmark */}
      <div className="absolute top-5 left-1/2 -translate-x-1/2 z-20 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535"/>
        </svg>
        <span className="font-display font-bold text-[15px] tracking-widest text-attense-text">
          ATTENSE
        </span>
      </div>

      {/* eyebrow */}
      <motion.div
        className="relative z-10 text-center mt-24 mb-10"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <span className="font-mono text-[11px] tracking-[0.35em] text-attense-dim uppercase">
          Who are you?
        </span>
      </motion.div>

      {/* two panels */}
      <div className="relative z-10 flex flex-1 px-10 pb-10 gap-4">

        {/* ── STUDENT panel ── */}
        <motion.div
          onMouseEnter={() => setHovered('student')}
          onMouseLeave={() => setHovered(null)}
          onClick={() => navigate('/dashboard')}
          animate={{ flex: hovered === 'student' ? 1.5 : hovered === 'firm' ? 0.65 : 1 }}
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="relative rounded-2xl overflow-hidden cursor-pointer border border-attense-border"
          style={{ minHeight: 480 }}
        >
          {/* bg glow */}
          <div className="absolute inset-0 overflow-hidden">
            {[{ left:'15%', w:260 },{ left:'45%', w:200 },{ left:'68%', w:180 }].map((b,i)=>(
              <motion.div key={i} className="absolute top-0 h-full origin-top"
                style={{ left:b.left, width:b.w,
                  background:'linear-gradient(180deg,rgba(255,21,53,0.5) 0%,rgba(180,10,30,0.2) 45%,transparent 100%)',
                  transform:'skewX(-18deg)', filter:'blur(30px)' }}
                animate={{ opacity: hovered==='student' ? 1 : 0.45 }}
                transition={{ duration:0.4 }}
              />
            ))}
            <div className="absolute inset-0 bg-gradient-to-t from-attense-bg/80 to-transparent" />
          </div>

          {/* content */}
          <div className="relative z-10 h-full flex flex-col justify-between p-8">
            <div>
              <div className="flex gap-2 mb-6">
                <span className="font-mono text-[9px] tracking-[0.25em] text-attense-red border border-attense-red/40 bg-attense-red/10 px-2.5 py-1 rounded">RED TEAM</span>
                <span className="font-mono text-[9px] tracking-[0.25em] text-attense-cyan border border-attense-cyan/40 bg-attense-cyan/10 px-2.5 py-1 rounded">BLUE TEAM</span>
              </div>
              <div className="text-attense-dim font-mono text-[9px] tracking-[0.3em] uppercase mb-2">Students</div>
              <h2 className="font-display font-bold text-attense-text text-[32px] leading-tight mb-3">
                Train in<br/>the Range
              </h2>
              <p className="text-attense-muted text-[13px] leading-relaxed max-w-xs">
                Choose your side. Attack the target or defend against it. Every action is scored in real time by the AI engine.
              </p>
            </div>

            <div>
              <div className="grid grid-cols-2 gap-3 mb-6">
                {['Dashboard','Missions','Gauntlet','Lab Modules','Reports','Settings'].map(l => (
                  <div key={l} className="flex items-center gap-2 text-attense-muted text-[11px] font-mono">
                    <span className="text-attense-red text-[8px]">▸</span>{l}
                  </div>
                ))}
              </div>
              <motion.div
                className="flex items-center gap-3 text-attense-red font-bold text-[12px] tracking-widest"
                animate={{ x: hovered === 'student' ? 4 : 0 }}
                transition={{ duration: 0.2 }}
              >
                ⚡ ENTER AS STUDENT →
              </motion.div>
            </div>
          </div>
        </motion.div>

        {/* ── FIRM panel ── */}
        <motion.div
          onMouseEnter={() => setHovered('firm')}
          onMouseLeave={() => setHovered(null)}
          onClick={() => navigate('/select')}
          animate={{ flex: hovered === 'firm' ? 1.5 : hovered === 'student' ? 0.65 : 1 }}
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="relative rounded-2xl overflow-hidden cursor-pointer border border-attense-border"
          style={{ minHeight: 480 }}
        >
          {/* bg glow — blue/cyan */}
          <div className="absolute inset-0 overflow-hidden">
            {[{ left:'10%',w:220 },{ left:'38%',w:280 },{ left:'65%',w:200 }].map((b,i)=>(
              <motion.div key={i} className="absolute top-0 h-full origin-top"
                style={{ left:b.left, width:b.w,
                  background:'linear-gradient(180deg,rgba(0,200,255,0.35) 0%,rgba(0,120,200,0.15) 45%,transparent 100%)',
                  transform:'skewX(-18deg)', filter:'blur(30px)' }}
                animate={{ opacity: hovered==='firm' ? 1 : 0.4 }}
                transition={{ duration:0.4 }}
              />
            ))}
            <div className="absolute inset-0 bg-gradient-to-t from-attense-bg/80 to-transparent" />
          </div>

          {/* content */}
          <div className="relative z-10 h-full flex flex-col justify-between p-8">
            <div>
              <div className="flex gap-2 mb-6">
                <span className="font-mono text-[9px] tracking-[0.25em] text-attense-cyan border border-attense-cyan/40 bg-attense-cyan/10 px-2.5 py-1 rounded">INCIDENT RESPONSE</span>
                <span className="font-mono text-[9px] tracking-[0.25em] text-attense-violet border border-attense-violet/40 bg-attense-violet/10 px-2.5 py-1 rounded">ENTERPRISE</span>
              </div>
              <div className="text-attense-dim font-mono text-[9px] tracking-[0.3em] uppercase mb-2">Firms</div>
              <h2 className="font-display font-bold text-attense-text text-[32px] leading-tight mb-3">
                Deploy for<br/>Your IR Team
              </h2>
              <p className="text-attense-muted text-[13px] leading-relaxed max-w-xs">
                Plug your incident response team into the AI evaluator. Get objective TTD / TTC scores and behavioral analysis per exercise.
              </p>
            </div>

            <div>
              {/* live metric preview */}
              <div className="grid grid-cols-3 gap-3 mb-6">
                {[['TTD AVG','47s','attense-red'],['TTC AVG','83s','attense-cyan'],['INCIDENTS','12','attense-violet']].map(([label,val,col])=>(
                  <div key={label} className="bg-attense-bg/60 border border-attense-border rounded-lg p-3 text-center">
                    <div className={`font-display font-bold text-[20px] text-${col}`}>{val}</div>
                    <div className="font-mono text-[8px] tracking-widest text-attense-dim mt-0.5">{label}</div>
                  </div>
                ))}
              </div>
              <motion.div
                className="flex items-center gap-3 text-attense-cyan font-bold text-[12px] tracking-widest"
                animate={{ x: hovered === 'firm' ? 4 : 0 }}
                transition={{ duration: 0.2 }}
              >
                🏢 ENTER AS FIRM →
              </motion.div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
