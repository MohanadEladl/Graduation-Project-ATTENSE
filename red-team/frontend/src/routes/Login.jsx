import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'

export default function Login() {
  const navigate = useNavigate()
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = () => {
    setLoading(true)
    setTimeout(() => navigate('/select'), 900)
  }

  return (
    <div className="relative min-h-screen bg-attense-bg overflow-hidden font-sans flex flex-col items-center justify-center">

      {/* beams — same as landing but dimmer */}
      <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
        {[
          { left: '20%', width: 200, delay: 0   },
          { left: '40%', width: 260, delay: 0.3 },
          { left: '62%', width: 180, delay: 0.6 },
        ].map((b, i) => (
          <div key={i} className="absolute top-0 h-full origin-top" style={{
            left: b.left, width: b.width,
            background: 'linear-gradient(180deg, rgba(255,21,53,0.28) 0%, rgba(180,10,30,0.12) 40%, transparent 100%)',
            transform: 'skewX(-18deg)', filter: 'blur(32px)',
          }} />
        ))}
        <div className="absolute inset-x-0 bottom-0 h-48 bg-gradient-to-t from-attense-bg to-transparent" />
      </div>

      {/* back */}
      <button onClick={() => navigate('/')}
        className="absolute top-6 left-8 z-20 flex items-center gap-2 text-attense-muted hover:text-attense-text transition-colors text-[12px] font-mono tracking-widest">
        ← BACK
      </button>

      {/* logo top */}
      <motion.div
        className="relative z-10 flex flex-col items-center mb-8"
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <div className="flex items-center gap-2 mb-2">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="#ff1535"/>
          </svg>
          <span className="font-display font-bold text-[22px] tracking-widest text-attense-text">
            ATTENSE
          </span>
        </div>
        <span className="font-mono text-[10px] tracking-[0.3em] text-attense-dim uppercase">Cyber Lab · Secure Access</span>
      </motion.div>

      {/* card */}
      <motion.div
        className="relative z-10 w-full max-w-sm"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, delay: 0.15 }}
      >
        <div className="bg-attense-panel border border-attense-border rounded-2xl p-8 shadow-[0_24px_64px_rgba(0,0,0,0.7)]"
             style={{ boxShadow: '0 24px 64px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.04)' }}>

          <h2 className="font-display font-bold text-attense-text text-[20px] tracking-wide mb-1">
            Authenticate
          </h2>
          <p className="text-attense-muted text-[12px] font-mono mb-7">
            Enter your operator credentials to proceed
          </p>

          <div className="space-y-4 mb-6">
            <div>
              <label className="block font-mono text-[10px] tracking-[0.25em] text-attense-dim uppercase mb-1.5">
                Username
              </label>
              <input
                value={user}
                onChange={e => setUser(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                placeholder="operator_id"
                className="w-full bg-attense-bg border border-attense-border rounded-lg px-4 py-3 text-attense-text font-mono text-[13px] placeholder-attense-dim focus:outline-none focus:border-attense-red/60 focus:shadow-glow-red transition-all"
              />
            </div>
            <div>
              <label className="block font-mono text-[10px] tracking-[0.25em] text-attense-dim uppercase mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={pass}
                onChange={e => setPass(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                placeholder="••••••••••••"
                className="w-full bg-attense-bg border border-attense-border rounded-lg px-4 py-3 text-attense-text font-mono text-[13px] placeholder-attense-dim focus:outline-none focus:border-attense-red/60 focus:shadow-glow-red transition-all"
              />
            </div>
          </div>

          <motion.button
            onClick={handleSubmit}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            className="w-full py-3.5 rounded-lg bg-attense-red text-white font-bold text-[13px] tracking-widest shadow-glow-red hover:bg-red-600 transition-all flex items-center justify-center gap-2"
          >
            {loading
              ? <span className="font-mono text-[12px] animate-pulse">AUTHENTICATING...</span>
              : '⚡ AUTHENTICATE'}
          </motion.button>

          <div className="mt-5 flex items-center justify-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-attense-mint" />
            <span className="font-mono text-[10px] text-attense-dim tracking-widest">TLS 1.3 · SESSION ENCRYPTED</span>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
