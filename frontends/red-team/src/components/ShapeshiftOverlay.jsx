import { useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import * as THREE from 'three'

function playMutationSound(color = '#fb923c') {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext
    if (!AudioCtx) return
    const ctx = new AudioCtx()
    const now = ctx.currentTime
    const gain = ctx.createGain()
    gain.gain.setValueAtTime(0.0001, now)
    gain.gain.exponentialRampToValueAtTime(0.22, now + 0.08)
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 2.85)
    gain.connect(ctx.destination)

    const hum = ctx.createOscillator()
    hum.type = 'sawtooth'
    hum.frequency.setValueAtTime(46, now)
    hum.frequency.exponentialRampToValueAtTime(31, now + 1.2)
    hum.connect(gain)
    hum.start(now)
    hum.stop(now + 2.9)

    const thunk = ctx.createOscillator()
    const thunkGain = ctx.createGain()
    thunk.type = 'square'
    thunk.frequency.setValueAtTime(color === '#2ee39a' ? 120 : 92, now + 1.82)
    thunkGain.gain.setValueAtTime(0.0001, now + 1.78)
    thunkGain.gain.exponentialRampToValueAtTime(0.35, now + 1.84)
    thunkGain.gain.exponentialRampToValueAtTime(0.0001, now + 2.02)
    thunk.connect(thunkGain)
    thunkGain.connect(ctx.destination)
    thunk.start(now + 1.78)
    thunk.stop(now + 2.04)
  } catch {
    // Browser audio is optional and may be blocked.
  }
}

function ShaderBackground() {
  const containerRef = useRef(null)
  const sceneRef = useRef(null)

  useEffect(() => {
    if (!containerRef.current) return
    const container = containerRef.current

    const vertexShader = `
      void main() {
        gl_Position = vec4( position, 1.0 );
      }
    `
    const fragmentShader = `
      #define TWO_PI 6.2831853072
      #define PI 3.14159265359

      precision highp float;
      uniform vec2 resolution;
      uniform float time;

      void main(void) {
        vec2 uv = (gl_FragCoord.xy * 2.0 - resolution.xy) / min(resolution.x, resolution.y);
        float t = time*0.05;
        float lineWidth = 0.002;

        vec3 color = vec3(0.0);
        for(int j = 0; j < 3; j++){
          for(int i=0; i < 5; i++){
            color[j] += lineWidth*float(i*i) / abs(fract(t - 0.01*float(j)+float(i)*0.01)*5.0 - length(uv) + mod(uv.x+uv.y, 0.2));
          }
        }

        gl_FragColor = vec4(color[0],color[1],color[2],1.0);
      }
    `

    const camera = new THREE.Camera()
    camera.position.z = 1
    const scene = new THREE.Scene()
    const geometry = new THREE.PlaneGeometry(2, 2)
    const uniforms = {
      time: { type: 'f', value: 20.0 },
      resolution: { type: 'v2', value: new THREE.Vector2() },
    }
    const material = new THREE.ShaderMaterial({ uniforms, vertexShader, fragmentShader })
    const mesh = new THREE.Mesh(geometry, material)
    scene.add(mesh)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(window.devicePixelRatio)
    container.appendChild(renderer.domElement)

    const onResize = () => {
      const w = container.clientWidth
      const h = container.clientHeight
      renderer.setSize(w, h)
      uniforms.resolution.value.x = renderer.domElement.width
      uniforms.resolution.value.y = renderer.domElement.height
    }
    onResize()
    window.addEventListener('resize', onResize, false)

    // Run for exactly 3.1s (one mutation cycle) then stop
    const DURATION_MS = 3100
    const startMs = performance.now()
    let animId

    const animate = () => {
      const elapsed = performance.now() - startMs
      if (elapsed >= DURATION_MS) {
        renderer.render(scene, camera)
        return
      }
      animId = requestAnimationFrame(animate)
      uniforms.time.value += 0.05
      renderer.render(scene, camera)
    }
    sceneRef.current = { animId: 0, renderer }
    animate()

    return () => {
      window.removeEventListener('resize', onResize)
      cancelAnimationFrame(animId)
      if (container && renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement)
      }
      renderer.dispose()
      geometry.dispose()
      material.dispose()
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className="absolute inset-0"
      style={{ overflow: 'hidden', mixBlendMode: 'screen' }}
    />
  )
}

function MutationCore({ color }) {
  const paths = [
    'M10 20 h70 q5 0 5 5 v20',
    'M190 16 h-76 q-5 0-5 5 v25',
    'M38 78 h48 q5 0 5-5 v-16',
    'M162 84 h-46 q-5 0-5-5 v-18',
    'M100 6 v30',
    'M100 94 v-30',
  ]
  return (
    <svg viewBox="0 0 200 100" style={{ width: 'min(620px, 82vw)', overflow: 'visible' }}>
      <defs>
        <filter id="mutation-core-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feDropShadow dx="0" dy="0" stdDeviation="5" floodColor={color} floodOpacity="0.9" />
          <feDropShadow dx="0" dy="0" stdDeviation="12" floodColor={color} floodOpacity="0.5" />
        </filter>
        <radialGradient id="mutation-core-grad">
          <stop offset="0%" stopColor="#fff" />
          <stop offset="35%" stopColor={color} />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
      </defs>
      <g stroke="rgba(255,255,255,0.22)" fill="none" strokeWidth="0.45">
        {paths.map((p, i) => <path key={i} d={p} />)}
      </g>
      {paths.map((p, i) => (
        <motion.circle
          key={p}
          r="5"
          fill="url(#mutation-core-grad)"
          filter="url(#mutation-core-glow)"
          initial={{ offsetDistance: '0%', opacity: 0 }}
          animate={{ offsetDistance: ['0%', '65%', '100%'], opacity: [0, 1, 0.1] }}
          transition={{ duration: 1.05, delay: 0.3 + i * 0.055, ease: 'easeIn' }}
          style={{ offsetPath: `path('${p}')` }}
        />
      ))}
      <motion.rect
        x="76" y="30" width="48" height="40" rx="4"
        fill="rgba(4,6,12,0.94)"
        stroke={color}
        strokeWidth="1"
        filter="url(#mutation-core-glow)"
        initial={{ opacity: 0, scale: 0.88 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.55, delay: 0.52, ease: [0.22, 1, 0.36, 1] }}
        style={{ transformOrigin: '100px 50px' }}
      />
      <motion.text
        x="100" y="53" textAnchor="middle"
        fontFamily="monospace" fontSize="7" fontWeight="700"
        fill={color}
        filter="url(#mutation-core-glow)"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.7, delay: 0.72, ease: 'easeOut' }}
      >
        MUTATE
      </motion.text>
    </svg>
  )
}

export default function ShapeshiftOverlay({ event, soundEnabled = false, onReveal, onDone }) {
  const color = event?.color || '#fb923c'

  useEffect(() => {
    if (!event) return
    if (soundEnabled) playMutationSound(color)
    const reveal = window.setTimeout(() => onReveal?.(), 1800)
    const done = window.setTimeout(() => onDone?.(), 3100)
    return () => {
      window.clearTimeout(reveal)
      window.clearTimeout(done)
    }
  }, [event?.id, soundEnabled, color, onReveal, onDone])

  return (
    <AnimatePresence>
      {event && (
        <motion.div
          key={event.id}
          className="fixed inset-0 z-[80] pointer-events-none overflow-hidden"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          style={{ background: 'rgba(2,4,9,0.82)' }}
        >
          {/* Three.js shader background */}
          <ShaderBackground />

          <style>{`
            @keyframes mutation-noise {
              0%   { background-position: 0 0; }
              20%  { background-position: -18px 12px; }
              40%  { background-position: 24px -8px; }
              60%  { background-position: -12px 20px; }
              80%  { background-position: 16px -16px; }
              100% { background-position: 0 0; }
            }
          `}</style>

          {/* ── Beat 1: THE TELL (0.0–0.6s) ── */}

          {/* Grayscale wash */}
          <motion.div
            className="absolute inset-0"
            initial={{ filter: 'grayscale(0)', opacity: 0 }}
            animate={{ filter: ['grayscale(0)', 'grayscale(1)', 'grayscale(0.7)'], opacity: [0, 0.92, 0.75] }}
            transition={{ duration: 0.62 }}
            style={{
              background: `radial-gradient(circle at 50% 50%, transparent 0 40%, ${color}20 68%, rgba(0,0,0,0.92) 100%)`,
            }}
          />

          {/* Noise grain */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0.14, 0.08, 0] }}
            transition={{ duration: 1.4, delay: 0 }}
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='1'/%3E%3C/svg%3E")`,
              backgroundRepeat: 'repeat',
              backgroundSize: '160px 160px',
              animation: 'mutation-noise 0.18s steps(1) infinite',
              mixBlendMode: 'overlay',
            }}
          />

          {/* ── Beat 2: THE RUPTURE (0.6–1.8s) ── */}

          {/* Chromatic aberration — full-screen R channel shifted right */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0, x: 0 }}
            animate={{ opacity: [0, 0.55, 0.35, 0], x: [0, 18, 14, 0] }}
            transition={{ duration: 1.05, delay: 0.55, ease: 'easeOut' }}
            style={{
              background: 'rgba(255,20,20,0.18)',
              mixBlendMode: 'screen',
            }}
          />

          {/* Chromatic aberration — full-screen B channel shifted left */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0, x: 0 }}
            animate={{ opacity: [0, 0.5, 0.3, 0], x: [0, -16, -12, 0] }}
            transition={{ duration: 1.05, delay: 0.6, ease: 'easeOut' }}
            style={{
              background: 'rgba(40,80,255,0.18)',
              mixBlendMode: 'screen',
            }}
          />

          {/* Mutation color flash ring */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0.85, 0.2] }}
            transition={{ duration: 1.1, delay: 0.58 }}
            style={{}}
          >
            <div className="absolute inset-0" style={{
              border: `2px solid ${color}70`,
              transform: 'translate(-12px, 4px)',
              mixBlendMode: 'screen',
            }} />
            <div className="absolute inset-0" style={{
              border: '2px solid rgba(60,140,255,0.55)',
              transform: 'translate(14px, -5px)',
              mixBlendMode: 'screen',
            }} />
          </motion.div>

          {/* MutationCore SVG — converges to center */}
          <motion.div
            className="absolute inset-0 flex items-center justify-center"
            initial={{ opacity: 0, scale: 0.85 }}
            animate={{ opacity: [0, 1, 0.9, 0], scale: [0.85, 1.1, 1.02, 1.22] }}
            transition={{ duration: 1.65, delay: 0.42, ease: [0.22, 1, 0.36, 1] }}
          >
            <MutationCore color={color} />
          </motion.div>

          {/* ── Beat 3: THE REVEAL (1.8–3.0s) ── */}

          {/* Re-saturation flash — world snaps back */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 0.28, 0] }}
            transition={{ duration: 0.22, delay: 1.78 }}
            style={{ background: `radial-gradient(circle at 50% 50%, ${color}40, transparent 70%)` }}
          />

          {/* Reveal label — smooth cinematic rise */}
          <motion.div
            className="absolute left-1/2 bottom-[16%] -translate-x-1/2 text-center"
            style={{ whiteSpace: 'nowrap' }}
            initial={{ opacity: 0, y: 32, filter: 'blur(12px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ duration: 0.85, delay: 1.72, ease: [0.22, 1, 0.36, 1] }}
          >
            <motion.div
              className="font-mono text-[10px] mb-3"
              style={{ color, letterSpacing: '0.28em' }}
              initial={{ opacity: 0, letterSpacing: '0.08em' }}
              animate={{ opacity: 1, letterSpacing: '0.48em' }}
              transition={{ duration: 1.1, delay: 1.82, ease: [0.22, 1, 0.36, 1] }}
            >
              ENVIRONMENT REWRITTEN
            </motion.div>
            <motion.div
              style={{
                fontFamily: "'Rajdhani', sans-serif",
                fontSize: 32,
                fontWeight: 700,
                letterSpacing: '0.08em',
                color: '#f4f7ff',
                textShadow: `0 0 32px ${color}cc, 0 0 80px ${color}55`,
              }}
              initial={{ opacity: 0, scale: 0.92 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.7, delay: 1.88, ease: [0.22, 1, 0.36, 1] }}
            >
              {event.label}
            </motion.div>
            {event.taunt && (
              <motion.div
                className="font-mono text-[11px] mt-3"
                style={{ color: color + 'bb', maxWidth: 420, lineHeight: 1.6 }}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.7, delay: 2.1, ease: 'easeOut' }}
              >
                {event.taunt}
              </motion.div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
