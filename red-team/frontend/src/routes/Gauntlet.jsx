/**
 * Gauntlet.jsx — Advanced challenge page.
 *
 * Sections:
 *   ⛓ ATTACK CHAINS  — multi-phase kill-chain operations
 *   ⚡ MUTATION MODE  — target evolves mid-mission
 *
 * All sub-components are defined in this file to keep the route self-contained.
 * Visual design ported from the standalone gauntlet prototype.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence, useMotionValue, useTransform } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import {
  Zap, Workflow, Crosshair, Server, Database, Radar, KeyRound, Code, Repeat,
  SquareTerminal, FolderTree, Upload, Timer, Lock, ShieldCheck, Filter,
  FolderLock, Ban, FileX, FileCheck, Braces, Check, ChevronRight, ArrowRight,
  RotateCcw, X,
} from 'lucide-react'

// ─── Chain metadata ────────────────────────────────────────────────────────────
const CHAIN_META = {
  full_compromise: {
    id: 'full_compromise',
    icon: Crosshair,
    name: 'Full Compromise',
    tagline: 'FULL COMPROMISE',
    threat: 'APT-CLASS',
    difficulty: 'EXTREME',
    difficultyColor: '#ff1535',
    accentColor: '#ff1535',
    glowColor: 'rgba(255,21,53,0.18)',
    borderGlow: 'rgba(255,21,53,0.45)',
    steps: ['RECON', 'BRUTE FORCE', 'XSS', 'CSRF'],
    stepIcons: [Radar, KeyRound, Code, Repeat],
    description:
      'Execute a complete network takeover — map the surface, breach authentication, inject scripts, and forge cross-site requests. Every phase builds on the last.',
    objective: 'Full unauthorized access + session hijack',
    chainId: 'full_compromise',
  },
  root_the_box: {
    id: 'root_the_box',
    icon: Server,
    name: 'Root The Box',
    tagline: 'ROOT THE BOX',
    threat: 'OS-LEVEL',
    difficulty: 'CRITICAL',
    difficultyColor: '#8b2fff',
    accentColor: '#8b2fff',
    glowColor: 'rgba(139,47,255,0.18)',
    borderGlow: 'rgba(139,47,255,0.45)',
    steps: ['RECON', 'CMD INJECTION', 'DIR TRAVERSAL', 'FILE UPLOAD'],
    stepIcons: [Radar, SquareTerminal, FolderTree, Upload],
    description:
      'Escalate from zero to root. Fingerprint the target, inject OS commands, traverse the filesystem, and plant your payload via unrestricted file upload.',
    objective: 'Remote code execution + filesystem control',
    chainId: 'root_the_box',
  },
  data_exfiltration: {
    id: 'data_exfiltration',
    icon: Database,
    name: 'Data Exfiltration',
    tagline: 'DATA EXFILTRATION',
    threat: 'INSIDER-THREAT',
    difficulty: 'HIGH',
    difficultyColor: '#f5c400',
    accentColor: '#f5c400',
    glowColor: 'rgba(245,196,0,0.14)',
    borderGlow: 'rgba(245,196,0,0.4)',
    steps: ['RECON', 'BRUTE FORCE', 'DIR TRAVERSAL', 'CSRF'],
    stepIcons: [Radar, KeyRound, FolderTree, Repeat],
    description:
      'Silently drain sensitive data. Enumerate attack vectors, crack credentials, walk the file system for secrets, then weaponize cross-site requests to cover your tracks.',
    objective: 'Credential theft + sensitive data disclosure',
    chainId: 'data_exfiltration',
  },
}
const CHAIN_ORDER = ['full_compromise', 'root_the_box', 'data_exfiltration']

// ─── Mutation definitions ──────────────────────────────────────────────────────
const MUTATION_DEFS = [
  {
    id: 'bf_delay',
    module: 'brute_force',
    moduleLabel: 'Brute Force',
    icon: Timer,
    label: 'Rate Limiter',
    color: '#ff6b00',
    glow: 'rgba(255,107,0,0.2)',
    description: 'A 2-second artificial delay is injected on every login attempt, crippling fast-spray tools.',
    hint: 'Slow your wordlist or add request delays in your tool config.',
    impact: 'HIGH',
  },
  {
    id: 'bf_lockout',
    module: 'brute_force',
    moduleLabel: 'Brute Force',
    icon: Lock,
    label: 'Account Lockout',
    color: '#ff1535',
    glow: 'rgba(255,21,53,0.2)',
    description: 'After 5 consecutive failed logins the account is locked for 60 seconds — triggering lockout is detectable.',
    hint: 'Rotate target accounts, watch for 403 responses, slow down.',
    impact: 'HIGH',
  },
  {
    id: 'xss_encode',
    module: 'xss',
    moduleLabel: 'XSS',
    icon: Code,
    label: 'Output Encoding',
    color: '#00c8ff',
    glow: 'rgba(0,200,255,0.2)',
    description: 'Angle brackets < > are HTML-encoded in the response — but event handlers remain injectable.',
    hint: 'Drop script tags. Use onerror=, onload=, onfocus= payloads instead.',
    impact: 'MEDIUM',
  },
  {
    id: 'xss_csp',
    module: 'xss',
    moduleLabel: 'XSS',
    icon: ShieldCheck,
    label: 'CSP Header',
    color: '#2ee39a',
    glow: 'rgba(46,227,154,0.2)',
    description: 'A Content-Security-Policy header is injected, blocking all inline script execution.',
    hint: 'Look for script-src bypasses, JSONP endpoints, or CSP misconfigurations.',
    impact: 'CRITICAL',
  },
  {
    id: 'ci_filter_pipe',
    module: 'cmd_injection',
    moduleLabel: 'Command Injection',
    icon: Filter,
    label: 'Pipe Filtered',
    color: '#8b2fff',
    glow: 'rgba(139,47,255,0.2)',
    description: 'The pipe character | is stripped from all host input before it reaches the OS layer.',
    hint: 'Substitute with semicolons, backticks, or $() subshell syntax.',
    impact: 'MEDIUM',
  },
  {
    id: 'ci_filter_semi',
    module: 'cmd_injection',
    moduleLabel: 'Command Injection',
    icon: Filter,
    label: 'Semicolon Filtered',
    color: '#f5c400',
    glow: 'rgba(245,196,0,0.2)',
    description: 'Semicolons are stripped from host input — the most common command separator is gone.',
    hint: 'Try pipe, backtick, or $() injection. Newline (%0a) may also work.',
    impact: 'MEDIUM',
  },
  {
    id: 'dt_dotdot_filtered',
    module: 'dir_traversal',
    moduleLabel: 'Dir Traversal',
    icon: FolderLock,
    label: 'Dot-Dot Filtered',
    color: '#06b6d4',
    glow: 'rgba(6,182,212,0.2)',
    description: 'The sequence ../ is stripped from the path input before it reaches the filesystem layer.',
    hint: 'Try URL encoding: ..%2f or double encoding: ..%252f.',
    impact: 'HIGH',
  },
  {
    id: 'dt_absolute_path_only',
    module: 'dir_traversal',
    moduleLabel: 'Dir Traversal',
    icon: Ban,
    label: 'Absolute Path Blocked',
    color: '#22d3ee',
    glow: 'rgba(34,211,238,0.2)',
    description: 'Paths starting with / are rejected — only relative paths are accepted.',
    hint: 'Use relative traversal from the app root without a leading slash.',
    impact: 'MEDIUM',
  },
  {
    id: 'fu_extension_blocklist',
    module: 'file_upload',
    moduleLabel: 'File Upload',
    icon: FileX,
    label: 'Extension Blocklist',
    color: '#a855f7',
    glow: 'rgba(168,85,247,0.2)',
    description: 'Common executable extensions (.php, .py, .sh) are rejected by the upload handler.',
    hint: 'Try double extensions (.php.jpg), null bytes, or uncommon executable types.',
    impact: 'HIGH',
  },
  {
    id: 'fu_mime_check',
    module: 'file_upload',
    moduleLabel: 'File Upload',
    icon: FileCheck,
    label: 'MIME Type Check',
    color: '#c084fc',
    glow: 'rgba(192,132,252,0.2)',
    description: 'Content-Type must match image/* — the server now validates MIME type on upload.',
    hint: 'Intercept and set Content-Type: image/jpeg while keeping your payload.',
    impact: 'HIGH',
  },
  {
    id: 'csrf_referer_check',
    module: 'csrf',
    moduleLabel: 'CSRF',
    icon: ShieldCheck,
    label: 'Referer Check',
    color: '#f43f5e',
    glow: 'rgba(244,63,94,0.2)',
    description: 'The server validates that the Referer header originates from the same host.',
    hint: 'Try omitting the Referer header — some implementations only block wrong origins.',
    impact: 'MEDIUM',
  },
  {
    id: 'csrf_json_only',
    module: 'csrf',
    moduleLabel: 'CSRF',
    icon: Braces,
    label: 'JSON-Only Update',
    color: '#fb7185',
    glow: 'rgba(251,113,133,0.2)',
    description: 'The state-changing endpoint only accepts application/json, breaking form-based CSRF.',
    hint: 'Use fetch() with a CORS-preflighted JSON body to bypass the simple-request restriction.',
    impact: 'HIGH',
  },
]
const MUTATION_GROUPS = [
  { module: 'brute_force',   label: 'BRUTE FORCE' },
  { module: 'xss',           label: 'XSS — REFLECTED' },
  { module: 'cmd_injection', label: 'COMMAND INJECTION' },
  { module: 'dir_traversal', label: 'DIR TRAVERSAL' },
  { module: 'file_upload',   label: 'FILE UPLOAD' },
  { module: 'csrf',          label: 'CSRF' },
]

const MUTATION_MODULES = [
  {
    module: 'brute_force',
    moduleLabel: 'Brute Force',
    label: 'Adaptive Login Portal',
    color: '#ff6b00',
    glow: 'rgba(255,107,0,0.2)',
    impact: 'HIGH',
    description: 'Attack a login portal while its authentication contract changes mid-run.',
    briefing: "You will attack a login portal. Intelligence suggests the target's defenses are adaptive. Expect the environment to change.",
  },
  {
    module: 'xss',
    moduleLabel: 'XSS',
    label: 'Reflective Surface Drift',
    color: '#2ee39a',
    glow: 'rgba(46,227,154,0.2)',
    impact: 'HIGH',
    description: 'Probe reflected XSS while filters and parameter contracts shift under pressure.',
    briefing: 'You will weaponize a search surface. Defensive rewrites may invalidate your payload context without warning.',
  },
  {
    module: 'cmd_injection',
    moduleLabel: 'Command Injection',
    label: 'Shell Contract Breaker',
    color: '#8b2fff',
    glow: 'rgba(139,47,255,0.2)',
    impact: 'CRITICAL',
    description: 'Exploit OS command injection while separators and input names mutate live.',
    briefing: 'You will attack a diagnostics endpoint. Expect input handling to mutate and break common shell syntax.',
  },
  {
    module: 'dir_traversal',
    moduleLabel: 'Dir Traversal',
    label: 'Filesystem Maze',
    color: '#06b6d4',
    glow: 'rgba(6,182,212,0.2)',
    impact: 'HIGH',
    description: 'Walk the target filesystem while path filters and encoding rules shift mid-mission.',
    briefing: 'You will exploit a file-read endpoint. Path normalization and encoding rules may change without notice — adapt your traversal sequence.',
  },
  {
    module: 'file_upload',
    moduleLabel: 'File Upload',
    label: 'Payload Drop Zone',
    color: '#a855f7',
    glow: 'rgba(168,85,247,0.2)',
    impact: 'HIGH',
    description: 'Bypass upload restrictions while extension and MIME-type defenses activate on the fly.',
    briefing: 'You will upload a malicious payload. The upload handler may add new defenses mid-run — extension blocks and MIME checks can appear at any time.',
  },
  {
    module: 'csrf',
    moduleLabel: 'CSRF',
    label: 'Cross-Site Forger',
    color: '#f43f5e',
    glow: 'rgba(244,63,94,0.2)',
    impact: 'HIGH',
    description: 'Forge state-changing cross-site requests while the server strengthens its validation.',
    briefing: 'You will forge authenticated requests. Referer checks and JSON-only policies may engage during the operation — keep adapting your request format.',
  },
]

// ─── AuroraFlow — exact lukebaffait.fr hero background ────────────────────────
// Uses the real CoreRenderer (vendored to /hero/) + the original project data
// (gradient → red/orange background.png → flow-field warp → blur). Replicated
// 1:1 from the source site's startShader(): mount a #hero-canvas with a
// data-cr-project-src blob, then call CoreRenderer.init().
let _heroScriptsPromise = null
function loadHeroScripts() {
  if (_heroScriptsPromise) return _heroScriptsPromise
  const addScript = (src) => new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-hero-src="${src}"]`)
    if (existing) { resolve(); return }
    const sc = document.createElement('script')
    sc.src = src
    sc.async = false
    sc.dataset.heroSrc = src
    sc.onload = () => resolve()
    sc.onerror = () => reject(new Error(`Failed to load ${src}`))
    document.head.appendChild(sc)
  })
  // hero-project.js sets window._heroProjectData; core-renderer.js exposes window.CoreRenderer
  _heroScriptsPromise = addScript('/hero/hero-project.js').then(() => addScript('/hero/core-renderer.js'))
  return _heroScriptsPromise
}

// The background is a persistent singleton: created once, initialized once, and
// never destroyed — only hidden/shown across navigation. The renderer's WebGL
// context + ticker are global, so tearing it down on unmount and re-initialising
// on the next visit left the canvas blank. Keeping one live instance avoids both
// the disappear-on-revisit bug and the re-init delay.
let _heroWrap = null
let _heroInited = false

function mountHeroBackground() {
  // app-shell has no CSS transform, so position:fixed resolves to the real
  // viewport (full screen, behind the transparent navbar). <main> keeps a
  // transform from the fade-up animation, which would clip a fixed child.
  const host = document.getElementById('app-shell') || document.body

  // (Re)create if it was never built or got detached (e.g. after visiting the
  // home page, which lives outside the app-shell and unmounts it).
  if (!_heroWrap || !_heroWrap.isConnected) {
    _heroWrap = document.createElement('div')
    _heroWrap.style.cssText =
      'position:fixed;inset:0;z-index:-1;pointer-events:none;background:#07090f;overflow:hidden'
    const canvasHost = document.createElement('div')
    canvasHost.id = 'hero-canvas'
    canvasHost.style.cssText = 'position:absolute;inset:0;width:100%;height:100%'
    const overlay = document.createElement('div')
    overlay.style.cssText =
      'position:absolute;inset:0;pointer-events:none;' +
      'background:radial-gradient(ellipse 90% 80% at 50% 42%, transparent 45%, rgba(4,6,12,0.4) 100%)'
    _heroWrap.appendChild(canvasHost)
    _heroWrap.appendChild(overlay)
    _heroInited = false // fresh canvas host → needs a fresh init
  }
  if (_heroWrap.parentElement !== host) host.appendChild(_heroWrap)
  _heroWrap.style.display = 'block'
  return _heroWrap
}

function AuroraFlow() {
  useEffect(() => {
    let cancelled = false
    const wrap = mountHeroBackground()

    loadHeroScripts().then(() => {
      if (cancelled || _heroInited) return
      const projectData = window._heroProjectData
      if (!projectData || !window.CoreRenderer) {
        console.error('Hero renderer/data unavailable')
        return
      }
      const canvasHost = wrap.querySelector('#hero-canvas')
      if (!canvasHost) return
      canvasHost.removeAttribute('data-cr-initialized')
      const blob = new Blob([JSON.stringify(projectData)], { type: 'application/json' })
      const blobUrl = URL.createObjectURL(blob)
      canvasHost.setAttribute('data-cr-project-src', blobUrl)
      _heroInited = true
      window.CoreRenderer.init()
        .then(() => URL.revokeObjectURL(blobUrl))
        .catch((err) => { _heroInited = false; console.error('CoreRenderer init failed:', err) })
    }).catch((err) => console.error(err))

    // Hide on leave — keep the instance alive so revisits are instant.
    return () => {
      cancelled = true
      if (_heroWrap) _heroWrap.style.display = 'none'
    }
  }, [])

  return null
}

// ─── HoverButton — glassmorphic with cursor-trailing glow circles ──────────────
function HoverButton({ style = {}, onClick, children, isActive }) {
  const btnRef = useRef(null)
  const [listening, setListening] = useState(false)
  const [circles, setCircles] = useState([])
  const lastAdded = useRef(0)

  const createCircle = useCallback((x, y) => {
    const w = btnRef.current?.offsetWidth || 1
    const xPct = (x / w) * 100
    const color = `linear-gradient(to right, #a0d9f8 ${xPct}%, #3a5bbf ${xPct}%)`
    const id = Date.now() + Math.random()
    setCircles(prev => [...prev, { id, x, y, color, fadeState: null }])
  }, [])

  const handlePointerMove = (e) => {
    if (!listening) return
    const now = Date.now()
    if (now - lastAdded.current > 100) {
      lastAdded.current = now
      const rect = e.currentTarget.getBoundingClientRect()
      createCircle(e.clientX - rect.left, e.clientY - rect.top)
    }
  }

  useEffect(() => {
    circles.forEach(c => {
      if (c.fadeState !== null) return
      const tIn  = setTimeout(() => setCircles(prev => prev.map(p => p.id === c.id ? { ...p, fadeState: 'in' } : p)), 0)
      const tOut = setTimeout(() => setCircles(prev => prev.map(p => p.id === c.id ? { ...p, fadeState: 'out' } : p)), 1000)
      const tDel = setTimeout(() => setCircles(prev => prev.filter(p => p.id !== c.id)), 2200)
      return () => { clearTimeout(tIn); clearTimeout(tOut); clearTimeout(tDel) }
    })
  }, [circles])

  const bA = isActive ? 0.45 : 0.2
  const gA = isActive ? 0.18 : 0.1
  const boA = isActive ? 0.28 : 0.15

  return (
    <button
      ref={btnRef}
      onClick={onClick}
      onPointerMove={handlePointerMove}
      onPointerEnter={() => setListening(true)}
      onPointerLeave={() => setListening(false)}
      style={{
        position: 'relative', isolation: 'isolate', padding: 0,
        borderRadius: 26, border: 'none',
        background: 'rgba(43,55,80,0.1)', backdropFilter: 'blur(14px)',
        color: '#e6ecf7', cursor: 'pointer', overflow: 'hidden',
        boxShadow: [
          `inset 0 0 0 1px rgba(170,202,255,${bA})`,
          `inset 0 0 16px 0 rgba(170,202,255,${gA})`,
          `inset 0 -3px 12px 0 rgba(170,202,255,${boA})`,
          '0 1px 3px 0 rgba(0,0,0,0.50)',
          '0 4px 12px 0 rgba(0,0,0,0.45)',
        ].join(', '),
        transition: 'box-shadow 0.35s ease',
        ...style,
      }}
    >
      {circles.map(({ id, x, y, color, fadeState }) => (
        <div key={id} style={{
          position: 'absolute', width: 14, height: 14,
          left: x, top: y, transform: 'translate(-50%, -50%)',
          borderRadius: '50%', filter: 'blur(16px)',
          pointerEvents: 'none', zIndex: 0, background: color,
          opacity: fadeState === 'in' ? 0.85 : 0,
          transition: fadeState === 'out' ? 'opacity 1.2s ease-out' : 'opacity 0.3s ease-out',
        }} />
      ))}
      <div style={{ position: 'relative', zIndex: 1 }}>{children}</div>
    </button>
  )
}

// ─── Section navigator (Chains | Mutations) ────────────────────────────────────
function HeroSectionNav({ active, onSelect }) {
  const sections = [
    { id: 'chains',    icon: Workflow, label: 'ATTACK CHAINS',  sub: 'Multi-phase operations',       count: 3, countLabel: 'OPERATIONS', accent: '#ff6b85', accentSoft: 'rgba(255,107,133,0.14)' },
    { id: 'mutations', icon: Zap,      label: 'MUTATION MODE',  sub: 'Adaptive defense challenges',  count: 13, countLabel: 'MUTATIONS',  accent: '#f5c46a', accentSoft: 'rgba(245,196,106,0.13)' },
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 22, maxWidth: 1100, margin: '0 auto 56px' }}>
      {sections.map((s, i) => {
        const isAct = active === s.id
        const SecIcon = s.icon
        return (
          <motion.div key={s.id} initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 + i * 0.1, duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
            whileHover={{ y: -5 }} whileTap={{ scale: 0.985 }} style={{ display: 'flex' }}>
            <HoverButton onClick={() => onSelect(s.id)} isActive={isAct} style={{ width: '100%', minHeight: 178, textAlign: 'left' }}>
              <div style={{ padding: '32px 36px 30px', display: 'flex', gap: 26, alignItems: 'center', minHeight: 178 }}>
                {/* Icon tile */}
                <div style={{
                  width: 86, height: 86, borderRadius: 18,
                  border: `1.5px solid rgba(170,202,255,${isAct ? 0.4 : 0.16})`,
                  background: isAct ? `linear-gradient(135deg, ${s.accentSoft}, rgba(58,91,191,0.06))` : 'rgba(255,255,255,0.025)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: isAct ? s.accent : '#7a8aab', flexShrink: 0,
                  transition: 'all 0.3s',
                  boxShadow: isAct ? `inset 0 0 18px ${s.accentSoft}, 0 0 22px ${s.accentSoft}` : 'none',
                  filter: isAct ? `drop-shadow(0 0 18px ${s.accent}55)` : 'none',
                }}><SecIcon size={38} strokeWidth={1.5} /></div>
                {/* Text */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.28em', color: isAct ? s.accent : '#4a5580', marginBottom: 8, transition: 'color 0.3s' }}>
                    {isAct ? '● ACTIVE SECTION' : '○ SELECT'}
                  </div>
                  <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 30, fontWeight: 700, letterSpacing: '0.06em', color: isAct ? '#f4f7ff' : '#c8d0e8', lineHeight: 1.05, marginBottom: 8, textShadow: isAct ? '0 0 26px rgba(170,202,255,0.45)' : 'none', transition: 'all 0.3s' }}>
                    {s.label}
                  </div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: isAct ? '#8b9bba' : '#5a6580', letterSpacing: '0.02em' }}>{s.sub}</div>
                </div>
                {/* Count */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0, paddingLeft: 18, borderLeft: `1px solid rgba(170,202,255,${isAct ? 0.22 : 0.08})`, transition: 'border-color 0.3s' }}>
                  <div style={{ fontFamily: "'Rajdhani', monospace", fontSize: 56, fontWeight: 700, color: isAct ? '#e6ecf7' : '#3a4560', lineHeight: 1, letterSpacing: '-0.02em', transition: 'all 0.3s', textShadow: isAct ? `0 0 24px rgba(170,202,255,0.35), 0 0 36px ${s.accent}40` : 'none' }}>{s.count}</div>
                  <div style={{ fontFamily: 'monospace', fontSize: 8, letterSpacing: '0.22em', color: isAct ? s.accent + 'cc' : '#2a3050', marginTop: 6, transition: 'color 0.3s' }}>{s.countLabel}</div>
                </div>
              </div>
            </HoverButton>
          </motion.div>
        )
      })}
    </div>
  )
}

// ─── Phase timeline node ───────────────────────────────────────────────────────
function PhaseNode({ icon: Icon, label, index, total, accentColor, active, completed }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <motion.div
        initial={{ scale: 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 0.1 + index * 0.1, type: 'spring', stiffness: 250, damping: 22 }}
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
        <span style={{ fontFamily: 'monospace', fontSize: 8, letterSpacing: '0.14em', color: active ? accentColor : completed ? accentColor + '60' : '#2a3050' }}>
          {String(index + 1).padStart(2, '0')}
        </span>
        <div style={{
          width: 58, height: 58, borderRadius: '50%',
          border: `1.5px solid ${active ? accentColor : completed ? accentColor + '55' : accentColor + '22'}`,
          background: active ? `radial-gradient(circle, ${accentColor}28 0%, transparent 70%)` : completed ? accentColor + '10' : 'rgba(255,255,255,0.015)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: active ? accentColor : completed ? accentColor + '90' : accentColor + '45',
          position: 'relative',
          boxShadow: active ? `0 0 28px ${accentColor}40, 0 0 10px ${accentColor}25` : 'none',
          transition: 'all 0.35s ease',
        }}>
          {completed ? <Check size={24} strokeWidth={2.5} /> : (Icon && <Icon size={22} strokeWidth={1.75} />)}
          {active && (
            <motion.div
              animate={{ scale: [1, 1.4, 1], opacity: [0.5, 0, 0.5] }}
              transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
              style={{ position: 'absolute', inset: -8, borderRadius: '50%', border: `1px solid ${accentColor}55` }}
            />
          )}
        </div>
        <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.16em', color: active ? accentColor : completed ? accentColor + '70' : '#3a4560', whiteSpace: 'nowrap' }}>{label}</span>
      </motion.div>

      {index < total - 1 && (
        <div style={{ width: 58, height: 1, margin: '0 10px', marginBottom: 28, position: 'relative', background: completed ? `linear-gradient(90deg, ${accentColor}60, ${accentColor}40)` : `linear-gradient(90deg, ${accentColor}30, ${accentColor}10)`, overflow: 'hidden' }}>
          <motion.div
            animate={{ x: ['-100%', '200%'] }}
            transition={{ duration: 2.5, repeat: Infinity, ease: 'linear', delay: index * 0.3 }}
            style={{ position: 'absolute', inset: 0, width: '40%', background: `linear-gradient(90deg, transparent, ${accentColor}, transparent)` }}
          />
        </div>
      )}
    </div>
  )
}

// ─── Chain hero card ───────────────────────────────────────────────────────────
function ChainHeroCard({ meta, index, isActive, currentPhase, isComplete, checking, chainError, onStart, onAdvance, onReset }) {
  const [hovered, setHovered] = useState(false)
  const ChainIcon = meta.icon
  const cardRef = useRef(null)
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)
  const spotlightX = useTransform(mouseX, v => `${v}px`)
  const spotlightY = useTransform(mouseY, v => `${v}px`)

  const handleMouseMove = (e) => {
    const rect = cardRef.current?.getBoundingClientRect()
    if (!rect) return
    mouseX.set(e.clientX - rect.left)
    mouseY.set(e.clientY - rect.top)
  }

  return (
    <motion.div
      ref={cardRef}
      initial={{ opacity: 0, y: 44 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.12, duration: 0.65, ease: [0.23, 1, 0.32, 1] }}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'relative', borderRadius: 22,
        border: `1px solid ${hovered || isActive ? meta.borderGlow : 'rgba(255,255,255,0.06)'}`,
        background: 'rgba(10,13,20,0.78)', backdropFilter: 'blur(14px)',
        overflow: 'hidden', marginBottom: 30,
        boxShadow: hovered || isActive ? `0 0 90px ${meta.glowColor}, 0 28px 80px rgba(0,0,0,0.55)` : '0 4px 36px rgba(0,0,0,0.38)',
        transition: 'border-color 0.35s, box-shadow 0.35s',
      }}>

      {/* Mouse spotlight */}
      {hovered && (
        <motion.div style={{
          position: 'absolute', width: 600, height: 600, borderRadius: '50%',
          background: `radial-gradient(circle at center, ${meta.glowColor} 0%, transparent 65%)`,
          pointerEvents: 'none', transform: 'translate(-50%, -50%)',
          left: spotlightX, top: spotlightY, zIndex: 0,
        }} />
      )}

      {/* Top accent bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent 0%, ${meta.accentColor} 25%, ${meta.accentColor} 75%, transparent 100%)`,
        opacity: hovered || isActive ? 1 : 0.45, transition: 'opacity 0.35s',
      }} />

      {/* Giant icon watermark */}
      <div style={{
        position: 'absolute', right: 36, top: '50%', transform: 'translateY(-50%)',
        color: meta.accentColor, opacity: hovered || isActive ? 0.07 : 0.03,
        lineHeight: 1, pointerEvents: 'none',
        userSelect: 'none', transition: 'opacity 0.4s', zIndex: 0,
      }}><ChainIcon size={210} strokeWidth={1} /></div>

      <div style={{ position: 'relative', zIndex: 1, padding: '38px 44px 34px' }}>
        {/* Header row */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 30, gap: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
            {/* Icon tile */}
            <motion.div
              animate={hovered ? { boxShadow: `0 0 48px ${meta.glowColor}, 0 0 20px ${meta.glowColor}` } : { boxShadow: '0 0 0px transparent' }}
              transition={{ duration: 0.35 }}
              style={{
                width: 76, height: 76, borderRadius: 20,
                border: `2px solid ${meta.accentColor}55`,
                background: `linear-gradient(135deg, ${meta.accentColor}22, ${meta.accentColor}08)`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: meta.accentColor, flexShrink: 0, position: 'relative',
              }}>
              <ChainIcon size={34} strokeWidth={1.75} />
              <div style={{ position: 'absolute', inset: -5, borderRadius: 24, border: `1px solid ${meta.accentColor}18` }} />
            </motion.div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.24em', color: '#4a5580' }}>{meta.threat}</span>
                <span style={{ color: '#1e2440', fontSize: 9, fontFamily: 'monospace' }}>·</span>
                <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.2em', color: '#4a5580' }}>{meta.steps.length} PHASES</span>
                <span style={{ color: '#1e2440', fontSize: 9, fontFamily: 'monospace' }}>·</span>
                <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.18em', padding: '3px 10px', borderRadius: 5, border: `1px solid ${meta.difficultyColor}55`, color: meta.difficultyColor, background: `${meta.difficultyColor}12` }}>{meta.difficulty}</span>
              </div>
              <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 34, fontWeight: 700, letterSpacing: '0.08em', color: '#f0f4ff', lineHeight: 1.05, textShadow: hovered || isActive ? `0 0 40px ${meta.accentColor}40` : 'none', transition: 'text-shadow 0.35s' }}>
                {meta.tagline}
              </div>
            </div>
          </div>

          {/* Status badge */}
          {isActive && (
            <motion.div initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }}
              style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', borderRadius: 20, flexShrink: 0, border: isComplete ? '1px solid rgba(46,227,154,0.45)' : `1px solid ${meta.accentColor}60`, background: isComplete ? 'rgba(46,227,154,0.08)' : `${meta.accentColor}10` }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: isComplete ? '#2ee39a' : meta.accentColor, boxShadow: isComplete ? '0 0 10px #2ee39a' : `0 0 10px ${meta.accentColor}` }} />
              <span style={{ fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.2em', color: isComplete ? '#2ee39a' : meta.accentColor }}>
                {isComplete ? 'OPERATION COMPLETE' : `PHASE ${currentPhase + 1} / ${meta.steps.length}`}
              </span>
            </motion.div>
          )}
        </div>

        {/* Phase timeline */}
        <div style={{ padding: '26px 28px', borderRadius: 14, background: 'rgba(0,0,0,0.32)', border: `1px solid ${meta.accentColor}18`, marginBottom: 26, overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.3em', color: '#3a4560' }}>ATTACK PHASES</div>
            {isActive && !isComplete && <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.2em', color: meta.accentColor + '90' }}>IN PROGRESS</div>}
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', minWidth: 'fit-content', justifyContent: 'center' }}>
            {meta.steps.map((step, i) => (
              <PhaseNode key={step + i} icon={meta.stepIcons[i]} label={step} index={i} total={meta.steps.length}
                accentColor={meta.accentColor}
                active={isActive && !isComplete && i === currentPhase}
                completed={isActive && (i < currentPhase || isComplete)} />
            ))}
          </div>
        </div>

        {/* Brief + Objective */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 28 }}>
          <div style={{ padding: '20px 24px', borderRadius: 12, background: `${meta.accentColor}08`, border: `1px solid ${meta.accentColor}20` }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.3em', color: meta.accentColor, opacity: 0.8, marginBottom: 12 }}>OPERATION BRIEF</div>
            <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, color: '#8b9bba', lineHeight: 1.75, margin: 0 }}>{meta.description}</p>
          </div>
          <div style={{ padding: '20px 24px', borderRadius: 12, background: 'rgba(0,0,0,0.28)', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.3em', color: '#4a5580', marginBottom: 12 }}>OBJECTIVE</div>
            <p style={{ fontFamily: 'monospace', fontSize: 12, color: meta.accentColor, lineHeight: 1.7, margin: 0, letterSpacing: '0.03em' }}>{meta.objective}</p>
          </div>
        </div>

        {/* Chain error message */}
        {chainError && (
          <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
            style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, padding: '10px 16px', borderRadius: 8, border: '1px solid rgba(248,113,113,0.35)', background: 'rgba(248,113,113,0.08)', fontFamily: 'monospace', fontSize: 11, color: '#f87171', letterSpacing: '0.04em' }}>
            <X size={13} strokeWidth={2.5} /> {chainError}
          </motion.div>
        )}

        {/* Action bar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#2e3850', letterSpacing: '0.18em', display: 'flex', alignItems: 'center', gap: 12 }}>
            <span>MULTI-PHASE CHAIN</span>
            <span>·</span>
            <span>EVIDENCE-BASED ADVANCEMENT</span>
          </div>

          {!isActive ? (
            <motion.button onClick={onStart}
              whileHover={{ scale: 1.04, boxShadow: `0 0 56px ${meta.glowColor}, 0 8px 36px rgba(0,0,0,0.55)` }}
              whileTap={{ scale: 0.97 }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 9,
                fontFamily: 'monospace', fontSize: 11, fontWeight: 700, letterSpacing: '0.24em',
                padding: '15px 42px', borderRadius: 11, border: `1px solid ${meta.accentColor}80`,
                background: `linear-gradient(135deg, ${meta.accentColor} 0%, ${meta.accentColor}cc 100%)`,
                color: meta.accentColor === '#f5c400' ? '#07090f' : '#fff', cursor: 'pointer',
                boxShadow: `0 0 32px ${meta.glowColor}, 0 4px 24px rgba(0,0,0,0.45)`,
                position: 'relative', overflow: 'hidden',
              }}>
              INITIATE OPERATION <ArrowRight size={15} strokeWidth={2.5} />
            </motion.button>
          ) : isComplete ? (
            <div style={{ display: 'flex', gap: 10 }}>
              <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'monospace', fontSize: 11, color: '#2ee39a', letterSpacing: '0.2em', padding: '13px 30px', border: '1px solid rgba(46,227,154,0.4)', borderRadius: 11, background: 'rgba(46,227,154,0.08)' }}>
                <Check size={14} strokeWidth={2.5} /> OPERATION COMPLETE
              </motion.div>
              <motion.button onClick={onReset} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.16em', padding: '13px 22px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)', color: '#8b9bba', cursor: 'pointer' }}>
                <RotateCcw size={13} strokeWidth={2.25} /> RESET
              </motion.button>
            </div>
          ) : (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <motion.button onClick={onReset} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.16em', padding: '12px 22px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.03)', color: '#6b7fa3', cursor: 'pointer' }}>
                ABORT
              </motion.button>
              <motion.button onClick={checking ? undefined : onAdvance}
                whileHover={checking ? {} : { scale: 1.04, boxShadow: `0 0 36px ${meta.glowColor}, 0 6px 24px rgba(0,0,0,0.5)` }}
                whileTap={checking ? {} : { scale: 0.97 }}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 9,
                  fontFamily: 'monospace', fontSize: 11, fontWeight: 700, letterSpacing: '0.2em',
                  padding: '13px 32px', borderRadius: 11, border: `1px solid ${meta.accentColor}70`,
                  background: checking
                    ? 'rgba(255,255,255,0.05)'
                    : `linear-gradient(135deg, ${meta.accentColor}cc 0%, ${meta.accentColor}80 100%)`,
                  color: checking ? '#6b7fa3' : (meta.accentColor === '#f5c400' ? '#07090f' : '#fff'),
                  cursor: checking ? 'not-allowed' : 'pointer',
                  boxShadow: checking ? 'none' : `0 0 24px ${meta.glowColor}`,
                  position: 'relative', overflow: 'hidden',
                }}>
                {checking
                  ? 'CHECKING PROGRESS…'
                  : currentPhase === meta.steps.length - 1
                    ? <>COMPLETE OPERATION <Check size={15} strokeWidth={2.5} /></>
                    : <>NEXT PHASE <ArrowRight size={15} strokeWidth={2.5} /></>}
              </motion.button>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  )
}

// ─── Attack Chains section ─────────────────────────────────────────────────────
function AttackChainsSection() {
  const navigate = useNavigate()
  // sessions: { [chainId]: { chainSessionId, phase, complete, checking, error } }
  const [sessions, setSessions] = useState({})

  const start = async (id) => {
    try {
      const result = await api.chains.start(id, `gauntlet-${id}-${Date.now()}`)
      setSessions(s => ({
        ...s,
        [id]: { chainSessionId: result.id, phase: result.current_step_index ?? 0, complete: false, checking: false, error: null },
      }))
    } catch (err) {
      setSessions(s => ({
        ...s,
        [id]: { chainSessionId: null, phase: 0, complete: false, checking: false, error: 'Failed to start chain. Is the backend running?' },
      }))
    }
  }

  const advance = async (id) => {
    const sess = sessions[id]
    if (!sess?.chainSessionId) return
    setSessions(s => ({ ...s, [id]: { ...s[id], checking: true, error: null } }))
    try {
      // Evidence-based gate: verify the current step is actually complete
      const checkResult = await api.chains.check(sess.chainSessionId)
      if (!checkResult.complete) {
        const meta = CHAIN_META[id]
        const stepLabel = meta.steps[sess.phase] ?? 'current phase'
        setSessions(s => ({
          ...s,
          [id]: { ...s[id], checking: false, error: `Complete the ${stepLabel} phase first — reach 60% progress before advancing.` },
        }))
        return
      }
      // Step is done — advance on the backend
      const advResult = await api.chains.advance(sess.chainSessionId)
      const newPhase = advResult.current_step_index ?? sess.phase + 1
      const isComplete = advResult.completed_at !== null && advResult.completed_at !== undefined
      setSessions(s => ({
        ...s,
        [id]: { ...s[id], phase: newPhase, complete: isComplete, checking: false, error: null },
      }))
    } catch (err) {
      const detail = err?.detail || err?.message || String(err)
      setSessions(s => ({ ...s, [id]: { ...s[id], checking: false, error: detail } }))
    }
  }

  const reset = (id) => setSessions(s => { const n = { ...s }; delete n[id]; return n })

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      {CHAIN_ORDER.map((id, idx) => {
        const meta = CHAIN_META[id]
        const sess = sessions[id]
        return (
          <ChainHeroCard key={id} meta={meta} index={idx}
            isActive={!!sess} currentPhase={sess?.phase ?? 0} isComplete={!!sess?.complete}
            checking={!!sess?.checking} chainError={sess?.error ?? null}
            onStart={() => start(id)}
            onAdvance={() => advance(id)}
            onReset={() => reset(id)} />
        )
      })}
    </div>
  )
}

// ─── Mutation catalog card ─────────────────────────────────────────────────────
function MutationCard({ mut, index }) {
  const [expanded, setExpanded] = useState(false)
  const MutIcon = mut.icon
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.04 + index * 0.06, duration: 0.4 }}
      onClick={() => setExpanded(e => !e)}
      style={{
        position: 'relative', borderRadius: 12,
        border: `1px solid ${expanded ? mut.color + '45' : mut.color + '20'}`,
        background: expanded ? `${mut.color}0c` : 'rgba(255,255,255,0.022)',
        padding: '18px 22px', marginBottom: 12, cursor: 'pointer',
        transition: 'all 0.25s ease', overflow: 'hidden',
        backdropFilter: 'blur(10px)',
      }}>
      {/* Left accent stripe */}
      <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: `linear-gradient(180deg, ${mut.color}, ${mut.color}40)`, borderRadius: '3px 0 0 3px' }} />

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingLeft: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, border: `1px solid ${mut.color}45`, background: `${mut.color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: mut.color, flexShrink: 0 }}><MutIcon size={17} strokeWidth={1.75} /></div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.22em', color: '#4a5280' }}>{mut.moduleLabel.toUpperCase()}</span>
              <span style={{ fontFamily: 'monospace', fontSize: 8, padding: '2px 7px', borderRadius: 3, border: `1px solid ${mut.color}55`, color: mut.color, background: `${mut.color}12`, letterSpacing: '0.18em' }}>{mut.impact}</span>
            </div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 600, color: '#d8e0f5' }}>{mut.label}</div>
          </div>
        </div>
        <motion.div animate={{ rotate: expanded ? 90 : 0 }} transition={{ duration: 0.2 }}
          style={{ color: mut.color, display: 'flex', opacity: 0.85 }}><ChevronRight size={16} strokeWidth={2.25} /></motion.div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}>
            <div style={{ paddingLeft: 14, paddingTop: 16 }}>
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: '#7a8aab', lineHeight: 1.75, marginBottom: 14 }}>{mut.description}</p>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 16px', borderRadius: 8, background: `${mut.color}0a`, border: `1px solid ${mut.color}22` }}>
                <span style={{ fontFamily: 'monospace', fontSize: 9, color: mut.color, letterSpacing: '0.22em', whiteSpace: 'nowrap', paddingTop: 1 }}>HINT</span>
                <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#9ba8c8', lineHeight: 1.65 }}>{mut.hint}</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

const MODULE_ICONS = { brute_force: KeyRound, xss: Code, cmd_injection: SquareTerminal, dir_traversal: FolderTree, file_upload: Upload, csrf: Repeat }
const INTENSITY_CHOICES = [
  { id: 'single',     label: 'Single Shift',  desc: '1 shift · 60–180s window' },
  { id: 'escalating', label: 'Escalating',    desc: '2 shifts · pressure rises' },
  { id: 'chaos',      label: 'Chaos',          desc: '3 shifts · 25–75s windows' },
]

// ─── Mutation launch card ─────────────────────────────────────────────────────
function MutationLaunchCard({ op, index }) {
  const navigate = useNavigate()
  const [intensity, setIntensity] = useState('single')
  const [launching, setLaunching] = useState(false)
  const [error, setError] = useState(null)
  const [hovered, setHovered] = useState(false)
  const cardRef = useRef(null)
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)
  const spotlightX = useTransform(mouseX, v => `${v}px`)
  const spotlightY = useTransform(mouseY, v => `${v}px`)

  const handleMouseMove = (e) => {
    const rect = cardRef.current?.getBoundingClientRect()
    if (!rect) return
    mouseX.set(e.clientX - rect.left)
    mouseY.set(e.clientY - rect.top)
  }

  const launch = async () => {
    if (launching) return
    setLaunching(true)
    setError(null)
    try {
      const session = await api.sessions.create(op.module, {
        mode: 'tutorial',
        mutation_mode: true,
        mutation_intensity: intensity,
      })
      navigate(`/workspace/${session.session_id}?mutation=1&intensity=${encodeURIComponent(intensity)}`)
    } catch (err) {
      setError(err.message)
      setLaunching(false)
    }
  }

  const OpIcon = MODULE_ICONS[op.module] || Radar

  return (
    <motion.div
      ref={cardRef}
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'relative', borderRadius: 20,
        border: `1px solid ${hovered ? op.color + '55' : 'rgba(255,255,255,0.06)'}`,
        background: 'rgba(10,13,20,0.78)', backdropFilter: 'blur(14px)',
        overflow: 'hidden', marginBottom: 24,
        boxShadow: hovered ? `0 0 80px ${op.glow}, 0 24px 70px rgba(0,0,0,0.5)` : '0 4px 32px rgba(0,0,0,0.35)',
        transition: 'border-color 0.3s, box-shadow 0.3s',
      }}>

      {/* Mouse spotlight */}
      {hovered && (
        <motion.div style={{
          position: 'absolute', width: 500, height: 500, borderRadius: '50%',
          background: `radial-gradient(circle at center, ${op.glow} 0%, transparent 65%)`,
          pointerEvents: 'none', transform: 'translate(-50%, -50%)',
          left: spotlightX, top: spotlightY, zIndex: 0,
        }} />
      )}

      {/* Top accent bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent 0%, ${op.color} 25%, ${op.color} 75%, transparent 100%)`,
        opacity: hovered ? 1 : 0.4, transition: 'opacity 0.3s',
      }} />

      {/* Watermark */}
      <div style={{
        position: 'absolute', right: 16, top: '50%', transform: 'translateY(-50%)',
        fontFamily: 'monospace', fontSize: 108, color: op.color,
        opacity: hovered ? 0.055 : 0.022,
        lineHeight: 1, pointerEvents: 'none', userSelect: 'none',
        transition: 'opacity 0.4s', zIndex: 0, letterSpacing: '-0.04em', whiteSpace: 'nowrap',
      }}>{op.moduleLabel.toUpperCase()}</div>

      <div style={{ position: 'relative', zIndex: 1, padding: '32px 40px 30px' }}>

        {/* Header row */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20, marginBottom: 24 }}>
          <motion.div
            animate={hovered ? { boxShadow: `0 0 40px ${op.glow}, 0 0 18px ${op.glow}` } : { boxShadow: '0 0 0px transparent' }}
            transition={{ duration: 0.3 }}
            style={{
              width: 64, height: 64, borderRadius: 18, flexShrink: 0,
              border: `2px solid ${op.color}55`,
              background: `linear-gradient(135deg, ${op.color}22, ${op.color}08)`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: op.color,
            }}>
            <OpIcon size={28} strokeWidth={1.75} />
          </motion.div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.24em', color: '#4a5280' }}>{op.moduleLabel.toUpperCase()}</span>
              <span style={{ color: '#1e2440', fontFamily: 'monospace', fontSize: 9 }}>·</span>
              <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.18em', padding: '2px 8px', borderRadius: 4, border: `1px solid ${op.color}55`, color: op.color, background: `${op.color}12` }}>{op.impact}</span>
              <span style={{ color: '#1e2440', fontFamily: 'monospace', fontSize: 9 }}>·</span>
              <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.22em', color: '#4a5280' }}>MUTATION OP</span>
            </div>
            <div style={{
              fontFamily: "'Rajdhani', sans-serif", fontSize: 26, fontWeight: 700,
              letterSpacing: '0.06em', color: '#f0f4ff', lineHeight: 1.1,
              textShadow: hovered ? `0 0 30px ${op.color}50` : 'none', transition: 'text-shadow 0.3s',
            }}>{op.label.toUpperCase()}</div>
          </div>
        </div>

        {/* Briefing */}
        <div style={{ padding: '16px 20px', borderRadius: 12, background: `${op.color}08`, border: `1px solid ${op.color}1e`, marginBottom: 22 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.26em', color: op.color, opacity: 0.8, marginBottom: 10 }}>MISSION BRIEFING</div>
          <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13.5, color: '#8b9bba', lineHeight: 1.75 }}>{op.briefing}</div>
        </div>

        {/* Intensity picker */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.26em', color: '#4a5580', marginBottom: 10 }}>MUTATION INTENSITY</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {INTENSITY_CHOICES.map(c => {
              const active = c.id === intensity
              return (
                <button key={c.id} onClick={() => setIntensity(c.id)}
                  style={{
                    borderRadius: 10, cursor: 'pointer', textAlign: 'left',
                    border: `1px solid ${active ? op.color + '88' : 'rgba(255,255,255,0.07)'}`,
                    background: active ? `${op.color}18` : 'rgba(255,255,255,0.025)',
                    padding: '12px 14px', transition: 'all 0.2s',
                  }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: active ? op.color : '#c8d0e8', marginBottom: 4 }}>{c.label}</div>
                  <div style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.04em', color: active ? op.color + 'aa' : '#3a4560' }}>{c.desc}</div>
                </button>
              )
            })}
          </div>
        </div>

        {/* INITIATE button */}
        <motion.button onClick={launch} disabled={launching}
          whileHover={!launching ? { scale: 1.02, boxShadow: `0 0 60px ${op.glow}, 0 8px 36px rgba(0,0,0,0.5)` } : {}}
          whileTap={!launching ? { scale: 0.98 } : {}}
          style={{
            width: '100%', borderRadius: 12,
            border: `1px solid ${op.color}80`,
            background: `linear-gradient(135deg, ${op.color} 0%, ${op.color}cc 100%)`,
            color: '#07090f', padding: '15px 24px',
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
            fontFamily: 'monospace', fontSize: 12, fontWeight: 800, letterSpacing: '0.22em',
            cursor: launching ? 'wait' : 'pointer',
            boxShadow: `0 0 32px ${op.glow}`,
            position: 'relative', overflow: 'hidden',
          }}>
          {launching ? 'INITIATING...' : <>INITIATE MUTATION OP <ArrowRight size={16} strokeWidth={2.5} /></>}
        </motion.button>
        {error && (
          <div style={{ marginTop: 10, fontFamily: 'monospace', fontSize: 10, color: '#ff6080' }}>{error}</div>
        )}
      </div>
    </motion.div>
  )
}

function CpuArchitecture({ width = 360, height = 220 }) {
  const LIGHTS = [
    { id: 1, path: 'M 10 20 h 79.5 q 5 0 5 5 v 24',                                                    dur: 5,   delay: 0,   grad: 'cpu-blue-grad' },
    { id: 2, path: 'M 180 10 h -69.7 q -5 0 -5 5 v 24',                                                dur: 5.5, delay: 0.6, grad: 'cpu-yellow-grad' },
    { id: 3, path: 'M 130 20 v 21.8 q 0 5 -5 5 h -10',                                                 dur: 4,   delay: 1.1, grad: 'cpu-pinkish-grad' },
    { id: 4, path: 'M 170 80 v -21.8 q 0 -5 -5 -5 h -50',                                              dur: 5.2, delay: 1.6, grad: 'cpu-white-grad' },
    { id: 5, path: 'M 135 65 h 15 q 5 0 5 5 v 10 q 0 5 -5 5 h -39.8 q -5 0 -5 -5 v -20',             dur: 6.5, delay: 0.3, grad: 'cpu-green-grad' },
    { id: 6, path: 'M 94.8 95 v -36',                                                                   dur: 3.5, delay: 0.9, grad: 'cpu-orange-grad' },
    { id: 7, path: 'M 88 88 v -15 q 0 -5 -5 -5 h -10 q -5 0 -5 -5 v -5 q 0 -5 5 -5 h 14',            dur: 6,   delay: 1.4, grad: 'cpu-cyan-grad' },
    { id: 8, path: 'M 30 30 h 25 q 5 0 5 5 v 6.5 q 0 5 5 5 h 20',                                     dur: 5.5, delay: 0.5, grad: 'cpu-rose-grad' },
  ]
  return (
    <svg width={width} height={height} viewBox="0 0 200 100" style={{ display: 'block', overflow: 'visible' }}>
      <g stroke="rgba(255,255,255,0.18)" fill="none" strokeWidth="0.3">
        <path d="M 10 20 h 79.5 q 5 0 5 5 v 30" /><path d="M 180 10 h -69.7 q -5 0 -5 5 v 30" />
        <path d="M 130 20 v 21.8 q 0 5 -5 5 h -10" /><path d="M 170 80 v -21.8 q 0 -5 -5 -5 h -50" />
        <path d="M 135 65 h 15 q 5 0 5 5 v 10 q 0 5 -5 5 h -39.8 q -5 0 -5 -5 v -20" />
        <path d="M 94.8 95 v -36" /><path d="M 88 88 v -15 q 0 -5 -5 -5 h -10 q -5 0 -5 -5 v -5 q 0 -5 5 -5 h 14" />
        <path d="M 30 30 h 25 q 5 0 5 5 v 6.5 q 0 5 5 5 h 20" />
      </g>
      {LIGHTS.map(l => (
        <g key={l.id} mask={`url(#cpu-mask-${l.id})`}>
          <circle cx="0" cy="0" r="8" fill={`url(#${l.grad})`}>
            <animateMotion dur={`${l.dur}s`} begin={`${l.delay}s`} repeatCount="indefinite" path={l.path} rotate="auto" />
          </circle>
        </g>
      ))}
      <g fill="url(#cpu-connection-gradient)">
        <rect x="93" y="37" width="2.5" height="5" rx="0.7" /><rect x="104" y="37" width="2.5" height="5" rx="0.7" />
        <rect x="93" y="58" width="2.5" height="5" rx="0.7" /><rect x="104" y="58" width="2.5" height="5" rx="0.7" />
        <rect x="82.5" y="44.5" width="2.5" height="5" rx="0.7" transform="rotate(-90 83.75 47)" />
        <rect x="82.5" y="51" width="2.5" height="5" rx="0.7" transform="rotate(-90 83.75 53.5)" />
        <rect x="115" y="44.5" width="2.5" height="5" rx="0.7" transform="rotate(-90 116.25 47)" />
        <rect x="115" y="51" width="2.5" height="5" rx="0.7" transform="rotate(-90 116.25 53.5)" />
      </g>
      <rect x="85" y="40" width="30" height="20" rx="2" fill="#181818" stroke="rgba(255,255,255,0.08)" strokeWidth="0.3" filter="url(#cpu-light-shadow)" />
      <rect x="86.5" y="41.5" width="27" height="17" rx="1.4" fill="none" stroke="rgba(170,202,255,0.12)" strokeWidth="0.25" />
      <text x="100" y="52" fontSize="5.2" textAnchor="middle" fontFamily="'JetBrains Mono', monospace" fill="url(#cpu-text-gradient)" fontWeight="600" letterSpacing="0.12em">TARGET</text>
      <defs>
        <mask id="cpu-mask-1"><path d="M 10 20 h 79.5 q 5 0 5 5 v 24" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-2"><path d="M 180 10 h -69.7 q -5 0 -5 5 v 24" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-3"><path d="M 130 20 v 21.8 q 0 5 -5 5 h -10" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-4"><path d="M 170 80 v -21.8 q 0 -5 -5 -5 h -50" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-5"><path d="M 135 65 h 15 q 5 0 5 5 v 10 q 0 5 -5 5 h -39.8 q -5 0 -5 -5 v -20" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-6"><path d="M 94.8 95 v -36" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-7"><path d="M 88 88 v -15 q 0 -5 -5 -5 h -10 q -5 0 -5 -5 v -5 q 0 -5 5 -5 h 14" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <mask id="cpu-mask-8"><path d="M 30 30 h 25 q 5 0 5 5 v 6.5 q 0 5 5 5 h 20" strokeWidth="0.6" stroke="white" fill="none" /></mask>
        <radialGradient id="cpu-blue-grad" fx="1"><stop offset="0%" stopColor="#00E8ED" /><stop offset="50%" stopColor="#08F" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-yellow-grad" fx="1"><stop offset="0%" stopColor="#FFD800" /><stop offset="50%" stopColor="#FFB300" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-pinkish-grad" fx="1"><stop offset="0%" stopColor="#FF008B" /><stop offset="50%" stopColor="#830CD1" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-white-grad" fx="1"><stop offset="0%" stopColor="white" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-green-grad" fx="1"><stop offset="0%" stopColor="#22c55e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-orange-grad" fx="1"><stop offset="0%" stopColor="#f97316" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-cyan-grad" fx="1"><stop offset="0%" stopColor="#06b6d4" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <radialGradient id="cpu-rose-grad" fx="1"><stop offset="0%" stopColor="#f43f5e" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        <linearGradient id="cpu-connection-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4F4F4F" /><stop offset="60%" stopColor="#121214" /></linearGradient>
        <linearGradient id="cpu-text-gradient" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#666666"><animate attributeName="offset" values="-2; -1; 0" dur="5s" repeatCount="indefinite" calcMode="spline" keyTimes="0; 0.5; 1" keySplines="0.4 0 0.2 1; 0.4 0 0.2 1" /></stop>
          <stop offset="25%" stopColor="white"><animate attributeName="offset" values="-1; 0; 1" dur="5s" repeatCount="indefinite" calcMode="spline" keyTimes="0; 0.5; 1" keySplines="0.4 0 0.2 1; 0.4 0 0.2 1" /></stop>
          <stop offset="50%" stopColor="#666666"><animate attributeName="offset" values="0; 1; 2" dur="5s" repeatCount="indefinite" calcMode="spline" keyTimes="0; 0.5; 1" keySplines="0.4 0 0.2 1; 0.4 0 0.2 1" /></stop>
        </linearGradient>
        <filter id="cpu-light-shadow" x="-50%" y="-50%" width="200%" height="200%"><feDropShadow dx="0" dy="1" stdDeviation="1.5" floodColor="black" floodOpacity="0.5" /></filter>
      </defs>
    </svg>
  )
}

// ─── Mutation Mode section ─────────────────────────────────────────────────────
function MutationModeSection() {
  const [phase, setPhase] = useState('intro')

  if (phase === 'catalog') {
    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} style={{ maxWidth: 760, margin: '0 auto' }}>
        <motion.button onClick={() => setPhase('intro')} whileHover={{ x: -3 }}
          style={{ fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.2em', background: 'none', border: 'none', color: '#5a6580', cursor: 'pointer', marginBottom: 32, padding: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
          ← BACK TO OVERVIEW
        </motion.button>

        {/* Catalog header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 32, gap: 24, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'rgba(245,196,0,0.7)', letterSpacing: '0.24em', marginBottom: 10 }}>MUTATION OPERATIONS</div>
            <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 30, fontWeight: 700, color: '#f0f4ff', letterSpacing: '0.04em', marginBottom: 16 }}>Pick a module, then adapt live.</div>
            {/* Stats strip */}
            <div style={{ display: 'flex', gap: 0, overflow: 'hidden', borderRadius: 10, border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(10,13,20,0.6)', backdropFilter: 'blur(10px)', width: 'fit-content' }}>
              {[
                { label: 'MODULES', value: '6' },
                { label: 'MUTATIONS', value: '13', highlight: true },
                { label: 'MAX SHIFTS', value: '3' },
              ].map((s, i) => (
                <div key={s.label} style={{ padding: '12px 22px', background: s.highlight ? 'rgba(245,196,0,0.06)' : 'transparent', borderRight: i < 2 ? '1px solid rgba(255,255,255,0.06)' : 'none', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 20, fontWeight: 700, color: s.highlight ? '#f5c400' : '#d8e0f5', letterSpacing: '0.04em', marginBottom: 3 }}>{s.value}</div>
                  <div style={{ fontFamily: 'monospace', fontSize: 8, letterSpacing: '0.24em', color: '#3e4860' }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ opacity: 0.55, flexShrink: 0 }}>
            <CpuArchitecture width={220} height={136} />
          </div>
        </div>

        {MUTATION_MODULES.map((op, i) => (
          <MutationLaunchCard key={op.module} op={op} index={i} />
        ))}
      </motion.div>
    )
  }

  // Intro stage
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.55 }}
      style={{ minHeight: '72vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '40px 24px 70px', position: 'relative' }}>

      {/* CPU animation */}
      <motion.div initial={{ opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.1, duration: 0.65, ease: [0.23, 1, 0.32, 1] }}
        style={{ position: 'relative', marginBottom: 28, zIndex: 1, width: 520, maxWidth: '92vw' }}>
        <CpuArchitecture width="100%" height={260} />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.28 }}
        style={{ fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.4em', color: 'rgba(245,196,0,0.6)', marginBottom: 18, zIndex: 1 }}>
        ADVANCED · ADAPTIVE CHALLENGE
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.38 }}
        style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 72, fontWeight: 700, letterSpacing: '0.1em', lineHeight: 1, marginBottom: 26, background: 'linear-gradient(135deg, #f5c400 0%, #ffaa00 40%, #ff8c00 70%, #f5c400 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text', filter: 'drop-shadow(0 0 40px rgba(245,196,0,0.4))', zIndex: 1 }}>
        MUTATION MODE
      </motion.div>

      <motion.p initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.48 }}
        style={{ fontFamily: "'Inter', sans-serif", fontSize: 15.5, color: '#6b7a99', lineHeight: 1.85, maxWidth: 580, marginBottom: 14, zIndex: 1 }}>
        The target evolves mid-mission. Defense mechanisms activate dynamically — rate limiters, output encoding, CSP headers, and input filters engage without warning.
      </motion.p>
      <motion.p initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.54 }}
        style={{ fontFamily: "'Inter', sans-serif", fontSize: 15.5, color: '#6b7a99', lineHeight: 1.85, maxWidth: 540, marginBottom: 44, zIndex: 1 }}>
        Your technique must adapt or fail. Static payloads won&apos;t survive here.
      </motion.p>

      {/* Stats strip */}
      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}
        style={{ display: 'flex', gap: 0, marginBottom: 56, overflow: 'hidden', borderRadius: 12, border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(10,13,20,0.5)', backdropFilter: 'blur(10px)', zIndex: 1 }}>
        {[{ label: 'MUTATIONS', value: '13', highlight: false }, { label: 'MODULES AFFECTED', value: '6', highlight: true }, { label: 'MAX DIFFICULTY', value: 'CRITICAL', highlight: false }].map((stat, i) => (
          <div key={stat.label} style={{ padding: '18px 34px', background: stat.highlight ? 'rgba(245,196,0,0.07)' : 'transparent', borderRight: i < 2 ? '1px solid rgba(255,255,255,0.06)' : 'none', textAlign: 'center', minWidth: 150 }}>
            <div style={{ fontFamily: "'Rajdhani', monospace", fontSize: 28, fontWeight: 700, color: stat.highlight ? '#f5c400' : '#d8e0f5', letterSpacing: '0.04em', marginBottom: 6 }}>{stat.value}</div>
            <div style={{ fontFamily: 'monospace', fontSize: 8, letterSpacing: '0.26em', color: '#3e4860' }}>{stat.label}</div>
          </div>
        ))}
      </motion.div>

      {/* Divider */}
      <motion.div initial={{ opacity: 0, scaleX: 0 }} animate={{ opacity: 1, scaleX: 1 }} transition={{ delay: 0.7, duration: 0.55 }}
        style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 36, width: '100%', maxWidth: 580, zIndex: 1 }}>
        <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, transparent, rgba(245,196,0,0.4))' }} />
        <span style={{ fontFamily: 'monospace', fontSize: 13, letterSpacing: '0.14em', color: 'rgba(245,196,0,0.85)', whiteSpace: 'nowrap', fontWeight: 500 }}>Are you ready for the challenge?</span>
        <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, rgba(245,196,0,0.4), transparent)' }} />
      </motion.div>

      {/* CTA */}
      <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.82 }}
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, zIndex: 1 }}>
        <motion.button onClick={() => setPhase('catalog')}
          whileHover={{ scale: 1.06, boxShadow: '0 0 70px rgba(245,196,0,0.45), 0 10px 40px rgba(0,0,0,0.55)' }}
          whileTap={{ scale: 0.97 }}
          style={{ position: 'relative', overflow: 'hidden', fontFamily: 'monospace', fontSize: 13, fontWeight: 700, letterSpacing: '0.3em', padding: '18px 64px', borderRadius: 12, border: '1px solid rgba(245,196,0,0.6)', background: 'linear-gradient(135deg, #f5c400 0%, #ffaa00 50%, #ff8c00 100%)', color: '#07090f', cursor: 'pointer', boxShadow: '0 0 40px rgba(245,196,0,0.32), 0 4px 24px rgba(0,0,0,0.45)' }}>
          START MUTATION MODE →
        </motion.button>
        <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#3a4560', letterSpacing: '0.22em' }}>VIEW ALL 13 ACTIVE MUTATIONS</span>
      </motion.div>
    </motion.div>
  )
}

// ─── Main Gauntlet page ────────────────────────────────────────────────────────
// ─── GauntletTitle — per-letter roll-up reveal, staggered from center ─────────
function GauntletTitle() {
  const letters = 'GAUNTLET'.split('')
  const mid = (letters.length - 1) / 2
  return (
    <h1 aria-label="GAUNTLET" style={{
      display: 'flex', justifyContent: 'center', flexWrap: 'nowrap',
      fontFamily: "'Rajdhani', sans-serif", fontSize: 'clamp(64px, 10vw, 112px)',
      fontWeight: 700, letterSpacing: '0.12em', lineHeight: 1, margin: '0 0 22px',
      filter: 'drop-shadow(0 0 60px rgba(255,255,255,0.12)) drop-shadow(0 0 40px rgba(255,21,53,0.18))',
    }}>
      {letters.map((ch, i) => (
        <span key={i} aria-hidden="true" style={{
          display: 'inline-block', overflow: 'hidden',
          padding: '0.14em 0', margin: '-0.14em 0',
        }}>
          <motion.span
            initial={{ y: '120%' }}
            animate={{ y: '0%' }}
            transition={{ duration: 0.72, ease: [0.16, 1, 0.3, 1], delay: 0.2 + Math.abs(i - mid) * 0.05 }}
            style={{
              display: 'inline-block',
              background: 'linear-gradient(180deg, #ffffff 0%, #d4dcf0 42%, #8190b0 100%)',
              WebkitBackgroundClip: 'text', backgroundClip: 'text',
              WebkitTextFillColor: 'transparent', color: 'transparent',
            }}
          >{ch}</motion.span>
        </span>
      ))}
    </h1>
  )
}

export default function Gauntlet() {
  const [section, setSection] = useState('chains')

  return (
    <div style={{ position: 'relative', minHeight: '100vh', width: '100%', color: '#fff' }}>
      <AuroraFlow />

      <div style={{ position: 'relative', zIndex: 1, padding: '0 24px 80px' }}>

        {/* Hero header */}
        <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
          style={{ textAlign: 'center', paddingTop: 72, paddingBottom: 14 }}>

          {/* Pill badge */}
          <motion.div initial={{ scale: 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ delay: 0.15 }}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 10, padding: '8px 18px', borderRadius: 24, border: '1px solid rgba(255,21,53,0.35)', background: 'rgba(255,21,53,0.08)', marginBottom: 28, backdropFilter: 'blur(8px)' }}>
            <span style={{ display: 'flex', color: '#ff4060', filter: 'drop-shadow(0 0 6px rgba(255,64,96,0.55))' }}><Zap size={14} strokeWidth={2.25} /></span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.3em', color: '#ff6080', fontWeight: 700 }}>ADVANCED OPERATIONS CENTER</span>
          </motion.div>

          {/* Title — letters roll up from a clipped baseline, staggered from center */}
          <GauntletTitle />

          {/* Subtitle */}
          <motion.p initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.38 }}
            style={{ fontFamily: "'Inter', sans-serif", fontSize: 15, color: '#5a6a88', letterSpacing: '0.04em', margin: '0 0 56px' }}>
            Advanced scenarios. No hints. Adapt or fail.
          </motion.p>

          {/* Section nav */}
          <HeroSectionNav active={section} onSelect={setSection} />
        </motion.div>

        {/* Section content */}
        <AnimatePresence mode="wait">
          {section === 'chains' ? (
            <motion.div key="chains" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ duration: 0.4 }}>
              <AttackChainsSection />
            </motion.div>
          ) : (
            <motion.div key="mutations" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ duration: 0.4 }}>
              <MutationModeSection />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
