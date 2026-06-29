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
import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence, useMotionValue, useTransform } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import GauntletIntro from '../components/GauntletIntro.jsx'
import {
  Zap, Workflow, Radar, KeyRound, Code, Repeat,
  SquareTerminal, FolderTree, Upload, Timer, Lock, ShieldCheck, Filter,
  FolderLock, Ban, FileX, FileCheck, Braces, Check, ChevronRight, ArrowRight,
  RotateCcw, X,
} from 'lucide-react'

// ─── Chain metadata ────────────────────────────────────────────────────────────
const CHAIN_META = {
  full_compromise: {
    id: 'full_compromise',
    cardImage: 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&w=800&q=80',
    name: 'Full Compromise',
    tagline: 'FULL COMPROMISE',
    threat: 'APT-CLASS',
    difficulty: 'EXTREME',
    difficultyColor: '#ff1535',
    accentColor: '#ff1535',
    glowColor: 'rgba(255,21,53,0.18)',
    borderGlow: 'rgba(255,21,53,0.45)',
    steps: ['RECON', 'BRUTE FORCE', 'XSS', 'CSRF'],
    stepModules: ['recon', 'brute_force', 'xss', 'csrf'],
    stepIcons: [Radar, KeyRound, Code, Repeat],
    description:
      'Execute a complete network takeover — map the surface, breach authentication, inject scripts, and forge cross-site requests. Every phase builds on the last.',
    objective: 'Full unauthorized access + session hijack',
    chainId: 'full_compromise',
  },
  root_the_box: {
    id: 'root_the_box',
    cardImage: 'https://images.unsplash.com/photo-1597733336794-12d05021d510?auto=format&fit=crop&w=800&q=80',
    name: 'Root The Box',
    tagline: 'ROOT THE BOX',
    threat: 'OS-LEVEL',
    difficulty: 'CRITICAL',
    difficultyColor: '#8b2fff',
    accentColor: '#8b2fff',
    glowColor: 'rgba(139,47,255,0.18)',
    borderGlow: 'rgba(139,47,255,0.45)',
    steps: ['RECON', 'CMD INJECTION', 'DIR TRAVERSAL', 'FILE UPLOAD'],
    stepModules: ['recon', 'cmd_injection', 'dir_traversal', 'file_upload'],
    stepIcons: [Radar, SquareTerminal, FolderTree, Upload],
    description:
      'Escalate from zero to root. Fingerprint the target, inject OS commands, traverse the filesystem, and plant your payload via unrestricted file upload.',
    objective: 'Remote code execution + filesystem control',
    chainId: 'root_the_box',
  },
  data_exfiltration: {
    id: 'data_exfiltration',
    cardImage: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=800&q=80',
    name: 'Data Exfiltration',
    tagline: 'DATA EXFILTRATION',
    threat: 'INSIDER-THREAT',
    difficulty: 'HIGH',
    difficultyColor: '#f5c400',
    accentColor: '#f5c400',
    glowColor: 'rgba(245,196,0,0.14)',
    borderGlow: 'rgba(245,196,0,0.4)',
    steps: ['RECON', 'BRUTE FORCE', 'DIR TRAVERSAL', 'CSRF'],
    stepModules: ['recon', 'brute_force', 'dir_traversal', 'csrf'],
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
const GAUNTLET_REVEAL_DELAY = 0.75
const GAUNTLET_EASE = [0.22, 0.61, 0.36, 1]
const LOADER_COLUMNS = Array.from({ length: 7 }, (_, i) => i)
const LOADER_CENTER_ORDER = [3, 2, 4, 1, 5, 0, 6]
const LOADER_RANDOM_ORDER = [2, 5, 0, 4, 1, 6, 3]
const LOADER_CENTER_STAGGER = 0.25 / Math.max(LOADER_COLUMNS.length - 1, 1)
const LOADER_RANDOM_STAGGER = 0.1 / Math.max(LOADER_COLUMNS.length - 1, 1)

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

// Webflow-style entrance loader from the reference site.
function GauntletEntranceLoader() {
  return (
    <motion.div
      aria-hidden="true"
      data-gauntlet-loader="true"
      initial={{ opacity: 1 }}
      animate={{ opacity: 0 }}
      transition={{ delay: 1.82, duration: 0.01, ease: 'linear' }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 998,
        pointerEvents: 'none',
        display: 'grid',
        gridTemplateColumns: 'repeat(7, minmax(0, 1fr))',
        gridTemplateRows: '1fr',
      }}
    >
      <motion.div
        initial={{ opacity: 0.05 }}
        animate={{ opacity: 0 }}
        transition={{ delay: GAUNTLET_REVEAL_DELAY, duration: 0.5, ease: 'linear' }}
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 1,
          mixBlendMode: 'normal',
          backgroundImage:
            "url(\"https://cdn.prod.website-files.com/666b07338a0357cfca554b8f/67362371bb84787d1e1c3557_402107790_STATIC_NOISE_400.gif\")",
          backgroundPosition: '0 0',
          backgroundSize: 200,
        }}
      />

      {LOADER_COLUMNS.map((column) => {
        const centerDelay = LOADER_CENTER_ORDER.indexOf(column) * LOADER_CENTER_STAGGER
        const collapseDelay = GAUNTLET_REVEAL_DELAY + LOADER_RANDOM_ORDER.indexOf(column) * LOADER_RANDOM_STAGGER

        return (
          <motion.div
            key={column}
            data-gauntlet-loader-column="true"
            initial={{ scaleY: 1, backgroundColor: 'rgba(0,0,0,1)' }}
            animate={{
              scaleY: [1, 1, 0],
              backgroundColor: [
                'rgba(0,0,0,1)',
                'rgba(50,50,50,0.35)',
                'rgba(50,50,50,0.35)',
              ],
            }}
            transition={{
              scaleY: { delay: collapseDelay, duration: 0.875, ease: GAUNTLET_EASE },
              backgroundColor: {
                delay: centerDelay,
                duration: 1,
                ease: GAUNTLET_EASE,
                times: [0, 1, 1],
              },
            }}
            style={{
              zIndex: 2,
              marginRight: -1,
              transformOrigin: '0 100%',
              backdropFilter: 'blur(5vw)',
              WebkitBackdropFilter: 'blur(5vw)',
              willChange: 'transform, background-color',
            }}
          />
        )
      })}

      <motion.div
        initial={{ opacity: 1 }}
        animate={{ opacity: 0 }}
        transition={{ delay: GAUNTLET_REVEAL_DELAY, duration: 0.5, ease: 'linear' }}
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 3,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '2.5rem',
        }}
      />
    </motion.div>
  )
}

// ─── Section navigator — segmented control ────────────────────────────────────
function HeroSectionNav({ active, onSelect }) {
  const sections = [
    { id: 'chains',    icon: Workflow, label: 'ATTACK CHAINS', sub: 'Multi-phase operations', count: 3,  countLabel: 'OPS'      },
    { id: 'mutations', icon: Zap,      label: 'MUTATION MODE', sub: 'Adaptive defense',       count: 13, countLabel: 'MUTATIONS' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.15, duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
      style={{
        display: 'flex', maxWidth: 860, margin: '0 auto 56px',
        background: 'rgba(8,8,12,0.72)', borderRadius: 18,
        border: '1px solid rgba(255,21,53,0.16)',
        padding: 5, gap: 4,
        backdropFilter: 'blur(18px)', WebkitBackdropFilter: 'blur(18px)',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04), 0 4px 32px rgba(0,0,0,0.5)',
      }}
    >
      {sections.map((s) => {
        const isAct = active === s.id
        const SecIcon = s.icon
        return (
          <motion.button
            key={s.id}
            onClick={() => onSelect(s.id)}
            whileTap={{ scale: 0.98 }}
            style={{
              flex: 1, position: 'relative', padding: '16px 22px',
              borderRadius: 13, border: 'none', background: 'transparent',
              cursor: 'pointer', display: 'flex', alignItems: 'center',
              gap: 14, textAlign: 'left', isolation: 'isolate',
            }}
          >
            {/* Sliding active background */}
            {isAct && (
              <motion.div
                layoutId="seg-active-bg"
                style={{
                  position: 'absolute', inset: 0, borderRadius: 13,
                  background: 'linear-gradient(135deg, rgba(255,21,53,0.13) 0%, rgba(160,8,24,0.05) 100%)',
                  border: '1px solid rgba(255,21,53,0.30)',
                  boxShadow: '0 0 28px rgba(255,21,53,0.09), inset 0 1px 0 rgba(255,255,255,0.05)',
                }}
                transition={{ type: 'spring', stiffness: 500, damping: 38 }}
              />
            )}

            {/* Icon */}
            <div style={{
              width: 40, height: 40, borderRadius: 10, flexShrink: 0,
              background: isAct ? 'rgba(255,21,53,0.10)' : 'rgba(255,255,255,0.025)',
              border: `1px solid ${isAct ? 'rgba(255,21,53,0.38)' : 'rgba(255,255,255,0.06)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: isAct ? '#ff4060' : '#2e3850',
              position: 'relative', zIndex: 1,
              boxShadow: isAct ? '0 0 16px rgba(255,21,53,0.22)' : 'none',
              transition: 'all 0.25s ease',
            }}>
              <SecIcon size={18} strokeWidth={1.75} />
            </div>

            {/* Text */}
            <div style={{ flex: 1, minWidth: 0, position: 'relative', zIndex: 1 }}>
              <div style={{
                fontFamily: "'Rajdhani', sans-serif", fontSize: 14, fontWeight: 700,
                letterSpacing: '0.1em', lineHeight: 1.1, marginBottom: 3,
                color: isAct ? '#eef2ff' : '#2e3850',
                textShadow: isAct ? '0 0 18px rgba(210,220,255,0.25)' : 'none',
                transition: 'color 0.25s, text-shadow 0.25s',
              }}>{s.label}</div>
              <div style={{
                fontFamily: "'Inter', sans-serif", fontSize: 10.5,
                color: isAct ? '#5a6a88' : '#1e2535',
                letterSpacing: '0.025em',
                transition: 'color 0.25s',
              }}>{s.sub}</div>
            </div>

            {/* Count badge */}
            <div style={{
              position: 'relative', zIndex: 1, flexShrink: 0,
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              background: isAct ? 'rgba(255,21,53,0.07)' : 'rgba(255,255,255,0.02)',
              border: `1px solid ${isAct ? 'rgba(255,21,53,0.22)' : 'rgba(255,255,255,0.04)'}`,
              borderRadius: 9, padding: '5px 11px', minWidth: 46,
              transition: 'all 0.25s',
            }}>
              <div style={{
                fontFamily: "'Rajdhani', sans-serif", fontSize: 24, fontWeight: 700,
                lineHeight: 1, letterSpacing: '-0.02em',
                color: isAct ? '#ff4060' : '#1a2038',
                textShadow: isAct ? '0 0 20px rgba(255,21,53,0.5)' : 'none',
                transition: 'all 0.25s',
              }}>{s.count}</div>
              <div style={{
                fontFamily: 'monospace', fontSize: 6, letterSpacing: '0.15em',
                color: isAct ? 'rgba(255,64,96,0.6)' : '#12182c',
                marginTop: 2, transition: 'color 0.25s',
              }}>{s.countLabel}</div>
            </div>
          </motion.button>
        )
      })}
    </motion.div>
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

// ─── Attack Chains section — lukebaffait.fr/works pattern ─────────────────────
// Left: scrollable list of chain names, items shift horizontally by distance
// from viewport center (closest = x:0, furthest = x:80px).
// Right: single sticky card that cross-fades when active chain changes.
function AttackChainsSection() {
  const navigate = useNavigate()
  const [activeIdx, setActiveIdx] = useState(0)
  const [sessions, setSessions] = useState({})
  const [launchingId, setLaunchingId] = useState(null)
  const itemRefs = useRef([])
  const sectionRef = useRef(null)
  const cardRef = useRef(null)

  // Scroll-driven horizontal offset + active detection.
  // NOTE: this app scrolls inside an inner <main overflow-y:auto> container,
  // NOT the window — so we must find that container and listen on IT.
  useEffect(() => {
    // Find the nearest scrollable ancestor of this section.
    let scroller = sectionRef.current?.parentElement
    while (scroller && scroller !== document.body) {
      const oy = getComputedStyle(scroller).overflowY
      if ((oy === 'auto' || oy === 'scroll') && scroller.scrollHeight > scroller.clientHeight) break
      scroller = scroller.parentElement
    }
    const target = scroller && scroller !== document.body ? scroller : window
    const getH = () => (target === window ? window.innerHeight : target.clientHeight)
    const getTop = () => (target === window ? 0 : target.getBoundingClientRect().top)

    let raf = 0
    const onScroll = () => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(() => {
        const cy = getTop() + getH() / 2            // viewport-center of the scroll container
        let closestIdx = 0, closestDist = Infinity
        itemRefs.current.forEach((el, i) => {
          if (!el) return
          const rect = el.getBoundingClientRect()
          const itemCy = rect.top + rect.height / 2
          const dist = Math.abs(itemCy - cy)
          el.style.transform = `translateX(${Math.min(dist / (getH() / 2), 1) * 80}px)`
          if (dist < closestDist) { closestDist = dist; closestIdx = i }
        })
        setActiveIdx(closestIdx)
      })
    }
    target.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    onScroll()
    return () => {
      cancelAnimationFrame(raf)
      target.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
    }
  }, [])

  // Mouse-following 3D tilt on the sticky card (the lukebaffait "3D" feel).
  useEffect(() => {
    let curRX = 0, curRY = 0, tgtRX = 0, tgtRY = 0, raf = 0, hovering = false
    const section = sectionRef.current
    if (!section) return
    const onMove = (e) => {
      const card = cardRef.current
      if (!card) return
      const r = card.getBoundingClientRect()
      const px = (e.clientX - (r.left + r.width / 2)) / (r.width / 2)   // -1..1
      const py = (e.clientY - (r.top + r.height / 2)) / (r.height / 2)  // -1..1
      tgtRY = Math.max(-1, Math.min(1, px)) * 6      // ±6deg
      tgtRX = Math.max(-1, Math.min(1, py)) * -5     // ±5deg
      hovering = true
    }
    const onLeave = () => { tgtRX = 0; tgtRY = 0; hovering = false }
    const loop = () => {
      curRX += (tgtRX - curRX) * 0.12
      curRY += (tgtRY - curRY) * 0.12
      const card = cardRef.current
      if (card) card.style.transform = `perspective(1100px) rotateX(${curRX.toFixed(2)}deg) rotateY(${curRY.toFixed(2)}deg)`
      raf = requestAnimationFrame(loop)
    }
    section.addEventListener('mousemove', onMove)
    section.addEventListener('mouseleave', onLeave)
    loop()
    return () => {
      cancelAnimationFrame(raf)
      section.removeEventListener('mousemove', onMove)
      section.removeEventListener('mouseleave', onLeave)
    }
  }, [])

  // INITIATE OPERATION → launch the lab for the chain's first phase, exactly
  // like launching a module. The chain session is registered on the backend so
  // phase progress (measured against the shared target) is tracked; chain
  // context is carried in the workspace URL for later phase advancement.
  const start = async (id) => {
    if (launchingId) return
    setLaunchingId(id)
    const meta = CHAIN_META[id]
    try {
      const chain = await api.chains.start(id, `gauntlet-${id}-${Date.now()}`)
      const phase = chain.current_step_index ?? 0
      const moduleId = meta.stepModules[phase]
      const session = await api.sessions.create(moduleId)
      navigate(`/workspace/${session.session_id}?chain=${chain.id}&chainId=${id}&phase=${phase}`)
    } catch (err) {
      setLaunchingId(null)
      setSessions(s => ({
        ...s,
        [id]: { ...(s[id] || {}), error: 'Failed to launch operation. Is the backend running?' },
      }))
    }
  }

  const advance = async (id) => {
    const sess = sessions[id]
    if (!sess?.chainSessionId) return
    setSessions(s => ({ ...s, [id]: { ...s[id], checking: true, error: null } }))
    try {
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
    <div ref={sectionRef} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', position: 'relative', maxWidth: 1280, margin: '0 auto', padding: '0 32px' }}>

      {/* ── LEFT: scrollable list ── */}
      <div style={{ padding: '45vh 48px 75vh 0' }}>
        {CHAIN_ORDER.map((id, idx) => {
          const meta = CHAIN_META[id]
          const isAct = idx === activeIdx
          const sess = sessions[id]
          return (
            <div
              key={id}
              ref={el => { itemRefs.current[idx] = el }}
              style={{
                marginBottom: idx < CHAIN_ORDER.length - 1 ? '36vh' : 0,
                willChange: 'transform',
                transition: 'transform 0.55s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
              }}
            >
              <div style={{
                fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.32em',
                color: isAct ? meta.accentColor + 'cc' : '#1e2535',
                marginBottom: 12,
                transition: 'color 0.4s ease',
              }}>
                {String(idx + 1).padStart(2, '0')} / {meta.threat}
              </div>
              <div style={{
                fontFamily: "'Rajdhani', sans-serif", fontWeight: 700,
                fontSize: 'clamp(42px, 5.5vw, 80px)', lineHeight: 0.9, letterSpacing: '-0.01em',
                color: isAct ? '#f4f7ff' : '#1a2030',
                transition: 'color 0.4s ease',
              }}>
                {meta.tagline}
              </div>
              {isAct && (
                <motion.div
                  initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
                  style={{ marginTop: 18, display: 'flex', flexWrap: 'wrap', gap: 8 }}
                >
                  {meta.steps.map((step, i) => (
                    <span key={i} style={{
                      fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.18em',
                      padding: '5px 12px', borderRadius: 999,
                      border: `1px solid ${meta.accentColor}30`,
                      color: meta.accentColor + '99',
                      background: `${meta.accentColor}08`,
                    }}>{step}</span>
                  ))}
                  {sess && (
                    <span style={{
                      fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.18em',
                      padding: '5px 12px', borderRadius: 999,
                      border: `1px solid ${sess.complete ? '#2ee39a40' : meta.accentColor + '50'}`,
                      color: sess.complete ? '#2ee39a' : meta.accentColor,
                      background: sess.complete ? 'rgba(46,227,154,0.08)' : `${meta.accentColor}0f`,
                    }}>
                      {sess.complete ? '✓ COMPLETE' : `PHASE ${sess.phase + 1}/${meta.steps.length}`}
                    </span>
                  )}
                </motion.div>
              )}
            </div>
          )
        })}
      </div>

      {/* ── RIGHT: sticky card ── */}
      <div style={{ position: 'sticky', top: 0, height: '100vh', display: 'flex', alignItems: 'center', padding: '0 24px 0 40px' }}>
        <div style={{ width: '100%', maxWidth: 480 }}>
          <AnimatePresence mode="wait">
            {CHAIN_ORDER.map((id, idx) => {
              if (idx !== activeIdx) return null
              const meta = CHAIN_META[id]
              const sess = sessions[id]
              const isComplete = !!sess?.complete
              const currentPhase = sess?.phase ?? 0
              const checking = !!sess?.checking
              const chainError = sess?.error ?? null
              return (
                <motion.div
                  key={id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1, transition: { duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] } }}
                  exit={{ opacity: 0, transition: { duration: 0.15 } }}
                >
                  {/* Visual card — mouse-tilt 3D */}
                  <div ref={cardRef} style={{
                    position: 'relative', borderRadius: 28, overflow: 'hidden',
                    height: 260, marginBottom: 22,
                    border: `1px solid ${meta.accentColor}30`,
                    boxShadow: `0 0 80px ${meta.glowColor}, 0 24px 64px rgba(0,0,0,0.5)`,
                    willChange: 'transform', transformStyle: 'preserve-3d',
                  }}>
                    {/* Real photo */}
                    <img
                      src={meta.cardImage}
                      alt={meta.name}
                      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'center' }}
                    />
                    {/* Light vignette only at the corners so the photo stays visible
                        but the "01/03" and difficulty labels remain readable. */}
                    <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse 120% 100% at 50% 45%, transparent 40%, rgba(4,6,12,0.72) 100%)' }} />
                    {/* Accent colour tint */}
                    <div style={{ position: 'absolute', inset: 0, mixBlendMode: 'overlay', background: `linear-gradient(145deg, ${meta.accentColor}55 0%, transparent 60%)` }} />
                    {/* Subtle grid */}
                    <div style={{ position: 'absolute', inset: 0, opacity: 0.035, backgroundImage: `repeating-linear-gradient(0deg,#fff 0px,#fff 1px,transparent 1px,transparent 44px),repeating-linear-gradient(90deg,#fff 0px,#fff 1px,transparent 1px,transparent 44px)` }} />
                    <div style={{ position: 'absolute', top: 18, right: 22, fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.28em', color: meta.accentColor + 'cc' }}>
                      {String(idx + 1).padStart(2, '0')} / 03
                    </div>
                    <div style={{ position: 'absolute', bottom: 18, left: 22, fontFamily: "'Rajdhani', sans-serif", fontStyle: 'italic', fontSize: 15, fontWeight: 600, color: meta.difficultyColor, letterSpacing: '0.04em', textShadow: `0 0 20px ${meta.difficultyColor}55` }}>
                      {meta.difficulty}
                    </div>
                  </div>

                  {/* Category */}
                  <div style={{ fontFamily: 'monospace', fontSize: 10, letterSpacing: '0.28em', color: '#3a4560', marginBottom: 10 }}>
                    {meta.threat}
                  </div>

                  {/* Description */}
                  <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, lineHeight: 1.72, color: '#8a98b8', margin: '0 0 18px' }}>
                    {meta.description}
                  </p>

                  {/* Active phase tracker */}
                  {sess && !isComplete && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', overflowX: 'auto', marginBottom: 18 }}>
                      {meta.steps.map((step, i) => (
                        <PhaseNode key={step + i} icon={meta.stepIcons[i]} label={step} index={i} total={meta.steps.length}
                          accentColor={meta.accentColor}
                          active={!isComplete && i === currentPhase}
                          completed={i < currentPhase || isComplete} />
                      ))}
                    </div>
                  )}

                  {/* Error */}
                  {chainError && (
                    <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
                      style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, padding: '9px 14px', borderRadius: 8, border: '1px solid rgba(248,113,113,0.35)', background: 'rgba(248,113,113,0.08)', fontFamily: 'monospace', fontSize: 11, color: '#f87171', letterSpacing: '0.04em' }}>
                      <X size={13} strokeWidth={2.5} /> {chainError}
                    </motion.div>
                  )}

                  {/* Actions */}
                  {!sess ? (
                    <motion.button onClick={launchingId ? undefined : () => start(id)}
                      whileHover={launchingId ? {} : { scale: 1.03, boxShadow: `0 0 40px ${meta.glowColor}` }}
                      whileTap={launchingId ? {} : { scale: 0.97 }}
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: 8,
                        fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.22em',
                        padding: '13px 30px', borderRadius: 11, border: `1px solid ${meta.accentColor}80`,
                        background: `linear-gradient(135deg, ${meta.accentColor} 0%, ${meta.accentColor}cc 100%)`,
                        color: meta.accentColor === '#f5c400' ? '#07090f' : '#fff',
                        cursor: launchingId ? 'wait' : 'pointer',
                        opacity: launchingId === id ? 0.7 : 1,
                        boxShadow: `0 0 24px ${meta.glowColor}`,
                      }}>
                      {launchingId === id
                        ? 'LAUNCHING LAB…'
                        : <>INITIATE OPERATION <ArrowRight size={14} strokeWidth={2.5} /></>}
                    </motion.button>
                  ) : isComplete ? (
                    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                      <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'monospace', fontSize: 11, color: '#2ee39a', letterSpacing: '0.18em', padding: '12px 22px', border: '1px solid rgba(46,227,154,0.4)', borderRadius: 11, background: 'rgba(46,227,154,0.08)' }}>
                        <Check size={14} strokeWidth={2.5} /> OPERATION COMPLETE
                      </motion.div>
                      <motion.button onClick={() => reset(id)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.15em', padding: '12px 18px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)', color: '#8b9bba', cursor: 'pointer' }}>
                        <RotateCcw size={12} strokeWidth={2.25} /> RESET
                      </motion.button>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                      <motion.button onClick={() => reset(id)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                        style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.15em', padding: '12px 18px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.03)', color: '#6b7fa3', cursor: 'pointer' }}>
                        ABORT
                      </motion.button>
                      <motion.button onClick={checking ? undefined : () => advance(id)}
                        whileHover={checking ? {} : { scale: 1.03, boxShadow: `0 0 30px ${meta.glowColor}` }}
                        whileTap={checking ? {} : { scale: 0.97 }}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 8,
                          fontFamily: 'monospace', fontSize: 10, fontWeight: 700, letterSpacing: '0.18em',
                          padding: '12px 24px', borderRadius: 11, border: `1px solid ${meta.accentColor}70`,
                          background: checking ? 'rgba(255,255,255,0.05)' : `linear-gradient(135deg, ${meta.accentColor}cc 0%, ${meta.accentColor}80 100%)`,
                          color: checking ? '#6b7fa3' : (meta.accentColor === '#f5c400' ? '#07090f' : '#fff'),
                          cursor: checking ? 'not-allowed' : 'pointer',
                          boxShadow: checking ? 'none' : `0 0 20px ${meta.glowColor}`,
                        }}>
                        {checking
                          ? 'CHECKING…'
                          : currentPhase === meta.steps.length - 1
                            ? <>COMPLETE <Check size={13} strokeWidth={2.5} /></>
                            : <>NEXT PHASE <ArrowRight size={13} strokeWidth={2.5} /></>}
                      </motion.button>
                    </div>
                  )}
                </motion.div>
              )
            })}
          </AnimatePresence>
        </div>
      </div>
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
  return (
    <h1 aria-label="GAUNTLET" style={{
      display: 'flex', justifyContent: 'center', flexWrap: 'nowrap',
      fontFamily: "'Rajdhani', sans-serif", fontSize: 'clamp(64px, 10vw, 112px)',
      fontWeight: 700, letterSpacing: '0.12em', lineHeight: 1, margin: '0 0 22px',
      filter: 'drop-shadow(0 0 60px rgba(255,255,255,0.12)) drop-shadow(0 0 40px rgba(255,21,53,0.18))',
    }}>
      {letters.map((ch, i) => (
        <span key={i} aria-hidden="true" style={{
          display: 'inline-block',
          background: 'linear-gradient(180deg, #ffffff 0%, #d4dcf0 42%, #8190b0 100%)',
          WebkitBackgroundClip: 'text', backgroundClip: 'text',
          WebkitTextFillColor: 'transparent', color: 'transparent',
        }}>{ch}</span>
      ))}
    </h1>
  )
}

export default function Gauntlet() {
  const [section, setSection] = useState('chains')
  // Driven by the entrance preloader (GauntletIntro) finishing its panel wipe.
  const [entranceDone, setEntranceDone] = useState(false)

  const sectionRevealDelay = entranceDone ? 0 : GAUNTLET_REVEAL_DELAY + 0.06

  return (
    <div style={{ position: 'relative', minHeight: '100vh', width: '100%', color: '#fff' }}>
      <AuroraFlow />
      {!entranceDone && <GauntletIntro onDone={() => setEntranceDone(true)} />}

      <motion.div
        initial={{ opacity: 0, y: '-1.5rem' }}
        animate={{ opacity: 1, y: '0rem' }}
        transition={{ delay: GAUNTLET_REVEAL_DELAY, duration: 0.9, ease: GAUNTLET_EASE }}
        style={{ position: 'relative', zIndex: 1, padding: '0 24px 80px' }}
      >

        {/* Hero header */}
        <motion.div initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
          style={{ textAlign: 'center', paddingTop: 72, paddingBottom: 14 }}>

          {/* Title — letters roll up from a clipped baseline, staggered from center */}
          <GauntletTitle />

          {/* Subtitle */}
          <motion.p initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: GAUNTLET_REVEAL_DELAY + 0.38 }}
            style={{ fontFamily: "'Inter', sans-serif", fontSize: 15, color: '#5a6a88', letterSpacing: '0.04em', margin: '0 0 56px' }}>
            Advanced scenarios. No hints. Adapt or fail.
          </motion.p>

          {/* Section nav */}
          <HeroSectionNav active={section} onSelect={setSection} />
        </motion.div>

        {/* Section content */}
        <AnimatePresence mode="wait">
          {section === 'chains' ? (
            <motion.div key="chains" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ delay: sectionRevealDelay, duration: 0.4 }}>
              <AttackChainsSection />
            </motion.div>
          ) : (
            <motion.div key="mutations" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ delay: sectionRevealDelay, duration: 0.4 }}>
              <MutationModeSection />
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  )
}
