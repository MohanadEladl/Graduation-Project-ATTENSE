import { useId, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import RangeSidebar from '../components/RangeSidebar.jsx'
import { useRangeStats, WINDOWS } from '../hooks/useRangeStats.js'
import { getAccount, saveAccount, changePassword, hasPassword, getPasswordMeta } from '../lib/account.js'
import {
  Crosshair,
  CheckCircle2,
  Layers,
  Database,
  Activity,
  Cpu,
  Info,
  Zap,
  Sun,
  Clock,
  ChevronDown,
  MoreHorizontal,
  Crosshair as TargetIcon,
  BarChart3,
  Search,
  ArrowRight,
  User,
  Lock,
  Mail,
  Shield,
  Check,
  AlertCircle,
  Camera,
  Eye,
  EyeOff,
  Trash2,
  ShieldCheck,
  KeyRound,
  BadgeCheck,
  AlertTriangle,
  RotateCcw,
  LogOut,
} from 'lucide-react'

/* ── Settings · sectioned ──
   Efferd "dashboard-10" block plus real operator account settings, switched in
   place by RangeSidebar. Renders inside RangeLayout beside the (collision-safe)
   sidebar. Sections: Overview (live range dashboard), Account, Security. */

const SECTION_META = {
  overview: { title: 'Overview', icon: BarChart3 },
  account: { title: 'Account', icon: User },
  security: { title: 'Security', icon: Lock },
}

const TILES = [
  { key: 'active', label: 'Active Missions', icon: Crosshair },
  { key: 'completedToday', label: 'Completed Today', icon: CheckCircle2 },
  { key: 'total', label: 'Total Sessions', icon: Layers },
  { key: 'modules', label: 'Lab Modules', icon: Database },
  { key: 'successRate', label: 'Success Rate', icon: Activity },
  { key: 'toolsOnline', label: 'Tools Online', icon: Cpu },
]

const STATE_COLOR = {
  running: '#ff1535',
  completed: '#00c8ff',
  error: '#f87171',
  idle: '#4a5363',
}

function relTime(ts) {
  const t = Number(ts) || 0
  if (!t) return '—'
  const s = Date.now() / 1000 - t
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export default function Settings() {
  const navigate = useNavigate()
  const [section, setSection] = useState('overview')
  const [winKey, setWinKey] = useState('12h')
  const [query, setQuery] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const stats = useRangeStats(winKey)

  const meta = SECTION_META[section]
  const TitleIcon = meta.icon

  return (
    <div className="flex h-full text-[#e6e8ee] animate-fade-up">
      <RangeSidebar
        section={section}
        onSelect={setSection}
        online={stats.online}
        moduleCount={stats.moduleCount}
        collapsed={!sidebarOpen}
        onToggle={() => setSidebarOpen(o => !o)}
      />
      <div className="flex min-w-0 flex-1 flex-col overflow-y-auto">
        {/* Top bar */}
        <div className="flex items-center justify-between border-b border-[#1a2030] px-5 py-3">
          <div className="flex items-center gap-2 text-sm text-[#e6e8ee]">
            <TitleIcon className="h-4 w-4 text-[#ff1535]" />
            {meta.title}
          </div>
          <div className="flex items-center gap-3">
            {section === 'overview' && (
              <div className="flex items-center gap-2 rounded-lg border border-[#1a2030] bg-[#10141d] px-3 py-1.5 text-xs text-[#7a8699]">
                <Search className="h-3.5 w-3.5 text-[#4a5363]" />
                <input
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder="Find…"
                  className="w-28 bg-transparent text-xs text-[#e6e8ee] placeholder:text-[#4a5363] transition-all focus:w-40 focus:outline-none"
                />
              </div>
            )}
            <div className="h-7 w-7 rounded-full bg-gradient-to-br from-[#ff1535] to-[#8b2fff]" />
          </div>
        </div>

        {section === 'overview' && (
          <OverviewPanel stats={stats} winKey={winKey} setWinKey={setWinKey} query={query} navigate={navigate} />
        )}
        {section === 'account' && <AccountPanel />}
        {section === 'security' && <SecurityPanel />}
      </div>
    </div>
  )
}

/* ───────────────────────── Overview (live dashboard) ───────────────────────── */

function OverviewPanel({ stats, winKey, setWinKey, query, navigate }) {
  const cycleWindow = () =>
    setWinKey(k => {
      const i = WINDOWS.findIndex(w => w.key === k)
      return WINDOWS[(i + 1) % WINDOWS.length].key
    })

  const dist = stats.statusDist
  const distTotal = dist.running + dist.completed + dist.idle || 1
  const distSegments = [
    { label: 'Running', n: dist.running, color: '#ff1535' },
    { label: 'Completed', n: dist.completed, color: '#00c8ff' },
    { label: 'Idle', n: dist.idle, color: '#4a5363' },
  ]

  const recent = useMemo(() => {
    const q = query.trim().toLowerCase()
    const rows = q
      ? stats.recent.filter(s =>
          [s.module_name, s.module_id, s.scenario_id, s.session_id, s.state]
            .filter(Boolean)
            .some(v => String(v).toLowerCase().includes(q)),
        )
      : stats.recent
    return rows.slice(0, 12)
  }, [stats.recent, query])

  return (
    <div className="px-6 py-5">
      {/* Welcome */}
      <div className="mb-5 flex items-start justify-between">
        <div>
          <Sun className="h-5 w-5 text-[#ffa724]" />
          <h1 className="mt-1.5 font-display text-xl font-semibold text-white">Range Overview</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={cycleWindow}
            className="flex items-center gap-2 rounded-lg border border-[#1a2030] bg-[#10141d] px-3 py-1.5 text-xs text-[#e6e8ee] transition-colors hover:bg-[#161b27]"
          >
            <Clock className="h-3.5 w-3.5 text-[#7a8699]" />
            {stats.window.label}
            <ChevronDown className="h-3.5 w-3.5 text-[#7a8699]" />
          </button>
          <button className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1a2030] bg-[#10141d] text-[#7a8699] transition-colors hover:bg-[#161b27]">
            <MoreHorizontal className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* KPI grid */}
      <div className="mb-4 overflow-hidden rounded-[10px] border border-[#1a2030] bg-[#0c0f16]">
        <div className="grid grid-cols-2 border-b border-[#1a2030] md:grid-cols-4">
          {TILES.slice(0, 4).map((t, i) => (
            <KpiCell key={t.key} tile={t} data={stats.counts[t.key]} loading={stats.loading} last={i === 3} index={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2">
          {TILES.slice(4).map((t, i) => (
            <KpiCell key={t.key} tile={t} data={stats.counts[t.key]} loading={stats.loading} last={i === 1} index={i + 4} />
          ))}
        </div>
      </div>

      {/* Insight + status distribution */}
      <div className="grid grid-cols-1 overflow-hidden rounded-[10px] border border-[#1a2030] bg-[#0c0f16] md:grid-cols-2">
        <div className="border-b border-[#1a2030] p-5 md:border-b-0 md:border-r">
          <div className="mb-3.5 flex items-center justify-between">
            <span className="flex items-center gap-2 text-xs text-[#e6e8ee]">
              <Activity className="h-4 w-4 text-[#ff1535]" />
              Range Insight
            </span>
            <button
              onClick={() => navigate('/reports')}
              className="flex items-center gap-1.5 text-xs text-[#7a8699] transition-colors hover:text-[#ff1535]"
            >
              <Zap className="h-3.5 w-3.5" />
              View reports
            </button>
          </div>
          <p className="text-lg font-light leading-snug text-[#7a8699]">
            {stats.insight.pre}
            <span className="font-medium text-white">{stats.insight.strong}</span>
            {stats.insight.post}
          </p>
        </div>
        <div className="p-5">
          <div className="mb-3.5 flex items-center justify-between">
            <span className="text-xs text-[#e6e8ee]">Mission status</span>
            <button
              onClick={() => navigate('/missions')}
              className="flex items-center gap-1.5 text-xs text-[#7a8699] transition-colors hover:text-[#ff1535]"
            >
              <TargetIcon className="h-3.5 w-3.5" />
              Open sessions
            </button>
          </div>
          <div className="mb-4 text-xl font-medium text-white">
            {dist.running + dist.completed + dist.idle}{' '}
            <span className="text-xs font-normal text-[#7a8699]">sessions</span>
          </div>
          <div className="mb-1.5 flex text-[11px] text-[#7a8699]">
            {distSegments.map(s => (
              <span key={s.label} style={{ flex: Math.max(s.n, 0.0001) }}>
                {Math.round((s.n / distTotal) * 100)}%
              </span>
            ))}
          </div>
          <div className="mb-3.5 flex h-2 gap-1">
            {distSegments.map(s => (
              <div key={s.label} className="rounded" style={{ flex: Math.max(s.n, 0.0001), background: s.color }} />
            ))}
          </div>
          <div className="flex gap-5 text-[11px] text-[#7a8699]">
            {distSegments.map(s => (
              <span key={s.label} className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
                {s.label} · {s.n}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Recent sessions */}
      <div className="mt-4 overflow-hidden rounded-[10px] border border-[#1a2030] bg-[#0c0f16]">
        <div className="flex items-center justify-between border-b border-[#1a2030] px-5 py-3.5">
          <div>
            <h3 className="text-sm font-medium text-white">Recent sessions</h3>
            <p className="mt-0.5 text-xs text-[#4a5363]">
              {query ? `Filtered by “${query}”` : 'Live mission activity across the range'}
            </p>
          </div>
          <button
            onClick={() => navigate('/missions')}
            className="rounded-lg border border-[#1a2030] bg-[#10141d] px-3 py-1.5 text-xs text-[#e6e8ee] transition-colors hover:bg-[#161b27]"
          >
            View all
          </button>
        </div>
        <div>
          {stats.loading && (
            <div className="px-5 py-10 text-center font-mono text-[11px] tracking-widest text-[#4a5363]">LOADING…</div>
          )}
          {!stats.loading && recent.length === 0 && (
            <div className="px-5 py-10 text-center text-xs text-[#4a5363]">
              {query ? 'No sessions match your search.' : 'No sessions yet — launch a mission to get started.'}
            </div>
          )}
          {!stats.loading &&
            recent.map(d => {
              const color = STATE_COLOR[d.state] || STATE_COLOR.idle
              return (
                <div
                  key={d.session_id}
                  onClick={() => navigate(`/workspace/${d.session_id}`)}
                  className="grid cursor-pointer grid-cols-[1fr_110px_120px_72px_88px_28px] items-center gap-2.5 border-b border-[#141925] px-5 py-3 last:border-b-0 hover:bg-white/[0.02]"
                >
                  <div className="min-w-0">
                    <div className="truncate text-xs font-medium text-white">
                      {d.module_name || d.module_id || 'Unknown module'}
                    </div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-[#4a5363]">{d.session_id?.slice(0, 12)}…</div>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs capitalize text-[#e6e8ee]">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                    {d.state || 'idle'}
                  </div>
                  <div className="flex items-center gap-2 pr-2">
                    <div className="h-[3px] flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                      <div className="h-full rounded-full" style={{ width: `${d.pct}%`, background: color }} />
                    </div>
                    <span className="font-mono text-[10px] text-[#7a8699]">{d.pct}%</span>
                  </div>
                  <div className="font-mono text-[11px] text-[#7a8699]">{d.scenario_id || '—'}</div>
                  <div className="text-[11px] text-[#7a8699]">{relTime(d.created_at)}</div>
                  <button className="text-[#4a5363] transition-colors hover:text-[#ff1535]">
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </div>
              )
            })}
        </div>
      </div>
    </div>
  )
}

function Sparkline({ data, stroke = '#ff1535' }) {
  const gid = useId()
  const w = 100
  const h = 40
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  const step = data.length > 1 ? w / (data.length - 1) : w
  const pts = data.map((v, i) => [i * step, h - 3 - ((v - min) / range) * (h - 6)])
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')
  const area = `${line} L${w},${h} L0,${h} Z`
  return (
    <div className="h-10 w-full">
      <svg viewBox="0 0 100 40" preserveAspectRatio="none" className="h-full w-full">
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={stroke} stopOpacity={0.35} />
            <stop offset="100%" stopColor={stroke} stopOpacity={0} />
          </linearGradient>
        </defs>
        <path d={area} fill={`url(#${gid})`} style={{ animation: 'fade-up 0.6s ease 0.2s both' }} />
        <path
          d={line}
          fill="none"
          stroke={stroke}
          strokeWidth={1.2}
          vectorEffect="non-scaling-stroke"
          pathLength="1"
          style={{
            strokeDasharray: 1,
            strokeDashoffset: 1,
            animation: 'draw-sparkline 1.1s ease 0.15s forwards',
          }}
        />
      </svg>
    </div>
  )
}

function KpiCell({ tile, data, loading, last, index = 0 }) {
  const Icon = tile.icon
  const value = loading ? '—' : data?.value ?? '—'
  const spark = data?.spark || new Array(12).fill(1)
  const hasChange = !loading && data?.change != null
  return (
    <div
      className={`flex min-h-[118px] flex-col px-3.5 pt-3 ${last ? '' : 'border-r border-[#1a2030]'}`}
      style={{ animation: `fade-up 0.45s ease ${index * 0.07}s both` }}
    >
      <div className="mb-2.5 flex items-center justify-between">
        <span className="flex items-center gap-1.5 text-[11px] text-[#7a8699]">
          <Icon className="h-3.5 w-3.5 text-[#7a8699]" />
          {tile.label}
        </span>
        <Info className="h-3.5 w-3.5 text-[#4a5363]" />
      </div>
      <div className="flex items-baseline justify-between">
        <span className="text-[22px] font-medium leading-none text-white">{value}</span>
        {hasChange && (
          <span className="flex items-center gap-0.5 text-[11px] text-[#7a8699]">
            {data.direction === 'up' ? '↑' : '↓'}
            {data.change}%
          </span>
        )}
      </div>
      <div className="mt-auto">
        <Sparkline data={spark} />
      </div>
    </div>
  )
}

/* ───────────────────────────── shared UI bits ──────────────────────────────── */

function Button({ children, onClick, disabled, variant = 'secondary', type = 'button', className = '' }) {
  const styles = {
    primary:
      'border border-[rgba(255,21,53,0.4)] bg-[rgba(255,21,53,0.16)] text-[#ff7088] hover:bg-[rgba(255,21,53,0.26)]',
    secondary:
      'border border-[#222a3a] bg-[#10141d] text-[#cdd3df] hover:bg-[#161b27] hover:text-white',
    ghost: 'border border-transparent text-[#7a8699] hover:bg-white/[0.04] hover:text-white',
    danger:
      'border border-[rgba(248,113,113,0.35)] bg-transparent text-[#f87171] hover:bg-[rgba(248,113,113,0.1)]',
  }
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3.5 py-2 text-xs font-semibold tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]} ${className}`}
    >
      {children}
    </button>
  )
}

// A settings card: optional header (title + description) then body rows.
function Card({ title, description, children, danger }) {
  return (
    <section className={`overflow-hidden rounded-xl border bg-[#0b0e15] ${danger ? 'border-[rgba(248,113,113,0.25)]' : 'border-[#1a2030]'}`}>
      {(title || description) && (
        <header className="border-b border-[#161c28] px-5 py-4">
          {title && <h2 className="text-sm font-semibold text-white">{title}</h2>}
          {description && <p className="mt-0.5 text-xs leading-relaxed text-[#7a8699]">{description}</p>}
        </header>
      )}
      {children}
    </section>
  )
}

function TextField({ label, description, value, onChange, type = 'text', placeholder, autoComplete, badge }) {
  return (
    <label className="block">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-[#8a93a6]">{label}</span>
        {badge}
      </div>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        className="w-full rounded-lg border border-[#222a3a] bg-[#10141d] px-3 py-2.5 text-sm text-[#e6e8ee] outline-none transition-colors placeholder:text-[#4a5363] focus:border-[rgba(255,21,53,0.5)] focus:ring-1 focus:ring-[rgba(255,21,53,0.25)]"
      />
      {description && <p className="mt-1.5 text-[11px] leading-relaxed text-[#5a6577]">{description}</p>}
    </label>
  )
}

function PasswordField({ label, value, onChange, autoComplete, placeholder }) {
  const [show, setShow] = useState(false)
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.12em] text-[#8a93a6]">{label}</span>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          className="w-full rounded-lg border border-[#222a3a] bg-[#10141d] py-2.5 pl-3 pr-10 text-sm text-[#e6e8ee] outline-none transition-colors placeholder:text-[#4a5363] focus:border-[rgba(255,21,53,0.5)] focus:ring-1 focus:ring-[rgba(255,21,53,0.25)]"
        />
        <button
          type="button"
          onClick={() => setShow(s => !s)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#4a5363] transition-colors hover:text-[#7a8699]"
          aria-label={show ? 'Hide password' : 'Show password'}
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </label>
  )
}

function Inline({ ok, children }) {
  return (
    <div
      className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-xs"
      style={{
        background: ok ? 'rgba(46,227,154,0.08)' : 'rgba(255,21,53,0.08)',
        border: `1px solid ${ok ? 'rgba(46,227,154,0.3)' : 'rgba(255,21,53,0.3)'}`,
        color: ok ? '#2ee39a' : '#ff7088',
      }}
    >
      {ok ? <Check className="h-3.5 w-3.5 shrink-0" /> : <AlertCircle className="h-3.5 w-3.5 shrink-0" />}
      {children}
    </div>
  )
}

function PanelHeader({ title, description }) {
  return (
    <div className="mb-6">
      <h1 className="font-display text-2xl font-semibold tracking-tight text-white">{title}</h1>
      <p className="mt-1 text-sm text-[#7a8699]">{description}</p>
    </div>
  )
}

function initialsOf(name) {
  return (name || 'O').trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase()
}

/* ───────────────────────────────── Account ─────────────────────────────────── */

function AccountPanel() {
  const navigate = useNavigate()
  const [baseline, setBaseline] = useState(getAccount)
  const [acct, setAcct] = useState(baseline)
  const [saved, setSaved] = useState(false)
  const [warn, setWarn] = useState(null)
  const fileRef = useRef(null)
  const set = (k, v) => setAcct(p => ({ ...p, [k]: v }))

  const dirty = JSON.stringify(acct) !== JSON.stringify(baseline)

  const save = () => {
    try {
      const next = saveAccount(acct)
      setBaseline(next)
      setSaved(true)
      setWarn(null)
      setTimeout(() => setSaved(false), 1800)
    } catch {
      setWarn('Could not save — your avatar image may be too large for local storage.')
    }
  }
  const discard = () => { setAcct(baseline); setWarn(null) }

  const onPickFile = e => {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    if (f.size > 1.5 * 1024 * 1024) {
      setWarn('Image is over 1.5 MB. Please choose a smaller picture.')
      return
    }
    const reader = new FileReader()
    reader.onload = () => { set('avatar', String(reader.result)); setWarn(null) }
    reader.readAsDataURL(f)
  }

  return (
    <div className="relative min-h-full">
      <div className="mx-auto max-w-2xl px-6 py-7 pb-28">
        <PanelHeader title="My Account" description="Manage your operator identity, avatar and contact details." />

        <div className="space-y-5">
          {/* Avatar + identity */}
          <Card title="Profile picture" description="PNG, JPG or GIF. Shown across the range. Stored on this device.">
            <div className="flex items-center gap-5 px-5 py-5">
              <div className="relative">
                {acct.avatar ? (
                  <img src={acct.avatar} alt="" className="h-20 w-20 rounded-full object-cover ring-2 ring-[#222a3a]" />
                ) : (
                  <div className="flex h-20 w-20 items-center justify-center rounded-full bg-gradient-to-br from-[#ff1535] to-[#8b2fff] text-2xl font-bold text-white ring-2 ring-[#222a3a]">
                    {initialsOf(acct.name)}
                  </div>
                )}
                <button
                  onClick={() => fileRef.current?.click()}
                  className="absolute -bottom-1 -right-1 flex h-7 w-7 items-center justify-center rounded-full border border-[#222a3a] bg-[#10141d] text-[#cdd3df] transition-colors hover:bg-[#1a2030] hover:text-white"
                  aria-label="Change picture"
                >
                  <Camera className="h-3.5 w-3.5" />
                </button>
                <input ref={fileRef} type="file" accept="image/*" onChange={onPickFile} className="hidden" />
              </div>
              <div className="flex flex-col gap-2">
                <Button variant="secondary" onClick={() => fileRef.current?.click()}>
                  <Camera className="h-3.5 w-3.5" /> Upload new
                </Button>
                {acct.avatar && (
                  <Button variant="ghost" onClick={() => set('avatar', '')}>
                    <Trash2 className="h-3.5 w-3.5" /> Remove
                  </Button>
                )}
              </div>
            </div>
          </Card>

          {/* Public profile */}
          <Card title="Public profile" description="How you appear to teammates on the range.">
            <div className="space-y-5 px-5 py-5">
              <TextField
                label="Display name"
                value={acct.name}
                onChange={v => set('name', v)}
                placeholder="Operator"
                description="Your name as shown on missions, reports and the leaderboard."
              />
              <TextField
                label="Operator ID"
                value={acct.operatorId}
                onChange={v => set('operatorId', v)}
                placeholder="operator_01"
                description="A unique handle. Lowercase letters, numbers and underscores."
              />
              <div>
                <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.12em] text-[#8a93a6]">Role</span>
                <div className="flex items-center gap-2 rounded-lg border border-[#161c28] bg-[#0c0f16] px-3 py-2.5 text-sm text-[#8a93a6]">
                  <Shield className="h-3.5 w-3.5 text-[#ff5c74]" />
                  {acct.role}
                  <span className="ml-auto text-[11px] text-[#4a5363]">Assigned by the range</span>
                </div>
              </div>
            </div>
          </Card>

          {/* Contact */}
          <Card title="Contact" description="Used for mission reports and range notifications.">
            <div className="px-5 py-5">
              <TextField
                label="Email address"
                type="email"
                value={acct.email}
                onChange={v => set('email', v)}
                placeholder="you@attense.local"
                autoComplete="email"
                badge={
                  <span className="inline-flex items-center gap-1 rounded-full bg-[rgba(46,227,154,0.12)] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-[#2ee39a]">
                    <BadgeCheck className="h-3 w-3" /> Verified
                  </span>
                }
              />
            </div>
          </Card>

          {warn && <Inline ok={false}>{warn}</Inline>}

          {/* Danger zone */}
          <Card title="Danger zone" description="Session-level actions for this device." danger>
            <div className="flex flex-col gap-3 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="text-xs font-medium text-white">Sign out</div>
                <div className="mt-0.5 text-[11px] text-[#7a8699]">End your operator session and return to the login screen.</div>
              </div>
              <Button variant="danger" onClick={() => navigate('/login')}>
                <LogOut className="h-3.5 w-3.5" /> Sign out
              </Button>
            </div>
          </Card>
        </div>
      </div>

      {/* Sticky unsaved-changes bar */}
      {dirty && (
        <div className="sticky bottom-0 border-t border-[#1a2030] bg-[#0b0e15]/95 backdrop-blur">
          <div className="mx-auto flex max-w-2xl items-center justify-between px-6 py-3">
            <span className="flex items-center gap-2 text-xs text-[#cdd3df]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#ffa724]" />
              You have unsaved changes
            </span>
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={discard}>
                <RotateCcw className="h-3.5 w-3.5" /> Discard
              </Button>
              <Button variant="primary" onClick={save}>
                {saved ? <><Check className="h-3.5 w-3.5" /> Saved</> : 'Save changes'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ───────────────────────────────── Security ────────────────────────────────── */

const STRENGTH = [
  { label: 'Too short', color: '#f87171' },
  { label: 'Weak', color: '#f87171' },
  { label: 'Fair', color: '#ffa724' },
  { label: 'Good', color: '#00c8ff' },
  { label: 'Strong', color: '#2ee39a' },
]

function scorePassword(pw) {
  if (!pw || pw.length < 8) return 0
  let s = 1
  if (pw.length >= 12) s++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++
  if (/\d/.test(pw)) s++
  if (/[^A-Za-z0-9]/.test(pw)) s++
  return Math.min(s, 4)
}

function SecurityPanel() {
  const meta = getPasswordMeta()
  const [open, setOpen] = useState(!meta.set)
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [conf, setConf] = useState('')
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const [existing, setExisting] = useState(meta.set)
  const [changedAt, setChangedAt] = useState(meta.changedAt)

  const score = scorePassword(next)
  const reset = () => { setCur(''); setNext(''); setConf(''); setMsg(null) }

  const submit = async () => {
    setMsg(null)
    if (next !== conf) {
      setMsg({ ok: false, text: 'New password and confirmation do not match.' })
      return
    }
    setBusy(true)
    try {
      await changePassword(cur, next)
      const m = getPasswordMeta()
      setExisting(true)
      setChangedAt(m.changedAt)
      setMsg({ ok: true, text: 'Password updated successfully.' })
      setCur(''); setNext(''); setConf('')
      setOpen(false)
    } catch (e) {
      setMsg({ ok: false, text: e.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl px-6 py-7">
      <PanelHeader title="Security" description="Protect your operator account on this device." />

      <div className="space-y-5">
        {/* Password */}
        <Card>
          <div className="flex items-center gap-4 px-5 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[#222a3a] bg-[#10141d] text-[#ff5c74]">
              <KeyRound className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-white">Password</div>
              <div className="mt-0.5 text-xs text-[#7a8699]">
                {existing
                  ? `Last changed ${changedAt ? relTime(changedAt) : 'recently'}.`
                  : 'No password set on this device yet.'}
              </div>
            </div>
            {!open && (
              <Button variant="secondary" onClick={() => { reset(); setOpen(true) }}>
                {existing ? 'Change' : 'Set password'}
              </Button>
            )}
          </div>

          {open && (
            <div className="space-y-4 border-t border-[#161c28] px-5 py-5">
              {existing && (
                <PasswordField label="Current password" value={cur} onChange={setCur} placeholder="••••••••" autoComplete="current-password" />
              )}
              <div>
                <PasswordField label="New password" value={next} onChange={setNext} placeholder="At least 8 characters" autoComplete="new-password" />
                {next && (
                  <div className="mt-2">
                    <div className="flex gap-1">
                      {[0, 1, 2, 3].map(i => (
                        <span
                          key={i}
                          className="h-1 flex-1 rounded-full transition-colors"
                          style={{ background: i < score ? STRENGTH[score].color : '#1a2030' }}
                        />
                      ))}
                    </div>
                    <span className="mt-1 block text-[11px]" style={{ color: STRENGTH[score].color }}>
                      {STRENGTH[score].label}
                    </span>
                  </div>
                )}
              </div>
              <PasswordField label="Confirm new password" value={conf} onChange={setConf} placeholder="Re-enter new password" autoComplete="new-password" />

              {msg && !msg.ok && <Inline ok={false}>{msg.text}</Inline>}

              <div className="flex items-center gap-2 pt-1">
                <Button variant="primary" onClick={submit} disabled={busy || !next || !conf}>
                  {busy ? 'Saving…' : existing ? 'Update password' : 'Set password'}
                </Button>
                {existing && (
                  <Button variant="ghost" onClick={() => { reset(); setOpen(false) }}>Cancel</Button>
                )}
              </div>
            </div>
          )}
        </Card>

        {msg && msg.ok && <Inline ok>{msg.text}</Inline>}

        {/* Two-factor (honestly unavailable on a serverless range) */}
        <Card>
          <div className="flex items-center gap-4 px-5 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[#222a3a] bg-[#10141d] text-[#7a8699]">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                Two-factor authentication
                <span className="rounded-full bg-[#1a2030] px-2 py-0.5 text-[10px] font-medium text-[#7a8699]">Unavailable</span>
              </div>
              <div className="mt-0.5 text-xs text-[#7a8699]">
                Requires an authentication server — not available on the local lab range.
              </div>
            </div>
            <Button variant="secondary" disabled>Set up</Button>
          </div>
        </Card>
      </div>

      <p className="mt-5 flex items-start gap-2 text-[11px] leading-relaxed text-[#5a6577]">
        <Lock className="mt-0.5 h-3 w-3 shrink-0" />
        The range has no authentication server, so this password is stored only as a SHA-256 hash in your
        browser. It guards this device's settings — not server access.
      </p>
    </div>
  )
}
