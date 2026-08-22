import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  Database,
  RadioTower,
  Settings,
  Shield,
  Sliders,
  Trash2,
  TrendingUp,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import Header from '../components/layout/Header'
import { useWebSocket } from '../hooks/useWebSocket'
import {
  getAnalytics,
  getStatus,
  getRecentEvents,
  getAdminConfig,
  toggleDemoTraffic,
  clearLLMCache,
  resetSessions,
} from '../utils/api'

function Count({ to, suffix = '' }) {
  const [val, setVal] = useState(0)

  useEffect(() => {
    if (!to) return
    const n = parseInt(to) || 0
    const step = Math.max(1, Math.ceil(n / 30))
    let cur = 0
    const id = setInterval(() => {
      cur = Math.min(cur + step, n)
      setVal(cur)
      if (cur >= n) clearInterval(id)
    }, 25)
    return () => clearInterval(id)
  }, [to])

  return <>{val.toLocaleString()}{suffix}</>
}

function MetricCard({ label, value, color, delay = 0, selected = false, onClick }) {
  return (
    <motion.button
      type="button"
      onClick={onClick}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.42 }}
      className={`stat-item${selected ? ' is-active' : ''}`}
      style={{ '--stat-accent': color, paddingTop: 6, paddingBottom: 6 }}
    >
      <div className="stat-num" style={{ fontSize: 38, lineHeight: 1, color: selected ? color : '#ffffff', fontWeight: 800, fontFamily: '"Outfit", sans-serif', transition: 'color 0.25s ease' }}>
        {typeof value === 'number' ? <Count to={value} /> : value}
      </div>
      <div style={{ marginTop: 9, fontSize: 10.5, color: '#8e8e93', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
        {label}
      </div>
    </motion.button>
  )
}

function InsightRow({ title, body, color, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.35 }}
      className="row-item"
      style={{ alignItems: 'flex-start' }}
    >
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, boxShadow: `0 0 12px ${color}`, marginTop: 5, flexShrink: 0 }} />
      <div>
        <div style={{ color: '#ffffff', fontSize: 12.5, fontWeight: 700, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
          {title}
        </div>
        <p style={{ color: '#98989D', fontSize: 11.5, lineHeight: 1.45, marginTop: 3, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
          {body}
        </p>
      </div>
    </motion.div>
  )
}

function isSynthetic(ev) {
  return ev.source === 'demo' || (typeof ev.session_id === 'string' && ev.session_id.startsWith('demo_'))
}

function FeedRow({ ev, i }) {
  const colors = { block: '#ff453a', warn: '#ff9f0a', allow: '#30d158' }
  const color = colors[ev.action] || '#86868b'
  const synthetic = isSynthetic(ev)
  const ts = ev.timestamp
    ? new Date(ev.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '-'

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: i * 0.02, duration: 0.25 }}
      className="threat-row"
      style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      title={synthetic ? 'Synthetic demo event, not real inspected traffic' : undefined}
    >
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0, boxShadow: `0 0 10px ${color}` }} />
      <span className={`badge badge-${ev.action}`} style={{ width: 62, justifyContent: 'center' }}>
        {ev.action}
      </span>
      <span style={{ fontSize: 12, color: '#ffffff', fontFamily: '"Plus Jakarta Sans", sans-serif', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
        {synthetic && (
          <span style={{
            fontSize: 8.5, fontWeight: 800, letterSpacing: '0.05em', color: '#c9a3ff',
            background: 'rgba(191,143,255,0.14)', border: '1px solid rgba(191,143,255,0.3)',
            borderRadius: 4, padding: '1.5px 5px', flexShrink: 0,
          }}>
            SYNTHETIC
          </span>
        )}
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {ev.input_preview || ev.threat_category || '-'}
        </span>
      </span>
      <span style={{ fontSize: 12, fontFamily: 'monospace', color, flexShrink: 0, fontWeight: 700 }}>
        {ev.trust_score}
      </span>
      <span style={{ fontSize: 11, color: '#D1D1D6', fontFamily: '"Plus Jakarta Sans", sans-serif', width: 54, textAlign: 'right' }}>
        {ts}
      </span>
    </motion.div>
  )
}

export default function Dashboard() {
  const [analytics, setAnalytics] = useState(null)
  const [status, setStatus] = useState(null)
  const [feed, setFeed] = useState([])
  const [wsConn, setWsConn] = useState(false)
  const [adminConfig, setAdminConfig] = useState({ demo_traffic_enabled: true, llm_cache_size: 0, total_active_sessions: 0 })
  const [toast, setToast] = useState(null)
  const [selectedMetric, setSelectedMetric] = useState('total')

  const { connected } = useWebSocket((msg) => {
    setWsConn(true)
    if (msg.type === 'threat_event') setFeed(p => [msg, ...p].slice(0, 60))
    if (msg.type === 'init' && msg.recent_events) setFeed(msg.recent_events)
  })

  useEffect(() => setWsConn(connected), [connected])

  const refreshAdmin = () => {
    getAdminConfig().then(setAdminConfig).catch(() => {})
  }

  const showToast = (message, type) => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const handleToggleTraffic = async () => {
    try {
      const res = await toggleDemoTraffic()
      setAdminConfig(prev => ({ ...prev, demo_traffic_enabled: res.enabled }))
      showToast(res.message, 'success')
    } catch {
      showToast('Failed to toggle demo traffic.', 'error')
    }
  }

  const handleClearCache = async () => {
    try {
      const res = await clearLLMCache()
      showToast(res.message, 'success')
      refreshAdmin()
    } catch {
      showToast('Failed to clear cache.', 'error')
    }
  }

  const handleResetSessions = async () => {
    try {
      const res = await resetSessions()
      showToast(res.message, 'success')
      refreshAdmin()
    } catch {
      showToast('Failed to wipe sessions.', 'error')
    }
  }

  useEffect(() => {
    Promise.all([getAnalytics(), getStatus(), getRecentEvents(30)])
      .then(([a, s, e]) => {
        setAnalytics(a)
        setStatus(s)
        if (e.events?.length) setFeed(p => p.length ? p : e.events)
      })
      .catch(() => {})
    refreshAdmin()
    const id = setInterval(() => {
      getAnalytics().then(setAnalytics).catch(() => {})
      refreshAdmin()
    }, 12000)
    return () => clearInterval(id)
  }, [])

  const t = analytics?.totals || {}
  const total = parseInt(t.total) || 0
  const blocked = parseInt(t.blocked) || 0
  const warned = parseInt(t.warned) || 0
  const allowed = parseInt(t.allowed) || 0
  const avg = t.avg_score ? Math.round(t.avg_score) : 100
  const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0
  const reviewRate = total > 0 ? Math.round(((blocked + warned) / total) * 100) : 0
  const safeRate = total > 0 ? Math.round((allowed / total) * 100) : 100
  const postureColor = avg > 70 ? '#30d158' : avg > 40 ? '#ff9f0a' : '#ff453a'
  const postureLabel = avg > 70 ? 'Stable' : avg > 40 ? 'Watchful' : 'High risk'
  const summaryText = avg > 70
    ? 'Most inspected traffic is passing cleanly, with the guard still watching for spikes.'
    : avg > 40
      ? 'Traffic is mixed. The guard is catching meaningful risk and the session deserves attention.'
      : 'Risk is concentrated. Blocks are high enough that the agent path should be reviewed.'
  const metricDetails = {
    total: {
      title: 'Total inspected',
      color: '#ffffff',
      body: `${total.toLocaleString()} requests were checked by the guard in this session.`,
      detail: 'This is the traffic volume behind every other dashboard figure.',
    },
    block: {
      title: 'Block rate',
      color: '#ff453a',
      body: `${blockRate}% of inspected requests were stopped before reaching the agent.`,
      detail: 'A high block rate means the guard is seeing prompts with clear policy or security risk.',
    },
    detection: {
      title: 'Detection rate',
      color: '#ff9f0a',
      body: `${reviewRate}% of traffic triggered either a warning or a block.`,
      detail: 'This captures the full attention queue, including borderline prompts that need review.',
    },
    trust: {
      title: 'Average trust score',
      color: postureColor,
      body: `${avg} out of 100 is the current trust average across inspected traffic.`,
      detail: 'Higher scores mean cleaner prompts, fewer risky patterns, and healthier sessions.',
    },
  }
  const activeMetric = metricDetails[selectedMetric] || metricDetails.total
  const warningRate = total > 0 ? Math.round((warned / total) * 100) : 0
  const trafficMix = [
    { label: 'Blocked', value: blocked, rate: blockRate, color: '#ff453a' },
    { label: 'Warned', value: warned, rate: warningRate, color: '#ff9f0a' },
    { label: 'Allowed', value: allowed, rate: safeRate, color: '#30d158' },
  ]

  const daily = (analytics?.daily_trend || []).reverse().map(d => ({
    date: d.date?.slice(5),
    blocked: d.blocked || 0,
    warned: d.warned || 0,
    allowed: d.allowed || 0,
  }))

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header
        title="Dashboard"
        subtitle="Security posture, explained in plain language"
        wsConnected={wsConn}
      />

      <div className="flex-1 overflow-y-auto p-6 sm:p-8 lg:p-10 pb-14">
        <div className="max-w-[1240px] mx-auto space-y-9">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45 }}
            className="card glass-sheen p-7"
            style={{
              minHeight: 190,
              background: 'linear-gradient(135deg, rgba(0,113,227,0.18), rgba(22,22,24,0.72) 42%, rgba(255,69,58,0.10))',
            }}
          >
            <div className="grid grid-cols-1 xl:grid-cols-[1.25fr_0.75fr] gap-6 xl:gap-8 items-center">
              <div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '7px 11px', borderRadius: 999, background: `${postureColor}16`, border: `1px solid ${postureColor}35`, color: postureColor, fontSize: 11, fontWeight: 800, letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                  <RadioTower size={13} />
                  {postureLabel} posture
                </div>
                <h2 style={{ marginTop: 14, fontSize: 26, lineHeight: 1.2, color: '#ffffff', fontFamily: '"Outfit", sans-serif', fontWeight: 800, maxWidth: 720 }}>
                  {summaryText}
                </h2>
                <p style={{ marginTop: 10, color: '#B0B0B6', fontSize: 13, lineHeight: 1.55, maxWidth: 650, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                  Every figure below is computed from inspected traffic: volume checked, share that passed cleanly, share that required intervention, and the current trust posture.
                </p>

                <div className="row-list mt-6" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
                  <InsightRow
                    title={`${safeRate}% clean`}
                    body="Requests that passed without policy action. Higher means normal work is flowing."
                    color="#30d158"
                    delay={0.05}
                  />
                  <InsightRow
                    title={`${reviewRate}% reviewed`}
                    body="Prompts that triggered a warning or block. This is the attention queue."
                    color="#ff9f0a"
                    delay={0.1}
                  />
                  <InsightRow
                    title={status ? `${(status.pattern_count || 0) + (status.output_pattern_count || 0)} signatures` : 'Loading signatures'}
                    body="Detection rules loaded across input and output guard layers."
                    color="#0071e3"
                    delay={0.15}
                  />
                </div>
              </div>

              <div className="panel" style={{ display: 'grid', placeItems: 'center', minHeight: 164 }}>
                <div style={{
                  width: 120,
                  height: 120,
                  borderRadius: '50%',
                  display: 'grid',
                  placeItems: 'center',
                  background: `conic-gradient(${postureColor} ${Math.max(0, Math.min(avg, 100)) * 3.6}deg, rgba(255,255,255,0.08) 0deg)`,
                  boxShadow: `0 0 46px ${postureColor}22`,
                  }}>
                  <div style={{
                    width: 88,
                    height: 88,
                    borderRadius: '50%',
                    background: 'rgba(8,8,9,0.86)',
                    display: 'grid',
                    placeItems: 'center',
                    border: '1px solid rgba(255,255,255,0.12)',
                  }}>
                      <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 30, lineHeight: 1, color: postureColor, fontFamily: '"Outfit", sans-serif', fontWeight: 800 }}>
                        {avg}
                      </div>
                      <div style={{ color: '#D1D1D6', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 800, marginTop: 7 }}>
                        trust score
                      </div>
                    </div>
                  </div>
                </div>
                <p style={{ marginTop: 9, textAlign: 'center', color: '#D1D1D6', fontSize: 10.5, lineHeight: 1.42, maxWidth: 250 }}>
                  Trust score compresses pattern matches, warnings, blocks, and behavioral signals into one posture indicator.
                </p>
              </div>
            </div>
          </motion.div>

          <div className="panel" style={{ paddingTop: 22, paddingBottom: 20, borderTop: '1px solid rgba(255,255,255,0.08)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="stat-strip">
            <MetricCard
              label="Total Inspected"
              value={total}
              color="#ffffff"
              delay={0.05}
              selected={selectedMetric === 'total'}
              onClick={() => setSelectedMetric('total')}
            />
            <MetricCard
              label="Block Rate"
              value={`${blockRate}%`}
              color="#ff453a"
              delay={0.1}
              selected={selectedMetric === 'block'}
              onClick={() => setSelectedMetric('block')}
            />
            <MetricCard
              label="Detection Rate"
              value={`${reviewRate}%`}
              color="#ff9f0a"
              delay={0.15}
              selected={selectedMetric === 'detection'}
              onClick={() => setSelectedMetric('detection')}
            />
            <MetricCard
              label="Avg Trust Score"
              value={avg}
              color={postureColor}
              delay={0.2}
              selected={selectedMetric === 'trust'}
              onClick={() => setSelectedMetric('trust')}
            />
          </div>
          </div>

          <AnimatePresence mode="wait">
            <motion.div
              key={selectedMetric}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22 }}
              className="panel"
              style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(260px, 1fr) minmax(280px, 0.75fr)',
                gap: 24,
                alignItems: 'center',
                paddingLeft: 4,
                borderLeft: `2px solid ${activeMetric.color}60`,
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ width: 9, height: 9, borderRadius: '50%', background: activeMetric.color, boxShadow: `0 0 14px ${activeMetric.color}` }} />
                  <span style={{ color: '#ffffff', fontSize: 14, fontWeight: 800, fontFamily: '"Outfit", sans-serif' }}>
                    {activeMetric.title}
                  </span>
                </div>
                <p style={{ color: '#D1D1D6', fontSize: 12, lineHeight: 1.45, marginTop: 8, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                  <span style={{ color: '#ffffff', fontWeight: 700 }}>{activeMetric.body}</span> {activeMetric.detail}
                </p>
              </div>

              <div style={{ display: 'grid', gap: 8 }}>
                {trafficMix.map(item => (
                  <div key={item.label}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center', marginBottom: 5 }}>
                      <span style={{ color: '#ffffff', fontSize: 11.5, fontWeight: 700, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{item.label}</span>
                      <span style={{ color: item.color, fontSize: 11.5, fontWeight: 800, fontFamily: 'monospace' }}>
                        {item.value.toLocaleString()} / {item.rate}%
                      </span>
                    </div>
                    <div style={{ height: 5, borderRadius: 999, overflow: 'hidden', background: 'rgba(255,255,255,0.08)' }}>
                      <div style={{ width: `${Math.min(item.rate, 100)}%`, height: '100%', borderRadius: 999, background: item.color, boxShadow: `0 0 12px ${item.color}55` }} />
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          </AnimatePresence>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 xl:gap-8">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.22 }}
              className="xl:col-span-2 panel"
            >
              <div className="panel-header">
                <span className="panel-title" style={{ fontSize: 14 }}>
                  Risk Over 7 Days
                </span>
                <TrendingUp size={15} color="#4da3ff" />
              </div>
              <ResponsiveContainer width="100%" height={188}>
                <AreaChart data={daily}>
                  <defs>
                    <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ff453a" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="#ff453a" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gWarn" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ff9f0a" stopOpacity={0.20} />
                      <stop offset="100%" stopColor="#ff9f0a" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                  <XAxis dataKey="date" stroke="#D1D1D6" fontSize={10} fontFamily='"Plus Jakarta Sans"' axisLine={false} tickLine={false} />
                  <YAxis stroke="#D1D1D6" fontSize={10} fontFamily='"Plus Jakarta Sans"' axisLine={false} tickLine={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="blocked" stroke="#ff453a" fill="url(#gBlock)" strokeWidth={2.5} name="Blocked" />
                  <Area type="monotone" dataKey="warned" stroke="#ff9f0a" fill="url(#gWarn)" strokeWidth={2} name="Warned" />
                </AreaChart>
              </ResponsiveContainer>
              <p className="panel-foot">
                This chart shows whether risk is spiking or calming down. Red means blocked traffic, amber means warnings.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.27 }}
              className="xl:col-span-3 panel panel-divide"
            >
              <div className="panel-header">
                <div className="flex items-center gap-2">
                  <Activity size={15} color="#4da3ff" />
                  <span className="panel-title" style={{ fontSize: 14 }}>
                    Recent Decisions
                  </span>
                  <span className="live-dot" style={{ width: 5, height: 5 }} />
                </div>
                <span style={{ fontSize: 11, fontFamily: '"Plus Jakarta Sans", sans-serif', color: '#98989D', fontWeight: 600 }}>
                  {feed.length} events
                </span>
              </div>

              <div className="flex items-center gap-3 pb-2.5 mb-1.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                {['', 'Action', 'Prompt preview', 'Score', 'Time'].map((h, i) => (
                  <span key={i} style={{
                    fontSize: 10,
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                    color: '#D1D1D6',
                    fontWeight: 700,
                    fontFamily: '"Plus Jakarta Sans", sans-serif',
                    flex: i === 2 ? 1 : 'none',
                    width: i === 0 ? 7 : i === 1 ? 62 : i === 3 ? 42 : i === 4 ? 54 : 'auto',
                    textAlign: i > 2 ? 'right' : 'left',
                  }}>
                    {h}
                  </span>
                ))}
              </div>

              <div className="overflow-y-auto" style={{ maxHeight: 258 }}>
                <AnimatePresence>
                  {feed.length > 0 ? (
                    feed.map((ev, i) => <FeedRow key={`${ev.id}-${i}`} ev={ev} i={i} />)
                  ) : (
                    <div className="flex flex-col items-center justify-center py-16" style={{ color: '#D1D1D6' }}>
                      <Shield size={30} style={{ marginBottom: 12, opacity: 0.35 }} />
                      <p style={{ fontSize: 12, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>No events yet. Run the Simulator</p>
                    </div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 xl:gap-8">
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.32, duration: 0.4 }}
              className="xl:col-span-2 panel"
            >
              <div className="panel-header">
                <div className="flex items-center gap-2">
                  <Sliders size={14} color="#4da3ff" />
                  <span className="panel-title" style={{ fontSize: 14 }}>
                    Controls
                  </span>
                </div>
              </div>

              <div className="space-y-3">
                <button
                  onClick={handleToggleTraffic}
                  className="flex items-center justify-between w-full p-3.5 rounded-xl transition-all duration-250 text-left hover:bg-[rgba(255,255,255,0.02)]"
                  style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}
                >
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#ffffff', fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Demo Traffic</div>
                    <div style={{ fontSize: 11, color: '#D1D1D6', marginTop: 3, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Feeds the dashboard with sample events.</div>
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 800, color: adminConfig.demo_traffic_enabled ? '#30d158' : '#ff9f0a', fontFamily: 'monospace' }}>
                    {adminConfig.demo_traffic_enabled ? 'RUNNING' : 'PAUSED'}
                  </span>
                </button>

                <div className="grid grid-cols-2 gap-3">
                  <button onClick={handleClearCache} className="btn btn-secondary text-xs flex items-center justify-center gap-2 py-3 rounded-xl">
                    <Trash2 size={13} /> Cache
                  </button>
                  <button onClick={handleResetSessions} className="btn btn-secondary text-xs flex items-center justify-center gap-2 py-3 rounded-xl">
                    <Database size={13} /> Sessions
                  </button>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.36, duration: 0.4 }}
              className="xl:col-span-3 panel panel-divide"
            >
              <div className="panel-header">
                <div className="flex items-center gap-2">
                  <Settings size={14} color="#4da3ff" />
                  <span className="panel-title" style={{ fontSize: 14 }}>
                    Engine Status
                  </span>
                </div>
              </div>

              <div className="row-list" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 24 }}>
                <InsightRow title="Model layer" body={
                  status?.llm_provider === 'github_models' ? 'GitHub Models is active for deeper analysis.'
                  : status?.llm_provider === 'groq' ? 'Groq is active for deeper analysis.'
                  : status?.llm_provider === 'openrouter' ? 'OpenRouter is active for deeper analysis.'
                  : 'Pattern-only mode is active for fast local checks.'
                } color="#4da3ff" />
                <InsightRow title="Socket stream" body={`${status?.ws_clients ?? 0} live dashboard connection${(status?.ws_clients ?? 0) === 1 ? '' : 's'} receiving events.`} color="#30d158" />
                <InsightRow title="Session memory" body={`${adminConfig.total_active_sessions} active session${adminConfig.total_active_sessions === 1 ? '' : 's'} currently tracked.`} color="#ff9f0a" />
                <InsightRow title="Cache size" body={`${adminConfig.llm_cache_size} cached model result${adminConfig.llm_cache_size === 1 ? '' : 's'} stored for faster repeats.`} color="#ffffff" />
              </div>
            </motion.div>
          </div>
        </div>

        <AnimatePresence>
          {toast && (
            <motion.div
              initial={{ opacity: 0, y: 15, x: '-50%' }}
              animate={{ opacity: 1, y: 0, x: '-50%' }}
              exit={{ opacity: 0, y: 15, x: '-50%' }}
              style={{
                position: 'fixed',
                bottom: 24,
                left: '50%',
                transform: 'translateX(-50%)',
                zIndex: 100,
                background: 'rgba(15, 15, 15, 0.9)',
                border: `1px solid ${toast.type === 'error' ? 'rgba(255,69,58,0.25)' : 'rgba(48,209,88,0.25)'}`,
                boxShadow: '0 8px 30px rgba(0, 0, 0, 0.5)',
                borderRadius: 12,
                padding: '10px 18px',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12,
                color: '#ffffff',
                fontFamily: '"Plus Jakarta Sans", sans-serif',
                backdropFilter: 'blur(20px)',
              }}
            >
              <div style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: toast.type === 'error' ? '#ff453a' : '#30d158',
                boxShadow: `0 0 6px ${toast.type === 'error' ? '#ff453a' : '#30d158'}`,
              }} />
              {toast.message}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
