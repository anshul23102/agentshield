import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, TrendingUp, Activity } from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'
import Header from '../components/layout/Header'
import { useWebSocket } from '../hooks/useWebSocket'
import { getAnalytics, getStatus, getRecentEvents } from '../utils/api'

/* ── Animated counter ── */
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

/* ── KPI card ── */
function KPI({ value, label, sub, valueColor = '#ffffff', delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="card p-6"
    >
      <div style={{ fontSize: 11, color: '#9ca3af', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12, fontWeight: 600 }}>
        {label}
      </div>
      <div className="stat-num" style={{ fontSize: 38, color: valueColor, fontWeight: 700 }}>
        {typeof value === 'number' ? <Count to={value} /> : value}
      </div>
      {sub && <div style={{ fontSize: 11, color: '#71717a', marginTop: 6, fontWeight: 500 }}>{sub}</div>}
    </motion.div>
  )
}

/* ── Threat feed row ── */
function FeedRow({ ev, i }) {
  const colors = { block: '#ff453a', warn: '#ff9f0a', allow: '#30d158' }
  const color  = colors[ev.action] || '#86868b'
  const ts = ev.timestamp
    ? new Date(ev.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: i * 0.02, duration: 0.25 }}
      className="threat-row"
      style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
    >
      {/* Status dot with pulsing effect */}
      <div style={{
        width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: `0 0 8px ${color}`
      }} />

      {/* Badge */}
      <span className={`badge badge-${ev.action}`} style={{ flexShrink: 0 }}>
        {ev.action}
      </span>

      {/* Preview */}
      <span style={{ fontSize: 12, color: '#f5f5f7', fontFamily: '"IBM Plex Mono"', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {ev.input_preview || ev.threat_category || '—'}
      </span>

      {/* Score */}
      <span style={{ fontSize: 12, fontFamily: '"IBM Plex Mono"', color, flexShrink: 0, fontWeight: 600 }}>
        {ev.trust_score}
      </span>

      {/* Time */}
      <span style={{ fontSize: 11, color: '#86868b', fontFamily: '"IBM Plex Mono"', flexShrink: 0 }}>
        {ts}
      </span>
    </motion.div>
  )
}

export default function Dashboard() {
  const [analytics, setAnalytics] = useState(null)
  const [status,    setStatus]    = useState(null)
  const [feed,      setFeed]      = useState([])
  const [wsConn,    setWsConn]    = useState(false)

  const { connected } = useWebSocket((msg) => {
    setWsConn(true)
    if (msg.type === 'threat_event') setFeed(p => [msg, ...p].slice(0, 80))
    if (msg.type === 'init' && msg.recent_events) setFeed(msg.recent_events)
  })
  useEffect(() => setWsConn(connected), [connected])

  useEffect(() => {
    Promise.all([getAnalytics(), getStatus(), getRecentEvents(40)])
      .then(([a, s, e]) => {
        setAnalytics(a)
        setStatus(s)
        if (e.events?.length) setFeed(p => p.length ? p : e.events)
      })
      .catch(() => {})
    const id = setInterval(() => getAnalytics().then(setAnalytics).catch(() => {}), 20_000)
    return () => clearInterval(id)
  }, [])

  const t     = analytics?.totals || {}
  const total = parseInt(t.total)  || 0
  const blocked = parseInt(t.blocked) || 0
  const warned  = parseInt(t.warned)  || 0
  const allowed = parseInt(t.allowed) || 0
  const avg   = t.avg_score ? Math.round(t.avg_score) : 100

  const daily = (analytics?.daily_trend || []).reverse().map(d => ({
    date: d.date?.slice(5),
    blocked: d.blocked || 0,
    warned:  d.warned  || 0,
    allowed: d.allowed || 0,
  }))

  const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header
        title="Dashboard"
        subtitle="Bidirectional threat monitoring — inputs and outputs"
        wsConnected={wsConn}
      />

      <div className="flex-1 overflow-y-auto p-8 space-y-6">

        {/* ── KPIs ── */}
        <div className="grid grid-cols-4 gap-4">
          <KPI value={blocked}  label="Threats Blocked" valueColor="#ff453a" delay={0}   />
          <KPI value={warned}   label="Warnings"        valueColor="#ff9f0a" delay={0.05} />
          <KPI value={allowed}  label="Safe Requests"   valueColor="#30d158" delay={0.10} />
          <KPI
            value={`${avg}`}
            label="Avg Trust Score"
            sub="/ 100"
            valueColor={avg > 70 ? '#30d158' : avg > 40 ? '#ff9f0a' : '#ff453a'}
            delay={0.15}
          />
        </div>

        {/* ── Secondary strip ── */}
        <div className="grid grid-cols-3 gap-4">
          <KPI value={status?.pattern_count || 54} label="Attack Signatures" sub="input + output guards" delay={0.2} />
          <KPI value={total} label="Total Inspected" sub="this session" delay={0.22} />
          <KPI
            value={`${blockRate}%`}
            label="Block Rate"
            sub={status?.llm_provider === 'github_models' ? 'LLM: GitHub AI' : 'LLM: pattern-only'}
            valueColor={blockRate > 20 ? '#ff453a' : '#f5f5f7'}
            delay={0.24}
          />
        </div>

        {/* ── 7-day trend + Live feed ── */}
        <div className="grid grid-cols-5 gap-6">

          {/* Trend chart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
            className="col-span-2 card p-5"
          >
            <div className="section-header" style={{ marginBottom: 16, paddingBottom: 14 }}>
              <span style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontSize: 13, fontWeight: 600, color: '#ffffff', letterSpacing: '-0.01em' }}>
                7-Day Trend
              </span>
              <TrendingUp size={14} color="#0071e3" />
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={daily}>
                <defs>
                  <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor="#ff453a" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#ff453a" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                <XAxis dataKey="date" stroke="#86868b" fontSize={10} fontFamily='"IBM Plex Mono"' />
                <YAxis stroke="#86868b" fontSize={10} fontFamily='"IBM Plex Mono"' />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(10, 10, 12, 0.8)',
                    backdropFilter: 'blur(16px)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '10px',
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontSize: '11px',
                    color: '#ffffff'
                  }}
                />
                <Area type="monotone" dataKey="blocked" stroke="#ff453a" fill="url(#gBlock)" strokeWidth={2} name="Blocked" />
                <Area type="monotone" dataKey="warned"  stroke="#ff9f0a" fill="none"          strokeWidth={1.5} name="Warned" />
              </AreaChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: '#86868b', marginTop: 12, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 10 }}>
              Aggregated weekly timeline comparing blocked threat vectors against warning notifications. Use this to identify multi-day attack spikes.
            </div>
          </motion.div>

          {/* Live feed — takes most of the space */}
          <motion.div
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}
            className="col-span-3 card p-5"
          >
            <div className="section-header" style={{ marginBottom: 16, paddingBottom: 14 }}>
              <div className="flex items-center gap-2">
                <Activity size={14} color="#0071e3" />
                <span style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontSize: 13, fontWeight: 600, color: '#ffffff', letterSpacing: '-0.01em' }}>
                  Live Threat Feed
                </span>
                <span className="live-dot" style={{ width: 5, height: 5 }} />
              </div>
              <span style={{ fontSize: 11, fontFamily: '"IBM Plex Mono"', color: '#86868b', fontWeight: 500 }}>
                {feed.length} events
              </span>
            </div>

            {/* Column headers */}
            <div className="flex items-center gap-3 pb-2.5 mb-1.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              {['', 'Action', 'Input preview', 'Score', 'Time'].map((h, i) => (
                <span key={i} style={{
                  fontSize: 10, letterSpacing: '0.04em', textTransform: 'uppercase', color: '#86868b',
                  fontWeight: 600,
                  flex: i === 2 ? 1 : 'none',
                  width: i === 0 ? 6 : i === 1 ? 56 : i === 3 ? 36 : i === 4 ? 64 : 'auto',
                }}>
                  {h}
                </span>
              ))}
            </div>

            <div className="overflow-y-auto" style={{ maxHeight: 280 }}>
              <AnimatePresence>
                {feed.length > 0 ? (
                  feed.map((ev, i) => <FeedRow key={`${ev.id}-${i}`} ev={ev} i={i} />)
                ) : (
                  <div className="flex flex-col items-center justify-center py-16" style={{ color: '#86868b' }}>
                    <Shield size={28} style={{ marginBottom: 12, opacity: 0.3 }} />
                    <p style={{ fontSize: 12, fontFamily: '"IBM Plex Mono"' }}>No events yet — run the Simulator</p>
                  </div>
                )}
              </AnimatePresence>
            </div>
            <div style={{ fontSize: 11, color: '#86868b', marginTop: 12, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 10 }}>
              Real-time stream of incoming agent inputs and outgoing payloads intercepted by the active layers. Pulsing indicators denote real-time mitigation actions.
            </div>
          </motion.div>
        </div>

      </div>
    </div>
  )
}
