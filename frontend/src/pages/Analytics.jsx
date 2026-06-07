import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'
import Header from '../components/layout/Header'
import { getAnalytics } from '../utils/api'

const COLORS = ['#FF3B30','#FF9F0A','#30D158','#0A84FF','#BF5AF2','#FF6961','#5E5CE6','#64D2FF']

function Card({ title, subtitle, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="card p-5"
    >
      <div className="section-header">
        <div>
          <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 600, fontSize: 13, color: '#888', letterSpacing: '-0.01em' }}>{title}</div>
          {subtitle && <div style={{ fontSize: 10, color: '#333', marginTop: 3 }}>{subtitle}</div>}
        </div>
      </div>
      {children}
    </motion.div>
  )
}

export default function Analytics() {
  const [data, setData] = useState(null)

  useEffect(() => {
    getAnalytics().then(setData).catch(() => {})
    const id = setInterval(() => getAnalytics().then(setData).catch(() => {}), 20_000)
    return () => clearInterval(id)
  }, [])

  const t        = data?.totals || {}
  const total    = parseInt(t.total) || 0
  const blocked  = parseInt(t.blocked) || 0
  const warned   = parseInt(t.warned)  || 0
  const allowed  = parseInt(t.allowed) || 0
  const avgScore = t.avg_score ? Math.round(t.avg_score) : 100
  const blockRate= total > 0 ? ((blocked / total) * 100).toFixed(1) : 0

  const daily    = (data?.daily_trend || []).reverse()
  const cats     = (data?.categories  || []).filter(c => c.threat_category).slice(0, 7)
  const patterns = data?.top_patterns || []
  const hourly   = Array.from({ length: 24 }, (_, h) => ({ hour: `${h}h`, count: 0 }))
  ;(data?.hourly_today || []).forEach(({ hour, count }) => { if (hourly[hour]) hourly[hour].count = count })

  const pieData = [
    { name: 'Blocked', value: blocked },
    { name: 'Warned',  value: warned },
    { name: 'Allowed', value: allowed },
  ].filter(d => d.value > 0)

  const kpis = [
    { label: 'Total Inspected', value: total.toLocaleString() },
    { label: 'Block Rate',      value: `${blockRate}%`,        color: '#FF3B30' },
    { label: 'Detection Rate',  value: total > 0 ? `${(((blocked+warned)/total)*100).toFixed(1)}%` : '—', color: '#FF9F0A' },
    { label: 'Avg Trust Score', value: avgScore,               color: avgScore > 70 ? '#30D158' : '#FF9F0A' },
  ]

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header title="Analytics" subtitle="Detection performance across all dimensions" />

      <div className="flex-1 overflow-y-auto p-8 space-y-6">

        {/* KPI strip */}
        <div className="grid grid-cols-4 gap-4">
          {kpis.map((k, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="card p-5 text-center"
            >
              <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 36, color: k.color || '#f0f0f0', letterSpacing: '-0.05em', lineHeight: 1 }}>
                {k.value}
              </div>
              <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.06em', textTransform: 'uppercase', marginTop: 8 }}>
                {k.label}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Distribution + 7-day */}
        <div className="grid grid-cols-3 gap-6">
          <Card title="Action Distribution" subtitle="by verdict" delay={0.1}>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={72} dataKey="value" strokeWidth={0}>
                  {pieData.map((_, i) => <Cell key={i} fill={['#FF3B30','#FF9F0A','#30D158'][i]} />)}
                </Pie>
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: 11, fontFamily: '"IBM Plex Mono"' }} />
              </PieChart>
            </ResponsiveContainer>
          </Card>

          <Card title="7-Day Trend" subtitle="blocked vs warned" delay={0.15} >
            <div className="col-span-2" style={{ display: 'contents' }}>
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={daily}>
                <CartesianGrid strokeDasharray="2 2" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="date" stroke="#333" fontSize={10} fontFamily='"IBM Plex Mono"' />
                <YAxis stroke="#333" fontSize={10} fontFamily='"IBM Plex Mono"' />
                <Tooltip />
                <Line type="monotone" dataKey="blocked" stroke="#FF3B30" strokeWidth={1.5} dot={false} name="Blocked" />
                <Line type="monotone" dataKey="warned"  stroke="#FF9F0A" strokeWidth={1.5} dot={false} name="Warned" />
              </LineChart>
            </ResponsiveContainer>
            </div>
          </Card>

          <Card title="Category Breakdown" subtitle="top attack types" delay={0.2}>
            <div className="space-y-2.5 mt-1">
              {cats.length > 0 ? cats.map((c, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span style={{ fontSize: 10, color: '#444', width: 100, flexShrink: 0, fontFamily: '"IBM Plex Mono"', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {c.threat_category?.split(' ').slice(0,2).join(' ')}
                  </span>
                  <div style={{ flex: 1, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(c.count / (cats[0]?.count || 1)) * 100}%` }}
                      transition={{ delay: 0.3 + i * 0.04, duration: 0.5 }}
                      style={{ height: '100%', borderRadius: 2, background: COLORS[i % COLORS.length] }}
                    />
                  </div>
                  <span style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"', flexShrink: 0, width: 20, textAlign: 'right' }}>
                    {c.count}
                  </span>
                </div>
              )) : (
                <div style={{ textAlign: 'center', padding: '24px 0', color: '#333', fontSize: 11, fontFamily: '"IBM Plex Mono"' }}>
                  Run the Simulator to populate
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Hourly */}
        <Card title="Hourly Activity Today" subtitle="threat events per hour" delay={0.3}>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={hourly} barSize={8}>
              <CartesianGrid strokeDasharray="2 2" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="hour" stroke="#333" fontSize={10} fontFamily='"IBM Plex Mono"' interval={5} />
              <YAxis stroke="#333" fontSize={10} fontFamily='"IBM Plex Mono"' />
              <Tooltip />
              <Bar dataKey="count" fill="#0A84FF" radius={[2,2,0,0]} name="Events" />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Top patterns */}
        {patterns.length > 0 && (
          <Card title="Top Triggered Patterns" subtitle="most-matched signatures" delay={0.35}>
            <div className="space-y-3">
              {patterns.slice(0, 8).map((p, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span style={{ fontSize: 11, fontFamily: '"IBM Plex Mono"', color: '#444', width: 72, flexShrink: 0 }}>{p.pattern_id}</span>
                  <div style={{ flex: 1, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(p.hit_count / (patterns[0]?.hit_count || 1)) * 100}%` }}
                      transition={{ delay: 0.4 + i * 0.04, duration: 0.5 }}
                      style={{ height: '100%', borderRadius: 2, background: COLORS[i % COLORS.length] }}
                    />
                  </div>
                  <span style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"', flexShrink: 0, width: 24, textAlign: 'right' }}>
                    {p.hit_count}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
