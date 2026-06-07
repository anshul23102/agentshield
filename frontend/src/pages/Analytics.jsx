import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'
import Header from '../components/layout/Header'
import { getAnalytics } from '../utils/api'

const COLORS = ['#0071E3', '#34C759', '#FF9500', '#FF3B30', '#AF52DE', '#5AC8FA', '#FF2D55', '#8E8E93']

function Card({ title, subtitle, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="card p-6"
    >
      <div className="section-header" style={{ marginBottom: 16, paddingBottom: 14, borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <div>
          <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 13, color: '#f5f5f7', letterSpacing: '-0.01em' }}>{title}</div>
          {subtitle && <div style={{ fontSize: 10, color: '#86868b', marginTop: 4, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{subtitle.toUpperCase()}</div>}
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
    { label: 'Block Rate',      value: `${blockRate}%`,        color: '#ff3b30' },
    { label: 'Detection Rate',  value: total > 0 ? `${(((blocked+warned)/total)*100).toFixed(1)}%` : '-', color: '#ff9500' },
    { label: 'Avg Trust Score', value: avgScore,               color: avgScore > 70 ? '#34c759' : '#ff9500' },
  ]

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header title="Analytics" subtitle="Detection performance across all dimensions" />

      <div className="flex-1 overflow-y-auto p-8 pb-12">
        <div className="max-w-[1200px] mx-auto space-y-10">

          {/* KPI strip */}
          <div className="grid grid-cols-4 gap-4">
            {kpis.map((k, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                className="card p-6 text-center"
              >
                <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 36, color: k.color || '#f5f5f7', letterSpacing: '-0.05em', lineHeight: 1 }}>
                  {k.value}
                </div>
                <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginTop: 8, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
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
                    {pieData.map((_, i) => <Cell key={i} fill={['#ff3b30','#ff9500','#34c759'][i]} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: 'rgba(15, 15, 15, 0.85)',
                      backdropFilter: 'blur(20px)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      fontFamily: '"Plus Jakarta Sans", sans-serif',
                      fontSize: '11px',
                      color: '#ffffff'
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11, fontFamily: '"Plus Jakarta Sans", sans-serif', color: '#86868b' }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                Proportion of inspection verdicts. Blocked: threats immediately dropped. Warned: suspected anomalies logged. Allowed: validated safe traffic.
              </div>
            </Card>

            <Card title="7-Day Trend" subtitle="blocked vs warned" delay={0.15} >
              <div className="col-span-2" style={{ display: 'contents' }}>
                <ResponsiveContainer width="100%" height={180}>
                  <LineChart data={daily}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.04)" vertical={false} />
                    <XAxis dataKey="date" stroke="#86868b" fontSize={10} fontFamily='"Plus Jakarta Sans"' axisLine={false} tickLine={false} />
                    <YAxis stroke="#86868b" fontSize={10} fontFamily='"Plus Jakarta Sans"' axisLine={false} tickLine={false} />
                    <Tooltip
                      contentStyle={{
                        background: 'rgba(15, 15, 15, 0.85)',
                        backdropFilter: 'blur(20px)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '12px',
                        fontFamily: '"Plus Jakarta Sans", sans-serif',
                        fontSize: '11px',
                        color: '#ffffff'
                      }}
                    />
                    <Line type="monotone" dataKey="blocked" stroke="#ff3b30" strokeWidth={2} dot={false} name="Blocked" />
                    <Line type="monotone" dataKey="warned"  stroke="#ff9500" strokeWidth={1.5} dot={false} name="Warned" />
                  </LineChart>
                </ResponsiveContainer>
                <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                  Daily comparison of hard drops (Blocked) versus soft warnings (Warned) over the trailing week.
                </div>
              </div>
            </Card>

            <Card title="Category Breakdown" subtitle="top attack types" delay={0.2}>
              <div className="space-y-2.5 mt-1">
                {cats.length > 0 ? cats.map((c, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span style={{ fontSize: 10, color: '#f5f5f7', width: 100, flexShrink: 0, fontFamily: '"Plus Jakarta Sans"', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                      {c.threat_category?.split(' ').slice(0,2).join(' ').toUpperCase()}
                    </span>
                    <div style={{ flex: 1, height: 4, background: 'rgba(255, 255, 255, 0.04)', borderRadius: 2, overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(c.count / (cats[0]?.count || 1)) * 100}%` }}
                        transition={{ delay: 0.3 + i * 0.04, duration: 0.5 }}
                        style={{ height: '100%', borderRadius: 2, background: COLORS[i % COLORS.length] }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans"', flexShrink: 0, width: 20, textAlign: 'right', fontWeight: 600 }}>
                      {c.count}
                    </span>
                  </div>
                )) : (
                  <div style={{ textAlign: 'center', padding: '24px 0', color: '#86868b', fontSize: 11, fontFamily: '"Plus Jakarta Sans"' }}>
                    RUN SIMULATOR TO POPULATE STATS
                  </div>
                )}
              </div>
              <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                Frequency breakdown of specific threat types. Higher values represent active attack vectors targeting agent endpoints.
              </div>
            </Card>
          </div>

          {/* Hourly */}
          <Card title="Hourly Activity Today" subtitle="threat events per hour" delay={0.3}>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={hourly} barSize={8}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.04)" vertical={false} />
                <XAxis dataKey="hour" stroke="#86868b" fontSize={10} fontFamily='"Plus Jakarta Sans"' interval={5} axisLine={false} tickLine={false} />
                <YAxis stroke="#86868b" fontSize={10} fontFamily='"Plus Jakarta Sans"' axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(15, 15, 15, 0.85)',
                    backdropFilter: 'blur(20px)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    fontFamily: '"Plus Jakarta Sans", sans-serif',
                    fontSize: '11px',
                    color: '#ffffff'
                  }}
                />
                <Bar dataKey="count" fill="#0071e3" radius={[2,2,0,0]} name="Events" />
              </BarChart>
            </ResponsiveContainer>
            <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
              Distribution of security logs by hour of day. Helps security operators detect automated brute-force windows.
            </div>
          </Card>

          {/* Top patterns */}
          {patterns.length > 0 && (
            <Card title="Top Triggered Patterns" subtitle="most-matched signatures" delay={0.35}>
              <div className="space-y-3 pb-4">
                {patterns.slice(0, 8).map((p, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span style={{ fontSize: 11, fontFamily: '"Plus Jakarta Sans"', color: '#0071e3', width: 72, flexShrink: 0, fontWeight: 500 }}>{p.pattern_id}</span>
                    <div style={{ flex: 1, height: 4, background: 'rgba(255, 255, 255, 0.04)', borderRadius: 2, overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${(p.hit_count / (patterns[0]?.hit_count || 1)) * 100}%` }}
                        transition={{ delay: 0.4 + i * 0.04, duration: 0.5 }}
                        style={{ height: '100%', borderRadius: 2, background: COLORS[i % COLORS.length] }}
                      />
                    </div>
                    <span style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"Plus Jakarta Sans"', flexShrink: 0, width: 24, textAlign: 'right', fontWeight: 600 }}>
                      {p.hit_count}
                    </span>
                  </div>
                ))}
              </div>
              <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                Individual security rule matches. Useful for assessing rule severity and adjusting pattern-matching rules.
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
