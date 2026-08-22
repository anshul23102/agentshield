import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, ChevronDown, ChevronUp } from 'lucide-react'
import Header from '../components/layout/Header'
import { getPatterns } from '../utils/api'

const LEVEL_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

function PatternRow({ p, i }) {
  const [open, setOpen] = useState(false)
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(i * 0.015, 0.4) }}
      style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 py-3.5 hover:bg-[rgba(255,255,255,0.02)] transition-colors duration-250"
        style={{ textAlign: 'left' }}
      >
        <span className={`badge badge-${p.threat_level}`} style={{ flexShrink: 0, minWidth: 72, justifyContent: 'center', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>{p.threat_level}</span>
        <span style={{ fontSize: 11, color: '#0071e3', fontFamily: '"Plus Jakarta Sans", sans-serif', flexShrink: 0, width: 64, fontWeight: 500 }}>{p.id}</span>
        <span style={{ fontSize: 13, color: '#f5f5f7', flex: 1, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{p.description}</span>
        <span style={{ fontSize: 11, color: '#86868b', flexShrink: 0, display: 'none', width: 180, fontWeight: 400, fontFamily: '"Plus Jakarta Sans", sans-serif' }}
          className="md:block truncate">
          {p.category.toUpperCase()}
        </span>
        {open ? <ChevronUp size={14} color="#86868b" /> : <ChevronDown size={14} color="#86868b" />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.25, 0.1, 0.25, 1] }}
            style={{ overflow: 'hidden' }}
          >
            <div className="pb-5 space-y-4" style={{ paddingLeft: 2 }}>
              <div style={{ fontSize: 12, color: '#86868b', fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                Classification Category: <span style={{ color: '#f5f5f7', fontWeight: 500 }}>{p.category}</span>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 8, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Exploit Signature Example</div>
                <div style={{ fontSize: 12, color: '#f5f5f7', fontFamily: 'monospace', lineHeight: 1.6, padding: '12px 16px', background: 'rgba(10, 10, 10, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12 }}>
                  "{p.example}"
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export default function Intelligence() {
  const [patterns, setPatterns] = useState([])
  const [stats,    setStats]    = useState({})
  const [search,   setSearch]   = useState('')
  const [level,    setLevel]    = useState('all')
  const [loading,  setLoading]  = useState(true)

  useEffect(() => {
    getPatterns()
      .then(d => { setPatterns(d.patterns || []); setStats(d.level_stats || {}) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filtered = patterns
    .filter(p => {
      const q = search.toLowerCase()
      return (
        (!q || p.description.toLowerCase().includes(q) || p.id.toLowerCase().includes(q) || p.category.toLowerCase().includes(q)) &&
        (level === 'all' || p.threat_level === level)
      )
    })
    .sort((a, b) => (LEVEL_ORDER[a.threat_level] ?? 9) - (LEVEL_ORDER[b.threat_level] ?? 9))

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header title="Threat Intelligence" subtitle={`${patterns.length} attack signatures across 10 categories`} />

      <div className="flex-1 overflow-y-auto p-6 sm:p-8 lg:p-10 pb-14">
        <div className="max-w-[1240px] mx-auto space-y-8">

          {/* Level stats text tabs */}
          <div className="flex items-center gap-6 border-b border-[rgba(255,255,255,0.08)] pb-1">
            {[
              ['all', 'All Signatures'],
              ['critical', 'Critical'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['low', 'Low']
            ].map(([k, l]) => {
              const count = k === 'all' ? patterns.length : (stats[k] || 0)
              const active = level === k
              return (
                <button
                  key={k}
                  onClick={() => setLevel(k)}
                  className="relative pb-4 text-sm font-medium transition-all duration-300 focus:outline-none"
                  style={{
                    color: active ? '#ffffff' : '#86868b',
                    fontFamily: '"Plus Jakarta Sans", sans-serif',
                    fontWeight: active ? 500 : 400
                  }}
                >
                  <span className="flex items-center gap-2">
                    {l}
                    <span className="text-xs opacity-80 px-1.5 py-0.5 rounded-full bg-[rgba(255,255,255,0.08)]" style={{ color: active ? '#ffffff' : '#86868b' }}>
                      {count}
                    </span>
                  </span>
                  {active && (
                    <motion.div
                      layoutId="activeTabUnderline"
                      className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#0071e3]"
                      transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                    />
                  )}
                </button>
              )
            })}
          </div>

          {/* Search */}
          <div className="relative">
            <Search size={14} color="#86868b" style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by signature ID, description, classification category…"
              className="input focus:ring-1 focus:ring-[#0071e3] focus:border-[#0071e3] transition-all duration-300"
              style={{
                paddingLeft: 44,
                background: 'rgba(10, 10, 10, 0.6)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '16px',
                height: '52px',
                fontSize: '14px',
                color: '#f5f5f7',
                fontFamily: '"Plus Jakarta Sans", sans-serif'
              }}
            />
          </div>

          {/* Count */}
          <div style={{ fontSize: 10, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500, letterSpacing: '0.05em' }}>
            FILTERED RESULTS: {filtered.length} OF {patterns.length} SIGNATURES
          </div>

          {/* List */}
          <div className="pb-8">
            {loading
              ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#86868b', fontSize: 12, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>LOADING INTELLIGENCE ENGINE…</div>
              : filtered.length === 0
                ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#86868b', fontSize: 12, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>NO SIGNATURES MATCH THE FILTER CRITERIA</div>
                : filtered.map((p, i) => <PatternRow key={p.id} p={p} i={i} />)
            }
          </div>
        </div>
      </div>
    </div>
  )
}
