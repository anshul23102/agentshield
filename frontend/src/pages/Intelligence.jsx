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
      className="card-flat overflow-hidden"
      style={{ marginBottom: 6 }}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 p-4"
        style={{ textAlign: 'left' }}
      >
        <span className={`badge badge-${p.threat_level}`} style={{ flexShrink: 0, minWidth: 72, justifyContent: 'center' }}>{p.threat_level}</span>
        <span style={{ fontSize: 11, color: '#0071e3', fontFamily: '"IBM Plex Mono"', flexShrink: 0, width: 64, fontWeight: 600 }}>{p.id}</span>
        <span style={{ fontSize: 13, color: '#ffffff', flex: 1, fontWeight: 500 }}>{p.description}</span>
        <span style={{ fontSize: 11, color: '#86868b', flexShrink: 0, display: 'none', width: 180, fontWeight: 500 }}
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
            transition={{ duration: 0.2 }}
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)', overflow: 'hidden' }}
          >
            <div className="p-5 space-y-4" style={{ background: 'rgba(255,255,255,0.01)' }}>
              <div style={{ fontSize: 12, color: '#86868b', fontWeight: 500 }}>
                Classification Category: <span style={{ color: '#ffffff', fontWeight: 600 }}>{p.category}</span>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 8, fontWeight: 600 }}>Exploit Signature Example</div>
                <div style={{ fontSize: 12, color: '#f5f5f7', fontFamily: '"IBM Plex Mono"', lineHeight: 1.6, padding: '12px 16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 10 }}>
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

      <div className="flex-1 overflow-y-auto p-8 space-y-6">

        {/* Level stats */}
        <div className="grid grid-cols-5 gap-4">
          {[['all', 'All Signatures'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([k, l]) => {
            const count = k === 'all' ? patterns.length : (stats[k] || 0)
            const active = level === k
            return (
              <motion.button
                key={k} whileHover={{ y: -2 }} whileTap={{ y: 0 }}
                onClick={() => setLevel(k)}
                className="card p-5 text-center"
                style={active ? { borderColor: 'rgba(0, 113, 227, 0.4)', background: 'rgba(0, 113, 227, 0.03)', boxShadow: '0 0 15px rgba(0,113,227,0.05)' } : {}}
              >
                <div style={{
                  fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif',
                  fontWeight: 600,
                  fontSize: 32,
                  color: active ? '#0071e3' : '#ffffff',
                  letterSpacing: '-0.04em',
                  lineHeight: 1
                }}>
                  {count}
                </div>
                <div style={{ fontSize: 10, color: active ? '#ffffff' : '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginTop: 8, fontWeight: 600 }}>
                  {l}
                </div>
              </motion.button>
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
            className="input"
            style={{ paddingLeft: 44 }}
          />
        </div>

        {/* Count */}
        <div style={{ fontSize: 11, color: '#86868b', fontFamily: '"IBM Plex Mono"', fontWeight: 600 }}>
          FILTERED RESULTS: {filtered.length} OF {patterns.length} SIGNATURES
        </div>

        {/* List */}
        <div className="space-y-1 pb-8">
          {loading
            ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#86868b', fontSize: 12, fontFamily: '"IBM Plex Mono"' }}>LOADING INTELLIGENCE ENGINE…</div>
            : filtered.length === 0
              ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#86868b', fontSize: 12, fontFamily: '"IBM Plex Mono"' }}>NO SIGNATURES MATCH THE FILTER CRITERIA</div>
              : filtered.map((p, i) => <PatternRow key={p.id} p={p} i={i} />)
          }
        </div>
      </div>
    </div>
  )
}
