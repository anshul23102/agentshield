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
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 p-3.5"
        style={{ textAlign: 'left' }}
      >
        <span className={`badge badge-${p.threat_level}`} style={{ flexShrink: 0 }}>{p.threat_level}</span>
        <span style={{ fontSize: 11, color: '#444', fontFamily: '"IBM Plex Mono"', flexShrink: 0, width: 64 }}>{p.id}</span>
        <span style={{ fontSize: 13, color: '#888', flex: 1 }}>{p.description}</span>
        <span style={{ fontSize: 11, color: '#333', flexShrink: 0, display: 'none', width: 180 }}
          className="md:block truncate">
          {p.category}
        </span>
        {open ? <ChevronUp size={13} color="#333" /> : <ChevronDown size={13} color="#333" />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ borderTop: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}
          >
            <div className="p-4 space-y-3" style={{ background: 'rgba(255,255,255,0.01)' }}>
              <div style={{ fontSize: 11, color: '#444' }}>
                Category: <span style={{ color: '#666' }}>{p.category}</span>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#333', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>Example</div>
                <div style={{ fontSize: 12, color: '#777', fontFamily: '"IBM Plex Mono"', lineHeight: 1.6, padding: '10px 14px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8 }}>
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
        <div className="grid grid-cols-5 gap-3">
          {[['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([k, l]) => {
            const count = k === 'all' ? patterns.length : (stats[k] || 0)
            const active = level === k
            return (
              <motion.button
                key={k} whileHover={{ y: -1 }} whileTap={{ y: 0 }}
                onClick={() => setLevel(k)}
                className="card p-4 text-center"
                style={active ? { borderColor: 'rgba(255,255,255,0.18)', background: '#171717' } : {}}
              >
                <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 28, color: '#f0f0f0', letterSpacing: '-0.04em' }}>
                  {count}
                </div>
                <div style={{ fontSize: 10, color: active ? '#888' : '#444', letterSpacing: '0.06em', textTransform: 'uppercase', marginTop: 4 }}>
                  {l}
                </div>
              </motion.button>
            )
          })}
        </div>

        {/* Search */}
        <div className="relative">
          <Search size={13} color="#444" style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by ID, description, category…"
            className="input"
            style={{ paddingLeft: 38 }}
          />
        </div>

        {/* Count */}
        <div style={{ fontSize: 11, color: '#333', fontFamily: '"IBM Plex Mono"' }}>
          {filtered.length} of {patterns.length} patterns
        </div>

        {/* List */}
        <div className="space-y-1">
          {loading
            ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#333', fontSize: 12, fontFamily: '"IBM Plex Mono"' }}>Loading…</div>
            : filtered.length === 0
              ? <div style={{ textAlign: 'center', padding: '48px 0', color: '#333', fontSize: 12, fontFamily: '"IBM Plex Mono"' }}>No patterns match</div>
              : filtered.map((p, i) => <PatternRow key={p.id} p={p} i={i} />)
          }
        </div>
      </div>
    </div>
  )
}
