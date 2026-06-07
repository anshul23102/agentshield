import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldCheck, Loader2, RotateCcw, ArrowRight, KeyRound, CreditCard, User, Database, FileWarning } from 'lucide-react'
import Header from '../components/layout/Header'
import { scanOutput, getDemoLeaks, getOutputPatterns } from '../utils/api'

const TYPE_ICONS = {
  'Secret / Credential':            KeyRound,
  'Financial Data':                 CreditCard,
  'Personal Identifiable Information': User,
  'Personal Information':           User,
  'Network / Infrastructure':       Database,
  'Infrastructure':                 Database,
  'System Prompt Leak':             FileWarning,
}

const SEV = { critical: '#FF3B30', high: '#FF9F0A', medium: '#888', low: '#444' }

export default function OutputGuard() {
  const [text,    setText]    = useState('')
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [demos,   setDemos]   = useState([])
  const [stats,   setStats]   = useState(null)
  const taRef = useRef(null)

  useEffect(() => {
    getDemoLeaks().then(d => setDemos(d.leaks || [])).catch(() => {})
    getOutputPatterns().then(setStats).catch(() => {})
  }, [])

  const run = async () => {
    if (!text.trim()) return
    setLoading(true); setResult(null)
    try {
      setTimeout(async () => {
        setResult(await scanOutput(text))
        setLoading(false)
      }, 500)
    } catch { setLoading(false) }
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header
        title="Output Guard"
        subtitle="Bidirectional — scans what your agent sends back"
        right={stats && (
          <div style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"' }}>
            {stats.total} leak signatures
          </div>
        )}
      />

      <div className="flex-1 overflow-y-auto p-8 space-y-6">

        {/* Flow diagram */}
        <div className="card-flat p-4 flex items-center gap-3 flex-wrap" style={{ gap: 12 }}>
          {[
            { label: 'User Input', color: '#555' },
            { label: 'Input Guard', color: '#0A84FF' },
            { label: 'AI Agent', color: '#888' },
            { label: 'Output Guard', color: '#30D158', active: true },
            { label: 'Safe Response', color: '#555' },
          ].map((step, i, arr) => (
            <div key={i} className="flex items-center gap-2">
              <div className="px-3 py-1.5 rounded-lg" style={{
                background: step.active ? 'rgba(48,209,88,0.1)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${step.active ? 'rgba(48,209,88,0.25)' : 'rgba(255,255,255,0.08)'}`,
                fontSize: 12, color: step.color, fontWeight: step.active ? 600 : 400,
              }}>
                {step.label}
              </div>
              {i < arr.length - 1 && <ArrowRight size={12} color="#333" />}
            </div>
          ))}
          <p style={{ fontSize: 11, color: '#555', marginLeft: 'auto', maxWidth: 280, textAlign: 'right', lineHeight: 1.5 }}>
            Most defenses only guard what goes <em>in</em>. AgentShield also
            guards what comes <em>out</em> — blocking data exfiltration.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-6">

          {/* Demo scenarios */}
          <div className="space-y-3">
            <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12 }}>
              Simulated Agent Responses
            </div>
            {demos.map(d => {
              const Icon = TYPE_ICONS[d.type] || KeyRound
              const safe = d.type === 'None'
              return (
                <motion.button
                  key={d.id}
                  whileHover={{ x: 3 }}
                  onClick={() => { setText(d.text); setResult(null); taRef.current?.focus() }}
                  className="w-full text-left card-flat p-4 flex items-center gap-3"
                >
                  <div style={{
                    width: 32, height: 32, borderRadius: 8, flexShrink: 0,
                    background: safe ? 'rgba(48,209,88,0.08)' : 'rgba(255,59,48,0.08)',
                    border: `1px solid ${safe ? 'rgba(48,209,88,0.15)' : 'rgba(255,59,48,0.15)'}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Icon size={14} color={safe ? '#30D158' : '#FF3B30'} />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, color: '#888', fontWeight: 500 }}>{d.name}</div>
                    <div style={{ fontSize: 11, color: '#444', fontFamily: '"IBM Plex Mono"', marginTop: 2 }}>{d.type}</div>
                  </div>
                </motion.button>
              )
            })}
          </div>

          {/* Input + result */}
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Agent Output to Scan</span>
                <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: '#333' }}>{text.length} chars</span>
              </div>
              <textarea
                ref={taRef}
                value={text}
                onChange={e => setText(e.target.value)}
                onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') run() }}
                placeholder={"Paste an agent response here…\n\nTry: 'Here is the key: AKIAIOSFODNN7EXAMPLE'"}
                className="input"
                style={{ minHeight: 160, fontSize: 12 }}
              />
            </div>

            <button onClick={run} disabled={loading || !text.trim()} className="btn btn-safe w-full">
              {loading
                ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Scanning…</>
                : <><ShieldCheck size={14} /> Scan for Data Leaks</>}
            </button>

            <AnimatePresence>
              {result && (
                <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-3">

                  {/* Verdict */}
                  <div className="card p-4 flex items-center justify-between"
                    style={{ borderColor: result.is_safe ? 'rgba(48,209,88,0.2)' : 'rgba(255,59,48,0.2)' }}>
                    <div>
                      <div style={{ fontFamily: '"Space Grotesk"', fontSize: 18, fontWeight: 700, color: result.is_safe ? '#30D158' : '#FF3B30', letterSpacing: '-0.03em' }}>
                        {result.is_safe ? 'Output Clean' : `${result.leaks_found.length} Leak${result.leaks_found.length > 1 ? 's' : ''} Redacted`}
                      </div>
                      <div style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"', marginTop: 4, lineHeight: 1.5 }}>
                        {result.reasoning}
                      </div>
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 16 }}>
                      <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 28, color: result.risk_score > 70 ? '#30D158' : result.risk_score > 40 ? '#FF9F0A' : '#FF3B30', letterSpacing: '-0.04em' }}>
                        {result.risk_score}
                      </div>
                      <div style={{ fontSize: 9, color: '#444', letterSpacing: '0.06em', textTransform: 'uppercase' }}>safety</div>
                    </div>
                  </div>

                  {/* Leaks */}
                  {result.leaks_found.length > 0 && (
                    <div className="card p-4">
                      <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 10 }}>
                        Detected
                      </div>
                      <div className="space-y-2">
                        {result.leaks_found.map((l, i) => {
                          const Icon = TYPE_ICONS[l.leak_type] || KeyRound
                          return (
                            <div key={i} className="flex items-center gap-3 p-2 rounded-lg"
                              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                              <Icon size={12} color={SEV[l.severity] || '#888'} />
                              <span style={{ fontSize: 12, color: '#777', flex: 1 }}>{l.description}</span>
                              <span className={`badge badge-${l.severity}`}>{l.severity}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Before / after */}
                  <div className="card p-4">
                    <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12 }}>
                      Redaction Result
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <div style={{ fontSize: 10, color: '#FF3B30', marginBottom: 6, letterSpacing: '0.04em' }}>RAW (unsafe)</div>
                        <div style={{ padding: '10px 12px', background: 'rgba(255,59,48,0.05)', border: '1px solid rgba(255,59,48,0.15)', borderRadius: 8, fontSize: 11, fontFamily: '"IBM Plex Mono"', color: '#ff7b73', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6, minHeight: 80 }}>
                          {text}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: 10, color: '#30D158', marginBottom: 6, letterSpacing: '0.04em' }}>SHIELDED (safe)</div>
                        <div style={{ padding: '10px 12px', background: 'rgba(48,209,88,0.05)', border: '1px solid rgba(48,209,88,0.15)', borderRadius: 8, fontSize: 11, fontFamily: '"IBM Plex Mono"', color: '#6de593', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6, minHeight: 80 }}>
                          {result.redacted_text}
                        </div>
                      </div>
                    </div>
                  </div>

                  <button onClick={() => { setResult(null); setText('') }} className="btn btn-secondary w-full text-xs">
                    <RotateCcw size={12} /> Scan another
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  )
}
