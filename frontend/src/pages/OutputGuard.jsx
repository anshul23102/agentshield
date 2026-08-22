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

const SEV = { critical: '#ff453a', high: '#ffb340', medium: '#a1a1aa', low: '#71717a' }

export default function OutputGuard() {
  const [text,    setText]    = useState('')
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)
  const [demos,   setDemos]   = useState([])
  const [stats,   setStats]   = useState(null)
  const taRef = useRef(null)

  useEffect(() => {
    getDemoLeaks().then(d => setDemos(d.leaks || [])).catch(() => {})
    getOutputPatterns().then(setStats).catch(() => {})
  }, [])

  const run = async () => {
    if (!text.trim()) return
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await scanOutput(text))
    } catch (e) {
      setError(e?.response?.status === 429
        ? 'Rate limit reached. Wait a moment and try again.'
        : 'Cannot reach the API. The backend may be waking up — retry in ~30 seconds.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header
        title="Output Guard"
        subtitle="Bidirectional protection: scans what your agent sends back"
        right={stats && (
          <div style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>
            {stats.total} leak signatures loaded
          </div>
        )}
      />

      <div className="flex-1 overflow-y-auto p-6 sm:p-8 lg:p-10 pb-14">
        <div className="max-w-[1240px] mx-auto space-y-10">

          {/* Flow diagram */}
          <div className="panel flex items-center gap-3 flex-wrap" style={{ gap: 12, paddingBottom: 20, borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            {[
              { label: 'User Input', color: '#86868b' },
              { label: 'Input Guard', color: '#0071e3', activeBorder: 'rgba(0, 113, 227, 0.3)', shadow: '0 0 10px rgba(0, 113, 227, 0.15)' },
              { label: 'Agent Core', color: '#86868b' },
              { label: 'Output Guard', color: '#30d158', active: true, activeBorder: 'rgba(48, 209, 88, 0.3)', shadow: '0 0 12px rgba(48, 209, 88, 0.2)' },
              { label: 'Safe Response', color: '#f5f5f7', activeBorder: 'rgba(255,255,255,0.08)' },
            ].map((step, i, arr) => (
              <div key={i} className="flex items-center gap-2">
                <div className="px-3.5 py-2 rounded-lg" style={{
                  background: step.active ? 'rgba(52,199,89,0.04)' : 'rgba(255,255,255,0.01)',
                  border: `1px solid ${step.activeBorder || 'rgba(255, 255, 255, 0.08)'}`,
                  boxShadow: step.shadow || 'none',
                  fontSize: 12, color: step.color, fontWeight: step.active || i === 4 ? 600 : 400,
                  fontFamily: '"Plus Jakarta Sans", sans-serif'
                }}>
                  {step.label}
                </div>
                {i < arr.length - 1 && <ArrowRight size={12} color="#86868b" />}
              </div>
            ))}
            <p style={{ fontSize: 11, color: '#86868b', marginLeft: 'auto', maxWidth: 280, textAlign: 'right', lineHeight: 1.6, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
              Most defenses only guard what goes <em style={{ color: '#0071e3', fontStyle: 'normal', fontWeight: 500 }}>in</em>. AgentShield also
              guards what comes <em style={{ color: '#30d158', fontStyle: 'normal', fontWeight: 500 }}>out</em>, blocking data exfiltration.
            </p>
            <div style={{ fontSize: 11, color: '#86868b', width: '100%', marginTop: 12, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 10, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
              Verifies agent outputs before delivery. Prevents data exfiltration, system prompt leakage, and exposed API credentials.
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 xl:gap-0">

            {/* Demo scenarios */}
            <div className="space-y-4">
              <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 6, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                Simulated Agent Outputs
              </div>
              <p style={{ fontSize: 13, color: '#86868b', lineHeight: 1.6, marginBottom: 12, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                Select a payload simulation to test how Output Guard isolates vulnerabilities:
              </p>
              <div className="row-list">
                {demos.map(d => {
                  const Icon = TYPE_ICONS[d.type] || KeyRound
                  const safe = d.type === 'None'
                  return (
                    <motion.button
                      key={d.id}
                      whileHover={{ x: 4 }}
                      onClick={() => { setText(d.text); setResult(null); taRef.current?.focus() }}
                      className="row-item w-full text-left transition-all duration-300"
                      style={{ background: 'none', borderTop: 'none', borderLeft: 'none', borderRight: 'none' }}
                    >
                      <div style={{
                        width: 30, height: 30, borderRadius: 8, flexShrink: 0,
                        background: safe ? 'rgba(52,199,89,0.08)' : 'rgba(255,59,48,0.08)',
                        border: `1px solid ${safe ? 'rgba(52,199,89,0.2)' : 'rgba(255,59,48,0.2)'}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                      }}>
                        <Icon size={13} color={safe ? '#30d158' : '#ff453a'} />
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 13, color: '#f5f5f7', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{d.name}</div>
                        <div style={{ fontSize: 11, color: '#98989D', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 3, fontWeight: 400 }}>{d.type.toUpperCase()}</div>
                      </div>
                    </motion.button>
                  )
                })}
              </div>
            </div>

            {/* Input + result */}
            <div className="space-y-6 panel-divide">
              <div>
                <div className="flex items-center justify-between mb-2.5">
                  <span style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Response Payload to Scan</span>
                  <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: '#86868b', fontWeight: 400 }}>{text.length} chars</span>
                </div>
                <textarea
                  ref={taRef}
                  value={text}
                  onChange={e => setText(e.target.value)}
                  onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') run() }}
                  placeholder={"Paste an agent response here…\n\nTry: 'Here is the key: AKIAIOSFODNN7EXAMPLE'"}
                  className="input focus:ring-1 focus:ring-[#30d158] focus:border-[#30d158] transition-all duration-300"
                  style={{
                    minHeight: 180,
                    fontSize: 13,
                    lineHeight: 1.6,
                    background: 'rgba(10, 10, 10, 0.6)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '16px',
                    padding: '16px',
                    color: '#f5f5f7',
                    fontFamily: '"Plus Jakarta Sans", sans-serif'
                  }}
                />
              </div>

              <button
                onClick={run}
                disabled={loading || !text.trim()}
                className="btn btn-safe w-full"
                style={{ fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500, transition: 'all 0.3s cubic-bezier(0.25, 0, 0, 1)' }}
              >
                {loading
                  ? <><Loader2 size={15} className="animate-spin" /> Scanning payload…</>
                  : <><ShieldCheck size={15} /> Scan agent output</>}
              </button>

              {error && (
                <div style={{ fontSize: 12, color: '#ff453a', fontFamily: '"Plus Jakarta Sans", sans-serif', padding: '12px 16px', background: 'rgba(255,69,58,0.05)', border: '1px solid rgba(255,69,58,0.15)', borderRadius: 12 }}>
                  {error}
                </div>
              )}

              <AnimatePresence>
                {result && (
                  <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-6">

                    {/* Verdict */}
                    <div>
                      <div className="flex items-center justify-between"
                        style={{ borderLeft: `2px solid ${result.is_safe ? 'rgba(52,199,89,0.5)' : 'rgba(255,59,48,0.5)'}`, paddingLeft: 16 }}>
                        <div>
                          <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontSize: 20, fontWeight: 600, color: result.is_safe ? '#30d158' : '#ff453a', letterSpacing: '-0.02em' }}>
                            {result.is_safe ? 'PAYLOAD CLEAN' : `${result.leaks_found.length} DATA LEAKS REDACTED`}
                          </div>
                          <div style={{ fontSize: 12, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 6, lineHeight: 1.5, fontWeight: 300 }}>
                            {result.reasoning}
                          </div>
                        </div>
                        <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 16 }}>
                          <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 30, color: result.risk_score > 70 ? '#30d158' : result.risk_score > 40 ? '#ff9f0a' : '#ff453a', letterSpacing: '-0.04em', filter: `drop-shadow(0 0 4px ${result.risk_score > 70 ? '#30d158' : '#ff9f0a'})` }}>
                            {result.risk_score}
                          </div>
                          <div style={{ fontSize: 9, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>safety</div>
                        </div>
                      </div>
                      <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300, paddingLeft: 16 }}>
                        Verifies agent outputs before delivery. Prevents data exfiltration, system prompt leakage, and exposed API credentials.
                      </div>
                    </div>

                    {/* Leaks */}
                    {result.leaks_found.length > 0 && (
                      <div className="panel" style={{ paddingTop: 20, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
                        <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 12, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                          Exfiltration Signatures Detected
                        </div>
                        <div className="space-y-2.5">
                          {result.leaks_found.map((l, i) => {
                            const Icon = TYPE_ICONS[l.leak_type] || KeyRound
                            const color = SEV[l.severity] || '#86868b'
                            return (
                              <div key={i} className="flex items-center gap-3.5 p-3 rounded-xl"
                                style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <Icon size={13} color={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
                                <span style={{ fontSize: 13, color: '#f5f5f7', flex: 1, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{l.description}</span>
                                <span className={`badge badge-${l.severity}`} style={{ fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>{l.severity}</span>
                              </div>
                            )
                          })}
                        </div>
                        <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 8, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                          List of patterns matched in the agent output. System automatically redacts these segments before sending them.
                        </div>
                      </div>
                    )}

                    {/* Before / after */}
                    <div className="panel" style={{ paddingTop: 20, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
                      <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 12, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                        Sanitization Analysis
                      </div>
                      <div className="grid grid-cols-2 gap-3.5">
                        <div>
                          <div style={{ fontSize: 10, color: '#ff453a', marginBottom: 6, letterSpacing: '0.05em', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>RAW (unsafe)</div>
                          <div style={{ padding: '12px 14px', background: 'rgba(255,69,58,0.04)', border: '1px solid rgba(255,69,58,0.18)', borderRadius: 12, fontSize: 12, fontFamily: 'monospace', color: '#ff453a', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6, minHeight: 90 }}>
                            {text}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: 10, color: '#30d158', marginBottom: 6, letterSpacing: '0.05em', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>SHIELDED (safe)</div>
                          <div style={{ padding: '12px 14px', background: 'rgba(48,209,88,0.04)', border: '1px solid rgba(48,209,88,0.18)', borderRadius: 12, fontSize: 12, fontFamily: 'monospace', color: '#30d158', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6, minHeight: 90 }}>
                            {result.redacted_text}
                          </div>
                        </div>
                      </div>
                      <div style={{ fontSize: 11, color: '#86868b', marginTop: 12, lineHeight: 1.5, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 10, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                        Redacts sensitive matches in real-time. Safe tokens are replaced with masked placeholders while preserving non-sensitive context.
                      </div>
                    </div>

                    <button
                      onClick={() => { setResult(null); setText('') }}
                      className="btn btn-secondary w-full text-xs"
                      style={{ fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 400 }}
                    >
                      <RotateCcw size={12} /> Scan Another Payload
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
