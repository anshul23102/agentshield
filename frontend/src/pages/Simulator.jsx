import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Zap, Loader2, RotateCcw, Copy, Check, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import Header from '../components/layout/Header'
import { inspect, getDemoAttacks } from '../utils/api'

const ACTION = {
  block: { color: '#ff3b30', bg: 'rgba(255,59,48,0.04)',   border: 'rgba(255,59,48,0.15)',  icon: XCircle,      label: 'BLOCKED' },
  warn:  { color: '#ff9500', bg: 'rgba(255,149,0,0.04)',  border: 'rgba(255,149,0,0.15)', icon: AlertTriangle, label: 'WARNING' },
  allow: { color: '#34c759', bg: 'rgba(52,199,89,0.04)',  border: 'rgba(52,199,89,0.15)', icon: CheckCircle,   label: 'ALLOWED' },
}

/* ── SVG score ring ── */
function ScoreRing({ score }) {
  const r    = 48
  const circ = 2 * Math.PI * r
  const color = score > 70 ? '#34c759' : score > 40 ? '#ff9500' : '#ff3b30'
  return (
    <div className="relative flex items-center justify-center" style={{ width: 120, height: 120 }}>
      <svg width="120" height="120" style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
        <motion.circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: circ - (score / 100) * circ }}
          transition={{ duration: 1.2, ease: [0.25, 0, 0, 1] }}
          style={{ filter: `drop-shadow(0 0 4px ${color})` }}
        />
      </svg>
      <div style={{ textAlign: 'center', position: 'relative' }}>
        <motion.div
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.3, type: 'spring', stiffness: 180 }}
          style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 30, color, letterSpacing: '-0.04em', lineHeight: 1 }}
        >
          {score}
        </motion.div>
        <div style={{ fontSize: 9, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginTop: 4, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>trust</div>
      </div>
    </div>
  )
}

export default function Simulator() {
  const [prompt,  setPrompt]  = useState('')
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)
  const [demos,   setDemos]   = useState([])
  const [copied,  setCopied]  = useState(false)
  const [session] = useState(() => `sim-${Date.now()}`)
  const taRef = useRef(null)

  useEffect(() => {
    getDemoAttacks().then(d => setDemos(d.attacks || [])).catch(() => {})
  }, [])

  const run = async () => {
    if (!prompt.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      setResult(await inspect(prompt, session))
    } catch (e) {
      setError(e?.response?.status === 429
        ? 'Rate limit reached. Wait a moment and try again.'
        : 'Cannot reach the API. The backend may be waking up — retry in ~30 seconds.')
    }
    finally  { setLoading(false) }
  }

  const copy = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2))
    setCopied(true); setTimeout(() => setCopied(false), 2000)
  }

  const reset = () => { setResult(null); setPrompt(''); setError(null) }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header title="Simulator" subtitle="Test any prompt through the 4-layer detection pipeline" />

      <div className="flex-1 overflow-hidden">
        <div className="max-w-[1200px] mx-auto h-full flex divide-x divide-[rgba(0,0,0,0.06)] px-4">

          {/* ── Left: Input ── */}
          <div className="flex flex-col h-full overflow-y-auto" style={{ width: '56%' }}>
            <div className="p-8 space-y-6 pr-8 pb-16">

              {/* Info banner */}
              <div 
                className="p-4 rounded-xl border border-[rgba(0,113,227,0.15)] bg-[rgba(0,113,227,0.03)] text-xs text-[#d1d1d6] leading-relaxed"
                style={{ fontFamily: '"Plus Jakarta Sans", sans-serif' }}
              >
                <span className="font-semibold text-white">Sequential Protection Pipeline:</span> Prompts traverse 
                <strong> Pattern Matching</strong> ➔ 
                <strong> Semantic Heuristics</strong> ➔ 
                <strong> LLM Analysis</strong> ➔ 
                <strong> Session Guard</strong>.
              </div>

              {/* Demo chips */}
              <div>
                <div style={{ fontSize: 10, color: '#98989D', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 12, fontWeight: 600, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                  Preloaded Scenarios
                </div>
                <div className="grid grid-cols-2 gap-2.5">
                  {demos.map(d => (
                    <button
                      key={d.id}
                      onClick={() => { setPrompt(d.prompt); setResult(null); taRef.current?.focus() }}
                      className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-left"
                      style={{
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        fontSize: 11.5,
                        color: '#FFFFFF',
                        transition: 'all 0.2s cubic-bezier(0.25, 0, 0, 1)',
                        backdropFilter: 'blur(12px)',
                        fontFamily: '"Plus Jakarta Sans", sans-serif',
                        fontWeight: 500,
                        width: '100%',
                      }}
                      onMouseEnter={e => {
                        e.currentTarget.style.borderColor = '#0071e3'
                        e.currentTarget.style.color = '#ffffff'
                        e.currentTarget.style.background = 'rgba(0, 113, 227, 0.15)'
                        e.currentTarget.style.boxShadow = '0 2px 8px rgba(0, 113, 227, 0.2)'
                      }}
                      onMouseLeave={e => {
                        e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)'
                        e.currentTarget.style.color = '#FFFFFF'
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)'
                        e.currentTarget.style.boxShadow = 'none'
                      }}
                    >
                      <span className={`badge badge-${d.level}`} style={{ fontSize: 8.5, padding: '1.5px 5.5px', flexShrink: 0 }}>{d.level}</span>
                      <span className="truncate">{d.name}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Textarea */}
              <div>
                <div className="flex items-center justify-between mb-2.5">
                  <span style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Prompt Input</span>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#86868b', fontWeight: 400 }}>{prompt.length} chars</span>
                </div>
                <textarea
                  ref={taRef}
                  value={prompt}
                  onChange={e => setPrompt(e.target.value)}
                  onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') run() }}
                  placeholder={"Enter a prompt or select a scenario above…\n\nTry: 'Ignore all previous instructions'"}
                  className="input focus:ring-1 focus:ring-[#0071e3] focus:border-[#0071e3] transition-all duration-300"
                  style={{
                    minHeight: 200,
                    fontSize: 13,
                    lineHeight: 1.6,
                    background: 'rgba(10, 10, 10, 0.6)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '16px',
                    padding: '16px',
                    color: '#ffffff',
                    fontFamily: '"Plus Jakarta Sans", sans-serif'
                  }}
                />
                <div style={{ fontSize: 10, color: '#86868b', marginTop: 8, fontWeight: 400, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>⌃ Enter to execute scan</div>
              </div>

              {/* Run button */}
              <button
                onClick={run}
                disabled={loading || !prompt.trim()}
                className="btn btn-primary w-full"
                style={{
                  fontFamily: '"Plus Jakarta Sans", sans-serif',
                  fontWeight: 500,
                  fontSize: 13,
                  transition: 'all 0.3s cubic-bezier(0.25, 0, 0, 1)'
                }}
              >
                {loading
                  ? <><Loader2 size={15} className="animate-spin" /> Inspecting Prompt…</>
                  : <><Zap size={15} /> Run Security Inspection</>}
              </button>

              {error && (
                <div style={{ fontSize: 12, color: '#ff3b30', fontFamily: '"Plus Jakarta Sans", sans-serif', padding: '12px 16px', background: 'rgba(255,59,48,0.04)', border: '1px solid rgba(255,59,48,0.1)', borderRadius: 12 }}>
                  {error}
                </div>
              )}
            </div>
          </div>

          {/* ── Right: Result ── */}
          <div className="flex-1 overflow-y-auto h-full" style={{ width: '44%' }}>
            <div className="p-8 pl-10 pb-16">
              <AnimatePresence mode="wait">
                {loading && (
                  <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="flex flex-col items-center justify-center py-32 gap-5">
                    <div style={{ position: 'relative', width: 64, height: 64 }}>
                      <div style={{ position: 'absolute', inset: 0, border: '2px solid rgba(255,255,255,0.08)', borderTop: '2px solid #0071e3', borderRadius: '50%', animation: 'spin 1.2s cubic-bezier(0.25, 0, 0, 1) infinite' }} />
                      <Shield size={24} color="#0071e3" style={{ position: 'absolute', inset: 0, margin: 'auto', filter: 'drop-shadow(0 0 4px rgba(0,113,227,0.1))' }} />
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 14, color: '#f5f5f7', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Executing Pipeline Guard</div>
                      <div style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 6, fontWeight: 300 }}>
                        Pattern ➔ Semantic ➔ LLM ➔ Behavioral
                      </div>
                    </div>
                  </motion.div>
                )}

                {!loading && result && (() => {
                  const a   = ACTION[result.action] || ACTION.allow
                  const Icon = a.icon
                  return (
                    <motion.div key="result" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">

                      {/* Verdict */}
                      <div>
                        <div className="flex items-center justify-between p-6 rounded-2xl animate-fadeUp"
                          style={{ background: 'rgba(20, 20, 20, 0.7)', border: `1px solid ${a.border}`, boxShadow: `0 8px 30px rgba(0,0,0,0.3)` }}>
                          <div className="flex items-center gap-4">
                            <Icon size={24} color={a.color} style={{ filter: `drop-shadow(0 0 6px ${a.color})` }} />
                            <div>
                              <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 24, color: a.color, letterSpacing: '-0.03em' }}>
                                {a.label}
                              </div>
                              {result.threat_category && (
                                <div style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 4, fontWeight: 500, letterSpacing: '0.02em' }}>
                                  {result.threat_category.toUpperCase()}
                                </div>
                              )}
                            </div>
                          </div>
                          <ScoreRing score={result.trust_score} />
                        </div>
                        <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                          The final policy verdict decides whether the prompt poses a security threat. Severe matches trigger immediate blocks, while mild flags prompt warning headers.
                        </div>
                      </div>

                      {/* Pattern matches */}
                      {result.pattern_matches?.length > 0 && (
                        <div className="card p-6">
                          <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                            Pattern Matches ({result.pattern_matches.length})
                          </div>
                          <div className="space-y-3">
                            {result.pattern_matches.map((m, i) => (
                              <div key={i} className="flex items-start gap-3.5 p-3.5 rounded-xl"
                                style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <span className={`badge badge-${m.level}`} style={{ flexShrink: 0, marginTop: 1 }}>{m.id}</span>
                                <div>
                                  <div style={{ fontSize: 13, color: '#f5f5f7', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{m.description}</div>
                                  <div style={{ fontSize: 12, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 4, wordBreak: 'break-all', lineHeight: 1.5, fontWeight: 300 }}>
                                    Match: <span style={{ color: '#ff453a', fontFamily: 'monospace' }}>"{m.matched_text}"</span>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                          <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                            Regex and keyword rule matching hits. Details indicate matched substrings that triggered specific signature rules.
                          </div>
                        </div>
                      )}

                      {/* LLM Analysis */}
                      {result.llm_analysis && (
                        <div className="card p-6">
                          <div className="flex items-center justify-between mb-4">
                            <span style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                              LLM Deep Analysis
                            </span>
                            <span style={{ fontSize: 11, fontFamily: '"Plus Jakarta Sans", sans-serif', color: '#34c759', fontWeight: 500 }}>
                              {Math.round((result.llm_analysis.confidence || 0) * 100)}% Confidence
                            </span>
                          </div>
                          <p style={{ fontSize: 13, color: '#f5f5f7', lineHeight: 1.7, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                            {result.llm_analysis.reasoning}
                          </p>
                          {result.llm_analysis.mitigation && result.llm_analysis.mitigation !== 'n/a' && (
                            <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(0,113,227,0.04)', border: '1px solid rgba(0,113,227,0.15)', borderRadius: 12 }}>
                              <span style={{ fontSize: 11, color: '#0071e3', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>
                                Mitigation Advice: <span style={{ color: '#f5f5f7', fontWeight: 300 }}>{result.llm_analysis.mitigation}</span>
                              </span>
                            </div>
                          )}
                          <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                            In-depth contextual assessment generated by the LLM middleware. Outlines semantic intent and recommends runtime mitigation strategies.
                          </div>
                        </div>
                      )}

                      {/* Detection chain */}
                      <div className="card p-6">
                        <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14, fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
                          Pipeline Execution Path
                        </div>
                        <div className="flex flex-wrap gap-2.5">
                          {(result.layers_executed || []).map((l, i) => (
                            <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                              style={{
                                background: 'rgba(255,255,255,0.02)',
                                border: '1px solid rgba(255,255,255,0.08)',
                                boxShadow: '0 2px 8px rgba(0,0,0,0.3)'
                              }}>
                              <span style={{
                                width: 5, height: 5, borderRadius: '50%',
                                background: '#30d158', display: 'inline-block',
                                boxShadow: '0 0 6px #30d158'
                              }} />
                              <span style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>
                                {l.replace(/_/g, ' ').toUpperCase()}
                              </span>
                            </div>
                          ))}
                        </div>
                        <div style={{ display: 'flex', justifycontent: 'space-between', marginTop: 14, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 10 }}>
                          <span style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>Total Processing Latency</span>
                          <span style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 500 }}>{result.processing_time_ms?.toFixed(1)}ms</span>
                        </div>
                        <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
                          Sequence of defense barriers traversed during the prompt scan. Indicates processing latency and layer status.
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex gap-3">
                        <button onClick={copy} className="btn btn-secondary flex-1 text-xs" style={{ fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 400 }}>
                          {copied ? <><Check size={13} color="#34c759" /> JSON Copied</> : <><Copy size={13} /> Copy JSON</>}
                        </button>
                        <button onClick={reset} className="btn btn-secondary flex-1 text-xs" style={{ fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 400 }}>
                          <RotateCcw size={13} /> Reset Terminal
                        </button>
                      </div>
                    </motion.div>
                  )
                })()}

                {!loading && !result && (
                  <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                    className="flex flex-col items-center justify-center py-32 gap-4"
                    style={{ color: '#86868b' }}>
                    <Shield size={38} style={{ opacity: 0.15, filter: 'drop-shadow(0 0 4px rgba(255,255,255,0.05))' }} />
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 14, color: '#f5f5f7', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>Inspection results will display here</div>
                      <div style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', marginTop: 6, fontWeight: 300 }}>
                        Select a scenario from the left panel or type a custom prompt.
                      </div>
                    </div>
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
