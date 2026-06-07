import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Zap, Loader2, RotateCcw, Copy, Check, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import Header from '../components/layout/Header'
import { inspect, getDemoAttacks } from '../utils/api'

const ACTION = {
  block: { color: '#ff453a', bg: 'rgba(255,69,58,0.06)',   border: 'rgba(255,69,58,0.25)',  icon: XCircle,      label: 'BLOCKED' },
  warn:  { color: '#ffb340', bg: 'rgba(255,179,64,0.06)',  border: 'rgba(255,179,64,0.25)', icon: AlertTriangle, label: 'WARNING' },
  allow: { color: '#34d399', bg: 'rgba(52,211,153,0.06)',  border: 'rgba(52,211,153,0.25)', icon: CheckCircle,   label: 'ALLOWED' },
}

/* ── SVG score ring ── */
function ScoreRing({ score }) {
  const r    = 48
  const circ = 2 * Math.PI * r
  const color = score > 70 ? '#30d158' : score > 40 ? '#ff9f0a' : '#ff453a'
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
          transition={{ duration: 1.2, ease: [0.4, 0, 0.2, 1] }}
          style={{ filter: `drop-shadow(0 0 4px ${color})` }}
        />
      </svg>
      <div style={{ textAlign: 'center', position: 'relative' }}>
        <motion.div
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.3, type: 'spring', stiffness: 180 }}
          style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontWeight: 600, fontSize: 30, color, letterSpacing: '-0.04em', lineHeight: 1 }}
        >
          {score}
        </motion.div>
        <div style={{ fontSize: 9, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginTop: 4, fontWeight: 600 }}>trust</div>
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
    } catch { setError('Cannot reach the API. Is the backend running on :8000?') }
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

      <div className="flex-1 overflow-hidden flex">

        {/* ── Left: Input ── */}
        <div className="flex flex-col" style={{ width: '50%', borderRight: '1px solid rgba(255,255,255,0.06)', overflowY: 'auto' }}>
          <div className="p-6 space-y-6">

            {/* Demo chips */}
            <div>
              <p style={{ fontSize: 12.5, color: '#86868b', lineHeight: 1.6, marginBottom: 16 }}>
                Test incoming prompts against our sequential guard layers. Prompts are analyzed through:
                <br />
                <strong style={{ color: '#f5f5f7', fontWeight: 500 }}>Pattern Matching ➔ Keyword Semantics ➔ LLM Deep Reasoning ➔ Behavioral Limits</strong>.
              </p>
              <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 12, fontWeight: 600 }}>
                Preloaded Scenarios
              </div>
              <div className="flex flex-wrap gap-2">
                {demos.map(d => (
                  <button
                    key={d.id}
                    onClick={() => { setPrompt(d.prompt); setResult(null); taRef.current?.focus() }}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-full"
                    style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                      fontSize: 11,
                      color: '#a1a1aa',
                      transition: 'all 0.2s ease',
                      backdropFilter: 'blur(8px)',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(0, 113, 227, 0.3)'; e.currentTarget.style.color = '#ffffff' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.05)'; e.currentTarget.style.color = '#a1a1aa' }}
                  >
                    <span className={`badge badge-${d.level}`} style={{ fontSize: 9, padding: '1px 5px' }}>{d.level}</span>
                    <span style={{ fontWeight: 500 }}>{d.name}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Textarea */}
            <div>
              <div className="flex items-center justify-between mb-2.5">
                <span style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 600 }}>Prompt Input</span>
                <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: '#86868b', fontWeight: 500 }}>{prompt.length} chars</span>
              </div>
              <textarea
                ref={taRef}
                value={prompt}
                onChange={e => setPrompt(e.target.value)}
                onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') run() }}
                placeholder={"Enter a prompt or select a scenario above…\n\nTry: 'Ignore all previous instructions'"}
                className="input"
                style={{ minHeight: 240, fontSize: 13, lineHeight: 1.6 }}
              />
              <div style={{ fontSize: 10, color: '#71717a', marginTop: 8, fontWeight: 500 }}>⌃ Enter to execute scan</div>
            </div>

            {/* Run button */}
            <button
              onClick={run}
              disabled={loading || !prompt.trim()}
              className="btn btn-primary w-full"
            >
              {loading
                ? <><Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} /> Inspecting Prompt…</>
                : <><Zap size={15} /> Run Security Inspection</>}
            </button>

            {error && (
              <div style={{ fontSize: 12, color: '#ff453a', fontFamily: '"IBM Plex Mono"', padding: '12px 16px', background: 'rgba(255,69,58,0.06)', border: '1px solid rgba(255,69,58,0.15)', borderRadius: 10 }}>
                {error}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Result ── */}
        <div className="flex-1 overflow-y-auto p-6 bg-[rgba(3,3,3,0.2)]">
          <AnimatePresence mode="wait">
            {loading && (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center h-full gap-5">
                <div style={{ position: 'relative', width: 64, height: 64 }}>
                  <div style={{ position: 'absolute', inset: 0, border: '2px solid rgba(255,255,255,0.04)', borderTop: '2px solid #0a84ff', borderRadius: '50%', animation: 'spin 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite' }} />
                  <Shield size={24} color="#0a84ff" style={{ position: 'absolute', inset: 0, margin: 'auto', filter: 'drop-shadow(0 0 4px rgba(10,132,255,0.3))' }} />
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 14, color: '#ffffff', fontWeight: 600 }}>Executing Pipeline Guard</div>
                  <div style={{ fontSize: 11, color: '#9ca3af', fontFamily: '"IBM Plex Mono"', marginTop: 6, fontWeight: 500 }}>
                    Pattern ➔ Semantic ➔ LLM ➔ Behavioral
                  </div>
                </div>
              </motion.div>
            )}

            {!loading && result && (() => {
              const a   = ACTION[result.action] || ACTION.allow
              const Icon = a.icon
              return (
                <motion.div key="result" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">

                  {/* Verdict */}
                  <div>
                    <div className="flex items-center justify-between p-6 rounded-2xl"
                      style={{ background: a.bg, border: `1px solid ${a.border}`, boxShadow: `0 8px 30px rgba(0,0,0,0.3)` }}>
                      <div className="flex items-center gap-4">
                        <Icon size={24} color={a.color} style={{ filter: `drop-shadow(0 0 6px ${a.color})` }} />
                        <div>
                          <div style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontWeight: 600, fontSize: 24, color: a.color, letterSpacing: '-0.03em' }}>
                            {a.label}
                          </div>
                          {result.threat_category && (
                            <div style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"IBM Plex Mono"', marginTop: 4, fontWeight: 600 }}>
                              {result.threat_category.toUpperCase()}
                            </div>
                          )}
                        </div>
                      </div>
                      <ScoreRing score={result.trust_score} />
                    </div>
                    <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5 }}>
                      The final policy verdict decides whether the prompt poses a security threat. Severe matches trigger immediate blocks, while mild flags prompt warning headers.
                    </div>
                  </div>

                  {/* Pattern matches */}
                  {result.pattern_matches?.length > 0 && (
                    <div className="card p-5">
                      <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14, fontWeight: 600 }}>
                        Pattern Matches ({result.pattern_matches.length})
                      </div>
                      <div className="space-y-3">
                        {result.pattern_matches.map((m, i) => (
                          <div key={i} className="flex items-start gap-3.5 p-3.5 rounded-xl"
                            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className={`badge badge-${m.level}`} style={{ flexShrink: 0, marginTop: 1 }}>{m.id}</span>
                            <div>
                              <div style={{ fontSize: 13, color: '#ffffff', fontWeight: 600 }}>{m.description}</div>
                              <div style={{ fontSize: 12, color: '#d2d2d7', fontFamily: '"IBM Plex Mono"', marginTop: 4, wordBreak: 'break-all', lineHeight: 1.5 }}>
                                Match: <span style={{ color: '#ff453a' }}>"{m.matched_text}"</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                      <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 8 }}>
                        Regex and keyword rule matching hits. Details indicate matched substrings that triggered specific signature rules.
                      </div>
                    </div>
                  )}

                  {/* LLM Analysis */}
                  {result.llm_analysis && (
                    <div className="card p-5">
                      <div className="flex items-center justify-between mb-4">
                        <span style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', fontWeight: 600 }}>
                          LLM Deep Analysis
                        </span>
                        <span style={{ fontSize: 11, fontFamily: '"IBM Plex Mono"', color: '#30d158', fontWeight: 600 }}>
                          {Math.round((result.llm_analysis.confidence || 0) * 100)}% Confidence
                        </span>
                      </div>
                      <p style={{ fontSize: 13, color: '#f5f5f7', lineHeight: 1.7, fontWeight: 400 }}>
                        {result.llm_analysis.reasoning}
                      </p>
                      {result.llm_analysis.mitigation && result.llm_analysis.mitigation !== 'n/a' && (
                        <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(0,113,227,0.06)', border: '1px solid rgba(0,113,227,0.2)', borderRadius: 10 }}>
                          <span style={{ fontSize: 11, color: '#0071e3', fontFamily: '"IBM Plex Mono"', fontWeight: 600 }}>
                            Mitigation Advice: <span style={{ color: '#f5f5f7', fontWeight: 400 }}>{result.llm_analysis.mitigation}</span>
                          </span>
                        </div>
                      )}
                      <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 8 }}>
                        In-depth contextual assessment generated by the LLM middleware. Outlines semantic intent and recommends runtime mitigation strategies.
                      </div>
                    </div>
                  )}

                  {/* Detection chain */}
                  <div className="card p-5">
                    <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14, fontWeight: 600 }}>
                      Pipeline Execution Path
                    </div>
                    <div className="flex flex-wrap gap-2.5">
                      {(result.layers_executed || []).map((l, i) => (
                        <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                          style={{
                            background: 'rgba(255,255,255,0.02)',
                            border: '1px solid rgba(255,255,255,0.06)',
                            boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
                          }}>
                          <span style={{
                            width: 5, height: 5, borderRadius: '50%',
                            background: '#30d158', display: 'inline-block',
                            boxShadow: '0 0 6px #30d158'
                          }} />
                          <span style={{ fontSize: 11, color: '#ffffff', fontFamily: '"IBM Plex Mono"', fontWeight: 600 }}>
                            {l.replace(/_/g, ' ').toUpperCase()}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div style={{ display: 'flex', justifycontent: 'space-between', marginTop: 14, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 10 }}>
                      <span style={{ fontSize: 11, color: '#86868b', fontFamily: '"IBM Plex Mono"', fontWeight: 500 }}>Total Processing Latency</span>
                      <span style={{ fontSize: 11, color: '#ffffff', fontFamily: '"IBM Plex Mono"', fontWeight: 600 }}>{result.processing_time_ms?.toFixed(1)}ms</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#86868b', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: 8 }}>
                      Sequence of defense barriers traversed during the prompt scan. Indicates processing latency and layer status.
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-3">
                    <button onClick={copy} className="btn btn-secondary flex-1 text-xs">
                      {copied ? <><Check size={13} color="#30d158" /> JSON Copied</> : <><Copy size={13} /> Copy JSON</>}
                    </button>
                    <button onClick={reset} className="btn btn-secondary flex-1 text-xs">
                      <RotateCcw size={13} /> Reset Terminal
                    </button>
                  </div>
                </motion.div>
              )
            })()}

            {!loading && !result && (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center h-full gap-4"
                style={{ color: '#86868b' }}>
                <Shield size={38} style={{ opacity: 0.15, filter: 'drop-shadow(0 0 4px rgba(255,255,255,0.05))' }} />
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 14, color: '#f5f5f7', fontWeight: 600 }}>Inspection results will display here</div>
                  <div style={{ fontSize: 11, color: '#86868b', fontFamily: '"IBM Plex Mono"', marginTop: 6, fontWeight: 500 }}>
                    Select a scenario from the left panel or type a custom prompt.
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
