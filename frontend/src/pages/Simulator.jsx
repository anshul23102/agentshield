import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Zap, Loader2, RotateCcw, Copy, Check, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import Header from '../components/layout/Header'
import { inspect, getDemoAttacks } from '../utils/api'

const ACTION = {
  block: { color: '#FF3B30', bg: 'rgba(255,59,48,0.08)',   border: 'rgba(255,59,48,0.2)',   icon: XCircle,      label: 'BLOCKED' },
  warn:  { color: '#FF9F0A', bg: 'rgba(255,159,10,0.08)',  border: 'rgba(255,159,10,0.2)',  icon: AlertTriangle, label: 'WARNING' },
  allow: { color: '#30D158', bg: 'rgba(48,209,88,0.08)',   border: 'rgba(48,209,88,0.2)',   icon: CheckCircle,   label: 'ALLOWED' },
}

/* ── SVG score ring ── */
function ScoreRing({ score }) {
  const r    = 48
  const circ = 2 * Math.PI * r
  const color = score > 70 ? '#30D158' : score > 40 ? '#FF9F0A' : '#FF3B30'
  return (
    <div className="relative flex items-center justify-center" style={{ width: 120, height: 120 }}>
      <svg width="120" height="120" style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <motion.circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: circ - (score / 100) * circ }}
          transition={{ duration: 1.2, ease: [0.4, 0, 0.2, 1] }}
        />
      </svg>
      <div style={{ textAlign: 'center', position: 'relative' }}>
        <motion.div
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.3, type: 'spring', stiffness: 180 }}
          style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 28, color, letterSpacing: '-0.04em', lineHeight: 1 }}
        >
          {score}
        </motion.div>
        <div style={{ fontSize: 9, color: '#444', letterSpacing: '0.06em', textTransform: 'uppercase', marginTop: 4 }}>trust</div>
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
          <div className="p-6 space-y-5">

            {/* Demo chips */}
            <div>
              <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 10 }}>
                Preloaded scenarios
              </div>
              <div className="flex flex-wrap gap-2">
                {demos.map(d => (
                  <button
                    key={d.id}
                    onClick={() => { setPrompt(d.prompt); setResult(null); taRef.current?.focus() }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-full"
                    style={{
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      fontSize: 11, color: '#666',
                      transition: 'all 0.15s ease',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'; e.currentTarget.style.color = '#f0f0f0' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = '#666' }}
                  >
                    <span className={`badge badge-${d.level}`} style={{ fontSize: 9, padding: '1px 5px' }}>{d.level}</span>
                    {d.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Textarea */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Prompt</span>
                <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: '#333' }}>{prompt.length} chars</span>
              </div>
              <textarea
                ref={taRef}
                value={prompt}
                onChange={e => setPrompt(e.target.value)}
                onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') run() }}
                placeholder={"Enter a prompt or select a scenario above…\n\nTry: 'Ignore all previous instructions'"}
                className="input"
                style={{ minHeight: 220, fontSize: 12 }}
              />
              <div style={{ fontSize: 10, color: '#333', marginTop: 6 }}>⌃ Enter to run</div>
            </div>

            {/* Run button */}
            <button
              onClick={run}
              disabled={loading || !prompt.trim()}
              className="btn btn-primary w-full"
            >
              {loading
                ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Analyzing…</>
                : <><Zap size={14} /> Run Shield Analysis</>}
            </button>

            {error && (
              <div style={{ fontSize: 12, color: '#FF3B30', fontFamily: '"IBM Plex Mono"', padding: '10px 14px', background: 'rgba(255,59,48,0.06)', border: '1px solid rgba(255,59,48,0.15)', borderRadius: 8 }}>
                {error}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Result ── */}
        <div className="flex-1 overflow-y-auto p-6">
          <AnimatePresence mode="wait">
            {loading && (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center h-full gap-5">
                <div style={{ position: 'relative', width: 56, height: 56 }}>
                  <div style={{ position: 'absolute', inset: 0, border: '1px solid rgba(255,255,255,0.06)', borderTop: '1px solid rgba(255,255,255,0.4)', borderRadius: '50%', animation: 'spin 1.5s linear infinite' }} />
                  <Shield size={20} color="#444" style={{ position: 'absolute', inset: 0, margin: 'auto' }} />
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 13, color: '#555' }}>Running detection pipeline</div>
                  <div style={{ fontSize: 11, color: '#333', fontFamily: '"IBM Plex Mono"', marginTop: 4 }}>
                    Pattern → Semantic → LLM → Behavioral
                  </div>
                </div>
              </motion.div>
            )}

            {!loading && result && (() => {
              const a   = ACTION[result.action] || ACTION.allow
              const Icon = a.icon
              return (
                <motion.div key="result" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">

                  {/* Verdict */}
                  <div className="flex items-center justify-between p-5 rounded-xl"
                    style={{ background: a.bg, border: `1px solid ${a.border}` }}>
                    <div className="flex items-center gap-4">
                      <Icon size={22} color={a.color} />
                      <div>
                        <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 22, color: a.color, letterSpacing: '-0.04em' }}>
                          {a.label}
                        </div>
                        {result.threat_category && (
                          <div style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"', marginTop: 3 }}>
                            {result.threat_category}
                          </div>
                        )}
                      </div>
                    </div>
                    <ScoreRing score={result.trust_score} />
                  </div>

                  {/* Pattern matches */}
                  {result.pattern_matches?.length > 0 && (
                    <div className="card p-4">
                      <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12 }}>
                        Pattern Matches ({result.pattern_matches.length})
                      </div>
                      <div className="space-y-2">
                        {result.pattern_matches.map((m, i) => (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg"
                            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                            <span className={`badge badge-${m.level}`} style={{ flexShrink: 0, marginTop: 1 }}>{m.id}</span>
                            <div>
                              <div style={{ fontSize: 12, color: '#888' }}>{m.description}</div>
                              <div style={{ fontSize: 11, color: '#444', fontFamily: '"IBM Plex Mono"', marginTop: 3 }}>
                                → "{m.matched_text}"
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* LLM Analysis */}
                  {result.llm_analysis && (
                    <div className="card p-4">
                      <div className="flex items-center justify-between mb-3">
                        <span style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                          LLM Analysis
                        </span>
                        <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: '#555' }}>
                          {Math.round((result.llm_analysis.confidence || 0) * 100)}% confidence
                        </span>
                      </div>
                      <p style={{ fontSize: 12, color: '#777', lineHeight: 1.6 }}>
                        {result.llm_analysis.reasoning}
                      </p>
                      {result.llm_analysis.mitigation && result.llm_analysis.mitigation !== 'n/a' && (
                        <div style={{ marginTop: 10, padding: '8px 12px', background: 'rgba(10,132,255,0.06)', border: '1px solid rgba(10,132,255,0.12)', borderRadius: 8 }}>
                          <span style={{ fontSize: 11, color: '#0A84FF', fontFamily: '"IBM Plex Mono"' }}>
                            Mitigation: {result.llm_analysis.mitigation}
                          </span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Detection chain */}
                  <div className="card p-4">
                    <div style={{ fontSize: 10, color: '#444', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12 }}>
                      Layers Executed
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {(result.layers_executed || []).map((l, i) => (
                        <div key={i} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
                          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                          <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#30D158', display: 'inline-block' }} />
                          <span style={{ fontSize: 11, color: '#666', fontFamily: '"IBM Plex Mono"' }}>
                            {l.replace(/_/g, ' ')}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                      <span style={{ fontSize: 10, color: '#333', fontFamily: '"IBM Plex Mono"' }}>Processing time</span>
                      <span style={{ fontSize: 10, color: '#555', fontFamily: '"IBM Plex Mono"' }}>{result.processing_time_ms?.toFixed(1)}ms</span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <button onClick={copy} className="btn btn-secondary flex-1 text-xs">
                      {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy JSON</>}
                    </button>
                    <button onClick={reset} className="btn btn-secondary flex-1 text-xs">
                      <RotateCcw size={12} /> Reset
                    </button>
                  </div>
                </motion.div>
              )
            })()}

            {!loading && !result && (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center h-full gap-4"
                style={{ color: '#333' }}>
                <Shield size={36} style={{ opacity: 0.2 }} />
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 13, color: '#444' }}>Results will appear here</div>
                  <div style={{ fontSize: 11, color: '#333', fontFamily: '"IBM Plex Mono"', marginTop: 4 }}>
                    Select a scenario or type a prompt
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
