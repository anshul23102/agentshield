import { useState } from 'react'
import { motion } from 'framer-motion'
import { Copy, Check, Shield, ArrowRight } from 'lucide-react'
import Header from '../components/layout/Header'

function Code({ code, lang = 'python' }) {
  const [copied, setCopied] = useState(false)
  const copy = () => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000) }

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.08)' }}>
      <div className="flex items-center justify-between px-4 py-2.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <span style={{ fontSize: 10, color: '#444', fontFamily: '"IBM Plex Mono"', letterSpacing: '0.04em' }}>{lang}</span>
        <button onClick={copy} className="flex items-center gap-1.5" style={{ fontSize: 10, color: '#444' }}>
          {copied ? <><Check size={10} color="#30D158" /> copied</> : <><Copy size={10} /> copy</>}
        </button>
      </div>
      <pre style={{ padding: '16px 20px', overflowX: 'auto' }}>
        <code style={{ fontFamily: '"IBM Plex Mono"', fontSize: 12, color: '#c0c0c0', lineHeight: 1.7 }}>
          {code}
        </code>
      </pre>
    </div>
  )
}

function Section({ title, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="card p-6 space-y-4"
    >
      <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 16, color: '#f0f0f0', letterSpacing: '-0.02em', paddingBottom: 16, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        {title}
      </div>
      {children}
    </motion.div>
  )
}

export default function Docs() {
  return (
    <div className="h-full flex flex-col overflow-hidden">
      <Header title="SDK & Integration" subtitle="Drop bidirectional protection into any agent in one line" />

      <div className="flex-1 overflow-y-auto p-8 space-y-5">

        <Section title="Quick Start" delay={0}>
          <Code lang="bash" code={`# 1. Start the backend
cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 2. Get a free API key (optional — enables LLM deep analysis)
# GitHub Models: github.com/settings/tokens (no scopes needed)
# Add to backend/.env → GITHUB_TOKEN=ghp_xxxxxx

# 3. Start the dashboard
cd frontend && npm run dev`} />
        </Section>

        <Section title="Bidirectional Protection" delay={0.05}>
          <p style={{ fontSize: 13, color: '#666', lineHeight: 1.7 }}>
            AgentShield guards both the <span style={{ color: '#f0f0f0' }}>input surface</span> (attacks
            coming in) and the <span style={{ color: '#f0f0f0' }}>output surface</span> (sensitive data
            leaking out). Most agent security tools only do the former.
          </p>

          {/* Flow */}
          <div className="flex items-center gap-2 flex-wrap py-2">
            {['User Input', 'Input Guard', 'Agent', 'Output Guard', 'Safe Response'].map((s, i, arr) => (
              <div key={i} className="flex items-center gap-2">
                <div style={{ padding: '6px 14px', borderRadius: 999, background: i === 1 || i === 3 ? 'rgba(10,132,255,0.1)' : 'rgba(255,255,255,0.04)', border: `1px solid ${i === 1 || i === 3 ? 'rgba(10,132,255,0.25)' : 'rgba(255,255,255,0.08)'}`, fontSize: 12, color: i === 1 || i === 3 ? '#0A84FF' : '#666', fontWeight: i === 1 || i === 3 ? 500 : 400 }}>
                  {s}
                </div>
                {i < arr.length - 1 && <ArrowRight size={12} color="#333" />}
              </div>
            ))}
          </div>

          <Code lang="python" code={`from agentshield_sdk import AgentShield

shield = AgentShield(base_url="http://localhost:8000")

# ── INPUT: block attacks before they reach the agent ──
verdict = shield.inspect(user_input)
if not verdict.is_safe:
    return f"Blocked ({verdict.action}): {verdict.reasoning}"

# ── Run your agent ────────────────────────────────────
raw_response = your_agent.run(user_input)

# ── OUTPUT: redact secrets/PII before they leave ─────
scan = shield.scan_output(raw_response)
return scan.redacted_text   # secrets automatically masked`} />
        </Section>

        <Section title="Multi-Turn Session Tracking" delay={0.1}>
          <p style={{ fontSize: 13, color: '#666', lineHeight: 1.7 }}>
            Session context enables Layer 4 behavioral analysis — detecting escalating
            multi-step attacks that look innocent one turn at a time.
          </p>
          <Code lang="python" code={`from agentshield_sdk import AgentShield, ShieldedSession

shield = AgentShield()

with ShieldedSession(shield, session_id="user-123") as sess:
    for msg in conversation:
        result = sess.inspect(msg)
        if result.is_blocked:
            print(f"Session compromised after {sess.block_count} blocks")
            break
        response = agent.run(msg)
        safe = shield.scan_output(response)
        yield safe.redacted_text`} />
        </Section>

        <Section title="REST API Reference" delay={0.15}>
          <div className="space-y-3">
            {[
              { method: 'POST', path: '/api/inspect',      color: '#0A84FF', desc: 'Inspect a prompt — full 4-layer input detection' },
              { method: 'POST', path: '/api/inspect/batch',color: '#0A84FF', desc: 'Batch inspect up to 50 prompts (parallel async)' },
              { method: 'POST', path: '/api/scan/output',  color: '#30D158', desc: 'Scan agent output — 23 data-leak signatures + redaction' },
              { method: 'GET',  path: '/api/analytics',    color: '#FF9F0A', desc: 'Full analytics: totals, categories, daily trend, hourly' },
              { method: 'GET',  path: '/api/patterns',     color: '#FF9F0A', desc: 'Browse the input attack pattern database' },
              { method: 'GET',  path: '/api/output/patterns', color: '#FF9F0A', desc: 'Browse the output data-leak signature database' },
              { method: 'WS',   path: '/ws/live',          color: '#BF5AF2', desc: 'WebSocket — real-time threat event stream' },
            ].map((e, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', fontWeight: 500, color: e.color, flexShrink: 0, padding: '2px 8px', background: `${e.color}18`, borderRadius: 4, border: `1px solid ${e.color}33`, marginTop: 2 }}>
                  {e.method}
                </span>
                <div>
                  <div style={{ fontSize: 12, fontFamily: '"IBM Plex Mono"', color: '#f0f0f0' }}>{e.path}</div>
                  <div style={{ fontSize: 11, color: '#555', marginTop: 3 }}>{e.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Section>

        <Section title="Detection Architecture" delay={0.2}>
          <div className="space-y-3">
            {[
              { n: 1, title: 'Pattern Matching', time: '<1ms',   color: '#FF3B30', desc: '54 compiled regex signatures across 10 categories. Critical patterns block immediately, no API call needed.' },
              { n: 2, title: 'Keyword Semantic', time: '~1ms',   color: '#FF9F0A', desc: '40+ keyword signals in 3 tiers (critical/high/medium). Runs entirely in-process.' },
              { n: 3, title: 'LLM Deep Analysis',time: '~500ms', color: '#0A84FF', desc: 'GitHub Models (GPT-4o-mini, free) performs contextual threat analysis with reasoning and mitigation advice.' },
              { n: 4, title: 'Behavioral Analysis',time: 'parallel',color:'#30D158',desc: 'Session-aware tracking detects multi-turn escalation, high message rates, and gradual context poisoning.' },
            ].map(l => (
              <div key={l.n} className="flex gap-4 p-4 rounded-xl" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ width: 32, height: 32, borderRadius: 8, background: `${l.color}12`, border: `1px solid ${l.color}25`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 13, color: l.color }}>
                  {l.n}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span style={{ fontSize: 13, fontWeight: 600, color: '#888' }}>{l.title}</span>
                    <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: l.color, padding: '1px 6px', background: `${l.color}12`, borderRadius: 4 }}>{l.time}</span>
                  </div>
                  <p style={{ fontSize: 12, color: '#555', lineHeight: 1.6 }}>{l.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>

      </div>
    </div>
  )
}
