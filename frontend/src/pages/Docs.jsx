import { useState } from 'react'
import { motion } from 'framer-motion'
import { Copy, Check, ArrowRight } from 'lucide-react'
import Header from '../components/layout/Header'

function Code({ code, lang = 'python' }) {
  const [copied, setCopied] = useState(false)
  const copy = () => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000) }

  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: 'rgba(10, 10, 10, 0.4)', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
      <div className="flex items-center justify-between px-4 py-2.5" style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <span style={{ fontSize: 10, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif', letterSpacing: '0.05em', fontWeight: 500 }}>{lang.toUpperCase()}</span>
        <button onClick={copy} className="flex items-center gap-1.5 hover:text-white transition-colors" style={{ fontSize: 10, color: '#86868b', fontWeight: 400, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
          {copied ? <><Check size={11} color="#30d158" /> copied</> : <><Copy size={11} /> copy</>}
        </button>
      </div>
      <pre style={{ padding: '16px 20px', overflowX: 'auto', margin: 0 }}>
        <code style={{ fontFamily: 'monospace', fontSize: 12, color: '#f5f5f7', lineHeight: 1.7 }}>
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
      className="card p-8 space-y-6"
    >
      <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 18, color: '#ffffff', letterSpacing: '-0.025em', paddingBottom: 16, borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
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

      <div className="flex-1 overflow-y-auto p-8 pb-12">
        <div className="max-w-[1200px] mx-auto space-y-10">

          <Section title="Quick Start" delay={0}>
            <Code lang="bash" code={`# 1. Start the backend
cd backend && python run_server.py

# 2. Get a free API key (optional, enables LLM deep analysis)
# GitHub Models: github.com/settings/tokens (no scopes needed)
# Add to backend/.env with GITHUB_TOKEN=ghp_xxxxxx

# 3. Start the dashboard
cd frontend && npm run dev`} />
          </Section>

          <Section title="Bidirectional Protection" delay={0.05}>
            <p style={{ fontSize: 13, color: '#86868b', lineHeight: 1.7, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
              AgentShield guards both the <span style={{ color: '#0071e3', fontWeight: 500 }}>input surface</span> (adversarial attacks
              coming in) and the <span style={{ color: '#30d158', fontWeight: 500 }}>output surface</span> (sensitive data
              leaking out). Most agent security tools only do the former.
            </p>

            {/* Flow */}
            <div className="flex items-center gap-2 flex-wrap py-2">
              {['User Input', 'Input Guard', 'Agent', 'Output Guard', 'Safe Response'].map((s, i, arr) => (
                <div key={i} className="flex items-center gap-2">
                  <div style={{
                    padding: '6px 14px',
                    borderRadius: 999,
                    background: i === 1 ? 'rgba(0,113,227,0.04)' : i === 3 ? 'rgba(52,199,89,0.04)' : 'rgba(255,255,255,0.01)',
                    border: `1px solid ${i === 1 ? 'rgba(0,113,227,0.25)' : i === 3 ? 'rgba(52,199,89,0.25)' : 'rgba(255,255,255,0.06)'}`,
                    fontSize: 12,
                    color: i === 1 ? '#0071e3' : i === 3 ? '#30d158' : '#86868b',
                    fontWeight: i === 1 || i === 3 ? 500 : 400,
                    fontFamily: '"Plus Jakarta Sans", sans-serif'
                  }}>
                    {s}
                  </div>
                  {i < arr.length - 1 && <ArrowRight size={12} color="#86868b" />}
                </div>
              ))}
            </div>

            <Code lang="python" code={`from agentshield_sdk import AgentShield

shield = AgentShield(base_url="http://localhost:8000")

# INPUT: block attacks before they reach the agent
verdict = shield.inspect(user_input)
if not verdict.is_safe:
    return f"Blocked ({verdict.action}): {verdict.reasoning}"

# Run your agent
raw_response = your_agent.run(user_input)

# OUTPUT: redact secrets and PII before they leave
scan = shield.scan_output(raw_response)
return scan.redacted_text   # secrets automatically masked`} />
          </Section>

          <Section title="Multi-Turn Session Tracking" delay={0.1}>
            <p style={{ fontSize: 13, color: '#86868b', lineHeight: 1.7, fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
              Session context enables Layer 4 behavioral analysis, detecting escalating
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
            <div className="space-y-4">
              {[
                { method: 'POST', path: '/api/inspect',      color: '#0071e3', desc: 'Inspect a prompt with full 4-layer input detection' },
                { method: 'POST', path: '/api/inspect/batch',color: '#0071e3', desc: 'Batch inspect up to 50 prompts (parallel async)' },
                { method: 'POST', path: '/api/scan/output',  color: '#30d158', desc: 'Scan agent output with 23 data-leak signatures plus redaction' },
                { method: 'GET',  path: '/api/analytics',    color: '#ff9f0a', desc: 'Full analytics: totals, categories, daily trend, hourly' },
                { method: 'GET',  path: '/api/patterns',     color: '#ff9f0a', desc: 'Browse the input attack pattern database' },
                { method: 'GET',  path: '/api/output/patterns', color: '#ff9f0a', desc: 'Browse the output data-leak signature database' },
                { method: 'WS',   path: '/ws/live',          color: '#af52de', desc: 'WebSocket real-time threat event stream' },
              ].map((e, i) => (
                <div key={i} className="flex items-start gap-4 p-5 rounded-2xl" style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 600, color: e.color, flexShrink: 0, padding: '3px 9px', background: `${e.color}10`, borderRadius: 6, border: `1px solid ${e.color}25`, marginTop: 1 }}>
                    {e.method}
                  </span>
                  <div>
                    <div style={{ fontSize: 13, fontFamily: 'monospace', color: '#ffffff', fontWeight: 500 }}>{e.path}</div>
                    <div style={{ fontSize: 12, color: '#86868b', marginTop: 6, fontWeight: 300, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{e.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <Section title="Detection Architecture" delay={0.2}>
            <div className="space-y-4">
              {[
                { n: 1, title: 'Pattern Matching', time: '<1ms',   color: '#ff453a', desc: '54 compiled regex signatures across 10 categories. Critical patterns block immediately, no API call needed.' },
                { n: 2, title: 'Keyword Semantic', time: '~1ms',   color: '#ff9f0a', desc: '40+ keyword signals in 3 tiers (critical/high/medium). Runs entirely in-process.' },
                { n: 3, title: 'LLM Deep Analysis',time: '~500ms', color: '#0071e3', desc: 'GitHub Models (GPT-4o-mini, free) performs contextual threat analysis with reasoning and mitigation advice.' },
                { n: 4, title: 'Behavioral Analysis',time: 'parallel',color:'#30d158',desc: 'Session-aware tracking detects multi-turn escalation, high message rates, and gradual context poisoning.' },
              ].map(l => (
                <div key={l.n} className="flex gap-4 p-6 rounded-2xl" style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ width: 34, height: 34, borderRadius: 8, background: `${l.color}10`, border: `1px solid ${l.color}25`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 14, color: l.color, boxShadow: `0 0 10px ${l.color}05` }}>
                    {l.n}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', fontFamily: '"Outfit", sans-serif' }}>{l.title}</span>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', color: l.color, padding: '2px 7px', background: `${l.color}10`, borderRadius: 5, fontWeight: 500 }}>{l.time}</span>
                    </div>
                    <p style={{ fontSize: 12.5, color: '#86868b', lineHeight: 1.7, fontWeight: 300, margin: 0, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>{l.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </Section>

        </div>
      </div>
    </div>
  )
}
