import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, Zap, ShieldCheck, Brain, ArrowRight } from 'lucide-react'
import InteractiveBackground from '../components/ui/InteractiveBackground'
import ParticleBackground from '../components/ui/ParticleBackground'
import { getStatus } from '../utils/api'

const FEATURES = [
  {
    icon: Zap,
    title: 'Pattern Matching Guard',
    desc: '54 compiled regex signatures intercepting exploit vectors in under 1ms.'
  },
  {
    icon: Brain,
    title: 'Semantic Context Guard',
    desc: 'Advanced keyword proximity mapping identifying context-poisoning payloads.'
  },
  {
    icon: ShieldCheck,
    title: 'LLM Reasoning Guard',
    desc: 'GitHub Models GPT-4o-mini deep analysis returning mitigation reasoning.'
  }
]

export default function Landing() {
  const AppleEase = [0.25, 0, 0, 1]
  const [liveStatus, setLiveStatus] = useState(null)

  useEffect(() => {
    getStatus().then(setLiveStatus).catch(() => {})
  }, [])

  return (
    <div className="min-h-screen bg-[#050505] text-[#F5F5F7] relative overflow-x-hidden" style={{
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Plus Jakarta Sans", "Inter", sans-serif'
    }}>
      <InteractiveBackground />
      <ParticleBackground />
      
      {/* Navbar */}
      <motion.nav 
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: AppleEase }}
        className="fixed top-0 left-0 right-0 z-50 glass-bar border-b"
      >
        <div className="max-w-[1200px] mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-md bg-[#0071E3] flex items-center justify-center shadow-md shadow-[#0071E3]/10">
              <Shield size={13} color="#ffffff" />
            </div>
            <span style={{ fontFamily: '"Outfit", sans-serif', fontWeight: 600, fontSize: 15, letterSpacing: '-0.01em' }}>
              AgentShield
            </span>
          </div>
          
          <div className="flex items-center gap-8 text-[13px] font-medium text-[#D1D1D6]">
            <a href="#features" className="hover:text-[#ffffff] transition-colors">Features</a>
            <a href="#showcase" className="hover:text-[#ffffff] transition-colors">Technology</a>
            <Link 
              to="/dashboard" 
              className="inline-flex items-center justify-center px-4 py-1.5 rounded-full bg-[#0071E3] text-[#ffffff] font-medium transition-all duration-200 hover:bg-[#0077ed] hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-[#0071E3]/20"
            >
              Launch Platform
            </Link>
          </div>
        </div>
      </motion.nav>

      {/* Hero Section */}
      <section className="min-h-screen flex flex-col justify-center items-center px-6 pt-24 pb-16 relative">
        <div className="max-w-[1200px] w-full text-center space-y-8 z-10">
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease: AppleEase }}
            className="space-y-4"
          >
            <div className="text-[11px] font-semibold tracking-[0.2em] text-[#0071E3] uppercase">
              Now Available
            </div>
            <h1 
              className="text-[64px] md:text-[96px] font-bold text-[#ffffff] leading-[1.05] max-w-[1000px] mx-auto"
              style={{ fontFamily: '"Outfit", -apple-system, BlinkMacSystemFont, sans-serif' }}
            >
              Zero trust for autonomous agents.
            </h1>
            <p 
              className="text-[20px] md:text-[24px] text-[#D1D1D6] max-w-[620px] mx-auto font-light leading-relaxed"
              style={{ fontFamily: '"Plus Jakarta Sans", sans-serif' }}
            >
              Real-time bidirectional protection shielding LLM outputs and inputs from injections, prompt leaks, and exfiltration.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6, ease: AppleEase }}
            className="flex items-center justify-center gap-4"
          >
            <Link 
              to="/dashboard" 
              className="inline-flex items-center gap-1.5 px-6 py-3 rounded-full bg-[#0071E3] text-[#ffffff] font-medium text-[14px] transition-all duration-200 hover:bg-[#0077ed] hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-[#0071E3]/20"
            >
              Launch Platform <ArrowRight size={14} />
            </Link>
            <a 
              href="#showcase" 
              className="inline-flex items-center px-6 py-3 rounded-full border border-white/10 text-[#ffffff] font-medium text-[14px] transition-all duration-200 hover:bg-white/[0.06] hover:scale-[1.02] active:scale-[0.98]"
            >
              Learn more
            </a>
          </motion.div>
        </div>

        {/* Decorative Grid Lines */}
        <div className="absolute inset-0 pointer-events-none grid grid-cols-6 max-w-[1200px] mx-auto px-6 z-0 opacity-[0.08] border-x border-white">
          <div className="border-r border-white h-full" />
          <div className="border-r border-white h-full" />
          <div className="border-r border-white h-full" />
          <div className="border-r border-white h-full" />
          <div className="border-r border-white h-full" />
        </div>
      </section>

      {/* Feature Grid Section */}
      <section id="features" className="py-28 bg-[#050505] border-t border-white/[0.06] relative z-10">
        <div className="max-w-[1200px] mx-auto px-6">
          <motion.div 
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.6, ease: AppleEase }}
            className="grid grid-cols-1 md:grid-cols-3 gap-12"
          >
            {FEATURES.map((f, i) => {
              const Icon = f.icon
              return (
                <div key={i} className="glass-elevated glass-sheen morphic-hover p-5 space-y-4">
                  <div className="w-10 h-10 rounded-xl bg-[#0071E3]/12 border border-[#0071E3]/25 flex items-center justify-center">
                    <Icon size={18} color="#0071E3" />
                  </div>
                  <h3 
                    className="text-[20px] font-bold text-[#ffffff]"
                    style={{ fontFamily: '"Outfit", sans-serif' }}
                  >
                    {f.title}
                  </h3>
                  <p 
                    className="text-[14px] text-[#D1D1D6] leading-relaxed font-light"
                    style={{ fontFamily: '"Plus Jakarta Sans", sans-serif' }}
                  >
                    {f.desc}
                  </p>
                </div>
              )
            })}
          </motion.div>
        </div>
      </section>

      {/* Product Showcase Section */}
      <section id="showcase" className="py-28 bg-[#070707] border-t border-white/[0.06] overflow-hidden relative z-10">
        <div className="max-w-[1200px] mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 items-center">
            
            {/* Image Left */}
            <motion.div 
              initial={{ opacity: 0, x: -35 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: "-100px" }}
              transition={{ duration: 0.7, ease: AppleEase }}
              className="lg:col-span-6 relative flex justify-center"
            >
              <img 
                src="/agentshield_hero.png" 
                alt="AgentShield Security Spec" 
                className="max-w-full h-auto max-h-[500px] object-contain rounded-2xl border border-white/10"
                style={{ boxShadow: '0 40px 90px rgba(0,0,0,0.62)' }}
              />
              
              {/* Asymmetric Floating Spec Callouts */}
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: 0.4, duration: 0.5 }}
                className="absolute top-10 -left-6 card-flat px-3.5 py-2 max-w-[150px] text-[11px]"
              >
                <div className="font-semibold text-[#ffffff]">Layer 1: Pattern</div>
                <div className="text-[#D1D1D6] mt-0.5">Regex validation drops threats instantly.</div>
              </motion.div>

              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: 0.6, duration: 0.5 }}
                className="absolute bottom-16 -right-6 card-flat px-3.5 py-2 max-w-[150px] text-[11px]"
              >
                <div className="font-semibold text-[#ffffff]">Layer 4: Behavior</div>
                <div className="text-[#D1D1D6] mt-0.5">Detects escalations over multi-turn sessions.</div>
              </motion.div>
            </motion.div>

            {/* Spec / Callouts Right */}
            <motion.div 
              initial={{ opacity: 0, x: 35 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: "-100px" }}
              transition={{ duration: 0.7, ease: AppleEase }}
              className="lg:col-span-6 space-y-8"
            >
              <div className="space-y-3">
                <div className="text-[11px] font-semibold tracking-[0.15em] text-[#0071E3] uppercase">Engineering Details</div>
                <h2 
                  className="text-[40px] md:text-[48px] font-bold text-[#ffffff] leading-tight"
                  style={{ fontFamily: '"Outfit", sans-serif' }}
                >
                  Dual-Guard Architecture.
                </h2>
                <p 
                  className="text-[15px] text-[#D1D1D6] leading-relaxed font-light"
                  style={{ fontFamily: '"Plus Jakarta Sans", sans-serif' }}
                >
                  Most guardrails fail because they are unidirectional. AgentShield executes bidirectional scanning, validating prompts before execution and sanitizing outputs before delivery.
                </p>
              </div>

              <div className="divide-y divide-white/[0.08] glass-elevated px-4">
                <div className="py-4 flex items-center justify-between text-[13px]">
                  <span className="font-medium text-[#ffffff]">Prompt Intercept Speed</span>
                  <span className="text-[#D1D1D6] font-mono">&lt; 1.2ms</span>
                </div>
                <div className="py-4 flex items-center justify-between text-[13px]">
                  <span className="font-medium text-[#ffffff]">PII Redaction Engines</span>
                  <span className="text-[#D1D1D6] font-mono">23 Signatures</span>
                </div>
                <div className="py-4 flex items-center justify-between text-[13px]">
                  <span className="font-medium text-[#ffffff]">Free LLM Provider Integration</span>
                  <span className="text-[#D1D1D6] font-mono">GitHub Models API</span>
                </div>
              </div>
            </motion.div>

          </div>
        </div>
      </section>

      {/* Live Engine Status Strip — real numbers from the running backend */}
      <section className="py-24 bg-[#050505] border-t border-white/[0.06] relative z-10">
        <div className="max-w-[1200px] mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, ease: AppleEase }}
            className="text-center space-y-3 mb-12"
          >
            <div className="text-[11px] font-semibold tracking-[0.2em] text-[#0071E3] uppercase">
              Live Engine Telemetry
            </div>
            <h2
              className="text-[32px] md:text-[40px] font-bold text-[#ffffff]"
              style={{ fontFamily: '"Outfit", sans-serif' }}
            >
              These numbers come from the running engine.
            </h2>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.15, duration: 0.6, ease: AppleEase }}
            className="grid grid-cols-2 md:grid-cols-4 gap-4"
          >
            {[
              { value: liveStatus?.pattern_count ?? '—', label: 'Input Signatures Loaded' },
              { value: liveStatus?.output_pattern_count ?? '—', label: 'Output Leak Signatures' },
              { value: liveStatus?.llm_available ? 'Active' : 'Pattern Mode', label: 'Model Analysis Layer' },
              { value: liveStatus?.total_messages?.toLocaleString() ?? '—', label: 'Messages Inspected' },
            ].map((s, i) => (
              <div key={i} className="glass-panel rounded-2xl p-6 text-center morphic-hover">
                <div
                  className="text-[36px] font-bold text-[#ffffff] leading-none"
                  style={{ fontFamily: '"Outfit", sans-serif' }}
                >
                  {s.value}
                </div>
                <div className="text-[11px] uppercase tracking-[0.08em] font-semibold text-[#D1D1D6] mt-3">
                  {s.label}
                </div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-[#070707] border-t border-white/[0.06] py-16 relative z-10 text-[13px] text-[#D1D1D6]">
        <div className="max-w-[1200px] mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
            <div className="space-y-4">
              <h4 className="font-semibold text-[#ffffff]">Platform</h4>
              <div className="flex flex-col gap-2.5">
                <Link to="/dashboard" className="hover:text-[#ffffff] transition-colors">Dashboard</Link>
                <Link to="/simulator" className="hover:text-[#ffffff] transition-colors">Simulator</Link>
                <Link to="/output-guard" className="hover:text-[#ffffff] transition-colors">Output Guard</Link>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="font-semibold text-[#ffffff]">Resources</h4>
              <div className="flex flex-col gap-2.5">
                <Link to="/docs" className="hover:text-[#ffffff] transition-colors">Documentation</Link>
                <Link to="/intelligence" className="hover:text-[#ffffff] transition-colors">Threat Database</Link>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="font-semibold text-[#ffffff]">Developer</h4>
              <div className="flex flex-col gap-2.5">
                <a href="https://github.com/anshul23102/agentshield" target="_blank" rel="noreferrer" className="hover:text-[#ffffff] transition-colors">GitHub Repository</a>
                <a href="https://agentshield-api-658e.onrender.com/status" target="_blank" rel="noreferrer" className="hover:text-[#ffffff] transition-colors">API Status</a>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="font-semibold text-[#ffffff]">Organization</h4>
              <div className="flex flex-col gap-2.5">
                <span className="cursor-not-allowed">About</span>
                <span className="cursor-not-allowed">Privacy Policy</span>
              </div>
            </div>
          </div>
          <div className="border-t border-white/[0.06] pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div>
              &copy; {new Date().getFullYear()} AgentShield Platform. All rights reserved.
            </div>
            <div className="flex gap-6">
              <span>Built for Microsoft Build AI 2026</span>
            </div>
          </div>
        </div>
      </footer>

    </div>
  )
}
