import { NavLink } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, LayoutDashboard, Zap, ShieldCheck,
  Brain, BarChart3, BookOpen, Github, Network
} from 'lucide-react'

const NAV = [
  { to: '/dashboard',    icon: LayoutDashboard, label: 'Dashboard'    },
  { to: '/pipeline',     icon: Network,         label: 'Guard Graph'  },
  { to: '/simulator',    icon: Zap,             label: 'Simulator'    },
  { to: '/output-guard', icon: ShieldCheck,     label: 'Output Guard' },
  { to: '/intelligence', icon: Brain,           label: 'Intelligence' },
  { to: '/analytics',    icon: BarChart3,       label: 'Analytics'    },
  { to: '/docs',         icon: BookOpen,        label: 'Docs'         },
]

export default function Sidebar() {
  return (
    <motion.aside
      initial={{ x: -16, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.4, ease: [0.25, 0, 0, 1] }}
      className="fixed left-0 top-0 h-full z-40 flex flex-col"
      style={{
        width: 220,
        background: 'rgba(10, 10, 10, 0.65)',
        backdropFilter: 'blur(30px)',
        WebkitBackdropFilter: 'blur(30px)',
        borderRight: '1px solid rgba(255, 255, 255, 0.08)',
      }}
    >
      {/* Logo */}
      <div className="px-5 pt-6 pb-5" style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg, rgba(0, 113, 227, 0.1) 0%, rgba(255, 255, 255, 0.15) 100%)',
            border: '1px solid rgba(0, 113, 227, 0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 2px 8px rgba(0, 113, 227, 0.08)'
          }}>
            <Shield size={15} color="#0071e3" />
          </div>
          <div>
            <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 15, color: '#f5f5f7', letterSpacing: '-0.02em' }}>
              AgentShield
            </div>
            <div className="flex items-center gap-1.5" style={{ marginTop: 2 }}>
              <span className="live-dot" style={{ width: 5, height: 5 }} />
              <span style={{ fontSize: 9, color: '#34c759', letterSpacing: '0.08em', fontWeight: 600 }}>ACTIVE</span>
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-5 space-y-1">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/dashboard'}>
            {({ isActive }) => (
              <motion.div
                whileHover={{ x: 3 }}
                transition={{ duration: 0.12 }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 12px', borderRadius: 9,
                  background: isActive ? 'rgba(255, 255, 255, 0.04)' : 'transparent',
                  border: `1px solid ${isActive ? 'rgba(255, 255, 255, 0.08)' : 'transparent'}`,
                  boxShadow: isActive ? '0 2px 8px rgba(0, 0, 0, 0.4)' : 'none',
                }}
              >
                <Icon
                  size={15}
                  style={{ color: isActive ? '#0071e3' : '#86868b', flexShrink: 0 }}
                />
                <span style={{
                  fontSize: 13, fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#ffffff' : '#86868b',
                  letterSpacing: '-0.015em',
                  fontFamily: '"Plus Jakarta Sans", sans-serif'
                }}>
                  {label}
                </span>
              </motion.div>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 pb-5" style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: 16 }}>
        <div style={{ fontSize: 10, color: '#86868b', letterSpacing: '0.05em', marginBottom: 8, textTransform: 'uppercase', fontWeight: 500, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
          Powered by
        </div>
        <div style={{ fontSize: 11, color: '#f5f5f7', fontFamily: '"Plus Jakarta Sans", sans-serif', lineHeight: 1.5, fontWeight: 400 }}>
          Azure AI Foundry<br />GitHub Models
        </div>
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 mt-4 hover:text-[#0071e3] transition-colors"
          style={{ fontSize: 11, color: '#86868b', fontFamily: '"Plus Jakarta Sans", sans-serif' }}
        >
          <Github size={12} /> GitHub
        </a>
      </div>
    </motion.aside>
  )
}
