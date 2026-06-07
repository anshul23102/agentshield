import { NavLink } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, LayoutDashboard, Zap, ShieldCheck,
  Brain, BarChart3, BookOpen, Github
} from 'lucide-react'

const NAV = [
  { to: '/',             icon: LayoutDashboard, label: 'Dashboard'    },
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
      transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
      className="fixed left-0 top-0 h-full z-40 flex flex-col"
      style={{
        width: 220,
        background: 'rgba(8,8,8,0.95)',
        backdropFilter: 'blur(24px)',
        borderRight: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      {/* Logo */}
      <div className="px-5 pt-6 pb-5" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="flex items-center gap-2.5">
          <div style={{
            width: 30, height: 30, borderRadius: 8,
            background: 'rgba(255,255,255,0.06)',
            border: '1px solid rgba(255,255,255,0.1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={14} color="#f0f0f0" />
          </div>
          <div>
            <div style={{ fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 14, color: '#f0f0f0', letterSpacing: '-0.02em' }}>
              AgentShield
            </div>
            <div className="flex items-center gap-1.5" style={{ marginTop: 2 }}>
              <span className="live-dot" style={{ width: 5, height: 5 }} />
              <span style={{ fontSize: 10, color: '#444', letterSpacing: '0.05em' }}>ACTIVE</span>
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'}>
            {({ isActive }) => (
              <motion.div
                whileHover={{ x: 2 }}
                transition={{ duration: 0.15 }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '7px 10px', borderRadius: 8,
                  background: isActive ? 'rgba(255,255,255,0.06)' : 'transparent',
                  border: `1px solid ${isActive ? 'rgba(255,255,255,0.10)' : 'transparent'}`,
                }}
              >
                <Icon
                  size={15}
                  style={{ color: isActive ? '#f0f0f0' : '#606060', flexShrink: 0 }}
                />
                <span style={{
                  fontSize: 13, fontWeight: isActive ? 500 : 400,
                  color: isActive ? '#f0f0f0' : '#606060',
                  letterSpacing: '-0.01em',
                }}>
                  {label}
                </span>
              </motion.div>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 pb-5" style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16 }}>
        <div style={{ fontSize: 10, color: '#333', letterSpacing: '0.05em', marginBottom: 8, textTransform: 'uppercase' }}>
          Powered by
        </div>
        <div style={{ fontSize: 11, color: '#555', fontFamily: '"IBM Plex Mono"' }}>
          Azure AI Foundry<br />GitHub Models
        </div>
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 mt-4"
          style={{ fontSize: 11, color: '#444' }}
        >
          <Github size={12} color="#444" /> GitHub
        </a>
      </div>
    </motion.aside>
  )
}
