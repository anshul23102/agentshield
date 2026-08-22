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
      className="glass-bar fixed left-0 top-0 h-full z-40 flex flex-col"
      style={{
        width: 248,
        borderRight: '1px solid rgba(255, 255, 255, 0.08)',
      }}
    >
      {/* Logo */}
      <div className="px-6 pt-7 pb-6" style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <div className="flex items-center gap-3">
          <div style={{
            width: 38, height: 38, borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(0, 113, 227, 0.16) 0%, rgba(255, 255, 255, 0.12) 100%)',
            border: '1px solid rgba(0, 113, 227, 0.28)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 4px 14px rgba(0, 113, 227, 0.14)', flexShrink: 0,
          }}>
            <Shield size={19} color="#4da3ff" strokeWidth={2.2} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 700, fontSize: 18.5, color: '#ffffff', letterSpacing: '-0.02em', lineHeight: 1.15 }}>
              AgentShield
            </div>
            <div className="flex items-center gap-1.5" style={{ marginTop: 4 }}>
              <span className="live-dot" style={{ width: 5, height: 5 }} />
              <span style={{ fontSize: 10, color: '#34c759', letterSpacing: '0.09em', fontWeight: 700, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>ACTIVE</span>
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-4 py-6 space-y-1">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/dashboard'}>
            {({ isActive }) => (
              <motion.div
                whileHover={{ x: isActive ? 0 : 2 }}
                transition={{ duration: 0.15 }}
                style={{
                  position: 'relative',
                  display: 'flex', alignItems: 'center', gap: 11,
                  padding: '10px 14px 10px 16px', borderRadius: 8,
                  background: isActive ? 'rgba(0, 113, 227, 0.1)' : 'transparent',
                }}
              >
                {isActive && (
                  <span style={{
                    position: 'absolute', left: 0, top: '18%', bottom: '18%', width: 2.5,
                    borderRadius: 2, background: '#4da3ff', boxShadow: '0 0 8px rgba(77,163,255,0.7)',
                  }} />
                )}
                <Icon
                  size={16}
                  strokeWidth={isActive ? 2.2 : 1.8}
                  style={{ color: isActive ? '#4da3ff' : '#8e8e93', flexShrink: 0 }}
                />
                <span style={{
                  fontSize: 13.5, fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#ffffff' : '#9a9aa0',
                  letterSpacing: '-0.01em',
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
      <div className="px-6 pb-6" style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: 18 }}>
        <div style={{ fontSize: 10, color: '#7a7a80', letterSpacing: '0.07em', marginBottom: 9, textTransform: 'uppercase', fontWeight: 600, fontFamily: '"Plus Jakarta Sans", sans-serif' }}>
          Powered by
        </div>
        <div style={{ fontSize: 12, color: '#d1d1d6', fontFamily: '"Plus Jakarta Sans", sans-serif', lineHeight: 1.6, fontWeight: 400 }}>
          Azure Foundry<br />GitHub Models
        </div>
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 mt-4 hover:text-[#4da3ff] transition-colors"
          style={{ fontSize: 11.5, color: '#8e8e93', fontFamily: '"Plus Jakarta Sans", sans-serif' }}
        >
          <Github size={13} /> GitHub
        </a>
      </div>
    </motion.aside>
  )
}
