import { motion } from 'framer-motion'
import { Wifi, WifiOff } from 'lucide-react'

export default function Header({ title, subtitle, wsConnected, right }) {
  return (
    <div
      className="flex items-center justify-between px-8 py-5"
      style={{
        background: 'rgba(10, 10, 10, 0.25)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
      }}
    >
      <div>
        <h1 style={{
          fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontWeight: 600, fontSize: 21,
          color: '#ffffff', letterSpacing: '-0.02em', lineHeight: 1.1,
        }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 12, color: '#9ca3af', marginTop: 5, letterSpacing: '-0.01em' }}>
            {subtitle}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {right}
        {wsConnected !== undefined && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg"
            style={{
              background: wsConnected ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
              border: `1px solid ${wsConnected ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
              boxShadow: wsConnected ? '0 0 10px rgba(16,185,129,0.1)' : '0 0 10px rgba(239,68,68,0.1)',
            }}>
            {wsConnected
              ? <Wifi size={11} color="#34d399" />
              : <WifiOff size={11} color="#ef4444" />}
            <span style={{
              fontSize: 10,
              fontFamily: '"IBM Plex Mono"',
              fontWeight: 600,
              color: wsConnected ? '#34d399' : '#ef4444',
              letterSpacing: '0.06em'
            }}>
              {wsConnected ? 'LIVE' : 'DISCONNECTED'}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
