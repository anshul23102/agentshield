import { motion } from 'framer-motion'
import { Wifi, WifiOff } from 'lucide-react'

export default function Header({ title, subtitle, wsConnected, right }) {
  return (
    <div
      className="flex items-center justify-between px-8 py-5"
      style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
    >
      <div>
        <h1 style={{
          fontFamily: '"Space Grotesk"', fontWeight: 700, fontSize: 20,
          color: '#f0f0f0', letterSpacing: '-0.03em', lineHeight: 1,
        }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 12, color: '#555', marginTop: 5, letterSpacing: '-0.01em' }}>
            {subtitle}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {right}
        {wsConnected !== undefined && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg"
            style={{
              background: wsConnected ? 'rgba(48,209,88,0.08)' : 'rgba(255,59,48,0.08)',
              border: `1px solid ${wsConnected ? 'rgba(48,209,88,0.2)' : 'rgba(255,59,48,0.15)'}`,
            }}>
            {wsConnected
              ? <Wifi size={11} color="#30D158" />
              : <WifiOff size={11} color="#FF3B30" />}
            <span style={{ fontSize: 10, fontFamily: '"IBM Plex Mono"', color: wsConnected ? '#30D158' : '#FF3B30', letterSpacing: '0.04em' }}>
              {wsConnected ? 'LIVE' : 'CONNECTING'}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
