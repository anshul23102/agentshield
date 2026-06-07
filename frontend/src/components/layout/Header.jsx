import { motion } from 'framer-motion'
import { Wifi, WifiOff } from 'lucide-react'

export default function Header({ title, subtitle, wsConnected, right }) {
  return (
    <div
      className="flex items-center justify-between px-8 py-5"
      style={{
        background: 'rgba(10, 10, 10, 0.65)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
      }}
    >
      <div>
        <h1 style={{
          fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 600, fontSize: 21,
          color: '#f5f5f7', letterSpacing: '-0.02em', lineHeight: 1.1,
        }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 12, color: '#86868b', marginTop: 5, letterSpacing: '-0.01em', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 300 }}>
            {subtitle}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {right}
        {wsConnected !== undefined && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg"
             style={{
               background: wsConnected ? 'rgba(52, 199, 89, 0.08)' : 'rgba(255, 59, 48, 0.08)',
               border: `1px solid ${wsConnected ? 'rgba(52, 199, 89, 0.15)' : 'rgba(255, 59, 48, 0.15)'}`,
               boxShadow: wsConnected ? '0 2px 8px rgba(52, 199, 89, 0.05)' : '0 2px 8px rgba(255, 59, 48, 0.05)',
             }}>
            {wsConnected
              ? <Wifi size={11} color="#34c759" />
              : <WifiOff size={11} color="#ff3b30" />}
            <span style={{
              fontSize: 10,
              fontFamily: '"Plus Jakarta Sans", sans-serif',
              fontWeight: 600,
              color: wsConnected ? '#34c759' : '#ff3b30',
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
