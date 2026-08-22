import { motion } from 'framer-motion'
import { Wifi, WifiOff } from 'lucide-react'

export default function Header({ title, subtitle, wsConnected, right }) {
  return (
    <div
      className="glass-bar flex items-center justify-between px-9 py-6"
      style={{
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
      }}
    >
      <div>
        <h1 style={{
          fontFamily: '"Outfit", "-apple-system", sans-serif', fontWeight: 700, fontSize: 25,
          color: '#ffffff', letterSpacing: '-0.025em', lineHeight: 1.1,
        }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 13, color: '#9a9aa0', marginTop: 6, letterSpacing: '-0.005em', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 400 }}>
            {subtitle}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {right}
        {wsConnected !== undefined && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg"
             style={{
               background: wsConnected ? 'linear-gradient(145deg, rgba(52, 199, 89, 0.14), rgba(52, 199, 89, 0.05))' : 'linear-gradient(145deg, rgba(255, 59, 48, 0.14), rgba(255, 59, 48, 0.05))',
               border: `1px solid ${wsConnected ? 'rgba(52, 199, 89, 0.15)' : 'rgba(255, 59, 48, 0.15)'}`,
               boxShadow: wsConnected ? '0 2px 8px rgba(52, 199, 89, 0.05)' : '0 2px 8px rgba(255, 59, 48, 0.05)',
               backdropFilter: 'blur(18px) saturate(150%)',
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
