import { useEffect, useState } from 'react'
import { Wifi, WifiOff } from 'lucide-react'

// The free hosting tier sleeps when idle, so the first connection can take up to
// a minute. Show a waiting state for that long before calling it a disconnect.
const WAKE_GRACE_MS = 75000

export default function Header({ title, subtitle, wsConnected, right }) {
  const [waking, setWaking] = useState(true)
  useEffect(() => {
    if (wsConnected) { setWaking(false); return }
    const t = setTimeout(() => setWaking(false), WAKE_GRACE_MS)
    return () => clearTimeout(t)
  }, [wsConnected])
  const connecting = !wsConnected && waking
  const tone = wsConnected ? '52, 199, 89' : connecting ? '255, 159, 10' : '255, 59, 48'
  const hex = wsConnected ? '#34c759' : connecting ? '#ff9f0a' : '#ff3b30'
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
             title={connecting ? 'Waking up the server. This can take up to a minute on the free tier.' : undefined}
             style={{
               background: `linear-gradient(145deg, rgba(${tone}, 0.14), rgba(${tone}, 0.05))`,
               border: `1px solid rgba(${tone}, 0.15)`,
               boxShadow: `0 2px 8px rgba(${tone}, 0.05)`,
               backdropFilter: 'blur(18px) saturate(150%)',
             }}>
            {wsConnected
              ? <Wifi size={11} color="#34c759" />
              : <WifiOff size={11} color={hex} />}
            <span style={{
              fontSize: 10,
              fontFamily: '"Plus Jakarta Sans", sans-serif',
              fontWeight: 600,
              color: hex,
              letterSpacing: '0.06em'
            }}>
              {wsConnected ? 'LIVE' : connecting ? 'WAKING UP THE SERVER' : 'DISCONNECTED'}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
