import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const LINES = [
  'Loading signatures',
  'Arming output guard',
  'Establishing channel',
  'Ready',
]

export default function LoadingScreen({ onComplete }) {
  const [pct, setPct]   = useState(0)
  const [line, setLine] = useState(0)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const start = performance.now()
    const DUR   = 1800
    let raf

    const tick = (now) => {
      const p = Math.min((now - start) / DUR, 1)
      const e = 1 - Math.pow(1 - p, 3)
      setPct(Math.round(e * 100))
      setLine(Math.min(LINES.length - 1, Math.floor(e * LINES.length)))
      if (p < 1) { raf = requestAnimationFrame(tick) }
      else { setTimeout(() => { setDone(true); setTimeout(onComplete, 500) }, 200) }
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [onComplete])

  return (
    <AnimatePresence>
      {!done && (
        <motion.div
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
          className="fixed inset-0 z-[10000] flex flex-col items-center justify-center"
          style={{ background: '#080808' }}
        >
          {/* Wordmark */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-12"
          >
            <div style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', fontSize: 42, fontWeight: 600, letterSpacing: '-0.04em', color: '#f5f5f7' }}>
              AgentShield
            </div>
            <div style={{ fontSize: 11, letterSpacing: '0.12em', color: '#86868b', textTransform: 'uppercase', marginTop: 8, fontWeight: 500 }}>
              Agent Security Platform
            </div>
          </motion.div>

          {/* Progress */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            style={{ width: 240 }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: '#86868b', fontFamily: '"IBM Plex Mono"' }}>{LINES[line]}</span>
              <span style={{ fontSize: 22, fontWeight: 600, color: '#f5f5f7', fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Outfit", sans-serif', letterSpacing: '-0.04em' }}>
                {pct}<span style={{ fontSize: 12, color: '#86868b' }}>%</span>
              </span>
            </div>
            <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', overflow: 'hidden', borderRadius: 1 }}>
              <motion.div
                style={{ height: '100%', background: 'linear-gradient(90deg, #0a84ff 0%, #ffffff 100%)', borderRadius: 1 }}
                animate={{ width: `${pct}%` }}
                transition={{ ease: 'linear', duration: 0.05 }}
              />
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
