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
            <div style={{ fontFamily: '"Space Grotesk", sans-serif', fontSize: 42, fontWeight: 700, letterSpacing: '-0.04em', color: '#f0f0f0' }}>
              AgentShield
            </div>
            <div style={{ fontSize: 11, letterSpacing: '0.2em', color: '#444', textTransform: 'uppercase', marginTop: 8 }}>
              AI Agent Security Platform
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
              <span style={{ fontSize: 11, color: '#444', fontFamily: '"IBM Plex Mono"' }}>{LINES[line]}</span>
              <span style={{ fontSize: 22, fontWeight: 700, color: '#f0f0f0', fontFamily: '"Space Grotesk"', letterSpacing: '-0.04em' }}>
                {pct}<span style={{ fontSize: 12, color: '#444' }}>%</span>
              </span>
            </div>
            <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', overflow: 'hidden', borderRadius: 1 }}>
              <motion.div
                style={{ height: '100%', background: '#f0f0f0', borderRadius: 1 }}
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
