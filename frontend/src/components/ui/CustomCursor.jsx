import { useEffect, useRef } from 'react'

/**
 * Minimal dot cursor: 4px white circle that follows the mouse exactly.
 * Grows slightly over interactive elements. No ring, no glow, no lag.
 * Inspired by enzo-casalini.dev's precision-first approach.
 */
export default function CustomCursor() {
  const ref = useRef(null)

  useEffect(() => {
    if (window.matchMedia('(pointer: coarse)').matches) return

    const dot = ref.current
    if (!dot) return

    let x = -20, y = -20

    const move = (e) => {
      x = e.clientX
      y = e.clientY
      dot.style.transform = `translate(${x}px, ${y}px)`
    }

    const over = (e) => {
      const el = e.target.closest('button, a, input, textarea, select, label, [role="button"]')
      dot.style.width  = el ? '10px' : '5px'
      dot.style.height = el ? '10px' : '5px'
      dot.style.marginLeft  = el ? '-5px' : '-2.5px'
      dot.style.marginTop   = el ? '-5px' : '-2.5px'
      dot.style.background  = el ? 'rgba(255,255,255,0.7)' : '#fff'
    }

    const down = () => { dot.style.opacity = '0.5' }
    const up   = () => { dot.style.opacity = '1' }

    window.addEventListener('mousemove', move, { passive: true })
    window.addEventListener('mouseover', over)
    window.addEventListener('mousedown', down)
    window.addEventListener('mouseup', up)

    return () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseover', over)
      window.removeEventListener('mousedown', down)
      window.removeEventListener('mouseup', up)
    }
  }, [])

  return (
    <div
      ref={ref}
      style={{
        position: 'fixed',
        top: 0, left: 0,
        width: 5, height: 5,
        marginLeft: -2.5, marginTop: -2.5,
        borderRadius: '50%',
        background: '#fff',
        pointerEvents: 'none',
        zIndex: 99999,
        transition: 'width 0.12s ease, height 0.12s ease, margin 0.12s ease, opacity 0.1s ease',
        willChange: 'transform',
      }}
    />
  )
}
