import { useEffect, useRef } from 'react'

/**
 * Premium mouse-tracking radial gradient background.
 * Uses high-performance CSS custom properties to avoid React re-renders,
 * providing a smooth 60fps flowing glow that follows the cursor.
 */
export default function InteractiveBackground() {
  const containerRef = useRef(null)

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!containerRef.current) return
      containerRef.current.style.background = `
        radial-gradient(circle 800px at ${e.clientX}px ${e.clientY}px, rgba(0, 113, 227, 0.08) 0%, rgba(175, 82, 222, 0.03) 45%, transparent 85%),
        #050505
      `
    }

    window.addEventListener('mousemove', handleMouseMove, { passive: true })

    // Initialize to center.
    if (containerRef.current) {
      containerRef.current.style.background = `
        radial-gradient(circle 800px at 50% 50%, rgba(0, 113, 227, 0.08) 0%, rgba(175, 82, 222, 0.03) 45%, transparent 85%),
        #050505
      `
    }

    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
    }
  }, [])

  return (
    <div
      ref={containerRef}
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 0,
        background: '#050505',
        transition: 'background 0.12s cubic-bezier(0.16, 1, 0.3, 1)'
      }}
    />
  )
}
