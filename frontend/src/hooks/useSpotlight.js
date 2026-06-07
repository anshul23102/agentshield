import { useEffect } from 'react'

/**
 * Adds a cursor-following radial spotlight to any element with the
 * `.spotlight-card` class for a subtle premium hover effect.
 */
export function useSpotlight() {
  useEffect(() => {
    const handler = (e) => {
      const cards = document.querySelectorAll('.spotlight-card')
      cards.forEach((card) => {
        const rect = card.getBoundingClientRect()
        const x = e.clientX - rect.left
        const y = e.clientY - rect.top
        // Only update if cursor is reasonably near the card.
        if (
          x > -200 && x < rect.width + 200 &&
          y > -200 && y < rect.height + 200
        ) {
          card.style.backgroundImage = `radial-gradient(circle at ${x}px ${y}px, rgba(255,255,255,0.08), transparent 36%)`
        }
      })
    }
    window.addEventListener('mousemove', handler, { passive: true })
    return () => window.removeEventListener('mousemove', handler)
  }, [])
}
