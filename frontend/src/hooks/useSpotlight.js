import { useEffect } from 'react'

/**
 * Adds a cursor-following radial spotlight to any element with the
 * `.spotlight-card` class — a subtle premium hover effect.
 * Updates CSS custom properties --mx / --my used by the .spotlight-card style.
 */
export function useSpotlight() {
  useEffect(() => {
    const handler = (e) => {
      const cards = document.querySelectorAll('.spotlight-card')
      cards.forEach((card) => {
        const rect = card.getBoundingClientRect()
        const x = e.clientX - rect.left
        const y = e.clientY - rect.top
        // Only update if cursor is reasonably near the card (perf)
        if (
          x > -200 && x < rect.width + 200 &&
          y > -200 && y < rect.height + 200
        ) {
          card.style.setProperty('--mx', `${x}px`)
          card.style.setProperty('--my', `${y}px`)
        }
      })
    }
    window.addEventListener('mousemove', handler, { passive: true })
    return () => window.removeEventListener('mousemove', handler)
  }, [])
}
