/**
 * Film grain / noise overlay — the signature texture of premium award-winning sites.
 * SVG fractal noise rendered as a fixed full-screen layer with screen blend mode.
 */
export default function GrainOverlay() {
  return (
    <div
      className="fixed inset-0 pointer-events-none z-[60] opacity-[0.04] mix-blend-overlay"
      style={{
        backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
        backgroundRepeat: 'repeat',
        animation: 'grainShift 0.4s steps(2) infinite',
      }}
    />
  )
}
