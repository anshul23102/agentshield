import { AlertTriangle, RotateCcw, Home } from 'lucide-react'

// Fallback UI for react-error-boundary. Without this, a render error in any
// lazy-loaded page (a bad API response shape, a null-ref in a chart, etc.)
// took down the whole app to a blank white screen with no way back short of
// a manual reload - no error boundary existed anywhere in the component tree.
export default function ErrorFallback({ error, resetErrorBoundary }) {
  return (
    <div
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        height: '100%', minHeight: 320, padding: 32, textAlign: 'center', gap: 14,
      }}
    >
      <div style={{
        width: 52, height: 52, borderRadius: 16, display: 'grid', placeItems: 'center',
        background: 'rgba(255, 69, 58, 0.12)', border: '1px solid rgba(255, 69, 58, 0.28)',
      }}>
        <AlertTriangle size={24} color="#ff453a" />
      </div>

      <h2 style={{
        margin: 0, fontSize: 18, fontWeight: 800, color: '#ffffff',
        fontFamily: '"Outfit", sans-serif',
      }}>
        Something went wrong on this page
      </h2>

      <p style={{
        margin: 0, maxWidth: 440, fontSize: 13, lineHeight: 1.55, color: '#D1D1D6',
        fontFamily: '"Plus Jakarta Sans", sans-serif',
      }}>
        The rest of AgentShield is unaffected - this only crashed the current view.
        {error?.message && (
          <>
            <br /><br />
            <code style={{ fontSize: 11.5, color: '#ff9f0a', background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4 }}>
              {error.message}
            </code>
          </>
        )}
      </p>

      <div style={{ display: 'flex', gap: 10, marginTop: 6 }}>
        <button
          onClick={resetErrorBoundary}
          className="btn btn-secondary"
          style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12.5, padding: '9px 16px', borderRadius: 10 }}
        >
          <RotateCcw size={14} /> Try again
        </button>
        <button
          onClick={() => { window.location.href = '/dashboard' }}
          style={{
            display: 'flex', alignItems: 'center', gap: 7, fontSize: 12.5, padding: '9px 16px', borderRadius: 10,
            background: '#0071e3', color: '#fff', border: 'none', cursor: 'pointer', fontFamily: '"Plus Jakarta Sans", sans-serif', fontWeight: 700,
          }}
        >
          <Home size={14} /> Back to Dashboard
        </button>
      </div>
    </div>
  )
}
