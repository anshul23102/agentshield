import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import { Suspense, lazy, useState } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import Sidebar from './components/layout/Sidebar'
import LoadingScreen from './components/ui/LoadingScreen'
import InteractiveBackground from './components/ui/InteractiveBackground'
import ParticleBackground from './components/ui/ParticleBackground'
import ErrorFallback from './components/ui/ErrorFallback'

const Landing     = lazy(() => import('./pages/Landing'))
const Dashboard   = lazy(() => import('./pages/Dashboard'))
const Simulator   = lazy(() => import('./pages/Simulator'))
const OutputGuard = lazy(() => import('./pages/OutputGuard'))
const Intelligence= lazy(() => import('./pages/Intelligence'))
const Analytics   = lazy(() => import('./pages/Analytics'))
const Docs        = lazy(() => import('./pages/Docs'))
const Pipeline    = lazy(() => import('./pages/Pipeline'))


function Loader() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div style={{ width: 24, height: 24, border: '1px solid rgba(255,255,255,0.1)', borderTop: '1px solid #0071e3', borderRadius: '50%', animation: 'spin 1.2s linear infinite' }} />
    </div>
  )
}

// Minimal, dependency-free fallback for the outer boundary - deliberately
// does not reuse app chrome/components, since those (Sidebar, backgrounds)
// are inside this same boundary and may be what's broken.
function RootErrorFallback({ error, resetErrorBoundary }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', gap: 14, padding: 32,
      background: '#08080a', color: '#fff', fontFamily: 'system-ui, sans-serif', textAlign: 'center',
    }}>
      <h1 style={{ fontSize: 20, fontWeight: 800, margin: 0 }}>AgentShield hit an unexpected error</h1>
      {error?.message && (
        <code style={{ fontSize: 12, color: '#ff9f0a', opacity: 0.85 }}>{error.message}</code>
      )}
      <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
        <button
          onClick={resetErrorBoundary}
          style={{ padding: '9px 16px', borderRadius: 10, background: 'rgba(255,255,255,0.08)', color: '#fff', border: '1px solid rgba(255,255,255,0.14)', cursor: 'pointer', fontSize: 13 }}
        >
          Try again
        </button>
        <button
          onClick={() => { window.location.href = '/' }}
          style={{ padding: '9px 16px', borderRadius: 10, background: '#0071e3', color: '#fff', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 700 }}
        >
          Reload
        </button>
      </div>
    </div>
  )
}

// Resets automatically on navigation, so an error on one page doesn't leave
// every other page permanently stuck behind the fallback UI.
function PageBoundary({ children }) {
  const location = useLocation()
  return (
    <ErrorBoundary FallbackComponent={ErrorFallback} resetKeys={[location.pathname]}>
      {children}
    </ErrorBoundary>
  )
}

export default function App() {
  const [booting, setBooting] = useState(() => !sessionStorage.getItem('as_booted'))

  return (
    <ErrorBoundary FallbackComponent={RootErrorFallback}>
      <BrowserRouter>
        {booting && <LoadingScreen onComplete={() => { sessionStorage.setItem('as_booted','1'); setBooting(false) }} />}

        <Routes>
          {/* Landing page without the platform sidebar */}
          <Route path="/" element={<Landing />} />

          {/* Platform Dashboard Layout */}
          <Route path="/*" element={
            <>
              {/* Layer 1 & 2: Interactive Mouse Gradient + 3D drifting particles */}
              <InteractiveBackground />
              <ParticleBackground />

              {/* Very faint top ambient aurora */}
              <div style={{
                position: 'fixed', top: 0, left: '50%', transform: 'translateX(-50%)',
                width: 800, height: 350, pointerEvents: 'none', zIndex: 0,
                background: 'radial-gradient(ellipse at top, rgba(0,113,227,0.06) 0%, transparent 70%)',
              }} />

              <div style={{ position: 'relative', zIndex: 10, display: 'flex', height: '100vh', overflow: 'hidden' }}>
                <Sidebar />
                <main style={{ flex: 1, marginLeft: 248, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                  <PageBoundary>
                    <Suspense fallback={<Loader />}>
                      <Routes>
                        <Route path="/dashboard"    element={<Dashboard />} />
                        <Route path="/simulator"    element={<Simulator />} />
                        <Route path="/output-guard" element={<OutputGuard />} />
                        <Route path="/intelligence" element={<Intelligence />} />
                        <Route path="/analytics"    element={<Analytics />} />
                        <Route path="/docs"         element={<Docs />} />
                        <Route path="/pipeline"     element={<Pipeline />} />

                      </Routes>
                    </Suspense>
                  </PageBoundary>
                </main>
              </div>
            </>
          } />
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
