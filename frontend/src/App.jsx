import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Suspense, lazy, useState } from 'react'
import Sidebar from './components/layout/Sidebar'
import LoadingScreen from './components/ui/LoadingScreen'
import InteractiveBackground from './components/ui/InteractiveBackground'
import ParticleBackground from './components/ui/ParticleBackground'

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

export default function App() {
  const [booting, setBooting] = useState(() => !sessionStorage.getItem('as_booted'))

  return (
    <BrowserRouter>
      {booting && <LoadingScreen onComplete={() => { sessionStorage.setItem('as_booted','1'); setBooting(false) }} />}

      <Routes>
        {/* Landing Page (no sidebar, full screen, clean Apple aesthetic) */}
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
              <main style={{ flex: 1, marginLeft: 220, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
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
              </main>
            </div>
          </>
        } />
      </Routes>
    </BrowserRouter>
  )
}
