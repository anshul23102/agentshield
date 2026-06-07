import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Suspense, lazy, useState } from 'react'
import Sidebar from './components/layout/Sidebar'
import ParticleBackground from './components/ui/ParticleBackground'
import LoadingScreen from './components/ui/LoadingScreen'

const Dashboard   = lazy(() => import('./pages/Dashboard'))
const Simulator   = lazy(() => import('./pages/Simulator'))
const OutputGuard = lazy(() => import('./pages/OutputGuard'))
const Intelligence= lazy(() => import('./pages/Intelligence'))
const Analytics   = lazy(() => import('./pages/Analytics'))
const Docs        = lazy(() => import('./pages/Docs'))

function Loader() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div style={{ width: 24, height: 24, border: '1px solid rgba(255,255,255,0.08)', borderTop: '1px solid rgba(255,255,255,0.4)', borderRadius: '50%', animation: 'spin 1.2s linear infinite' }} />
    </div>
  )
}

export default function App() {
  const [booting, setBooting] = useState(() => !sessionStorage.getItem('as_booted'))

  return (
    <BrowserRouter>
      {booting && <LoadingScreen onComplete={() => { sessionStorage.setItem('as_booted','1'); setBooting(false) }} />}

      {/* Subtle particle field */}
      <ParticleBackground />

      {/* Very faint top aurora */}
      <div style={{
        position: 'fixed', top: 0, left: '50%', transform: 'translateX(-50%)',
        width: 600, height: 300, pointerEvents: 'none', zIndex: 0,
        background: 'radial-gradient(ellipse at top, rgba(0,113,227,0.04) 0%, transparent 70%)',
      }} />

      <div style={{ position: 'relative', zIndex: 10, display: 'flex', height: '100vh', overflow: 'hidden' }}>
        <Sidebar />
        <main style={{ flex: 1, marginLeft: 220, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route path="/"             element={<Dashboard />} />
              <Route path="/simulator"    element={<Simulator />} />
              <Route path="/output-guard" element={<OutputGuard />} />
              <Route path="/intelligence" element={<Intelligence />} />
              <Route path="/analytics"    element={<Analytics />} />
              <Route path="/docs"         element={<Docs />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </BrowserRouter>
  )
}
