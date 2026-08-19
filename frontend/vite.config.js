import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// The backend URL/port was previously a bare hardcoded string in two places
// (here, and implicitly via VITE_API_URL in .env) - BACKEND_PORT lets a local
// dev setup point the proxy at a non-default backend port (e.g. when 8000 is
// already taken by something else) without editing this file.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backendUrl = `http://localhost:${env.BACKEND_PORT || '8000'}`

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': backendUrl,
        '/ws': { target: backendUrl, ws: true },
      },
    },
  }
})
