import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api`
  : '/api'

// The server requires an API key on every inspect/scan/analytics call. This
// dashboard is a first-party console: the person viewing it IS the operator,
// so the regular key travels in the bundle sent to their browser - that's an
// accepted tradeoff for a self-hosted or trusted deployment.
//
// The ADMIN key is different: it can mint/revoke API keys, wipe all session
// data, and clear the LLM cache - actions the person loading a *public* URL
// (e.g. an interview demo link) should never be able to trigger. Gating this
// behind `import.meta.env.DEV` isn't just a warning - Vite statically inlines
// DEV as literal `false` in any `vite build` output (what Vercel/Render ship),
// so `ADMIN_KEY` is `undefined` in every production bundle and the build's
// minifier dead-code-eliminates the reference entirely - VITE_ADMIN_KEY
// cannot end up in shipped JS no matter what env vars the hosting platform
// has configured. It only ever resolves in `npm run dev` on your own machine.
const API_KEY = import.meta.env.VITE_API_KEY
const ADMIN_KEY = import.meta.env.DEV ? import.meta.env.VITE_ADMIN_KEY : undefined

export const api = axios.create({
  baseURL: BASE,
  timeout: 15000,
  headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
})

const adminHeaders = ADMIN_KEY ? { 'X-Admin-Key': ADMIN_KEY } : {}

// Lets the UI hide admin-only controls entirely in production builds instead
// of showing buttons that would just 401 - see the ADMIN_KEY comment above.
export const hasAdminAccess = Boolean(ADMIN_KEY)

export const inspect = (text, sessionId, skipLlm = false) =>
  api.post('/inspect', { text, session_id: sessionId, skip_llm: skipLlm }).then(r => r.data)

export const inspectBatch = (items) =>
  api.post('/inspect/batch', { items }).then(r => r.data)

export const getRecentEvents = (limit = 50) =>
  api.get('/events/recent', { params: { limit } }).then(r => r.data)

export const getAnalytics = () =>
  api.get('/analytics').then(r => r.data)

export const getPatterns = (category, level) =>
  api.get('/patterns', { params: { category, level } }).then(r => r.data)

export const getStatus = () =>
  api.get('/status').then(r => r.data)

export const getDemoAttacks = () =>
  api.get('/demo/attacks').then(r => r.data)

export const scanOutput = (text, redact = true, sessionId) =>
  api.post('/scan/output', { text, redact, session_id: sessionId }).then(r => r.data)

export const getOutputPatterns = () =>
  api.get('/output/patterns').then(r => r.data)

export const getDemoLeaks = () =>
  api.get('/demo/leaks').then(r => r.data)

export const getSessionStats = (sessionId) =>
  api.get(`/session/${sessionId}`).then(r => r.data)

export const getWsTicket = () =>
  api.post('/ws-ticket').then(r => r.data)

export const getAdminConfig = () =>
  api.get('/admin/config', { headers: adminHeaders }).then(r => r.data)

export const toggleDemoTraffic = () =>
  api.post('/admin/toggle-generator', null, { headers: adminHeaders }).then(r => r.data)

export const clearLLMCache = () =>
  api.post('/admin/clear-cache', null, { headers: adminHeaders }).then(r => r.data)

export const resetSessions = () =>
  api.post('/admin/reset-sessions', null, { headers: adminHeaders }).then(r => r.data)
