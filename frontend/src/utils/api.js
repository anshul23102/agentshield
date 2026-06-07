import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api`
  : '/api'

export const api = axios.create({ baseURL: BASE, timeout: 15000 })

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
