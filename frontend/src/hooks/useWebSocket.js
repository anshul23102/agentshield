import { useEffect, useRef, useState, useCallback } from 'react'
import { getWsTicket } from '../utils/api'

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const retryRef = useRef(null)
  const mountedRef = useRef(false)
  const reconnectCountRef = useRef(0)
  const [connected, setConnected] = useState(false)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const getWsBase = () => {
    if (import.meta.env.VITE_API_URL) {
      return import.meta.env.VITE_API_URL.replace(/^https/, 'wss').replace(/^http/, 'ws')
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    return `${protocol}://${window.location.host}`
  }

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return
    const delay = Math.min(1000 * 2 ** reconnectCountRef.current, 30000)
    retryRef.current = setTimeout(() => {
      reconnectCountRef.current += 1
      connect()
    }, delay)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const connect = useCallback(async () => {
    if (!mountedRef.current) return
    wsRef.current?.close()

    // The browser's native WebSocket can't send custom headers, so a raw API
    // key can't ride along on the handshake without sitting in the URL where
    // it would leak into history/referrers/proxy logs. Instead, trade the key
    // for a short-lived, single-use ticket over an authenticated REST call,
    // and only the disposable ticket goes in the WS URL.
    let ticket
    try {
      const res = await getWsTicket()
      ticket = res.ticket
    } catch {
      scheduleReconnect()
      return
    }
    if (!mountedRef.current) return

    const ws = new WebSocket(`${getWsBase()}/ws/live?ticket=${encodeURIComponent(ticket)}`)

    ws.onopen = () => {
      setConnected(true)
      reconnectCountRef.current = 0
    }

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        onMessageRef.current?.(data)
      } catch {}
    }

    ws.onclose = () => {
      setConnected(false)
      scheduleReconnect()
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      clearTimeout(retryRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { connected }
}
