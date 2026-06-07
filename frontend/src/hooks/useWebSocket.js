import { useEffect, useRef, useState, useCallback } from 'react'

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const retryRef = useRef(null)
  const mountedRef = useRef(false)
  const reconnectCountRef = useRef(0)
  const [connected, setConnected] = useState(false)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const getWsUrl = () => {
    let wsUrl
    if (import.meta.env.VITE_API_URL) {
      const base = import.meta.env.VITE_API_URL.replace(/^https/, 'wss').replace(/^http/, 'ws')
      wsUrl = `${base}/ws/live`
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      wsUrl = `${protocol}://${window.location.host}/ws/live`
    }
    return wsUrl
  }

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    wsRef.current?.close()
    const wsUrl = getWsUrl()
    const ws = new WebSocket(wsUrl)

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
      if (!mountedRef.current) return
      // Exponential backoff reconnect
      const delay = Math.min(1000 * 2 ** reconnectCountRef.current, 30000)
      retryRef.current = setTimeout(() => {
        reconnectCountRef.current += 1
        connect()
      }, delay)
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
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
