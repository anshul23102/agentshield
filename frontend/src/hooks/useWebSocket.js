import { useEffect, useRef, useState, useCallback } from 'react'

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const [connected, setConnected] = useState(false)
  const [reconnectCount, setReconnectCount] = useState(0)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    let wsUrl
    if (import.meta.env.VITE_API_URL) {
      const base = import.meta.env.VITE_API_URL.replace(/^https/, 'wss').replace(/^http/, 'ws')
      wsUrl = `${base}/ws/live`
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      wsUrl = `${protocol}://${window.location.host}/ws/live`
    }
    const ws = new WebSocket(wsUrl)

    ws.onopen = () => setConnected(true)

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        onMessageRef.current?.(data)
      } catch {}
    }

    ws.onclose = () => {
      setConnected(false)
      // Exponential backoff reconnect
      const delay = Math.min(1000 * 2 ** reconnectCount, 30000)
      setTimeout(() => {
        setReconnectCount(c => c + 1)
        connect()
      }, delay)
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
  }, [reconnectCount])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [])

  return { connected }
}
