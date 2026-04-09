import { useState, useEffect, useRef, useCallback } from 'react'

interface WebSocketMessage {
  data: string
}

interface UseWebSocketReturn {
  lastMessage: WebSocketMessage | null
  sendMessage: (message: string) => void
  readyState: number
  reconnect: () => void
}

/**
 * Message types the frontend cares about; discard everything else.
 * StatsUpdate: traffic statistics, emitted by the backend at about 1/s
 * NewSession / SessionUpdate: trigger mail list refreshes
 * SecurityVerdict: trigger security stats refreshes
 * RefreshNeeded / DataSecurityAlert: low-frequency control messages
 */
const RELEVANT_TYPES = new Set([
  'StatsUpdate',
  'NewSession',
  'SessionUpdate',
  'SecurityVerdict',
  'RefreshNeeded',
  'DataSecurityAlert',
])

/** High-frequency message throttle interval (ms) - NewSession/SessionUpdate are emitted at most once every 5 seconds. */
const THROTTLE_MS = 5000

/** These message types are throttled instead of forwarding every update. */
const THROTTLED_TYPES = new Set(['NewSession', 'SessionUpdate', 'StatsUpdate'])

export function useWebSocket(url: string): UseWebSocketReturn {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number | null>(null)
  const mountedRef = useRef(true)
  /** Throttling: timestamp of the last forwarded throttled message type. */
  const lastThrottledRef = useRef(0)
  const throttleTimerRef = useRef(0)
  /** Latest pending message buffered inside the throttle window. */
  const pendingThrottledRef = useRef<WebSocketMessage | null>(null)

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    // SEC-H02: fetch a one-time ticket first so the JWT never appears in the WebSocket URL
    // Cookie-based auth: no need to read localStorage, cookie is sent automatically
    const fetchTicketAndConnect = async () => {
      try {
        const res = await fetch('/api/auth/ws-ticket', {
          method: 'POST',
          credentials: 'same-origin', // HttpOnly cookie auto-sent
        })
        if (!res.ok) {
          // Ticket fetch failed - connect to the base URL without credentials; the server may reject it
          console.warn('ws-ticket 获取失败，将尝试无凭据连接')
          return url
        }
        const data = await res.json()
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        return `${proto}//${window.location.host}/ws?ticket=${encodeURIComponent(data.ticket)}`
      } catch {
        return url  // Fall back to the base URL without credentials on network errors
      }
    }

    fetchTicketAndConnect().then(wsUrl => {
      if (!mountedRef.current || !wsUrl) return

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        if (!mountedRef.current) { ws.close(); return }
        console.log('WebSocket connected')
        setReadyState(WebSocket.OPEN)
      }

      ws.onmessage = (event) => {
        if (!mountedRef.current) return

        // Fast-path extraction of the type field to avoid a full JSON.parse
        const raw: string = event.data
        const typeMatch = raw.match(/"type"\s*:\s*"([^"]+)"/)
        if (!typeMatch) return
        const msgType = typeMatch[1]

        // Drop messages the frontend does not care about
        if (!RELEVANT_TYPES.has(msgType)) return

        const msg: WebSocketMessage = { data: raw }

        // Throttle high-frequency message types
        if (THROTTLED_TYPES.has(msgType)) {
          const now = Date.now()
          pendingThrottledRef.current = msg
          if (now - lastThrottledRef.current >= THROTTLE_MS) {
            // If the throttle window has expired, forward immediately
            lastThrottledRef.current = now
            pendingThrottledRef.current = null
            setLastMessage(msg)
          } else if (!throttleTimerRef.current) {
            // Inside the throttle window, schedule a timer to forward the latest message when the window closes
            const remaining = THROTTLE_MS - (now - lastThrottledRef.current)
            throttleTimerRef.current = window.setTimeout(() => {
              throttleTimerRef.current = 0
              lastThrottledRef.current = Date.now()
              const pending = pendingThrottledRef.current
              pendingThrottledRef.current = null
              if (pending && mountedRef.current) {
                setLastMessage(pending)
              }
            }, remaining)
          }
          return
        }

        // Non-throttled messages (StatsUpdate, SecurityVerdict, RefreshNeeded, etc.) are forwarded immediately
        setLastMessage(msg)
      }

      ws.onclose = () => {
        if (!mountedRef.current) return
        console.log('WebSocket disconnected')
        setReadyState(WebSocket.CLOSED)

        if (mountedRef.current) {
          if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current)
          }
          reconnectTimeoutRef.current = window.setTimeout(() => {
            if (mountedRef.current) {
              console.log('Attempting to reconnect...')
              connect()
            }
          }, 3000)
        }
      }

      ws.onerror = (error) => {
        if (!mountedRef.current) return
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
    }

    }) // end fetchTicketAndConnect().then()
  }, [url])

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
      if (throttleTimerRef.current) {
        clearTimeout(throttleTimerRef.current)
        throttleTimerRef.current = 0
      }

      if (wsRef.current) {
        wsRef.current.onopen = null
        wsRef.current.onmessage = null
        wsRef.current.onclose = null
        wsRef.current.onerror = null
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  const sendMessage = useCallback((message: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(message)
    }
  }, [])

  const reconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }
    connect()
  }, [connect])

  return {
    lastMessage,
    sendMessage,
    readyState,
    reconnect,
  }
}
