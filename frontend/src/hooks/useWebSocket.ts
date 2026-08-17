import { useState, useEffect, useRef, useCallback } from 'react'

interface WebSocketMessage {
  data: string
}

interface UseWebSocketReturn {
  lastMessage: WebSocketMessage | null
  sendMessage: (message: string) => void
  readyState: number
  connectionStatus: 'connecting' | 'connected' | 'reconnecting'
  reconnectAttempt: number
  lastConnectedAt: number | null
  lastMessageAt: number | null
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
  'Alert',
])

/** High-frequency message throttle interval (ms) - NewSession/SessionUpdate are emitted at most once every 5 seconds. */
const THROTTLE_MS = 5000

/** These message types are throttled instead of forwarding every update. */
const THROTTLED_TYPES = new Set(['NewSession', 'SessionUpdate', 'StatsUpdate'])

export function useWebSocket(url: string): UseWebSocketReturn {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'reconnecting'>('connecting')
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [lastConnectedAt, setLastConnectedAt] = useState<number | null>(null)
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number | null>(null)
  const reconnectAttemptRef = useRef(0)
  const connectingRef = useRef(false)
  const connectRef = useRef<() => void>(() => {})
  const mountedRef = useRef(true)
  /** Throttling state is isolated per message type so one event cannot hide another. */
  const lastThrottledRef = useRef(new Map<string, number>())
  const throttleTimerRef = useRef(new Map<string, number>())
  /** Latest pending message buffered inside each type's throttle window. */
  const pendingThrottledRef = useRef(new Map<string, WebSocketMessage>())
  const recordMessageActivity = useCallback(() => {
    const now = Date.now()
    setLastMessageAt(previous => {
      if (previous !== null && Math.floor(previous / 60_000) === Math.floor(now / 60_000)) {
        return previous
      }
      return now
    })
  }, [])

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current || reconnectTimeoutRef.current !== null) return

    const nextAttempt = reconnectAttemptRef.current + 1
    reconnectAttemptRef.current = nextAttempt
    setReconnectAttempt(nextAttempt)
    setConnectionStatus('reconnecting')
    const delay = Math.min(3_000 * (2 ** (nextAttempt - 1)), 30_000)
    reconnectTimeoutRef.current = window.setTimeout(() => {
      reconnectTimeoutRef.current = null
      if (mountedRef.current) connectRef.current()
    }, delay)
  }, [])

  const connect = useCallback(() => {
    if (!mountedRef.current || connectingRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    connectingRef.current = true
    setReadyState(WebSocket.CONNECTING)
    if (reconnectAttemptRef.current === 0) setConnectionStatus('connecting')

    // SEC-H02: fetch a one-time ticket first so the JWT never appears in the WebSocket URL
    // Cookie-based auth: no need to read localStorage, cookie is sent automatically
    const fetchTicketAndConnect = async () => {
      try {
        const res = await fetch('/api/auth/ws-ticket', {
          method: 'POST',
          credentials: 'same-origin', // HttpOnly cookie auto-sent
        })
        if (!res.ok) {
          console.warn(`ws-ticket request failed with status ${res.status}`)
          return null
        }
        const data = await res.json() as { ticket?: unknown }
        if (typeof data.ticket !== 'string' || data.ticket.length === 0) {
          console.warn('ws-ticket response did not contain a valid ticket')
          return null
        }
        const separator = url.includes('?') ? '&' : '?'
        return `${url}${separator}ticket=${encodeURIComponent(data.ticket)}`
      } catch {
        return null
      }
    }

    fetchTicketAndConnect().then(wsUrl => {
      connectingRef.current = false
      if (!mountedRef.current) return
      if (!wsUrl) {
        setReadyState(WebSocket.CLOSED)
        scheduleReconnect()
        return
      }

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        if (!mountedRef.current) { ws.close(); return }
        console.log('WebSocket connected')
        reconnectAttemptRef.current = 0
        setReconnectAttempt(0)
        setReadyState(WebSocket.OPEN)
        setConnectionStatus('connected')
        setLastConnectedAt(Date.now())
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
          const lastForwarded = lastThrottledRef.current.get(msgType)
          pendingThrottledRef.current.set(msgType, msg)
          if (lastForwarded === undefined || now - lastForwarded >= THROTTLE_MS) {
            // If the throttle window has expired, forward immediately
            lastThrottledRef.current.set(msgType, now)
            pendingThrottledRef.current.delete(msgType)
            recordMessageActivity()
            setLastMessage(msg)
          } else if (!throttleTimerRef.current.has(msgType)) {
            // Inside the throttle window, schedule a timer to forward the latest message when the window closes
            const remaining = THROTTLE_MS - (now - lastForwarded)
            const timer = window.setTimeout(() => {
              throttleTimerRef.current.delete(msgType)
              lastThrottledRef.current.set(msgType, Date.now())
              const pending = pendingThrottledRef.current.get(msgType)
              pendingThrottledRef.current.delete(msgType)
              if (pending && mountedRef.current) {
                recordMessageActivity()
                setLastMessage(pending)
              }
            }, remaining)
            throttleTimerRef.current.set(msgType, timer)
          }
          return
        }

        // Low-frequency messages (SecurityVerdict, RefreshNeeded, alerts) are forwarded immediately.
        recordMessageActivity()
        setLastMessage(msg)
      }

      ws.onclose = () => {
        if (!mountedRef.current) return
        console.log('WebSocket disconnected')
        if (wsRef.current === ws) wsRef.current = null
        setReadyState(WebSocket.CLOSED)
        scheduleReconnect()
      }

      ws.onerror = (error) => {
        if (!mountedRef.current) return
        console.error('WebSocket error:', error)
      }

      wsRef.current = ws
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      setReadyState(WebSocket.CLOSED)
      scheduleReconnect()
    }

    }) // end fetchTicketAndConnect().then()
  }, [recordMessageActivity, scheduleReconnect, url])

  connectRef.current = connect

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false
      connectingRef.current = false

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
      for (const timer of throttleTimerRef.current.values()) {
        clearTimeout(timer)
      }
      throttleTimerRef.current.clear()
      pendingThrottledRef.current.clear()
      lastThrottledRef.current.clear()

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
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    reconnectAttemptRef.current = 0
    setReconnectAttempt(0)
    setConnectionStatus('connecting')
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
    connectionStatus,
    reconnectAttempt,
    lastConnectedAt,
    lastMessageAt,
    reconnect,
  }
}
