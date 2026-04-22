import { useSyncExternalStore } from 'react'
import type { TrafficStats } from '../types'
import { EVENTS } from '../utils/events'

interface RealtimeTrafficSnapshot {
  stats: TrafficStats | null
  connected: boolean
}

const listeners = new Set<() => void>()
let initialized = false
let snapshot: RealtimeTrafficSnapshot = {
  stats: null,
  connected: false,
}

function statsEqual(a: TrafficStats | null, b: TrafficStats | null): boolean {
  if (a === b) return true
  if (!a || !b) return false
  return a.total_sessions === b.total_sessions
    && a.active_sessions === b.active_sessions
    && a.total_packets === b.total_packets
    && a.total_bytes === b.total_bytes
    && a.smtp_sessions === b.smtp_sessions
    && a.pop3_sessions === b.pop3_sessions
    && a.imap_sessions === b.imap_sessions
    && a.packets_per_second === b.packets_per_second
    && a.bytes_per_second === b.bytes_per_second
}

function emitIfChanged(next: RealtimeTrafficSnapshot) {
  if (snapshot.connected === next.connected && statsEqual(snapshot.stats, next.stats)) {
    return
  }

  snapshot = next
  listeners.forEach(listener => listener())
}

function initStore() {
  if (initialized || typeof window === 'undefined') return
  initialized = true

  window.addEventListener(EVENTS.STATS_UPDATE, (event: Event) => {
    const detail = (event as CustomEvent).detail
    emitIfChanged({
      stats: detail?.stats ?? snapshot.stats,
      connected: detail?.connected ?? snapshot.connected,
    })
  })

  window.addEventListener(EVENTS.CONNECTION_CHANGE, (event: Event) => {
    const detail = (event as CustomEvent).detail
    if (typeof detail?.connected !== 'boolean') return
    emitIfChanged({
      stats: snapshot.stats,
      connected: detail.connected,
    })
  })
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function getSnapshot() {
  return snapshot
}

export function useRealtimeTraffic() {
  initStore()
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}
