import { useState, useEffect, useCallback, useRef, startTransition } from 'react'
import type { SystemMetrics, ApiResponse } from '../types'
import { apiFetch } from '../utils/api'

export function useSystemMetrics(intervalMs = 30000) {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const prevRef = useRef<string>('')

  const fetchMetrics = useCallback(async () => {
    // Skip polling while the page is hidden to reduce API requests
    if (document.hidden) return
    try {
      const res = await apiFetch('/api/system/metrics')
      const data: ApiResponse<SystemMetrics> = await res.json()
      if (data.success && data.data) {
        // Shallow-compare key fields and re-render only when they change
        const key = `${data.data.cpu_usage?.toFixed(0)}-${data.data.memory_percent?.toFixed(0)}-${data.data.uptime_secs}`
        if (key !== prevRef.current) {
          prevRef.current = key
          startTransition(() => {
            setMetrics(data.data)
          })
        }
      }
    } catch {
      // silently fail
    }
  }, [])

  useEffect(() => {
    fetchMetrics()
    const id = setInterval(fetchMetrics, intervalMs)
    return () => clearInterval(id)
  }, [fetchMetrics, intervalMs])

  return metrics
}
