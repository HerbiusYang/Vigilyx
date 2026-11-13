import { useCallback, useEffect, useRef, useState } from 'react'
import type { ApiResponse } from '../types'
import { apiFetch } from '../utils/api'
import { EVENTS } from '../utils/events'

export interface PrivacyPolicy {
  enabled: boolean
}

async function readPolicy(response: Response): Promise<PrivacyPolicy> {
  const body = await response.json().catch(() => null) as ApiResponse<PrivacyPolicy> | null
  if (!body?.success || typeof body.data?.enabled !== 'boolean') throw new Error('privacy_policy_invalid')
  return { enabled: body.data.enabled }
}

async function loadPrivacyPolicy(signal?: AbortSignal): Promise<PrivacyPolicy> {
  return readPolicy(await apiFetch('/api/config/privacy', signal ? { signal } : undefined))
}

export function usePrivacyPolicy() {
  const [state, setState] = useState({ enabled: true, loading: true, error: false })
  const currentState = useRef(state)
  const refreshGeneration = useRef(0)
  const inFlightGeneration = useRef<number | null>(null)
  const pendingLookup = useRef<AbortController | null>(null)

  const updateState = useCallback((next: typeof state) => {
    const current = currentState.current
    if (current.enabled === next.enabled && current.loading === next.loading && current.error === next.error) return
    currentState.current = next
    setState(next)
  }, [])

  const checkPolicy = useCallback(async (lockImmediately: boolean) => {
    // Do not let periodic checks supersede an unfinished policy lookup.
    if (!lockImmediately && inFlightGeneration.current !== null) return
    pendingLookup.current?.abort()
    const generation = ++refreshGeneration.current
    inFlightGeneration.current = generation
    const controller = new AbortController()
    pendingLookup.current = controller
    const timeout = window.setTimeout(() => controller.abort(), 5000)
    let rejectOnAbort: (() => void) | undefined
    if (lockImmediately) {
      // Local changes hide delivered plaintext before checking the server.
      updateState({ ...currentState.current, enabled: true, loading: true })
    }
    try {
      // Resolve the deadline even if an underlying request never settles.
      const aborted = new Promise<never>((_, reject) => {
        rejectOnAbort = () => reject(new Error('privacy_policy_unavailable'))
        controller.signal.addEventListener('abort', rejectOnAbort, { once: true })
      })
      const policy = await Promise.race([loadPrivacyPolicy(controller.signal), aborted])
      if (generation !== refreshGeneration.current) return
      updateState({ enabled: policy.enabled, loading: false, error: false })
    } catch {
      if (generation !== refreshGeneration.current) return
      // A policy lookup failure must never expose plaintext in the browser.
      updateState({ enabled: true, loading: false, error: true })
    } finally {
      window.clearTimeout(timeout)
      if (rejectOnAbort) controller.signal.removeEventListener('abort', rejectOnAbort)
      if (pendingLookup.current === controller) pendingLookup.current = null
      if (inFlightGeneration.current === generation) inFlightGeneration.current = null
    }
  }, [updateState])

  const refresh = useCallback(() => checkPolicy(true), [checkPolicy])

  useEffect(() => {
    void refresh()
    const handleChange = () => { void refresh() }
    // Other tabs and operators can change the server policy without a local
    // event. Unchanged checks leave authorization and plaintext caches intact.
    const handleFocus = () => { void checkPolicy(false) }
    const handleVisibility = () => { if (!document.hidden) void checkPolicy(false) }
    const timer = window.setInterval(() => { void checkPolicy(false) }, 5000)
    window.addEventListener(EVENTS.PRIVACY_POLICY_CHANGED, handleChange)
    window.addEventListener('focus', handleFocus)
    document.addEventListener('visibilitychange', handleVisibility)
    return () => {
      refreshGeneration.current += 1
      inFlightGeneration.current = null
      pendingLookup.current?.abort()
      pendingLookup.current = null
      window.clearInterval(timer)
      window.removeEventListener(EVENTS.PRIVACY_POLICY_CHANGED, handleChange)
      window.removeEventListener('focus', handleFocus)
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  }, [refresh, checkPolicy])

  return { ...state, refresh }
}
