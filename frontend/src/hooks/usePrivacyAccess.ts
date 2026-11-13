import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type {
  ApiResponse,
  PrivacyAccessContext,
  PrivacyAccessRequest,
  PrivacyLease,
  PrivacyResourceRef,
  PrivacyScope,
} from '../types'
import { apiFetch } from '../utils/api'

export const PRIVACY_LEASE_HEADER = 'X-Vigilyx-Privacy-Lease'

export interface CreatePrivacyRequestInput {
  resource_type: PrivacyResourceRef['resource_type']
  resource_id: string
  scopes: PrivacyScope[]
  purpose: string
  ttl_seconds: number
  admin_key: string
}

interface PrivacyRequestQuery {
  status?: PrivacyAccessRequest['status']
  resource_type?: PrivacyResourceRef['resource_type']
  resource_id?: string
  limit?: number
}

type PrivacyEnvelope<T> = ApiResponse<T>

function queryString(query: PrivacyRequestQuery): string {
  const params = new URLSearchParams()
  if (query.status) params.set('status', query.status)
  if (query.resource_type) params.set('resource_type', query.resource_type)
  if (query.resource_id) params.set('resource_id', query.resource_id)
  if (query.limit) params.set('limit', String(query.limit))
  const value = params.toString()
  return value ? `?${value}` : ''
}

async function readData<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null) as PrivacyEnvelope<T> | null
  if (!body?.success || body.data == null) throw new Error('privacy_request_failed')
  return body.data
}

async function loadPrivacyContext(): Promise<PrivacyAccessContext> {
  return readData(await apiFetch('/api/privacy/context'))
}

async function loadPrivacyRequests(query: PrivacyRequestQuery = {}): Promise<PrivacyAccessRequest[]> {
  const data = await readData<PrivacyAccessRequest[] | { items: PrivacyAccessRequest[] }>(
    await apiFetch(`/api/privacy/access-requests${queryString(query)}`),
  )
  return Array.isArray(data) ? data : data.items
}

async function createPrivacyRequest(input: CreatePrivacyRequestInput): Promise<PrivacyAccessRequest> {
  return readData(await apiFetch('/api/privacy/access-requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  }))
}

export async function approvePrivacyRequest(requestId: string, factor: string): Promise<PrivacyAccessRequest> {
  return readData(await apiFetch(`/api/privacy/access-requests/${encodeURIComponent(requestId)}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ factor }),
  }))
}

export async function rejectPrivacyRequest(requestId: string, reason?: string): Promise<PrivacyAccessRequest> {
  return readData(await apiFetch(`/api/privacy/access-requests/${encodeURIComponent(requestId)}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(reason ? { reason } : {}),
  }))
}

export async function setPrivacyFactor(factor: string, currentFactor?: string): Promise<void> {
  await readData(await apiFetch('/api/privacy/factor', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ factor, ...(currentFactor ? { current_factor: currentFactor } : {}) }),
  }))
}

async function acquirePrivacyLease(requestId: string): Promise<PrivacyLease> {
  return readData(await apiFetch(`/api/privacy/access-requests/${encodeURIComponent(requestId)}/lease`))
}

async function revokePrivacyLease(requestId: string): Promise<void> {
  await apiFetch(`/api/privacy/access-requests/${encodeURIComponent(requestId)}/revoke`, { method: 'POST' })
}

function isLeaseUsable(lease: PrivacyLease | null, resource: PrivacyResourceRef | null): boolean {
  if (!lease || !resource || lease.resource_type !== resource.resource_type || lease.resource_id !== resource.resource_id) return false
  return Date.parse(lease.expires_at) > Date.now() && lease.uses_remaining > 0 && Boolean(lease.lease_handle)
}

export function usePrivacyAccess(resource: PrivacyResourceRef | null = null) {
  // Callers commonly construct this reference inline. Its identity must not
  // restart polling on every render or let an old resource refresh win.
  const resourceType = resource?.resource_type
  const resourceId = resource?.resource_id
  const stableResource = useMemo<PrivacyResourceRef | null>(() => (
    resourceType && resourceId ? { resource_type: resourceType, resource_id: resourceId } : null
  ), [resourceType, resourceId])
  const [context, setContext] = useState<PrivacyAccessContext | null>(null)
  const [requests, setRequests] = useState<PrivacyAccessRequest[]>([])
  const [lease, setLease] = useState<PrivacyLease | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const resourceKey = JSON.stringify([resourceType, resourceId])
  const currentResourceKey = useRef(resourceKey)
  currentResourceKey.current = resourceKey
  const refreshGeneration = useRef(0)
  const mutationEpoch = useRef(0)
  const inFlightAcquires = useRef(new Map<number, string>())
  const locallyRevoked = useRef(new Set<string>())

  const refresh = useCallback(async () => {
    const generation = ++refreshGeneration.current
    const isCurrent = () => generation === refreshGeneration.current && currentResourceKey.current === resourceKey
    setLoading(true)
    try {
      const [nextContext, nextRequests] = await Promise.all([
        loadPrivacyContext(),
        loadPrivacyRequests(stableResource ? { resource_type: stableResource.resource_type, resource_id: stableResource.resource_id, limit: 20 } : { limit: 50 }),
      ])
      if (!isCurrent()) return
      setContext(nextContext)
      setRequests(nextRequests)

      const serverLease = nextContext.active_leases.find(item =>
        stableResource && item.resource_type === stableResource.resource_type && item.resource_id === stableResource.resource_id,
      )
      // The server is authoritative: absence means revoked/exhausted, even
      // when the previously cached lease has not reached its local TTL.
      setLease(serverLease && isLeaseUsable(serverLease, stableResource) && !locallyRevoked.current.has(serverLease.request_id)
        ? serverLease : null)
      setError(null)
    } catch {
      if (!isCurrent()) return
      // A privacy service failure must never turn into plaintext access.
      setError('unavailable')
      setLease(null)
    } finally {
      if (isCurrent()) setLoading(false)
    }
  }, [stableResource, resourceKey])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => { void refresh() }, 5000)
    return () => {
      window.clearInterval(timer)
      refreshGeneration.current += 1
      mutationEpoch.current += 1
    }
  }, [refresh])

  useEffect(() => {
    if (!lease) return
    const remaining = Math.max(0, Date.parse(lease.expires_at) - Date.now())
    const timer = window.setTimeout(() => setLease(null), remaining)
    return () => window.clearTimeout(timer)
  }, [lease])

  const active = useMemo(() => isLeaseUsable(lease, stableResource) ? lease : null, [lease, stableResource])
  const canUse = useCallback((scope: PrivacyScope) => Boolean(active?.scopes.includes(scope)), [active])
  const leaseHeaders = useCallback((scope: PrivacyScope): HeadersInit | undefined => {
    if (!active || !active.scopes.includes(scope) || !active.lease_handle) return undefined
    return { [PRIVACY_LEASE_HEADER]: active.lease_handle }
  }, [active])

  const request = useCallback(async (input: Omit<CreatePrivacyRequestInput, 'resource_type' | 'resource_id'>) => {
    if (!stableResource) throw new Error('privacy_resource_missing')
    const created = await createPrivacyRequest({ ...input, resource_type: stableResource.resource_type, resource_id: stableResource.resource_id })
    if (currentResourceKey.current !== resourceKey) return created
    setRequests(current => [created, ...current.filter(item => item.request_id !== created.request_id)])
    return created
  }, [stableResource, resourceKey])

  const acquire = useCallback(async (requestId: string) => {
    // Context polling must not cancel a requested acquisition, but a newer
    // acquisition or an explicit lock must prevent its late response winning.
    const epoch = ++mutationEpoch.current
    inFlightAcquires.current.set(epoch, requestId)
    refreshGeneration.current += 1
    try {
      const nextLease = await acquirePrivacyLease(requestId)
      if (epoch !== mutationEpoch.current || currentResourceKey.current !== resourceKey || !isLeaseUsable(nextLease, stableResource)) throw new Error('privacy_lease_invalid')
      refreshGeneration.current += 1
      locallyRevoked.current.delete(requestId)
      setLease(nextLease)
      return nextLease
    } finally {
      inFlightAcquires.current.delete(epoch)
    }
  }, [stableResource, resourceKey])

  const lock = useCallback(async () => {
    const current = active
    mutationEpoch.current += 1
    refreshGeneration.current += 1
    if (current?.request_id) locallyRevoked.current.add(current.request_id)
    // The server may finish issuing an in-flight lease after this lock. A
    // later context poll must not restore that lease either.
    for (const requestId of inFlightAcquires.current.values()) locallyRevoked.current.add(requestId)
    setLease(null)
    if (current?.request_id) {
      await revokePrivacyLease(current.request_id).catch(() => {})
    }
  }, [active])

  return {
    context,
    requests,
    lease: active,
    loading,
    error,
    isAdmin: context?.current_user.role === 'admin' || context?.current_user.permissions.includes('privacy.request') === true,
    isAudit: context?.current_user.role === 'audit' || context?.current_user.permissions.includes('privacy.approve') === true,
    canUse,
    leaseHeaders,
    request,
    acquire,
    lock,
    refresh,
    setRequests,
  }
}
