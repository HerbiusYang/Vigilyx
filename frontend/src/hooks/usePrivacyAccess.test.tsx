import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { PrivacyAccessContext, PrivacyLease } from '../types'
import { apiFetch } from '../utils/api'
import { PRIVACY_LEASE_HEADER, usePrivacyAccess } from './usePrivacyAccess'

vi.mock('../utils/api', () => ({ apiFetch: vi.fn() }))
const apiMock = vi.mocked(apiFetch)

function lease(resourceId = 'session-example', ttl = 60_000): PrivacyLease {
  return {
    request_id: `request-${resourceId}`, resource_type: 'session', resource_id: resourceId,
    scopes: ['body'], expires_at: new Date(Date.now() + ttl).toISOString(),
    uses_remaining: 10, lease_handle: `synthetic-lease-${resourceId}`,
  }
}

function context(leases: PrivacyLease[]): PrivacyAccessContext {
  return {
    current_user: { id: 'example-user', role_id: 'example-role', username: 'example', display_name: 'Example',
      role: 'admin', permissions: [], factor_configured: true },
    active_leases: leases,
  }
}

function response(data: unknown): Response {
  return { ok: true, json: async () => ({ success: true, data }) } as Response
}

describe('privacy lease invalidation', () => {
  beforeEach(() => { vi.useFakeTimers(); apiMock.mockReset() })
  afterEach(() => { vi.useRealTimers() })

  it('invalidates a missing server lease before its local TTL and does not repoll on inline resource renders', async () => {
    let leases = [lease()]
    apiMock.mockImplementation(async input => response(String(input) === '/api/privacy/context' ? context(leases) : []))
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    expect(hook.result.current.leaseHeaders('body')).toEqual({ [PRIVACY_LEASE_HEADER]: leases[0].lease_handle })
    hook.rerender()
    await act(async () => {})
    expect(apiMock.mock.calls.filter(([input]) => String(input) === '/api/privacy/context')).toHaveLength(1)
    leases = []
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current.lease).toBeNull()
    expect(hook.result.current.leaseHeaders('body')).toBeUndefined()
    hook.unmount()
  })

  it('expires a lease locally without waiting for the next server poll', async () => {
    const current = lease('session-example', 1000)
    apiMock.mockImplementation(async input => response(String(input) === '/api/privacy/context' ? context([current]) : []))
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    expect(hook.result.current.canUse('body')).toBe(true)
    await act(async () => { await vi.advanceTimersByTimeAsync(1001) })
    expect(hook.result.current.canUse('body')).toBe(false)
    hook.unmount()
  })

  it('ignores a late refresh for a previously selected resource', async () => {
    let finishOld: ((value: Response) => void) | undefined
    let contextCalls = 0
    const current = lease('session-new')
    apiMock.mockImplementation(async input => {
      if (String(input) !== '/api/privacy/context') return response([])
      if (++contextCalls === 1) return new Promise<Response>(resolve => { finishOld = resolve })
      return response(context([current]))
    })
    const hook = renderHook(({ id }) => usePrivacyAccess({ resource_type: 'session', resource_id: id }),
      { initialProps: { id: 'session-old' } })
    hook.rerender({ id: 'session-new' })
    await act(async () => {})
    expect(hook.result.current.lease?.resource_id).toBe('session-new')
    await act(async () => { finishOld?.(response(context([lease('session-old')]))) })
    expect(hook.result.current.lease?.resource_id).toBe('session-new')
    hook.unmount()
  })

  it('does not resurrect a locally locked lease from a stale server snapshot', async () => {
    const current = lease()
    apiMock.mockImplementation(async input => response(String(input) === '/api/privacy/context' ? context([current]) : []))
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    await act(async () => { await hook.result.current.lock() })
    await act(async () => { await hook.result.current.refresh() })
    expect(hook.result.current.lease).toBeNull()
    hook.unmount()
  })

  it('does not restore access when an acquisition resolves after locking', async () => {
    let finishAcquire: ((value: Response) => void) | undefined
    let serverLeases: PrivacyLease[] = []
    apiMock.mockImplementation(async input => {
      const path = String(input)
      if (path.endsWith('/lease')) return new Promise<Response>(resolve => { finishAcquire = resolve })
      return response(path === '/api/privacy/context' ? context(serverLeases) : [])
    })
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    let acquisition: Promise<PrivacyLease | Error> | undefined
    act(() => { acquisition = hook.result.current.acquire('request-session-example').catch(error => error as Error) })
    await act(async () => { await hook.result.current.lock() })
    let result: PrivacyLease | Error | undefined
    await act(async () => {
      serverLeases = [lease()]
      finishAcquire?.(response(serverLeases[0]))
      result = await acquisition
    })
    expect(result).toBeInstanceOf(Error)
    await act(async () => { await hook.result.current.refresh() })
    expect(hook.result.current.lease).toBeNull()
    expect(hook.result.current.leaseHeaders('body')).toBeUndefined()
    let reacquisition: Promise<PrivacyLease> | undefined
    act(() => { reacquisition = hook.result.current.acquire('request-session-example') })
    await act(async () => {
      finishAcquire?.(response(serverLeases[0]))
      await reacquisition
    })
    expect(hook.result.current.canUse('body')).toBe(true)
    hook.unmount()
  })

  it('keeps the newer acquisition when two leases resolve out of order', async () => {
    const finishAcquire = new Map<string, (value: Response) => void>()
    apiMock.mockImplementation(async input => {
      const path = String(input)
      if (path.endsWith('/lease')) return new Promise<Response>(resolve => { finishAcquire.set(path, resolve) })
      return response(path === '/api/privacy/context' ? context([]) : [])
    })
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    let older: Promise<PrivacyLease | Error> | undefined
    let newer: Promise<PrivacyLease> | undefined
    act(() => {
      older = hook.result.current.acquire('request-older').catch(error => error as Error)
      newer = hook.result.current.acquire('request-newer')
    })
    const newLease = { ...lease(), request_id: 'request-newer', lease_handle: 'synthetic-newer-lease' }
    await act(async () => {
      finishAcquire.get('/api/privacy/access-requests/request-newer/lease')?.(response(newLease))
      await newer
    })
    let oldResult: PrivacyLease | Error | undefined
    await act(async () => {
      finishAcquire.get('/api/privacy/access-requests/request-older/lease')?.(response({ ...lease(), request_id: 'request-older' }))
      oldResult = await older
    })
    expect(oldResult).toBeInstanceOf(Error)
    expect(hook.result.current.leaseHeaders('body')).toEqual({ [PRIVACY_LEASE_HEADER]: newLease.lease_handle })
    hook.unmount()
  })

  it('allows a current acquisition to finish across a periodic context refresh', async () => {
    let finishAcquire: ((value: Response) => void) | undefined
    apiMock.mockImplementation(async input => {
      const path = String(input)
      if (path.endsWith('/lease')) return new Promise<Response>(resolve => { finishAcquire = resolve })
      return response(path === '/api/privacy/context' ? context([]) : [])
    })
    const hook = renderHook(() => usePrivacyAccess({ resource_type: 'session', resource_id: 'session-example' }))
    await act(async () => {})
    let acquisition: Promise<PrivacyLease> | undefined
    act(() => { acquisition = hook.result.current.acquire('request-session-example') })
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    await act(async () => {
      finishAcquire?.(response(lease()))
      await acquisition
    })
    expect(hook.result.current.canUse('body')).toBe(true)
    hook.unmount()
  })
})
