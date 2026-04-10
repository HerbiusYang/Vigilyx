import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { apiFetch, resetLogoutFlag } from '../api'

describe('apiFetch', () => {
  const originalFetch = globalThis.fetch
  const originalDispatchEvent = window.dispatchEvent

  beforeEach(() => {
    resetLogoutFlag()
    window.dispatchEvent = vi.fn()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    window.dispatchEvent = originalDispatchEvent
  })

  it('passes through a normal 200 response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: () => Promise.resolve({ success: true }),
    })

    const res = await apiFetch('/api/test')
    expect(res.ok).toBe(true)
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/test', {
      credentials: 'same-origin',
    })
  })

  it('always sets credentials to same-origin', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
    })

    await apiFetch('/api/test', { headers: { 'X-Custom': 'value' } })
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/test', {
      headers: { 'X-Custom': 'value' },
      credentials: 'same-origin',
    })
  })

  it('dispatches auth:logout on 401', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    })

    await expect(apiFetch('/api/test')).rejects.toThrow()
    expect(window.dispatchEvent).toHaveBeenCalledWith(expect.any(Event))
    const event = (window.dispatchEvent as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(event.type).toBe('auth:logout')
  })

  it('deduplicates 401 logout events', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    })

    await expect(apiFetch('/api/test1')).rejects.toThrow()
    await expect(apiFetch('/api/test2')).rejects.toThrow()

    // Only one logout event should be dispatched
    const logoutCalls = (window.dispatchEvent as ReturnType<typeof vi.fn>).mock.calls
      .filter(([e]: [Event]) => e.type === 'auth:logout')
    expect(logoutCalls).toHaveLength(1)
  })

  it('resetLogoutFlag allows re-triggering logout', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    })

    await expect(apiFetch('/api/test')).rejects.toThrow()
    resetLogoutFlag()
    await expect(apiFetch('/api/test')).rejects.toThrow()

    const logoutCalls = (window.dispatchEvent as ReturnType<typeof vi.fn>).mock.calls
      .filter(([e]: [Event]) => e.type === 'auth:logout')
    expect(logoutCalls).toHaveLength(2)
  })

  it('throws error with message from JSON response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 403,
      ok: false,
      text: () => Promise.resolve(JSON.stringify({ error: 'Forbidden access' })),
    })

    await expect(apiFetch('/api/test')).rejects.toThrow('Forbidden access')
  })

  it('throws error with plain text when not JSON', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 500,
      ok: false,
      text: () => Promise.resolve('Internal Server Error'),
    })

    await expect(apiFetch('/api/test')).rejects.toThrow('Internal Server Error')
  })

  it('throws HTTP status code when text() fails', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 502,
      ok: false,
      text: () => Promise.reject(new Error('stream error')),
    })

    await expect(apiFetch('/api/test')).rejects.toThrow('HTTP 502')
  })

  it('merges custom init options with credentials', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
    })

    await apiFetch('/api/test', {
      method: 'POST',
      body: JSON.stringify({ key: 'value' }),
    })

    expect(globalThis.fetch).toHaveBeenCalledWith('/api/test', {
      method: 'POST',
      body: JSON.stringify({ key: 'value' }),
      credentials: 'same-origin',
    })
  })
})
