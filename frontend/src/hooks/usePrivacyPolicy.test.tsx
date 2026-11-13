import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '../utils/api'
import { EVENTS } from '../utils/events'
import { usePrivacyPolicy } from './usePrivacyPolicy'

vi.mock('../utils/api', () => ({ apiFetch: vi.fn() }))
const apiMock = vi.mocked(apiFetch)
const response = (enabled: boolean) => ({ ok: true, json: async () => ({ success: true, data: { enabled } }) }) as Response

describe('privacy policy refresh', () => {
  beforeEach(() => { vi.useFakeTimers(); apiMock.mockReset() })
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

  it('locks immediately during policy changes and discards an older disabled response', async () => {
    let finishOld: ((value: Response) => void) | undefined
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    expect(hook.result.current.enabled).toBe(false)
    apiMock.mockImplementationOnce(() => new Promise<Response>(resolve => { finishOld = resolve }))
    act(() => { window.dispatchEvent(new Event(EVENTS.PRIVACY_POLICY_CHANGED)) })
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.loading).toBe(true)
    apiMock.mockResolvedValueOnce(response(true))
    await act(async () => { await hook.result.current.refresh() })
    await act(async () => { finishOld?.(response(false)) })
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.loading).toBe(false)
    hook.unmount()
  })

  it('detects a server policy change without a local policy event', async () => {
    let serverEnabled = false
    apiMock.mockImplementation(async () => response(serverEnabled))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    expect(hook.result.current.enabled).toBe(false)
    serverEnabled = true
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.loading).toBe(false)
    expect(apiMock).toHaveBeenCalledTimes(2)
    hook.unmount()
  })

  it('keeps unchanged silent checks from rerendering or temporarily locking plaintext', async () => {
    let finishPoll: ((value: Response) => void) | undefined
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    const unchanged = hook.result.current
    apiMock.mockImplementationOnce(() => new Promise<Response>(resolve => { finishPoll = resolve }))
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current).toBe(unchanged)
    expect(hook.result.current.loading).toBe(false)
    // A lookup remains silent until it resolves within the deadline.
    await act(async () => { await vi.advanceTimersByTimeAsync(4999) })
    expect(apiMock).toHaveBeenCalledTimes(2)
    await act(async () => { finishPoll?.(response(false)) })
    expect(hook.result.current).toBe(unchanged)
    hook.unmount()
  })

  it('fails closed when a silent server policy check fails', async () => {
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    expect(hook.result.current.enabled).toBe(false)
    apiMock.mockRejectedValueOnce(new Error('synthetic policy lookup failure'))
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.error).toBe(true)
    expect(hook.result.current.loading).toBe(false)
    hook.unmount()
  })

  it('rechecks server policy on focus before the next periodic check', async () => {
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    apiMock.mockResolvedValueOnce(response(true))
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    expect(hook.result.current.enabled).toBe(true)
    expect(apiMock).toHaveBeenCalledTimes(2)
    hook.unmount()
  })

  it('rechecks server policy when a hidden tab becomes visible', async () => {
    const hidden = vi.spyOn(document, 'hidden', 'get')
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    hidden.mockReturnValue(true)
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')) })
    expect(apiMock).toHaveBeenCalledTimes(1)
    apiMock.mockResolvedValueOnce(response(true))
    hidden.mockReturnValue(false)
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')) })
    expect(hook.result.current.enabled).toBe(true)
    expect(apiMock).toHaveBeenCalledTimes(2)
    hook.unmount()
  })

  it('ignores a late disabled poll after a newer policy-change check', async () => {
    let finishPoll: ((value: Response) => void) | undefined
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    apiMock.mockImplementationOnce(() => new Promise<Response>(resolve => { finishPoll = resolve }))
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    apiMock.mockResolvedValueOnce(response(true))
    await act(async () => { window.dispatchEvent(new Event(EVENTS.PRIVACY_POLICY_CHANGED)) })
    await act(async () => { finishPoll?.(response(false)) })
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.loading).toBe(false)
    hook.unmount()
  })

  it('times out a permanently pending silent lookup and permits the next server poll', async () => {
    let pendingSignal: AbortSignal | undefined
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    apiMock.mockImplementationOnce((_input, init) => {
      pendingSignal = init?.signal ?? undefined
      return new Promise<Response>(() => {})
    })
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current.enabled).toBe(false)
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(pendingSignal?.aborted).toBe(true)
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.error).toBe(true)
    expect(hook.result.current.loading).toBe(false)
    apiMock.mockResolvedValueOnce(response(true))
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(apiMock).toHaveBeenCalledTimes(3)
    expect(hook.result.current.error).toBe(false)
    hook.unmount()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('handles a fetch rejection on timeout abort and clears its deadline timer', async () => {
    let pendingSignal: AbortSignal | undefined
    apiMock.mockResolvedValueOnce(response(false))
    const hook = renderHook(() => usePrivacyPolicy())
    await act(async () => {})
    apiMock.mockImplementationOnce((_input, init) => {
      pendingSignal = init?.signal ?? undefined
      return new Promise<Response>((_resolve, reject) => {
        pendingSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
      })
    })
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(pendingSignal?.aborted).toBe(true)
    expect(hook.result.current.enabled).toBe(true)
    expect(hook.result.current.error).toBe(true)
    // Only the periodic policy check remains after the failed request.
    expect(vi.getTimerCount()).toBe(1)
    apiMock.mockResolvedValueOnce(response(false))
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(hook.result.current.enabled).toBe(false)
    expect(hook.result.current.error).toBe(false)
    hook.unmount()
    expect(vi.getTimerCount()).toBe(0)
  })
})
