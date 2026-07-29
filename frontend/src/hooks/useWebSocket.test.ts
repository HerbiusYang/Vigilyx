import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useWebSocket } from './useWebSocket'

type SocketHandler = ((event: { data: string }) => void) | null

class MockWebSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3
  static instances: MockWebSocket[] = []

  readonly url: string
  readyState = MockWebSocket.CONNECTING
  onopen: (() => void) | null = null
  onmessage: SocketHandler = null
  onclose: (() => void) | null = null
  onerror: ((error: unknown) => void) | null = null
  sent: string[] = []

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  receive(data: string) {
    this.onmessage?.({ data })
  }

  send(message: string) {
    this.sent.push(message)
  }

  close() {
    this.readyState = MockWebSocket.CLOSED
  }
}

async function renderConnectedHook() {
  const hook = renderHook(() => useWebSocket('ws://fallback.test/ws'))
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
  })
  const socket = MockWebSocket.instances[MockWebSocket.instances.length - 1]
  expect(socket).toBeDefined()
  act(() => socket!.open())
  return { hook, socket: socket! }
}

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-28T12:00:00Z'))
    MockWebSocket.instances = []
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ ticket: 'ticket/with spaces' }),
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('uses an encoded one-time ticket and reports the open state', async () => {
    const { hook, socket } = await renderConnectedHook()

    expect(socket.url).toContain('/ws?ticket=ticket%2Fwith%20spaces')
    expect(hook.result.current.readyState).toBe(MockWebSocket.OPEN)
    expect(hook.result.current.connectionStatus).toBe('connected')
    expect(hook.result.current.reconnectAttempt).toBe(0)
    expect(hook.result.current.lastConnectedAt).toBe(Date.now())
  })

  it('never opens an anonymous socket when ticket retrieval fails and retries with backoff', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 401 } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({ ticket: 'fresh-ticket' }),
      } as unknown as Response)

    const hook = renderHook(() => useWebSocket('ws://fallback.test/ws'))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(MockWebSocket.instances).toHaveLength(0)
    expect(hook.result.current.readyState).toBe(MockWebSocket.CLOSED)
    expect(hook.result.current.connectionStatus).toBe('reconnecting')
    expect(hook.result.current.reconnectAttempt).toBe(1)

    await act(async () => {
      vi.advanceTimersByTime(2_999)
      await Promise.resolve()
    })
    expect(MockWebSocket.instances).toHaveLength(0)

    await act(async () => {
      vi.advanceTimersByTime(1)
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(MockWebSocket.instances[0].url).toContain('ticket=fresh-ticket')
  })

  it('rejects an empty ticket instead of opening an unauthenticated socket', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response)

    const hook = renderHook(() => useWebSocket('ws://fallback.test/ws'))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(MockWebSocket.instances).toHaveLength(0)
    expect(hook.result.current.connectionStatus).toBe('reconnecting')
  })

  it('throttles NewSession, SessionUpdate, and StatsUpdate independently', async () => {
    const { hook, socket } = await renderConnectedHook()

    act(() => socket.receive('{"type":"NewSession","data":{"id":"mail-1"}}'))
    expect(hook.result.current.lastMessage?.data).toContain('mail-1')
    expect(hook.result.current.lastMessageAt).toBe(Date.now())

    act(() => socket.receive('{"type":"StatsUpdate","data":{"total":7}}'))
    expect(hook.result.current.lastMessage?.data).toContain('"total":7')

    act(() => socket.receive('{"type":"SessionUpdate","data":{"id":"mail-2"}}'))
    expect(hook.result.current.lastMessage?.data).toContain('mail-2')
  })

  it('flushes only the latest pending message for the same type', async () => {
    const { hook, socket } = await renderConnectedHook()

    act(() => socket.receive('{"type":"NewSession","data":{"id":"first"}}'))
    act(() => socket.receive('{"type":"NewSession","data":{"id":"second"}}'))
    act(() => socket.receive('{"type":"NewSession","data":{"id":"latest"}}'))
    expect(hook.result.current.lastMessage?.data).toContain('first')

    act(() => vi.advanceTimersByTime(4_999))
    expect(hook.result.current.lastMessage?.data).toContain('first')

    act(() => vi.advanceTimersByTime(1))
    expect(hook.result.current.lastMessage?.data).toContain('latest')
  })

  it('drops malformed and irrelevant messages', async () => {
    const { hook, socket } = await renderConnectedHook()

    act(() => socket.receive('not-json'))
    act(() => socket.receive('{"type":"InternalDebug","data":{}}'))

    expect(hook.result.current.lastMessage).toBeNull()
  })
})
