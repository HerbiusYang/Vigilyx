import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { apiFetch } from '../../utils/api'
import TrafficList, { getEmailListSubject, WhitelistButton } from './TrafficList'
import { createEmailSession } from '../../test/factories'
import { EVENTS } from '../../utils/events'
import type { EmailSession } from '../../types'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

describe('TrafficList whitelist action', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    mockedApiFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({ success: true, data: { session_id: 'session-001' }, error: null }),
    } as unknown as Response)
  })

  it('adds the session sender and source IP through the session API even when list data is redacted', async () => {
    const user = userEvent.setup()
    render(<WhitelistButton sessionId="session-001" />)

    await user.click(screen.getByRole('button', { name: '加白' }))

    expect(mockedApiFetch).toHaveBeenCalledWith('/api/sessions/session-001/whitelist', { method: 'POST' })
  })

  it('shows automatic IOC cleanup while making shared IOC preservation explicit', async () => {
    const user = userEvent.setup()
    mockedApiFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        data: {
          session_id: 'session-001',
          ioc_cleanup: { deleted: 2, preserved_shared: 1 },
        },
        error: null,
      }),
    } as unknown as Response)
    render(<WhitelistButton sessionId="session-001" />)

    await user.click(screen.getByRole('button', { name: '加白' }))

    expect(await screen.findByRole('button', {
      name: '已加白，删除 2 个 IOC（保留 1 个共享 IOC）',
    })).toBeDisabled()
  })

  it('keeps the redacted-row action available after the session API rejects it', async () => {
    const user = userEvent.setup()
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    mockedApiFetch.mockResolvedValueOnce({ ok: false, status: 400 } as Response)
    render(<WhitelistButton sessionId="session-without-sender" />)

    await user.click(screen.getByRole('button', { name: '加白' }))

    expect(await screen.findByRole('button', { name: '失败' })).not.toBeDisabled()
    errorSpy.mockRestore()
  })
})

describe('TrafficList subject privacy projection', () => {
  it('keeps the first and last character while hiding the middle', () => {
    expect(getEmailListSubject(' 关于123123的文件 ', false, '（无主题）', '(已加密)')).toBe('关******件')
  })

  it('does not expose a redaction label for a subject that is absent', () => {
    expect(getEmailListSubject(null, false, i18n.t('emailSecurity.noSubject'), '(已加密)')).toBe('(无主题)')
  })

  it('keeps the encrypted label for encrypted sessions', () => {
    expect(getEmailListSubject(null, true, '省略信息', '(已加密)')).toBe('(已加密)')
  })

  it('is idempotent for a subject already projected by the API', () => {
    expect(getEmailListSubject('关******件', false, '省略信息', '(已加密)')).toBe('关******件')
  })

  it('shows the original subject when the administrator disables privacy mode', () => {
    expect(getEmailListSubject(' 关于123123的文件 ', false, '省略信息', '(已加密)', false)).toBe('关于123123的文件')
  })
})

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

function response(data: unknown): Response {
  return { ok: true, status: 200, json: vi.fn().mockResolvedValue({ success: true, data, error: null }) } as unknown as Response
}

function listResponse(page: number, sender = `page-${page}@example.test`, hasMore = true, overrides: Partial<EmailSession> = {}): Response {
  return response({
    items: [createEmailSession({ id: `session-${sender}`, mail_from: sender, ...overrides })],
    total: 0, total_pages: 0, page, limit: 10, has_more: hasMore, total_is_exact: false,
  })
}

function LocationProbe() {
  return <output data-testid="list-location">{useLocation().search}</output>
}

function renderList(search = '') {
  return render(<MemoryRouter initialEntries={[`/emails${search}`]}>
    <TrafficList />
    <LocationProbe />
  </MemoryRouter>)
}

function listCalls() {
  return mockedApiFetch.mock.calls.filter(([input]) => String(input).startsWith('/api/sessions?'))
}

function countCalls() {
  return mockedApiFetch.mock.calls.filter(([input]) => String(input).startsWith('/api/sessions/count?'))
}

function requestParams(input: RequestInfo | URL) {
  return new URL(String(input), 'http://localhost').searchParams
}

function sharedFilters(input: RequestInfo | URL) {
  const params = requestParams(input)
  params.delete('page')
  params.delete('skip_count')
  params.delete('after')
  params.sort()
  return params.toString()
}

function privacyResponse(input: RequestInfo | URL) {
  return String(input) === '/api/config/privacy' ? response({ enabled: true }) : null
}

describe('TrafficList independent rows and totals', () => {
  beforeEach(async () => {
    vi.useRealTimers()
    localStorage.clear()
    sessionStorage.clear()
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('renders rows while the count is pending, then adds exact pagination without fetching rows again', async () => {
    const count = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? count.promise : listResponse(1)))
    renderList()

    expect(await screen.findByText('page-1@example.test')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.totalLoading'))).toBeVisible()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') })).toBeEnabled()
    expect(screen.queryByRole('button', { name: i18n.t('emailSecurity.lastPage') })).not.toBeInTheDocument()
    expect(requestParams(listCalls()[0][0]).get('skip_count')).toBe('true')
    expect(sharedFilters(listCalls()[0][0])).toBe(sharedFilters(countCalls()[0][0]))

    await act(async () => { count.resolve(response({ total: 120, total_pages: 12 })) })
    expect(screen.getByText(i18n.t('emailSecurity.paginationInfo', { total: 120 }))).toBeVisible()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.lastPage') })).toBeEnabled()
    expect(screen.getByText('page-1@example.test')).toBeVisible()
    expect(listCalls()).toHaveLength(1)
    expect(countCalls()).toHaveLength(1)
  })

  it('sizes the first page to the visible table height and keeps the automatic size out of the URL', async () => {
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockImplementation(function (this: HTMLElement) {
      return this.classList.contains('table-container') ? 37 * 12 + 20 : 0
    })
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? response({ total: 120, total_pages: 10 }) : listResponse(1)))
    renderList()

    expect(await screen.findByText('page-1@example.test')).toBeVisible()
    expect(listCalls()).toHaveLength(1)
    expect(requestParams(listCalls()[0][0]).get('limit')).toBe('12')
    expect(requestParams(countCalls()[0][0]).get('limit')).toBe('12')
    expect(screen.getByRole('combobox', { name: i18n.t('emailSecurity.pageSizeLabel') })).toHaveValue('auto')
    expect(screen.getByTestId('list-location').textContent).not.toContain('page_size')
  })

  it('labels an estimated total and keeps previous/next navigation instead of page numbers', async () => {
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?')
        ? response({ total: 43764888, total_pages: 4376489, exact: false })
        : listResponse(1)))
    renderList()

    expect(await screen.findByText(
      i18n.t('emailSecurity.paginationInfoEstimated', { total: (43764888).toLocaleString() }),
    )).toBeVisible()
    expect(screen.queryByText(i18n.t('emailSecurity.paginationInfo', { total: 43764888 }))).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: i18n.t('emailSecurity.lastPage') })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') })).toBeEnabled()
  })

  it('keeps rows and next-page navigation when counting fails, and allows an explicit retry', async () => {
    let countAttempts = 0
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) {
        if (++countAttempts === 1) throw new Error('count timed out')
        return response({ total: 30, total_pages: 3 })
      }
      return listResponse(Number(requestParams(input).get('page')))
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('page-1@example.test')).toBeVisible()
    expect(await screen.findByText(i18n.t('emailSecurity.totalUnavailable'))).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('page-2@example.test')).toBeVisible()
    expect(countCalls()).toHaveLength(1)
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.prevPage') })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.recountTotal') }))
    expect(await screen.findByText(i18n.t('emailSecurity.paginationInfo', { total: 30 }))).toBeVisible()
    expect(screen.getByText('page-2@example.test')).toBeVisible()
    expect(countCalls()).toHaveLength(2)
    expect(requestParams(listCalls()[listCalls().length - 1][0]).get('page')).toBe('2')
  })

  it('keeps the successful page after a failed next-page request and retries the requested page even after reconnection', async () => {
    let pageTwoAttempts = 0
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return response({ total: 30, total_pages: 3 })
      const page = Number(requestParams(input).get('page'))
      if (page === 2 && ++pageTwoAttempts === 1) throw new Error('Next page request timed out')
      return listResponse(page)
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('page-1@example.test')).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('Next page request timed out')).toBeVisible()
    expect(screen.getByText('page-1@example.test')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.currentPage', { page: 1 }))).toBeVisible()
    expect(new URLSearchParams(screen.getByTestId('list-location').textContent!).get('page')).toBeNull()

    await act(async () => { window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED)) })
    expect(screen.getByText('Next page request timed out')).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.retry') }))
    expect(await screen.findByText('page-2@example.test')).toBeVisible()
    expect(screen.queryByText('page-1@example.test')).not.toBeInTheDocument()
    expect(screen.queryByText('Next page request timed out')).not.toBeInTheDocument()
    await waitFor(() => expect(new URLSearchParams(screen.getByTestId('list-location').textContent!).get('page')).toBe('2'))
    expect(requestParams(listCalls()[listCalls().length - 1][0]).get('page')).toBe('2')
    expect(countCalls()).toHaveLength(1)
  })

  it('does not present old rows as results of a new filter whose page request failed', async () => {
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return response({ total: 30, total_pages: 3 })
      if (requestParams(input).get('protocol') === 'SMTP') throw new Error('SMTP list request timed out')
      return listResponse(1)
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('page-1@example.test')).toBeVisible()
    await user.selectOptions(screen.getByRole('combobox', { name: i18n.t('emailSecurity.colProtocol') }), 'SMTP')
    expect(await screen.findByText('SMTP list request timed out')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.loadFailedTitle'))).toBeVisible()
    expect(screen.queryByText('page-1@example.test')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.retry') })).toBeEnabled()
  })

  it('shows the original error view when the first page request fails without usable rows', async () => {
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return response({ total: 0, total_pages: 0 })
      throw new Error('First page request timed out')
    })
    renderList()
    expect(await screen.findByText('First page request timed out')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.loadFailedTitle'))).toBeVisible()
    expect(screen.queryByText(i18n.t('emailSecurity.noRestoredEmails'))).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.retry') })).toBeEnabled()
  })

  it('retries the requested page when the previously successful page was empty', async () => {
    let pageTwoAttempts = 0
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return response({ total: 30, total_pages: 3 })
      const page = Number(requestParams(input).get('page'))
      if (page === 1) return response({ items: [], total: 0, total_pages: 0, page, limit: 10, has_more: false, total_is_exact: false })
      if (++pageTwoAttempts === 1) throw new Error('Empty-page navigation timed out')
      return listResponse(page)
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText(i18n.t('emailSecurity.noRestoredEmails'))).toBeVisible()
    await user.click(screen.getByRole('button', { name: '2' }))
    expect(await screen.findByText('Empty-page navigation timed out')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.loadFailedTitle'))).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.retry') }))
    expect(await screen.findByText('page-2@example.test')).toBeVisible()
    expect(countCalls()).toHaveLength(1)
  })

  it.each(['success', 'failure'] as const)('ignores cancelled old row/count %s after a newer filter succeeds', async outcome => {
    const oldRows = deferred<Response>()
    const oldCount = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      const params = requestParams(input)
      const counting = String(input).includes('/count?')
      if (params.get('protocol') !== 'SMTP') return counting ? oldCount.promise : oldRows.promise
      return counting ? response({ total: 80, total_pages: 8 }) : listResponse(1, 'smtp-current@example.test')
    })
    const user = userEvent.setup()
    renderList()
    await waitFor(() => expect(countCalls()).toHaveLength(1))
    const oldRowSignal = listCalls()[0][1]!.signal!
    const oldCountSignal = countCalls()[0][1]!.signal!
    await user.selectOptions(screen.getByRole('combobox', { name: i18n.t('emailSecurity.colProtocol') }), 'SMTP')
    expect(await screen.findByText('smtp-current@example.test')).toBeVisible()
    expect(oldRowSignal.aborted).toBe(true)
    expect(oldCountSignal.aborted).toBe(true)

    await act(async () => {
      if (outcome === 'success') {
        oldRows.resolve(listResponse(4, 'stale@example.test'))
        oldCount.resolve(response({ total: 999, total_pages: 100 }))
      } else {
        oldRows.reject(new Error('old list failed'))
        oldCount.reject(new Error('old count failed'))
      }
    })
    expect(screen.getByText('smtp-current@example.test')).toBeVisible()
    expect(screen.queryByText('stale@example.test')).not.toBeInTheDocument()
    expect(screen.queryByText('old list failed')).not.toBeInTheDocument()
    expect(screen.queryByText(i18n.t('emailSecurity.totalUnavailable'))).not.toBeInTheDocument()
    expect(screen.getByText(i18n.t('emailSecurity.paginationInfo', { total: 80 }))).toBeVisible()
    expect(countCalls()).toHaveLength(2)
  })

  it('preserves URL page, filters and risk fields, sharing one frozen cutoff while a late count arrives', async () => {
    let now = new Date('2026-10-08T08:00:00Z').getTime()
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    sessionStorage.setItem('vigilyx-inbound-src', '192.0.2.10')
    sessionStorage.setItem('vigilyx-inbound-dst', '198.51.100.10')
    const count = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? count.promise : listResponse(Number(requestParams(input).get('page')), undefined, true, {
        threat_level: 'high', threat_type: 'phishing',
      })))
    const user = userEvent.setup()
    renderList('?page=3&page_size=20&protocol_filter=POP3&status_filter=completed&content_filter_mode=ALL&time_filter=30m&direction_filter=inbound&auth_filter_mode=AUTH_SUCCESS')
    expect(await screen.findByText('page-3@example.test')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.threatHigh'))).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.threatType.phishing'))).toBeVisible()
    const first = requestParams(listCalls()[0][0])
    expect(Object.fromEntries(first)).toMatchObject({
      page: '3', limit: '20', protocol: 'POP3', status: 'completed', content_filter: 'NON_ENCRYPTED',
      auth_filter: 'AUTH_SUCCESS', source_ips: '192.0.2.10', dest_ips: '198.51.100.10', skip_count: 'true',
    })
    expect(first.get('since')).toBeTruthy()
    expect(sharedFilters(listCalls()[0][0])).toBe(sharedFilters(countCalls()[0][0]))
    now += 20_000
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('page-4@example.test')).toBeVisible()
    expect(sharedFilters(listCalls()[1][0])).toBe(sharedFilters(listCalls()[0][0]))
    expect(countCalls()).toHaveLength(1)

    await act(async () => { count.resolve(response({ total: 150, total_pages: 8 })) })
    expect(screen.getByText('page-4@example.test')).toBeVisible()
    expect(screen.queryByText('page-3@example.test')).not.toBeInTheDocument()
    expect(new URLSearchParams(screen.getByTestId('list-location').textContent!).get('page')).toBe('4')
    expect(screen.getByRole('combobox', { name: i18n.t('emailSecurity.pageSizeLabel') })).toHaveValue('20')
  })

  it('does not recount on WS refresh or reconnection and keeps rows after a background error', async () => {
    vi.useFakeTimers()
    let failRefresh = false
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return response({ total: 40, total_pages: 4 })
      if (failRefresh) throw new Error('background connection failed')
      return listResponse(1)
    })
    renderList()
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(screen.getByText('page-1@example.test')).toBeVisible()
    failRefresh = true
    await act(async () => {
      window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
      await vi.advanceTimersByTimeAsync(1500)
    })
    expect(screen.getByText('page-1@example.test')).toBeVisible()
    expect(screen.getByText(i18n.t('emailSecurity.sessionListRefreshFailed'))).toBeVisible()
    expect(countCalls()).toHaveLength(1)
    failRefresh = false
    await act(async () => { window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED)) })
    expect(screen.getByText('page-1@example.test')).toBeVisible()
    expect(screen.queryByText(i18n.t('emailSecurity.sessionListRefreshFailed'))).not.toBeInTheDocument()
    expect(listCalls()).toHaveLength(3)
    expect(countCalls()).toHaveLength(1)
  })

  it('refreshes an expired relative cutoff with one new matching row/count pair without resetting the URL page', async () => {
    let now = new Date('2026-10-08T08:00:00Z').getTime()
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? response({ total: 80, total_pages: 8 }) : listResponse(Number(requestParams(input).get('page')))))
    renderList('?page=3&time_filter=30m')
    expect(await screen.findByText('page-3@example.test')).toBeVisible()
    const firstSince = requestParams(listCalls()[0][0]).get('since')
    now += 61_000
    await act(async () => { window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED)) })
    await waitFor(() => expect(countCalls()).toHaveLength(2))
    expect(requestParams(listCalls()[1][0]).get('since')).not.toBe(firstSince)
    expect(sharedFilters(listCalls()[1][0])).toBe(sharedFilters(countCalls()[1][0]))
    expect(requestParams(listCalls()[1][0]).get('page')).toBe('3')
    expect(screen.getByText('page-3@example.test')).toBeVisible()
  })

  it('uses snapshot-scoped cursors and trusts has_more=false even when the final page is full', async () => {
    const count = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return count.promise
      const params = requestParams(input)
      const page = Number(params.get('page'))
      const filtered = params.get('protocol') === 'SMTP'
      return response({
        items: Array.from({ length: 10 }, (_, i) => createEmailSession({
          id: `cursor-${filtered}-${page}-${i}`, mail_from: `cursor-${filtered}-${page}-${i}@example.test`,
        })),
        total: 0, total_pages: 0, page, limit: 10, total_is_exact: false,
        has_more: page === 1, next_cursor: page === 1 ? 'opaque:+/page-two' : undefined,
      })
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('cursor-false-1-0@example.test')).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('cursor-false-2-0@example.test')).toBeVisible()
    expect(requestParams(listCalls()[1][0]).get('after')).toBe('opaque:+/page-two')
    expect(requestParams(countCalls()[0][0]).has('after')).toBe(false)
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') })).toBeDisabled()

    await user.selectOptions(screen.getByRole('combobox', { name: i18n.t('emailSecurity.colProtocol') }), 'SMTP')
    expect(await screen.findByText('cursor-true-1-0@example.test')).toBeVisible()
    expect(requestParams(listCalls()[2][0]).has('after')).toBe(false)
    expect(requestParams(listCalls()[2][0]).get('page')).toBe('1')
    expect(countCalls()).toHaveLength(2)
  })

  it('invalidates later cursors when page one is refreshed', async () => {
    let headVersion = 1
    const count = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => {
      const privacy = privacyResponse(input)
      if (privacy) return privacy
      if (String(input).includes('/count?')) return count.promise
      const page = Number(requestParams(input).get('page'))
      return response({
        items: [createEmailSession({ mail_from: `head-${headVersion}-page-${page}@example.test` })],
        total: 0, total_pages: 0, page, limit: 10, total_is_exact: false,
        has_more: true, next_cursor: `head-${headVersion}-after-${page}`,
      })
    })
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('head-1-page-1@example.test')).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('head-1-page-2@example.test')).toBeVisible()
    expect(requestParams(listCalls()[1][0]).get('after')).toBe('head-1-after-1')
    headVersion = 2
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.prevPage') }))
    expect(await screen.findByText('head-2-page-1@example.test')).toBeVisible()
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.nextPage') }))
    expect(await screen.findByText('head-2-page-2@example.test')).toBeVisible()
    expect(requestParams(listCalls()[3][0]).get('after')).toBe('head-2-after-1')
    expect(countCalls()).toHaveLength(1)
  })

  it('reuses the count during automatic polling and pauses hidden-page polling', async () => {
    vi.useFakeTimers()
    const visibility = vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? response({ total: 40, total_pages: 4 }) : listResponse(1)))
    renderList()
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    await act(async () => {
      fireEvent.change(screen.getByRole('combobox', { name: i18n.t('emailSecurity.autoRefreshLabel') }), { target: { value: '1000' } })
    })
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(countCalls()).toHaveLength(1)
    expect(listCalls().length).toBeGreaterThan(1)
    const priorRequests = listCalls().length
    visibility.mockReturnValue(true)
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(listCalls()).toHaveLength(priorRequests)
    expect(countCalls()).toHaveLength(1)
  })

  it('aborts both outstanding requests on unmount and ignores their late completion', async () => {
    const rows = deferred<Response>()
    const count = deferred<Response>()
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? count.promise : rows.promise))
    const view = renderList()
    await waitFor(() => expect(countCalls()).toHaveLength(1))
    const rowSignal = listCalls()[0][1]!.signal!
    const countSignal = countCalls()[0][1]!.signal!
    view.unmount()
    expect(rowSignal.aborted).toBe(true)
    expect(countSignal.aborted).toBe(true)
    await act(async () => {
      rows.resolve(listResponse(1))
      count.resolve(response({ total: 80, total_pages: 8 }))
    })
    expect(screen.queryByText('page-1@example.test')).not.toBeInTheDocument()
  })
})

describe('TrafficList compact row presentation', () => {
  beforeEach(async () => {
    vi.useRealTimers()
    localStorage.clear()
    sessionStorage.clear()
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('merges security level and threat type into one risk cell and shows status as a labelled dot', async () => {
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?')
        ? response({ total: 2, total_pages: 1 })
        : response({
          items: [
            createEmailSession({ id: 'risky', mail_from: 'risky@example.test', status: 'timeout', threat_level: 'medium', threat_type: 'phishing' }),
            createEmailSession({ id: 'plain', mail_from: 'plain@example.test' }),
          ],
          total: 0, total_pages: 0, page: 1, limit: 10, has_more: false, total_is_exact: false,
        })))
    renderList()

    const riskyRow = (await screen.findByText('risky@example.test')).closest('tr')!
    const riskCell = within(riskyRow).getByText(i18n.t('emailSecurity.threatMedium')).closest('td')!
    expect(within(riskCell).getByText(i18n.t('emailSecurity.threatType.phishing'))).toBeVisible()
    expect(riskCell).toHaveAttribute('title', `${i18n.t('emailSecurity.threatMedium')} · ${i18n.t('emailSecurity.threatType.phishing')}`)
    expect(within(riskyRow).getByRole('img', {
      name: i18n.t('emailSecurity.statusTitle', { status: i18n.t('emailSecurity.statusTimeout') }),
    })).toBeInTheDocument()
    expect(within(riskyRow).queryByText(i18n.t('emailSecurity.statusTimeout'))).not.toBeInTheDocument()

    // A session without a verdict, attachment or matched direction keeps
    // muted placeholders instead of losing the columns.
    const plainRow = screen.getByText('plain@example.test').closest('tr')!
    expect(within(plainRow).getAllByText('–').length).toBeGreaterThanOrEqual(3)
    expect(within(plainRow).getByTitle(i18n.t('emailSecurity.directionUnknownTitle'))).toBeInTheDocument()
  })

  it('folds authentication and status filters behind a toggle and resets every filter', async () => {
    mockedApiFetch.mockImplementation(async input => privacyResponse(input)
      ?? (String(input).includes('/count?') ? response({ total: 1, total_pages: 1 }) : listResponse(1, undefined, false)))
    const user = userEvent.setup()
    renderList()
    expect(await screen.findByText('page-1@example.test')).toBeVisible()

    const authLabel = i18n.t('emailSecurity.allAuth')
    expect(screen.queryByRole('combobox', { name: authLabel })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: i18n.t('emailSecurity.resetFilters') })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.moreFilters') }))
    await user.selectOptions(screen.getByRole('combobox', { name: authLabel }), 'AUTH_FAILED')
    await waitFor(() => expect(requestParams(listCalls()[listCalls().length - 1][0]).get('auth_filter')).toBe('AUTH_FAILED'))

    // Collapsing keeps the active filter applied and visible as a count.
    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.lessFilters') }))
    expect(screen.queryByRole('combobox', { name: authLabel })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: i18n.t('emailSecurity.moreFilters') })).toHaveTextContent('1')

    await user.click(screen.getByRole('button', { name: i18n.t('emailSecurity.resetFilters') }))
    await waitFor(() => expect(requestParams(listCalls()[listCalls().length - 1][0]).get('auth_filter')).toBeNull())
    expect(screen.queryByRole('button', { name: i18n.t('emailSecurity.resetFilters') })).not.toBeInTheDocument()
  })
})
