import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import Quarantine from './Quarantine'
import type { PrivacyLease, PrivacyResourceRef, PrivacyScope } from '../../types'

const { apiFetchMock, navigateMock, translateMock, privacyMock, policyMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
  navigateMock: vi.fn(),
  translateMock: vi.fn((key: string, options?: { page?: number }) =>
    key === 'quarantine.pageNum' ? `page ${options?.page}` : key),
  privacyMock: { lease: null as PrivacyLease | null, error: null as string | null },
  policyMock: { enabled: false, loading: false, error: false },
}))

vi.mock('../../utils/api', () => ({ apiFetch: apiFetchMock }))
vi.mock('../../hooks/usePrivacyPolicy', () => ({ usePrivacyPolicy: () => policyMock }))
vi.mock('../../hooks/usePrivacyAccess', () => ({
  usePrivacyAccess: (resource: PrivacyResourceRef | null) => {
    const lease = privacyMock.lease?.resource_id === resource?.resource_id ? privacyMock.lease : null
    return { ...privacyMock, lease, leaseHeaders: (scope: PrivacyScope) => lease?.scopes.includes(scope)
      ? { 'X-Vigilyx-Privacy-Lease': lease.lease_handle } : undefined }
  },
}))
vi.mock('../../utils/format', () => ({
  formatTimeFull: (value: string) => value,
  formatSize: (value: number) => `${value} B`,
}))
vi.mock('react-router-dom', () => ({ useNavigate: () => navigateMock }))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: translateMock,
  }),
}))

function response(data: unknown, ok = true) {
  return Promise.resolve({
    ok,
    status: ok ? 200 : 500,
    json: () => Promise.resolve(data),
  })
}

const entry = (id: string) => ({
  id,
  session_id: `session-${id}`,
  verdict_id: null,
  mail_from: 'sender@example.com',
  rcpt_to: ['recipient@example.com'],
  subject: `Quarterly report ${id}`,
  threat_level: 'high',
  reason: `suspicious attachment ${id}`,
  status: 'quarantined',
  created_at: '2026-07-28T12:00:00Z',
  released_at: null,
  released_by: null,
  ttl_days: 30,
  raw_eml_size: 2048,
})

describe('Quarantine', () => {
  beforeEach(() => {
    privacyMock.lease = null
    privacyMock.error = null
    Object.assign(policyMock, { enabled: false, loading: false, error: false })
    localStorage.clear()
    localStorage.setItem('vigilyx-deploy-mode', 'mirror')
    apiFetchMock.mockReset()
    navigateMock.mockReset()
    translateMock.mockClear()
    apiFetchMock.mockImplementation((url: string) => {
      if (url === '/api/config/deployment-mode') {
        return response({ success: true, data: { mode: 'mta' } })
      }
      if (url === '/api/security/quarantine/stats') {
        return response({
          success: true,
          data: { quarantined: 1, releasing: 0, released: 2, total: 3 },
        })
      }
      if (url.startsWith('/api/security/quarantine?')) {
        return response({
          success: true,
          data: {
            items: [
              entry('q-1'),
            ],
          },
        })
      }
      if (url === '/api/security/quarantine/q-1/preview') {
        return response({
          success: true,
          data: {
            body_text: 'This is the quarantined message body.',
            body_html_source: null,
            attachments: [{
              filename: 'invoice.pdf',
              content_type: 'application/pdf',
              size: 4096,
              hash: 'a'.repeat(64),
            }],
            parse_warning: null,
          },
        })
      }
      throw new Error(`unexpected request: ${url}`)
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('can switch from cached mirror mode to API-reported MTA mode without a hook-order crash', async () => {
    render(<Quarantine />)

    expect(screen.getByText('quarantine.mirrorModeTitle')).toBeInTheDocument()
    expect(await screen.findByText('Quarterly report q-1')).toBeInTheDocument()
    expect(screen.getByText('sender@example.com')).toBeInTheDocument()
    expect(screen.getByText('suspicious attachment q-1')).toBeInTheDocument()

    await waitFor(() => {
      expect(apiFetchMock).toHaveBeenCalledWith('/api/security/quarantine/stats')
    })
  })

  it('previews the matching message and then opens its full detection evidence', async () => {
    const user = userEvent.setup()
    render(<Quarantine />)

    await user.click(await screen.findByRole('button', { name: 'quarantine.preview' }))
    expect(await screen.findByText('This is the quarantined message body.')).toBeInTheDocument()
    expect(screen.getByText(/invoice\.pdf/)).toHaveTextContent('4096 B')

    await user.click(screen.getByRole('button', { name: 'quarantine.viewEvidence' }))
    expect(navigateMock).toHaveBeenCalledWith('/emails/session-q-1')
    expect(screen.queryByText('quarantine.reasonExample')).not.toBeInTheDocument()
  })

  it('discards plaintext when privacy is enabled even if its replacement request fails', async () => {
    const original = apiFetchMock.getMockImplementation()!
    apiFetchMock.mockImplementation((url: string) => url.endsWith('/preview') && policyMock.enabled
      ? response({ error: 'privacy check unavailable' }, false) : original(url))
    const user = userEvent.setup()
    const view = render(<Quarantine />)
    await user.click(await screen.findByRole('button', { name: 'quarantine.preview' }))
    expect(await screen.findByText('This is the quarantined message body.')).toBeInTheDocument()
    policyMock.enabled = true
    view.rerender(<Quarantine />)
    expect(screen.queryByText('This is the quarantined message body.')).not.toBeInTheDocument()
    expect(await screen.findByText('privacy check unavailable')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'quarantine.hidePreview' }))
    await user.click(screen.getByRole('button', { name: 'quarantine.preview' }))
    expect(screen.queryByText('This is the quarantined message body.')).not.toBeInTheDocument()
    expect(apiFetchMock.mock.calls.filter(([url]) => String(url).endsWith('/preview'))).toHaveLength(3)
  })

  it('hides an expired lease preview and re-reads without the old handle', async () => {
    policyMock.enabled = true
    privacyMock.lease = {
      request_id: 'request-example', resource_type: 'session', resource_id: 'session-q-1', scopes: ['body'],
      expires_at: '2099-01-01T00:00:00Z', uses_remaining: 10, lease_handle: 'synthetic-lease',
    }
    const original = apiFetchMock.getMockImplementation()!
    apiFetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (url.endsWith('/preview') && !init?.headers) {
        return response({ success: true, data: { body_text: null, body_html_source: null, attachments: [], parse_warning: null } })
      }
      return original(url, init)
    })
    const user = userEvent.setup()
    const view = render(<Quarantine />)
    await user.click(await screen.findByRole('button', { name: 'quarantine.preview' }))
    expect(await screen.findByText('This is the quarantined message body.')).toBeInTheDocument()
    privacyMock.lease = null
    view.rerender(<Quarantine />)
    expect(screen.queryByText('This is the quarantined message body.')).not.toBeInTheDocument()
    expect(await screen.findByText('quarantine.previewBodyUnavailable')).toBeInTheDocument()
    const previewCalls = apiFetchMock.mock.calls.filter(([url]) => String(url).endsWith('/preview'))
    expect(previewCalls[previewCalls.length - 1]?.[1]).toEqual(expect.objectContaining({ headers: undefined }))
  })

  it('cannot restore plaintext from a response arriving after authorization changed', async () => {
    let finishOld: ((value: unknown) => void) | undefined
    const original = apiFetchMock.getMockImplementation()!
    apiFetchMock.mockImplementation((url: string) => {
      if (!url.endsWith('/preview')) return original(url)
      if (!policyMock.enabled) return new Promise(resolve => { finishOld = resolve })
      return response({ success: true, data: { body_text: null, body_html_source: null, attachments: [], parse_warning: null } })
    })
    const user = userEvent.setup()
    const view = render(<Quarantine />)
    await user.click(await screen.findByRole('button', { name: 'quarantine.preview' }))
    await waitFor(() => expect(finishOld).toBeDefined())
    policyMock.enabled = true
    view.rerender(<Quarantine />)
    expect(await screen.findByText('quarantine.previewBodyUnavailable')).toBeInTheDocument()
    await act(async () => { finishOld?.(await response({ success: true, data: {
      body_text: 'Late synthetic private body', body_html_source: null, attachments: [], parse_warning: null,
    } })) })
    expect(screen.queryByText('Late synthetic private body')).not.toBeInTheDocument()
  })

  it('shows action progress, prevents duplicate actions, and surfaces a release failure', async () => {
    const user = userEvent.setup()
    vi.stubGlobal('confirm', vi.fn(() => true))
    let rejectRelease: ((value: unknown) => void) | undefined
    apiFetchMock.mockImplementation((url: string) => {
      if (url === '/api/config/deployment-mode') return response({ success: true, data: { mode: 'mta' } })
      if (url === '/api/security/quarantine/stats') {
        return response({ success: true, data: { quarantined: 1, releasing: 0, released: 0, total: 1 } })
      }
      if (url.startsWith('/api/security/quarantine?')) {
        return response({ success: true, data: { items: [entry('q-1')] } })
      }
      if (url === '/api/security/quarantine/q-1/preview') {
        return response({
          success: true,
          data: { body_text: 'reviewed body', body_html_source: null, attachments: [], parse_warning: null },
        })
      }
      if (url === '/api/security/quarantine/q-1/release') {
        return new Promise(resolve => { rejectRelease = resolve })
      }
      throw new Error(`unexpected request: ${url}`)
    })

    render(<Quarantine />)
    const releaseButton = await screen.findByRole('button', { name: 'quarantine.release' })
    expect(releaseButton).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'quarantine.preview' }))
    expect(await screen.findByText('reviewed body')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'quarantine.release' }))

    expect(screen.getByRole('button', { name: 'quarantine.releasingAction' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'quarantine.delete' })).toBeDisabled()
    expect(apiFetchMock.mock.calls.filter(([url]) => url === '/api/security/quarantine/q-1/release')).toHaveLength(1)

    rejectRelease?.({
      ok: false,
      status: 502,
      json: () => Promise.resolve({ error: 'downstream relay unavailable' }),
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('downstream relay unavailable')
  })

  it('keeps the previous-page control visible after navigating to an empty last page', async () => {
    const user = userEvent.setup()
    apiFetchMock.mockImplementation((url: string) => {
      if (url === '/api/config/deployment-mode') return response({ success: true, data: { mode: 'mta' } })
      if (url === '/api/security/quarantine/stats') {
        return response({ success: true, data: { quarantined: 30, releasing: 0, released: 0, total: 30 } })
      }
      if (url.startsWith('/api/security/quarantine?')) {
        const offset = Number(new URL(url, 'https://vigilyx.test').searchParams.get('offset'))
        return response({ success: true, data: { items: offset === 0 ? Array.from({ length: 30 }, (_, i) => entry(`q-${i}`)) : [] } })
      }
      throw new Error(`unexpected request: ${url}`)
    })

    render(<Quarantine />)
    await user.click(await screen.findByRole('button', { name: 'quarantine.nextPage' }))

    expect(await screen.findByText('quarantine.empty')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'quarantine.prevPage' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'quarantine.nextPage' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'quarantine.prevPage' }))
    expect(await screen.findByText('Quarterly report q-0')).toBeInTheDocument()
  })

  it('distinguishes a load failure from an empty quarantine and offers retry', async () => {
    apiFetchMock.mockImplementation((url: string) => {
      if (url === '/api/config/deployment-mode') return response({ success: true, data: { mode: 'mta' } })
      if (url === '/api/security/quarantine/stats') return response({ error: 'database unavailable' }, false)
      if (url.startsWith('/api/security/quarantine?')) return response({ success: true, data: { items: [] } })
      throw new Error(`unexpected request: ${url}`)
    })

    render(<Quarantine />)

    expect(await screen.findByRole('alert')).toHaveTextContent('database unavailable')
    expect(screen.getByRole('button', { name: 'quarantine.retry' })).toBeInTheDocument()
  })

  it('labels a release-blocked entry with the block reason and no release action', async () => {
    // PoC: before the fix a release_blocked entry fell into the default branch
    // and rendered as plain "quarantined" with zero explanation and no action
    // entry point, leaving operators staring at a stuck message.
    apiFetchMock.mockImplementation((url: string) => {
      if (url === '/api/config/deployment-mode') return response({ success: true, data: { mode: 'mta' } })
      if (url === '/api/security/quarantine/stats') {
        return response({ success: true, data: { quarantined: 0, releasing: 0, released: 0, total: 1 } })
      }
      if (url.startsWith('/api/security/quarantine?')) {
        return response({ success: true, data: { items: [{ ...entry('q-9'), status: 'release_blocked' }] } })
      }
      throw new Error(`unexpected request: ${url}`)
    })

    render(<Quarantine />)

    // Wait for the blocked entry row to load before counting labels.
    expect(await screen.findByText('Quarterly report q-9')).toBeInTheDocument()
    // Status cell + filter button both carry the blocked label.
    expect(screen.getAllByText('quarantine.statusReleaseBlocked').length).toBeGreaterThanOrEqual(2)
    // The block reason is visible as explanation text, not only as a tooltip.
    expect(screen.getAllByText('quarantine.releaseBlockedHint').length).toBeGreaterThan(0)
    // No release affordance, but the entry can still be deleted after review.
    expect(screen.queryByRole('button', { name: 'quarantine.release' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'quarantine.delete' })).toBeEnabled()
    // It must not masquerade as a normally quarantined entry.
    expect(screen.queryByText('quarantine.statusQuarantined')).not.toBeInTheDocument()
  })
})
