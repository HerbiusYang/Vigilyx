import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import Quarantine from './Quarantine'

const { apiFetchMock, navigateMock, translateMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
  navigateMock: vi.fn(),
  translateMock: vi.fn((key: string, options?: { page?: number }) =>
    key === 'quarantine.pageNum' ? `page ${options?.page}` : key),
}))

vi.mock('../../utils/api', () => ({ apiFetch: apiFetchMock }))
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
})
