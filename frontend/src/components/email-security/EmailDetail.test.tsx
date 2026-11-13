import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { createEmailSession, createSecurityVerdict } from '../../test/factories'
import type { ApiResponse, PrivacyLease, PrivacyScope } from '../../types'
import EmailDetail, { normalizeModuleResults } from './EmailDetail'
import { apiFetch } from '../../utils/api'

const { privacyMock, policyMock } = vi.hoisted(() => ({
  privacyMock: { lease: null as PrivacyLease | null, error: null as string | null },
  policyMock: { enabled: false, loading: false, error: false },
}))

vi.mock('../../hooks/usePrivacyPolicy', () => ({ usePrivacyPolicy: () => policyMock }))
vi.mock('../../hooks/usePrivacyAccess', () => ({
  PRIVACY_LEASE_HEADER: 'X-Vigilyx-Privacy-Lease',
  usePrivacyAccess: () => ({ ...privacyMock, requests: [], isAdmin: false, isAudit: false,
    refresh: async () => {}, leaseHeaders: (scope: PrivacyScope) => privacyMock.lease?.scopes.includes(scope)
      ? { 'X-Vigilyx-Privacy-Lease': privacyMock.lease.lease_handle } : undefined }),
}))

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

function jsonResponse<T>(body: ApiResponse<T>): Response {
  return {
    ok: true,
    status: 200,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

describe('EmailDetail actions', () => {
  let rescanRequested = false

  beforeEach(async () => {
    privacyMock.lease = null
    privacyMock.error = null
    Object.assign(policyMock, { enabled: false, loading: false, error: false })
    await i18n.changeLanguage('zh')
    rescanRequested = false
    mockedApiFetch.mockImplementation(async (input) => {
      const path = String(input)
      if (path.endsWith('/security-results')) return jsonResponse({ success: true, data: [], error: null })
      if (path.endsWith('/verdict')) {
        return jsonResponse({
          success: true,
          data: createSecurityVerdict(rescanRequested ? {
            id: 'verdict-002',
            threat_level: 'medium',
            created_at: '2026-08-23T10:05:02Z',
          } : {}),
          error: null,
        })
      }
      if (path.endsWith('/related')) return jsonResponse({ success: true, data: [], error: null })
      if (path.endsWith('/rescan')) {
        rescanRequested = true
        return jsonResponse({ success: true, data: { status: 'accepted' }, error: null })
      }
      if (path.endsWith('/whitelist')) return jsonResponse({ success: true, data: { session_id: 'session-001' }, error: null })
      if (path === '/api/sessions/session-001') return jsonResponse({ success: true, data: createEmailSession(), error: null })
      throw new Error(`Unexpected API call: ${path}`)
    })
  })

  it('opens one explicit feedback form from detail actions without a one-click write', async () => {
    const user = userEvent.setup()
    const original = mockedApiFetch.getMockImplementation()!
    mockedApiFetch.mockImplementation(async (input, init) => {
      if (String(input).endsWith('/feedback')) return jsonResponse({ success: true, data: { feedbacks: [], learning_status: null }, error: null })
      return original(input, init)
    })
    render(<MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>)
    await user.click(await screen.findByRole('button', { name: '纠正或确认判定' }))
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    expect(screen.getByLabelText('人工确认等级')).toHaveValue('')
    expect(screen.getByRole('button', { name: '提交反馈' })).toBeDisabled()
    expect(mockedApiFetch.mock.calls.filter(([input, init]) => String(input).endsWith('/feedback') && init?.method === 'POST')).toHaveLength(0)
  })

  it('removes an old plaintext message when its lease is invalidated and refresh fails', async () => {
    policyMock.enabled = true
    privacyMock.lease = { request_id: 'request-example', resource_type: 'session', resource_id: 'session-001',
      scopes: ['body'], expires_at: '2099-01-01T00:00:00Z', uses_remaining: 10, lease_handle: 'synthetic-lease' }
    const original = mockedApiFetch.getMockImplementation()!
    mockedApiFetch.mockImplementation(async (input, init) => {
      if (String(input) === '/api/sessions/session-001' && !privacyMock.lease) throw new Error('synthetic privacy refresh failure')
      return original(input, init)
    })
    const view = render(<MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>)
    expect(await screen.findByText('This is a test email body.')).toBeInTheDocument()
    privacyMock.lease = null
    view.rerender(<MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>)
    expect(screen.queryByText('This is a test email body.')).not.toBeInTheDocument()
    expect(await screen.findByText(i18n.t('emailSecurity.networkError'))).toBeInTheDocument()
  })

  it('ignores a late plaintext session response after the privacy policy changes', async () => {
    let finishOld: ((value: Response) => void) | undefined
    const original = mockedApiFetch.getMockImplementation()!
    mockedApiFetch.mockImplementation(async (input, init) => {
      if (String(input) !== '/api/sessions/session-001') return original(input, init)
      if (!policyMock.enabled) return new Promise<Response>(resolve => { finishOld = resolve })
      return jsonResponse({ success: true, data: createEmailSession({ subject: 'Redacted example',
        content: { ...createEmailSession().content, body_text: null, body_html: null }, privacy: { state: 'redacted' } }), error: null })
    })
    const tree = <MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>
    const view = render(tree)
    await waitFor(() => expect(finishOld).toBeDefined())
    policyMock.enabled = true
    // A fresh element is required to exercise the existing component's rerender.
    view.rerender(<MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>)
    expect(await screen.findByText('Redacted example')).toBeInTheDocument()
    await act(async () => { finishOld?.(jsonResponse({ success: true, data: createEmailSession(), error: null })) })
    expect(screen.queryByText('This is a test email body.')).not.toBeInTheDocument()
    expect(screen.queryByText('Test email subject')).not.toBeInTheDocument()
  })

  it.each(['limited', 'legacy'] as const)('shows %s detector coverage loss even when MIME capture is complete', async (mode) => {
    const original = mockedApiFetch.getMockImplementation()!
    mockedApiFetch.mockImplementation(async (input, init) => {
      if (String(input).endsWith('/verdict')) {
        return jsonResponse({ success: true, data: createSecurityVerdict({
          threat_level: 'safe', inspection_coverage: mode === 'limited' ? 'limited' : 'unknown',
          coverage_reasons: mode === 'limited' ? ['semantic_inspection_limited'] : [],
          categories: mode === 'legacy' ? ['inspection_coverage_incomplete'] : [],
        }), error: null })
      }
      return original(input, init)
    })
    render(<MemoryRouter initialEntries={['/emails/session-001']}>
      <Routes><Route path="/emails/:id" element={<EmailDetail />} /></Routes>
    </MemoryRouter>)
    expect(await screen.findByText(i18n.t('emailSecurity.inspectionIncompleteTitle'))).toBeInTheDocument()
    expect(screen.getByText(i18n.t('emailSecurity.inspectionIncompleteMessage'))).toBeInTheDocument()
  })

  it('connects detail rescan and whitelist actions to their session APIs', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/emails/session-001']}>
        <Routes>
          <Route path="/emails/:id" element={<EmailDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    await user.click(await screen.findByRole('button', { name: '重扫' }))
    expect(mockedApiFetch).toHaveBeenCalledWith('/api/sessions/session-001/rescan', { method: 'POST' })
    expect(await screen.findByRole('button', { name: '重新扫描完成' })).toBeInTheDocument()
    expect(mockedApiFetch.mock.calls.filter(([input]) => String(input).endsWith('/verdict')).length).toBeGreaterThan(1)

    await user.click(screen.getByRole('button', { name: '白名单操作' }))
    expect(mockedApiFetch).toHaveBeenCalledWith('/api/sessions/session-001/whitelist', { method: 'POST' })
  })

  it('keeps the security tab renderable when a module response omits optional fields', async () => {
    mockedApiFetch.mockImplementation(async (input) => {
      const path = String(input)
      if (path.endsWith('/security-results')) {
        return jsonResponse({
          success: true,
          data: [{
            module_id: 'link_reputation',
            module_name: 'Link Reputation',
            pillar: 'url',
            threat_level: 'safe',
            confidence: 0,
            summary: 'No suspicious links found',
            duration_ms: 12,
            analyzed_at: '2026-08-19T00:00:00Z',
          } as never],
          error: null,
        })
      }
      if (path.endsWith('/verdict')) return jsonResponse({ success: true, data: createSecurityVerdict(), error: null })
      if (path.endsWith('/related')) return jsonResponse({ success: true, data: [], error: null })
      if (path === '/api/sessions/session-001') return jsonResponse({ success: true, data: createEmailSession(), error: null })
      throw new Error(`Unexpected API call: ${path}`)
    })

    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/emails/session-001']}>
        <Routes>
          <Route path="/emails/:id" element={<EmailDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    const securityTab = (await screen.findAllByRole('button', { name: /安全分析/ }))
      .find(button => button.className.includes('detail-tab'))
    expect(securityTab).toBeDefined()
    await user.click(securityTab!)
    expect(screen.getByText('检测模块')).toBeInTheDocument()
    expect(normalizeModuleResults([{ module_id: 'partial' } as never])[0]).toMatchObject({
      categories: [],
      evidence: [],
      details: {},
    })
  })

  it('keeps module evidence visible when the verdict request fails independently', async () => {
    mockedApiFetch.mockImplementation(async (input) => {
      const path = String(input)
      if (path.endsWith('/verdict')) throw new Error('legacy verdict timestamp')
      if (path.endsWith('/security-results')) {
        return jsonResponse({
          success: true,
          data: [{
            module_id: 'content_scan',
            module_name: 'Content Scan',
            pillar: 'content',
            threat_level: 'safe',
            confidence: 0,
            categories: [],
            summary: 'No suspicious content found',
            evidence: [],
            details: {},
            duration_ms: 4,
            analyzed_at: '2026-08-21T00:00:00Z',
          } as never],
          error: null,
        })
      }
      if (path.endsWith('/related')) return jsonResponse({ success: true, data: [], error: null })
      if (path === '/api/sessions/session-001') return jsonResponse({ success: true, data: createEmailSession(), error: null })
      throw new Error(`Unexpected API call: ${path}`)
    })

    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/emails/session-001']}>
        <Routes>
          <Route path="/emails/:id" element={<EmailDetail />} />
        </Routes>
      </MemoryRouter>,
    )

    const securityTab = (await screen.findAllByRole('button', { name: /安全分析/ }))
      .find(button => button.className.includes('detail-tab'))
    await user.click(securityTab!)
    expect(await screen.findByText('内容扫描')).toBeInTheDocument()
  })
})
