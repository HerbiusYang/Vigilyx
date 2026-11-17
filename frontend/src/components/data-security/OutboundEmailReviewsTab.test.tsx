import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import type { EmailDataSecurityReview, EmailDataSecurityStats } from '../../types'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import { OutboundEmailReviewsTab } from './OutboundEmailReviewsTab'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

const stats: EmailDataSecurityStats = {
  total: 1,
  inspected: 0,
  encrypted: 0,
  incomplete: 1,
  failed: 0,
  dlp_hits: 1,
  quarantined: 0,
  blocked: 0,
  rejected: 0,
  unknown_direction: 1,
  confirmed_outbound: 0,
  outbound_candidates: 1,
  attribution_pending: 1,
  incomplete_sessions: 1,
}

const unknownReview: EmailDataSecurityReview = {
  id: 'dcfbd16d-0aed-48fb-b4fe-b382cba4ff04',
  session_id: 'dcfbd16d-0aed-48fb-b4fe-b382cba4ff04',
  dedupe_key: 'session:dcfbd16d-0aed-48fb-b4fe-b382cba4ff04',
  source: 'sniffer',
  direction: 'unknown',
  audit_class: 'outbound_candidate',
  direction_reason: 'outbound source or envelope could not be trusted',
  inspection_reason: 'protocol_anomaly:1',
  inspection_status: 'incomplete',
  dlp_result: 'hit',
  max_jrt_level: 3,
  dlp_matches: ['bank_card'],
  dlp_details: { bank_card: { count: 1 } },
  action: 'audit',
  delivery_status: 'mirror_audit',
  client_ip: '192.0.2.44',
  mail_from: 'u****@internal.example',
  external_recipient_domains: ['recipient.invalid'],
  recipient_count: 1,
  subject: '[REDACTED]',
  attachment_count: 0,
  attachments_scanned: 0,
  attachment_inspection_complete: true,
  encrypted: false,
  created_at: '2026-08-18T02:54:39Z',
  updated_at: '2026-08-18T02:54:39Z',
}

function response(data: unknown) {
  return {
    ok: true,
    status: 200,
    json: vi.fn().mockResolvedValue({ success: true, data, error: null }),
  } as unknown as Response
}

function mockReviewApi(review: EmailDataSecurityReview, reviewStats = stats) {
  mockedApiFetch.mockImplementation(async input => {
    const url = String(input)
    if (url.endsWith('/stats')) return response(reviewStats)
    if (url.endsWith(`/${review.id}`)) return response(review)
    return response({ items: [review], total: 1, page: 1, limit: 10, total_pages: 1 })
  })
}

describe('OutboundEmailReviewsTab evidence quality', () => {
  beforeEach(async () => {
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  it('explains unknown attribution and renders normalized, redacted evidence', async () => {
    mockReviewApi(unknownReview)
    const user = userEvent.setup()
    render(<OutboundEmailReviewsTab privacyMode={false} />)

    await user.click(await screen.findByText('u****@internal.example'))

    expect(await screen.findByRole('dialog')).toBeVisible()
    expect(screen.getByText('邮件主题')).toBeVisible()
    expect(screen.getByText('主题内容已隐藏')).toBeVisible()
    expect(screen.getByText('已脱敏')).toBeVisible()
    expect(screen.queryByText('[REDACTED]')).not.toBeInTheDocument()
    expect(await screen.findByText('外发身份待归因')).toBeVisible()
    expect(screen.getByText(/DLP 命中仅作审计/)).toBeVisible()
    expect(screen.getByText('SMTP 会话存在协议异常，内容覆盖不能视为完整')).toBeVisible()
    expect(screen.getByText('银行卡号 ×1')).toBeVisible()
    expect(screen.getByText('敏感值不落审查库，仅保留命中类别与数量。')).toBeVisible()
    expect(screen.getByText('无附件')).toBeVisible()
    expect(screen.getByRole('link', { name: '查看邮件完整详情' })).toHaveAttribute('href', `/emails/${unknownReview.session_id}`)
    expect(screen.queryByText('已完整检查')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '关闭审查详情' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('uses the precise content-coverage label for a trusted complete record', async () => {
    const complete = {
      ...unknownReview,
      id: 'f61dfd8e-cfab-4f99-a246-778dd9ce49d5',
      session_id: 'f61dfd8e-cfab-4f99-a246-778dd9ce49d5',
      direction: 'outbound' as const,
      audit_class: 'confirmed_outbound' as const,
      direction_reason: 'trusted source',
      inspection_reason: null,
      inspection_status: 'inspected' as const,
      dlp_result: 'clean' as const,
      dlp_matches: [],
      dlp_details: null,
    }
    mockReviewApi(complete, { ...stats, inspected: 1, incomplete: 0, dlp_hits: 0, unknown_direction: 0, confirmed_outbound: 1, outbound_candidates: 0, attribution_pending: 0, incomplete_sessions: 0 })
    render(<OutboundEmailReviewsTab privacyMode={false} />)

    expect((await screen.findAllByText('内容扫描完整')).length).toBeGreaterThan(0)
    expect(screen.queryByText('外发身份待归因')).not.toBeInTheDocument()
  })

  it('refreshes the list in the background when the realtime bridge signals new data', async () => {
    let current = unknownReview
    mockedApiFetch.mockImplementation(async input => {
      const url = String(input)
      if (url.endsWith('/stats')) return response(stats)
      return response({ items: [current], total: 1, page: 1, limit: 10, total_pages: 1 })
    })

    render(<OutboundEmailReviewsTab privacyMode={false} />)
    expect(await screen.findByText('recipient.invalid')).toBeVisible()

    current = {
      ...unknownReview,
      id: 'f0f0f0f0-0000-4000-8000-000000000001',
      session_id: 'f0f0f0f0-0000-4000-8000-000000000001',
      external_recipient_domains: ['new-recipient.invalid'],
    }
    window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))

    await waitFor(() => expect(screen.getByText('new-recipient.invalid')).toBeVisible())
    expect(screen.getByText('new-recipient.invalid')).toBeVisible()
  })
})
