import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import type { EngineStatus } from '../../types'
import { apiFetch } from '../../utils/api'
import OverviewTab from './OverviewTab'
import RiskVerdictTab from './RiskVerdictTab'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

function engineStatus(moduleId: string, failureCount = 0): EngineStatus {
  const totalRuns = 35_472
  return {
    running: true,
    uptime_seconds: 1,
    total_sessions_processed: totalRuns,
    total_verdicts_produced: totalRuns,
    sessions_per_second: 1,
    ai_service_available: false,
    module_metrics: [{
      module_id: moduleId,
      total_runs: totalRuns,
      avg_duration_ms: 14.7,
      max_duration_ms: 20,
      min_duration_ms: 1,
      success_rate: (totalRuns - failureCount) / totalRuns,
      failure_count: failureCount,
      timeout_count: 0,
    }],
  }
}

describe('OverviewTab module performance', () => {
  beforeEach(async () => {
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  it('shows one localized module name while retaining the stable id as a tooltip', () => {
    render(<OverviewTab stats={null} engineStatus={engineStatus('attach_qr_scan')} modules={[]} />)

    expect(screen.getByTitle('attach_qr_scan')).toHaveTextContent('附件二维码扫描')
    expect(screen.queryByText('attach_qr_scan')).not.toBeInTheDocument()
  })

  it('uses the English module label when English is selected', async () => {
    await i18n.changeLanguage('en')
    render(<OverviewTab stats={null} engineStatus={engineStatus('aitm_detect')} modules={[]} />)

    expect(screen.getByTitle('aitm_detect')).toHaveTextContent('AiTM Detection')
    expect(screen.queryByText('aitm_detect')).not.toBeInTheDocument()
  })

  it('does not round a non-perfect success rate up to 100 percent', () => {
    render(<OverviewTab stats={null} engineStatus={engineStatus('attach_qr_scan', 5)} modules={[]} />)

    expect(screen.getByText('99.99%')).toBeVisible()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
  })
})

describe('RiskVerdictTab score labels', () => {
  beforeEach(async () => {
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  it('shows fused risk separately from verdict confidence', async () => {
    mockedApiFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        data: {
          total: 1,
          items: [{
            verdict_id: 'verdict-001',
            session_id: 'session-001',
            threat_level: 'medium',
            risk_score: 0.72,
            confidence: 0.5,
            categories: [],
            summary: 'test',
            modules_run: 22,
            modules_flagged: 2,
            total_duration_ms: 15,
            created_at: '2026-08-18T00:00:00Z',
            mail_from: 'sender@example.com',
            rcpt_to: 'recipient@example.com',
            subject: '测试邮件',
            protocol: 'smtp',
            client_ip: '192.0.2.1',
            server_ip: '192.0.2.2',
          }],
        },
        error: null,
      }),
    } as unknown as Response)

    render(
      <MemoryRouter>
        <RiskVerdictTab />
      </MemoryRouter>,
    )

    expect(await screen.findByText('72%')).toBeVisible()
    expect(screen.getByText('50%')).toBeVisible()
    expect(screen.getByRole('columnheader', { name: '综合风险' })).toBeVisible()
    expect(screen.getByRole('columnheader', { name: '判定置信度' })).toBeVisible()
  })
})
