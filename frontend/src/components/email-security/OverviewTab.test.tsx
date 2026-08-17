import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import i18n from '../../i18n'
import type { EngineStatus } from '../../types'
import OverviewTab from './OverviewTab'

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
