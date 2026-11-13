import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import i18n from '../../i18n'
import type { DataSecurityEngineStatus, DataSecurityStats } from '../../types'
import { OverviewTab } from './OverviewTab'

const stats: DataSecurityStats = {
  total_incidents: 7,
  draft_abuse_count: 1,
  file_transit_count: 1,
  self_send_count: 2,
  volume_anomaly_count: 3,
  jrt_compliance_count: 0,
  high_severity_24h: 1,
  incidents_by_severity: { high: 1 },
  hourly_sessions: [
    { hour: '2026-08-18 11:00', count: 2_100 },
    { hour: '2026-08-18 12:00', count: 2_600 },
  ],
  hourly_email_reviews: [
    { hour: '2026-08-18 11:00', count: 120 },
    { hour: '2026-08-18 12:00', count: 163 },
  ],
  hourly_incidents: [
    { hour: '2026-08-18 11:00', count: 3 },
    { hour: '2026-08-18 12:00', count: 4 },
  ],
}

const engineStatus: DataSecurityEngineStatus = {
  running: true,
  http_sessions_processed: 4_700,
  incidents_detected: 7,
}

describe('data security trend chart', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  it('switches between the default 2D chart and the 3D perspective chart', () => {
    render(<OverviewTab stats={stats} engineStatus={engineStatus} />)

    const twoD = screen.getByRole('button', { name: '二维' })
    const threeD = screen.getByRole('button', { name: '3D 透视' })
    const chart = () => document.querySelector('.ds3-chart-svg')

    expect(twoD).toHaveAttribute('aria-pressed', 'true')
    expect(threeD).toHaveAttribute('aria-pressed', 'false')
    expect(chart()).not.toHaveClass('is-3d')

    fireEvent.click(threeD)
    expect(threeD).toHaveAttribute('aria-pressed', 'true')
    expect(twoD).toHaveAttribute('aria-pressed', 'false')
    expect(chart()).toHaveClass('is-3d')

    fireEvent.click(twoD)
    expect(twoD).toHaveAttribute('aria-pressed', 'true')
    expect(chart()).not.toHaveClass('is-3d')
  })
})
