import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { apiFetch } from '../../utils/api'
import IocTab from './IocTab'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

describe('IocTab Shadow evidence', () => {
  beforeEach(async () => {
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('en')
    mockedApiFetch.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/telemetry')) {
        return {
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            success: true,
            data: {
              shadow: {
                ioc_type: 'domain',
                indicator: 'share.example.test',
                traffic: {
                  observed_count: 3200,
                  outbound_count: 400,
                  inbound_count: 2800,
                  unknown_direction_count: 0,
                  provisional_threat_count: 1,
                  distinct_session_count: 3200,
                  distinct_activity_count: 4,
                  first_seen: '2026-01-01T00:00:00Z',
                  last_seen: '2026-08-24T00:00:00Z',
                },
                outcomes: { malicious: 1, normal: 0, unresolved: 3199 },
                score: {
                  prior_log_odds: -5.2,
                  raw_log_likelihood_ratio: 2.3,
                  decayed_log_likelihood_ratio: 1.8,
                  log_odds: -3.4,
                  probability: 0.032,
                  decay_factor: 0.78,
                  evidence_count: 1,
                  evidence_interval_lower: 0.01,
                  evidence_interval_upper: 0.8,
                },
                prior_source: 'provisional_verdicts',
                calibration_status: 'provisional_only',
                half_life_hours: 2160,
                age_seconds: 0,
                clusters: [],
                actionability: 'shadow_only',
              },
            },
          }),
        } as unknown as Response
      }
      return {
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          success: true,
          data: {
            items: [{
              id: 'ioc-001',
              indicator: 'share.example.test',
              ioc_type: 'domain',
              source: 'auto',
              verdict: 'suspicious',
              confidence: 0.8,
              first_seen: '2026-01-01T00:00:00Z',
              last_seen: '2026-08-24T00:00:00Z',
              hit_count: 1,
            }],
            total: 1,
            limit: 30,
            offset: 0,
          },
        }),
      } as unknown as Response
    })
  })

  it('shows denominator, interval, and shadow-only status separately from legacy confidence', async () => {
    const user = userEvent.setup()
    render(<IocTab />)

    await user.click(await screen.findByRole('button', { name: 'View Evidence' }))

    expect(await screen.findByText('Shadow probability: 3.2%')).toBeVisible()
    expect(screen.getByText('Evidence interval: 1.0% – 80.0%')).toBeVisible()
    expect(screen.getByText('Legacy confidence: 80.0%')).toBeVisible()
    expect(screen.getByText('Shadow only; no disposition impact')).toBeVisible()
    expect(screen.getByText('Local observations: 3200')).toBeVisible()
    expect(screen.getByText('Distinct activities: 4')).toBeVisible()
  })
})
