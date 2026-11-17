import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import DataSecurity from './DataSecurity'
import '../../i18n'

vi.mock('../../utils/api', () => ({ apiFetch: vi.fn() }))
vi.mock('../../hooks/usePrivacyPolicy', () => ({ usePrivacyPolicy: () => ({ enabled: true, loading: false, error: false }) }))
vi.mock('./OverviewTab', () => ({ OverviewTab: ({ stats }: { stats: { total_incidents: number } | null }) => <div data-testid="overview">{stats?.total_incidents ?? 'waiting'}</div> }))
vi.mock('./IncidentsTab', () => ({ IncidentsTab: () => <div>incident detail</div> }))

describe('data-security request scheduling', () => {
  beforeEach(() => {
    vi.mocked(apiFetch).mockReset()
    Object.defineProperty(document, 'hidden', { configurable: true, value: false })
  })
  afterEach(() => { cleanup(); vi.useRealTimers() })

  it('opens incident details without querying all-time overview aggregates', async () => {
    render(<MemoryRouter initialEntries={['/data-security/incidents/incident-1']}><DataSecurity /></MemoryRouter>)
    await screen.findByText('incident detail')
    expect(apiFetch).not.toHaveBeenCalled()
  })

  it('shows overview results while engine status is still pending', async () => {
    vi.mocked(apiFetch).mockImplementation(async input => {
      if (input === '/api/data-security/engine-status') return new Promise<Response>(() => {})
      return { json: async () => ({ success: true, data: { total_incidents: 17 } }) } as Response
    })
    render(<MemoryRouter initialEntries={['/data-security']}><DataSecurity /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('overview')).toHaveTextContent('17'))
  })

  it('coalesces timer and websocket refreshes while requests are pending', async () => {
    vi.useFakeTimers()
    vi.mocked(apiFetch).mockImplementation(() => new Promise<Response>(() => {}))
    render(<MemoryRouter initialEntries={['/data-security']}><DataSecurity /></MemoryRouter>)
    expect(apiFetch).toHaveBeenCalledTimes(3)
    await act(async () => {
      window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
      window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED))
      await vi.advanceTimersByTimeAsync(45000)
    })
    expect(apiFetch).toHaveBeenCalledTimes(3)
  })

  it('does not poll aggregates from a hidden page', () => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true })
    render(<MemoryRouter initialEntries={['/data-security']}><DataSecurity /></MemoryRouter>)
    expect(apiFetch).not.toHaveBeenCalled()
  })
})
