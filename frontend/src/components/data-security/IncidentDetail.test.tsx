import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import type { DataSecurityIncident } from '../../types'
import { apiFetch } from '../../utils/api'
import { IncidentDetail } from './IncidentDetail'

const access = vi.hoisted(() => ({ leaseHeaders: () => ({ 'X-Vigilyx-Privacy-Lease': 'synthetic-lease' }), error: false }))
vi.mock('../../utils/api', () => ({ apiFetch: vi.fn() }))
vi.mock('../../hooks/usePrivacyAccess', () => ({ usePrivacyAccess: () => access }))
vi.mock('../privacy/PrivacyAccessPanel', () => ({ PrivacyAccessPanel: () => null }))
afterEach(cleanup)

const incident: DataSecurityIncident = {
  id: 'incident-1', http_session_id: 'http-1', incident_type: 'draft_box_abuse',
  severity: 'medium', confidence: 0.85, summary: 'Saved draft observation',
  evidence: [], dlp_matches: ['large_amount'], details: null,
  client_ip: '192.0.2.1', detected_user: null, request_url: '/draft',
  host: 'mail.example.com', method: 'POST', created_at: '2026-11-15T00:00:00Z',
}

it('reads authorized evidence once and clears it when selecting another incident', async () => {
  vi.mocked(apiFetch).mockImplementation(async input => ({
    ok: true,
    json: async () => ({ success: true, data: String(input).includes('/incidents/') ? { ...incident, summary: 'Authorized first incident' } : { id: 'http-1', request_body_size: 0 } }),
  }) as Response)
  const { rerender } = render(<IncidentDetail incident={incident} onClose={() => {}} privacyMode={false} />)
  await screen.findByText('Authorized first incident')
  await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(2))
  vi.mocked(apiFetch).mockImplementation(() => new Promise<Response>(() => {}))
  rerender(<IncidentDetail incident={{ ...incident, id: 'incident-2', http_session_id: 'http-2', summary: 'Second incident' }} onClose={() => {}} privacyMode={false} />)
  expect(screen.queryByText('Authorized first incident')).not.toBeInTheDocument()
  expect(screen.getByText('Second incident')).toBeInTheDocument()
  expect(apiFetch).toHaveBeenCalledTimes(4)
})

it('shows SMTP risk without requesting a nonexistent HTTP body', async () => {
  vi.mocked(apiFetch).mockClear()
  const smtp = { ...incident, incident_type: 'sensitive_data_transfer' as const, method: 'SMTP', details: { source: 'smtp', authorization_status: 'unverified' } }
  vi.mocked(apiFetch).mockResolvedValue({ ok: true, json: async () => ({ success: true, data: smtp }) } as Response)
  render(<IncidentDetail incident={smtp} onClose={() => {}} privacyMode={false} />)
  await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(1))
  expect(String(vi.mocked(apiFetch).mock.calls[0][0])).toContain('/incidents/')
  expect(screen.queryByText('dataSecurity.requestBody')).not.toBeInTheDocument()
})
