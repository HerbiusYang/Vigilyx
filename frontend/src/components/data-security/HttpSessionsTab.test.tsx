import { act, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { HttpSessionItem, PrivacyLease, PrivacyScope } from '../../types'
import i18n from '../../i18n'
import { apiFetch } from '../../utils/api'
import { HttpSessionsTab } from './HttpSessionsTab'

const { privacyMock } = vi.hoisted(() => ({
  privacyMock: { lease: null as PrivacyLease | null, error: null as string | null },
}))
vi.mock('../../utils/api', () => ({ apiFetch: vi.fn() }))
vi.mock('../../hooks/usePrivacyAccess', () => ({
  usePrivacyAccess: () => ({ ...privacyMock, leaseHeaders: (scope: PrivacyScope) => privacyMock.lease?.scopes.includes(scope)
    ? { 'X-Vigilyx-Privacy-Lease': privacyMock.lease.lease_handle } : undefined }),
}))
const apiMock = vi.mocked(apiFetch)

function session(id: string, body: string): HttpSessionItem {
  return {
    id, client_ip: '192.0.2.10', client_port: 40000, server_ip: '198.51.100.10', server_port: 80,
    method: 'POST', uri: '/example', host: 'webmail.example.com', content_type: 'text/plain',
    request_body_size: 32, request_body: body, response_status: 200, uploaded_filename: null,
    uploaded_file_size: null, detected_user: 'user@example.com', detected_sender: null,
    detected_recipients: [], detected_file_type: null, body_is_binary: false, file_type_mismatch: null,
    body_temp_file: null, timestamp: '2026-10-08T00:00:00Z', network_session_id: null,
  }
}

function response(data: unknown): Response {
  return { ok: true, json: async () => ({ success: true, data }) } as Response
}

describe('HTTP detail privacy snapshots', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    privacyMock.lease = null
    privacyMock.error = null
    apiMock.mockReset()
    apiMock.mockImplementation(async input => {
      if (String(input).includes('?')) return response({ items: [session('http-example', 'List fallback secret')], total: 1 })
      return response(session('http-example', 'Synthetic private HTTP body'))
    })
  })

  it('clears an old body after lease loss even when re-reading fails, with no list-body fallback', async () => {
    privacyMock.lease = { request_id: 'request-example', resource_type: 'http_session', resource_id: 'http-example',
      scopes: ['http_body'], expires_at: '2099-01-01T00:00:00Z', uses_remaining: 10, lease_handle: 'synthetic-lease' }
    const view = render(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode={false} />)
    expect(await screen.findByText('Synthetic private HTTP body')).toBeInTheDocument()
    privacyMock.lease = null
    apiMock.mockRejectedValue(new Error('synthetic network failure'))
    view.rerender(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode={false} />)
    expect(screen.queryByText('Synthetic private HTTP body')).not.toBeInTheDocument()
    await act(async () => {})
    expect(screen.queryByText('Synthetic private HTTP body')).not.toBeInTheDocument()
    expect(screen.queryByText('List fallback secret')).not.toBeInTheDocument()
  })

  it('hides previously read plaintext as soon as privacy is enabled', async () => {
    const view = render(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode={false} />)
    expect(await screen.findByText('Synthetic private HTTP body')).toBeInTheDocument()
    apiMock.mockRejectedValue(new Error('synthetic network failure'))
    view.rerender(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode />)
    expect(screen.queryByText('Synthetic private HTTP body')).not.toBeInTheDocument()
    await act(async () => {})
    expect(screen.queryByText('Synthetic private HTTP body')).not.toBeInTheDocument()
  })

  it('rejects a late response from the previously selected HTTP session', async () => {
    let finishOld: ((value: Response) => void) | undefined
    apiMock.mockImplementation(async input => {
      if (String(input).includes('?')) return response({ items: [session('http-old', 'Old list body'), session('http-new', 'New list body')], total: 2 })
      if (String(input).endsWith('/http-old')) return new Promise<Response>(resolve => { finishOld = resolve })
      return response(session('http-new', 'Current synthetic body'))
    })
    const view = render(<HttpSessionsTab selectedId="http-old" onSelect={() => {}} privacyMode={false} />)
    await waitFor(() => expect(finishOld).toBeDefined())
    view.rerender(<HttpSessionsTab selectedId="http-new" onSelect={() => {}} privacyMode={false} />)
    expect(await screen.findByText('Current synthetic body')).toBeInTheDocument()
    await act(async () => { finishOld?.(response(session('http-old', 'Late previous private body'))) })
    expect(screen.queryByText('Late previous private body')).not.toBeInTheDocument()
    expect(screen.getByText('Current synthetic body')).toBeInTheDocument()
  })

  it('hides a leased body while policy is unavailable without consuming the lease again', async () => {
    privacyMock.lease = { request_id: 'request-example', resource_type: 'http_session', resource_id: 'http-example',
      scopes: ['http_body'], expires_at: '2099-01-01T00:00:00Z', uses_remaining: 10, lease_handle: 'synthetic-lease' }
    const view = render(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode />)
    expect(await screen.findByText('Synthetic private HTTP body')).toBeInTheDocument()
    const detailCalls = () => apiMock.mock.calls.filter(([input]) => String(input) === '/api/data-security/http-sessions/http-example')
    expect(detailCalls()).toHaveLength(1)
    view.rerender(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode privacyUnavailable />)
    expect(screen.queryByText('Synthetic private HTTP body')).not.toBeInTheDocument()
    expect(screen.queryByText('List fallback secret')).not.toBeInTheDocument()
    await act(async () => {})
    expect(detailCalls()).toHaveLength(1)
    view.rerender(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode />)
    expect(await screen.findByText('Synthetic private HTTP body')).toBeInTheDocument()
    expect(detailCalls()).toHaveLength(2)
  })

  it('rejects an in-flight leased body after the policy becomes unavailable', async () => {
    privacyMock.lease = { request_id: 'request-example', resource_type: 'http_session', resource_id: 'http-example',
      scopes: ['http_body'], expires_at: '2099-01-01T00:00:00Z', uses_remaining: 10, lease_handle: 'synthetic-lease' }
    let finishDetail: ((value: Response) => void) | undefined
    apiMock.mockImplementation(async input => {
      if (String(input).includes('?')) return response({ items: [session('http-example', 'List fallback secret')], total: 1 })
      return new Promise<Response>(resolve => { finishDetail = resolve })
    })
    const view = render(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode />)
    await waitFor(() => expect(finishDetail).toBeDefined())
    view.rerender(<HttpSessionsTab selectedId="http-example" onSelect={() => {}} privacyMode privacyUnavailable />)
    await act(async () => { finishDetail?.(response(session('http-example', 'Late leased private HTTP body'))) })
    expect(screen.queryByText('Late leased private HTTP body')).not.toBeInTheDocument()
    expect(screen.queryByText('List fallback secret')).not.toBeInTheDocument()
  })
})
