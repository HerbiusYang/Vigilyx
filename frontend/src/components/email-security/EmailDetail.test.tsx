import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { createEmailSession, createSecurityVerdict } from '../../test/factories'
import type { ApiResponse } from '../../types'
import EmailDetail from './EmailDetail'
import { apiFetch } from '../../utils/api'

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
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    mockedApiFetch.mockImplementation(async (input) => {
      const path = String(input)
      if (path.endsWith('/security-results')) return jsonResponse({ success: true, data: [], error: null })
      if (path.endsWith('/verdict')) return jsonResponse({ success: true, data: createSecurityVerdict(), error: null })
      if (path.endsWith('/related')) return jsonResponse({ success: true, data: [], error: null })
      if (path.endsWith('/rescan')) return jsonResponse({ success: true, data: { status: 'accepted' }, error: null })
      if (path.endsWith('/whitelist')) return jsonResponse({ success: true, data: { session_id: 'session-001' }, error: null })
      if (path === '/api/sessions/session-001') return jsonResponse({ success: true, data: createEmailSession(), error: null })
      throw new Error(`Unexpected API call: ${path}`)
    })
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

    await user.click(screen.getByRole('button', { name: '白名单操作' }))
    expect(mockedApiFetch).toHaveBeenCalledWith('/api/sessions/session-001/whitelist', { method: 'POST' })
  })
})
