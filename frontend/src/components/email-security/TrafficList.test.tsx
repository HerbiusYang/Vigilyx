import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { apiFetch } from '../../utils/api'
import { WhitelistButton } from './TrafficList'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

describe('TrafficList whitelist action', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    mockedApiFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({ success: true, data: { session_id: 'session-001' }, error: null }),
    } as unknown as Response)
  })

  it('adds the session sender and source IP through the session API', async () => {
    const user = userEvent.setup()
    render(<WhitelistButton sessionId="session-001" email="sender@example.com" ip="192.0.2.10" />)

    await user.click(screen.getByRole('button', { name: '加白' }))

    expect(mockedApiFetch).toHaveBeenCalledWith('/api/sessions/session-001/whitelist', { method: 'POST' })
  })
})
