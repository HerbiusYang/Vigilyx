import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'

vi.mock('./i18n', () => ({
  default: { t: (key: string) => key },
}))
vi.mock('react-i18next', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-i18next')>(),
  useTranslation: () => ({ t: (key: string) => key }),
}))
vi.mock('./components/auth/Login', () => ({
  default: () => <div>login-screen</div>,
}))
vi.mock('./components/auth/SetupWizard', () => ({
  default: () => <div>setup-screen</div>,
}))
vi.mock('./utils/api', () => ({
  apiFetch: vi.fn(),
  resetLogoutFlag: vi.fn(),
}))

describe('App session restoration', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows service unavailable for a network failure and only shows login after an unauthorized response', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch)
      .mockRejectedValueOnce(new Error('backend offline'))
      .mockResolvedValueOnce({ ok: false, status: 401 } as Response)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'app.serviceUnavailableTitle' })).toBeInTheDocument()
    expect(screen.queryByText('login-screen')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'app.retryConnection' }))
    expect(await screen.findByText('login-screen')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('does not misclassify a server error as an expired session', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 503 } as Response)

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'app.serviceUnavailableTitle' })).toBeInTheDocument()
    expect(screen.queryByText('login-screen')).not.toBeInTheDocument()
  })
})
