import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import Login from './Login'

vi.mock('react-i18next', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-i18next')>(),
  useTranslation: () => ({ t: (key: string) => key }),
}))

describe('Login', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('keeps the user on the login screen when the post-change re-login fails', async () => {
    const user = userEvent.setup()
    const onLogin = vi.fn()
    vi.mocked(fetch)
      .mockResolvedValueOnce({ json: vi.fn().mockResolvedValue({ success: true, must_change_password: true }) } as unknown as Response)
      .mockResolvedValueOnce({ json: vi.fn().mockResolvedValue({ success: true }) } as unknown as Response)
      .mockResolvedValueOnce({ json: vi.fn().mockResolvedValue({ success: false, error: 'fresh session failed' }) } as unknown as Response)

    render(<Login onLogin={onLogin} />)
    await user.type(screen.getByLabelText('auth.username'), 'admin')
    await user.type(screen.getByLabelText('auth.password'), 'OldPassword!123')
    await user.click(screen.getByRole('button', { name: 'auth.login' }))

    await user.type(await screen.findByLabelText('auth.newPasswordPlaceholder'), 'NewPassword!456')
    await user.type(screen.getByLabelText('auth.confirmPasswordPlaceholder'), 'NewPassword!456')
    await user.click(screen.getByRole('button', { name: 'auth.changePasswordAndLogin' }))

    expect(onLogin).not.toHaveBeenCalled()
    expect(await screen.findByRole('alert')).toHaveTextContent('fresh session failed')
    expect(screen.getByLabelText('auth.password')).toHaveValue('')
  })

  it('exposes labels, a keyboard-focusable password toggle, and live errors', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockRejectedValueOnce(new Error('offline'))

    render(<Login onLogin={vi.fn()} />)
    await user.type(screen.getByLabelText('auth.username'), 'admin')
    await user.type(screen.getByLabelText('auth.password'), 'SecretPassword!1')
    const toggle = screen.getByRole('button', { name: 'auth.showPassword' })
    expect(toggle).not.toHaveAttribute('tabindex', '-1')

    await user.click(screen.getByRole('button', { name: 'auth.login' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('auth.networkError')
  })

  it('returns to manual login when the network fails after the password was changed', async () => {
    const user = userEvent.setup()
    const onLogin = vi.fn()
    vi.mocked(fetch)
      .mockResolvedValueOnce({ json: vi.fn().mockResolvedValue({ success: true, must_change_password: true }) } as unknown as Response)
      .mockResolvedValueOnce({ json: vi.fn().mockResolvedValue({ success: true }) } as unknown as Response)
      .mockRejectedValueOnce(new Error('login endpoint unavailable'))

    render(<Login onLogin={onLogin} />)
    await user.type(screen.getByLabelText('auth.username'), 'admin')
    await user.type(screen.getByLabelText('auth.password'), 'OldPassword!123')
    await user.click(screen.getByRole('button', { name: 'auth.login' }))
    await user.type(await screen.findByLabelText('auth.newPasswordPlaceholder'), 'NewPassword!456')
    await user.type(screen.getByLabelText('auth.confirmPasswordPlaceholder'), 'NewPassword!456')
    await user.click(screen.getByRole('button', { name: 'auth.changePasswordAndLogin' }))

    expect(onLogin).not.toHaveBeenCalled()
    expect(await screen.findByRole('alert')).toHaveTextContent('auth.reloginFailed')
    expect(screen.getByLabelText('auth.password')).toHaveValue('')
  })
})
