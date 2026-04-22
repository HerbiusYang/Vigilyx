import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import { getPasswordPolicyHint, getPasswordStrength, validatePasswordInput } from '../../utils/passwordPolicy'

export default function AccountSettings() {
  const { t } = useTranslation()
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordMsg, setPasswordMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const handlePasswordChange = async () => {
    if (newPassword !== confirmPassword) {
      setPasswordMsg({ type: 'error', text: t('settings.passwordMismatch') })
      return
    }
    const passwordError = validatePasswordInput(newPassword)
    if (passwordError) {
      setPasswordMsg({ type: 'error', text: passwordError })
      return
    }
    try {
      const res = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
      })
      const data = await res.json()
      if (data.success) {
        setPasswordMsg({ type: 'success', text: t('settings.passwordChangeSuccess') })
        setOldPassword('')
        setNewPassword('')
        setConfirmPassword('')
      } else {
        setPasswordMsg({ type: 'error', text: data.error || t('settings.changeFailed') })
      }
    } catch {
      setPasswordMsg({ type: 'error', text: t('settings.networkError') })
    }
  }

  const passwordValidationError = validatePasswordInput(newPassword)
  const pwStrength = getPasswordStrength(newPassword)
  const pwStrengthLabel = [t('settings.pwWeak'), t('settings.pwMedium'), t('settings.pwStrong')]
  const pwStrengthColor = ['var(--status-error)', 'var(--accent-yellow)', 'var(--status-healthy)']

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon account">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          {t('settings.accountSecurity')}
        </h2>
        <p className="s-section-subtitle">{t('settings.accountSecuritySubtitle')}</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.changePassword')}</div>

        {passwordMsg && (
          <div className={`s-alert ${passwordMsg.type} in-form`}>
            {passwordMsg.type === 'success' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            )}
            <span>{passwordMsg.text}</span>
          </div>
        )}

        <div className="s-form-field">
          <label>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-form-label-icon"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            {t('settings.currentPassword')}
          </label>
          <input
            type="password"
            className="s-input"
            value={oldPassword}
            onChange={e => setOldPassword(e.target.value)}
            placeholder={t('settings.enterCurrentPassword')}
          />
        </div>
        <div className="s-form-field">
          <label>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-form-label-icon"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            {t('settings.newPassword')}
          </label>
          <input
            type="password"
            className="s-input"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            placeholder={t('settings.enterNewPassword')}
          />
          <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-tertiary)', lineHeight: 1.5 }}>
            {getPasswordPolicyHint()}
          </div>
          {pwStrength >= 0 && (
            <div className="s-pw-strength">
              <div className="s-pw-strength-bar">
                <div className="s-pw-strength-fill" style={{ width: `${(pwStrength + 1) * 33.33}%`, background: pwStrengthColor[pwStrength] }} />
              </div>
              <span className="s-pw-strength-label" style={{ color: pwStrengthColor[pwStrength] }}>
                {t('settings.passwordStrength')}: {pwStrengthLabel[pwStrength]}
              </span>
            </div>
          )}
        </div>
        <div className="s-form-field">
          <label>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-form-label-icon"><polyline points="20 6 9 17 4 12"/></svg>
            {t('settings.confirmNewPassword')}
          </label>
          <input
            type="password"
            className="s-input"
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            placeholder={t('settings.reenterNewPassword')}
          />
          {confirmPassword && newPassword && confirmPassword !== newPassword && (
            <span className="s-pw-mismatch">{t('settings.passwordMismatch')}</span>
          )}
        </div>
        <button
          className="s-btn-primary"
          onClick={handlePasswordChange}
          disabled={!oldPassword || !newPassword || !confirmPassword || newPassword !== confirmPassword || !!passwordValidationError}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          {t('settings.saveChanges')}
        </button>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.sessionManagement')}</div>
        {(() => {
          // Session state is managed by the HttpOnly cookie; the frontend no longer decodes the JWT
          return (
            <>
              <div className="s-setting-row">
                <div className="s-setting-info">
                   <span className="s-setting-label">{t('settings.currentLoginStatus')}</span>
                   <span className="s-setting-desc">{t('settings.httpOnlyCookieAuth')}</span>
                </div>
                <span className="s-status-badge online">
                  <span className="s-status-pulse" />
                  {t('settings.loggedIn')}
                </span>
              </div>
              <div className="s-setting-row">
                <div className="s-setting-info">
                   <span className="s-setting-label">{t('settings.logout')}</span>
                   <span className="s-setting-desc">{t('settings.logoutDesc')}</span>
                </div>
                <button className="s-btn-danger" onClick={async () => {
                  try {
                    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
                  } catch { /* continue logout */ }
                  window.dispatchEvent(new Event('auth:logout'))
                }}>
                  {t('settings.logout')}
                </button>
              </div>
            </>
          )
        })()}
      </div>
    </div>
  )
}
