import { useState } from 'react'
import { apiFetch } from '../../utils/api'
import { PASSWORD_POLICY_HINT, getPasswordStrength, validatePasswordInput } from '../../utils/passwordPolicy'

export default function AccountSettings() {
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordMsg, setPasswordMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const handlePasswordChange = async () => {
    if (newPassword !== confirmPassword) {
      setPasswordMsg({ type: 'error', text: '两次输入的密码不一致' })
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
        setPasswordMsg({ type: 'success', text: '密码修改成功' })
        setOldPassword('')
        setNewPassword('')
        setConfirmPassword('')
      } else {
        setPasswordMsg({ type: 'error', text: data.error || '修改失败' })
      }
    } catch {
      setPasswordMsg({ type: 'error', text: '请求失败，请检查网络连接' })
    }
  }

  const passwordValidationError = validatePasswordInput(newPassword)
  const pwStrength = getPasswordStrength(newPassword)
  const pwStrengthLabel = ['弱', '中', '强']
  const pwStrengthColor = ['var(--status-error)', 'var(--accent-yellow)', 'var(--status-healthy)']

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon account">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          账户安全
        </h2>
        <p className="s-section-subtitle">管理密码和会话，确保管理面板的访问安全</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">修改密码</div>

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
            当前密码
          </label>
          <input
            type="password"
            className="s-input"
            value={oldPassword}
            onChange={e => setOldPassword(e.target.value)}
            placeholder="输入当前密码"
          />
        </div>
        <div className="s-form-field">
          <label>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-form-label-icon"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            新密码
          </label>
          <input
            type="password"
            className="s-input"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            placeholder="输入新密码 (至少 12 位)"
          />
          <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-tertiary)', lineHeight: 1.5 }}>
            {PASSWORD_POLICY_HINT}
          </div>
          {pwStrength >= 0 && (
            <div className="s-pw-strength">
              <div className="s-pw-strength-bar">
                <div className="s-pw-strength-fill" style={{ width: `${(pwStrength + 1) * 33.33}%`, background: pwStrengthColor[pwStrength] }} />
              </div>
              <span className="s-pw-strength-label" style={{ color: pwStrengthColor[pwStrength] }}>
                密码强度: {pwStrengthLabel[pwStrength]}
              </span>
            </div>
          )}
        </div>
        <div className="s-form-field">
          <label>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-form-label-icon"><polyline points="20 6 9 17 4 12"/></svg>
            确认新密码
          </label>
          <input
            type="password"
            className="s-input"
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            placeholder="再次输入新密码"
          />
          {confirmPassword && newPassword && confirmPassword !== newPassword && (
            <span className="s-pw-mismatch">两次输入的密码不一致</span>
          )}
        </div>
        <button
          className="s-btn-primary"
          onClick={handlePasswordChange}
          disabled={!oldPassword || !newPassword || !confirmPassword || newPassword !== confirmPassword || !!passwordValidationError}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          保存修改
        </button>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">会话管理</div>
        {(() => {
          // Session state is managed by the HttpOnly cookie; the frontend no longer decodes the JWT
          return (
            <>
              <div className="s-setting-row">
                <div className="s-setting-info">
                  <span className="s-setting-label">当前登录状态</span>
                  <span className="s-setting-desc">HttpOnly cookie 认证</span>
                </div>
                <span className="s-status-badge online">
                  <span className="s-status-pulse" />
                  已登录
                </span>
              </div>
              <div className="s-setting-row">
                <div className="s-setting-info">
                  <span className="s-setting-label">退出登录</span>
                  <span className="s-setting-desc">清除会话并返回登录页面</span>
                </div>
                <button className="s-btn-danger" onClick={async () => {
                  try {
                    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
                  } catch { /* continue logout */ }
                  window.dispatchEvent(new Event('auth:logout'))
                }}>
                  退出登录
                </button>
              </div>
            </>
          )
        })()}
      </div>
    </div>
  )
}
