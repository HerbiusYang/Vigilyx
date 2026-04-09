import { useState, useRef, FormEvent } from 'react'
import type { LoginResponse } from '../../types'
import { PASSWORD_POLICY_HINT, getPasswordStrength, validatePasswordInput } from '../../utils/passwordPolicy'

/* -- Random palette: choose one color pair on each refresh, with no animation -- */
const PALETTES = [
  ['20,220,200', '80,120,255'],   // Aurora
  ['255,140,50', '240,60,120'],   // Sunset
  ['30,80,220', '0,200,160'],     // Deep sea
  ['180,60,255', '255,80,160'],   // Nebula
  ['60,200,255', '40,240,180'],   // Polar
  ['220,40,40', '255,120,30'],    // Magma
]

function useRandomPalette() {
  const ref = useRef<Record<string, string>>({})
  if (!Object.keys(ref.current).length) {
    const p = PALETTES[Math.floor(Math.random() * PALETTES.length)]
    ref.current = { '--gl-c1': p[0], '--gl-c2': p[1] }
  }
  return ref.current
}

interface LoginProps {
  onLogin: () => void
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const glowVars = useRandomPalette()

  // -- Forced password-change flow --
  const [mustChange, setMustChange] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changeLoading, setChangeLoading] = useState(false)
  const [changeError, setChangeError] = useState<string | null>(null)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', // Accept Set-Cookie
        body: JSON.stringify({ username, password }),
      })

      const data: LoginResponse = await response.json()

      if (data.success) {
        if (data.must_change_password) {
          setMustChange(true)
        } else {
          onLogin()
        }
      } else {
        setError(data.error || '登录失败')
      }
    } catch {
      setError('网络错误，请稍后重试')
    } finally {
      setLoading(false)
    }
  }

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault()
    setChangeError(null)

    const passwordError = validatePasswordInput(newPassword)
    if (passwordError) {
      setChangeError(passwordError)
      return
    }
    if (newPassword === password) {
      setChangeError('新密码不能与默认密码相同')
      return
    }
    if (newPassword !== confirmPassword) {
      setChangeError('两次输入的密码不一致')
      return
    }

    setChangeLoading(true)
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', // Cookie-based authentication
        body: JSON.stringify({ old_password: password, new_password: newPassword }),
      })
      const data = await res.json()
      if (data.success) {
        // Log in again after a successful password change to obtain a new cookie (the old tv cookie is already invalid)
        const loginRes = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ username, password: newPassword }),
        })
        const loginData: LoginResponse = await loginRes.json()
        if (loginData.success) {
          onLogin()
        } else {
          // Even if re-login fails, still notify the parent layer (the old cookie may still be valid)
          onLogin()
        }
      } else {
        setChangeError(data.error || '密码修改失败')
      }
    } catch {
      setChangeError('网络错误，请稍后重试')
    } finally {
      setChangeLoading(false)
    }
  }

  // -- Forced password-change screen --
  if (mustChange) {
    const passwordError = validatePasswordInput(newPassword)
    const pwStrength = getPasswordStrength(newPassword)
    const pwStrengthLabel = ['弱', '中', '强']
    const pwStrengthColor = ['#ef4444', '#eab308', '#22c55e']

    return (
      <div className="grok-login" style={glowVars as React.CSSProperties}>
        <div className="grok-bg" />

        <div className="grok-content">
          <div className="grok-title-wrap">
            <h1 className="grok-title" data-text="VIGILYX">VIGILYX</h1>
            <div className="grok-glow" />
          </div>

          <p className="grok-subtitle" style={{ color: '#eab308' }}>
            检测到默认密码，请立即修改
          </p>

          <form onSubmit={handleChangePassword} className="grok-form">
            {changeError && <div className="grok-error">{changeError}</div>}

            <div className="grok-input-group">
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="新密码 (至少 12 位)"
                required
                disabled={changeLoading}
                autoComplete="new-password"
                className="grok-input"
              />
              <span className="grok-hint" style={{ color: 'rgba(255,255,255,0.72)' }}>{PASSWORD_POLICY_HINT}</span>
              {pwStrength >= 0 && (
                <div className="grok-pw-bar">
                  <div className="grok-pw-fill" style={{
                    width: `${(pwStrength + 1) * 33.33}%`,
                    background: pwStrengthColor[pwStrength],
                  }} />
                  <span className="grok-pw-label" style={{ color: pwStrengthColor[pwStrength] }}>
                    {pwStrengthLabel[pwStrength]}
                  </span>
                </div>
              )}
            </div>

            <div className="grok-input-group">
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="确认新密码"
                required
                disabled={changeLoading}
                autoComplete="new-password"
                className="grok-input"
              />
              {confirmPassword && newPassword && confirmPassword !== newPassword && (
                <span className="grok-hint" style={{ color: '#ef4444' }}>密码不一致</span>
              )}
            </div>

            <button
              type="submit"
              className="grok-btn"
              disabled={changeLoading || !!passwordError || newPassword !== confirmPassword || newPassword === password}
            >
              {changeLoading ? <><span className="grok-spinner" />修改中...</> : '修改密码并登录'}
            </button>
          </form>
        </div>
      </div>
    )
  }

  // -- Standard login screen --
  return (
    <div className="grok-login" style={glowVars as React.CSSProperties}>
      <div className="grok-bg">
        <div className="gl-orb gl-orb--1" />
        <div className="gl-orb gl-orb--2" />
        <div className="gl-orb gl-orb--3" />
        <div className="gl-orb gl-orb--4" />
      </div>

      <div className="grok-content">
        <div className="grok-title-wrap">
          <h1 className="grok-title" data-text="Vigilyx">Vigilyx</h1>
          <div className="grok-glow" />
        </div>

        <p className="grok-subtitle">Email Threat Intelligence Platform</p>
        <p className="grok-subtitle-cn">邮件威胁智能化分析平台</p>

        <form onSubmit={handleSubmit} className="grok-form">
          {error && <div className="grok-error">{error}</div>}

          <div className="grok-input-group">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="用户名"
              required
              disabled={loading}
              autoComplete="username"
              className="grok-input"
            />
          </div>

          <div className="grok-input-group">
            <div className="grok-input-row">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="密码"
                required
                disabled={loading}
                autoComplete="current-password"
                className="grok-input"
              />
              {password && (
                <button
                  type="button"
                  className="grok-eye"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex={-1}
                >
                  {showPassword ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  )}
                </button>
              )}
            </div>
          </div>

          <button type="submit" className="grok-btn" disabled={loading}>
            {loading ? (
              <><span className="grok-spinner" />验证中...</>
            ) : (
              <>
                登 录
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: 8 }}>
                  <path d="M5 12h14m-7-7 7 7-7 7"/>
                </svg>
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  )
}
