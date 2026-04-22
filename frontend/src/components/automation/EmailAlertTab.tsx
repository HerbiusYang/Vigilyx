import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import i18n from '../../i18n'
import type { EmailAlertConfig, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import type { UiMessage } from './types'
import { getCommonThreatLevels } from './types'

function getPlaintextSmtpLockMessage(): string {
  return i18n.t('automation.error.plaintextSmtpLocked')
}

function normalizeSmtpUiError(message?: string): string {
  if (!message) return i18n.t('automation.error.saveFailed')
  if (message.includes('SMTP plaintext mode blocked')) {
    return getPlaintextSmtpLockMessage()
  }
  if (message.includes('No compatible authentication mechanism')) {
    return i18n.t('automation.error.smtpNoAuth')
  }
  if (message.includes('must either both be filled or both be left empty')) {
    return i18n.t('automation.error.smtpCredentialsPair')
  }
  return message
}

interface EmailAlertTabProps {
  config: EmailAlertConfig
  onConfigChange: (config: EmailAlertConfig) => void
  onSaved: () => void
}

export default function EmailAlertTab({ config, onConfigChange, onSaved }: EmailAlertTabProps) {
  const { t } = useTranslation()
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [msg, setMsg] = useState<UiMessage | null>(null)

  const handleSave = async () => {
    if (config.smtp_tls === 'none' && !config.allow_plaintext_smtp) {
      setMsg({ type: 'err', text: getPlaintextSmtpLockMessage() })
      return
    }
    setSaving(true)
    setMsg(null)
    try {
      const res = await apiFetch('/api/security/email-alert', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      const data: ApiResponse<{ saved: boolean }> = await res.json()
      if (data.success) {
        setMsg({ type: 'ok', text: t('automation.configSaved') })
        onSaved()
      } else {
        setMsg({ type: 'err', text: normalizeSmtpUiError(data.error || i18n.t('automation.error.saveFailed')) })
      }
    } catch (e: unknown) {
      const text = e instanceof Error ? e.message : t('automation.error.networkError')
      setMsg({ type: 'err', text: normalizeSmtpUiError(text) })
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    if (config.smtp_tls === 'none' && !config.allow_plaintext_smtp) {
      setMsg({ type: 'err', text: getPlaintextSmtpLockMessage() })
      return
    }
    setTesting(true)
    setMsg(null)
    try {
      const res = await apiFetch('/api/security/email-alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      const data: ApiResponse<{ success: boolean; message: string }> = await res.json()
      if (data.success && data.data?.success) {
        setMsg({ type: 'ok', text: t('automation.email.testSent') })
      } else {
        setMsg({ type: 'err', text: normalizeSmtpUiError(data.error || data.data?.message || i18n.t('automation.error.sendFailed')) })
      }
    } catch (e: unknown) {
      const text = e instanceof Error ? e.message : t('automation.error.networkError')
      setMsg({ type: 'err', text: normalizeSmtpUiError(text) })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="auto-alert-card">
      <div className="auto-alert-head">
        <div className="auto-alert-head-left">
          <div className="auto-alert-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
          </div>
          <div>
            <p className="auto-alert-head-title">{t('automation.email.title')}</p>
            <p className="auto-alert-head-desc">{t('automation.email.description')}</p>
          </div>
        </div>
        <label className="s-toggle">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={e => onConfigChange({ ...config, enabled: e.target.checked })}
          />
          <span className="s-toggle-slider" />
        </label>
      </div>

      <div className="auto-alert-body">
        <div className="auto-form-hint" style={{ marginBottom: 'var(--space-3)' }}>
          {t('automation.email.channelOnlyHint', { actionCode: 'email_alert' })}
        </div>
        <div className="auto-section">
          <div className="auto-section-label">{t('automation.email.smtpServer')}</div>
          <div className="auto-form-grid auto-form-grid--3">
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.serverAddress')}</label>
              <input
                className="auto-form-input"
                type="text"
                value={config.smtp_host}
                onChange={e => onConfigChange({ ...config, smtp_host: e.target.value })}
                placeholder="smtp.example.com"
              />
            </div>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.port')}</label>
              <input
                className="auto-form-input"
                type="number"
                value={config.smtp_port}
                onChange={e => onConfigChange({ ...config, smtp_port: parseInt(e.target.value, 10) || 587 })}
              />
            </div>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.encryption')}</label>
              <select
                className="auto-form-select"
                value={config.smtp_tls}
                onChange={e => onConfigChange({ ...config, smtp_tls: e.target.value })}
              >
                <option value="starttls">STARTTLS</option>
                <option value="tls">TLS/SSL</option>
                <option value="none">{t('automation.email.noEncryption')}</option>
              </select>
            </div>
          </div>
          <div className="auto-check-row">
            <label className="auto-check-label">
              <input
                type="checkbox"
                checked={Boolean(config.allow_plaintext_smtp)}
                onChange={e => onConfigChange({ ...config, allow_plaintext_smtp: e.target.checked })}
              />
              {t('automation.email.allowPlaintext')}
            </label>
          </div>
          <div className="auto-form-hint" style={{ marginTop: '8px' }}>
            {t('automation.email.plaintextHint')}
          </div>
          <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.username')}</label>
              <input
                className="auto-form-input"
                type="text"
                value={config.smtp_username}
                onChange={e => onConfigChange({ ...config, smtp_username: e.target.value })}
                placeholder="user@example.com"
              />
            </div>
            <div className="auto-form-group">
              <label className="auto-form-label">
                {t('automation.email.password')}
                {config.smtp_password_set && <span className="auto-form-label-hint">({t('automation.alreadySet')})</span>}
              </label>
              <input
                className="auto-form-input"
                type="password"
                value={config.smtp_password}
                onChange={e => onConfigChange({ ...config, smtp_password: e.target.value })}
                placeholder={config.smtp_password_set ? t('automation.secretConfiguredPlaceholder') : t('automation.email.enterPassword')}
              />
              {config.smtp_password_set && (
                <div className="auto-form-hint" style={{ marginTop: '6px' }}>
                  {t('automation.secretConfiguredHint')}
                </div>
              )}
            </div>
          </div>
          <div className="auto-form-hint" style={{ marginTop: '8px' }}>
            {t('automation.email.credentialsHint')}
          </div>
          <div className="auto-form-grid" style={{ marginTop: 'var(--space-3)' }}>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.fromAddress')}</label>
              <input
                className="auto-form-input"
                type="email"
                value={config.from_address}
                onChange={e => onConfigChange({ ...config, from_address: e.target.value })}
                placeholder="vigilyx-alert@example.com"
              />
            </div>
          </div>
        </div>

        <div className="auto-section">
          <div className="auto-section-label">{t('automation.alertRules')}</div>
          <div className="auto-form-grid auto-form-grid--2-narrow">
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.email.adminEmail')}</label>
              <input
                className="auto-form-input"
                type="email"
                value={config.admin_email}
                onChange={e => onConfigChange({ ...config, admin_email: e.target.value })}
                placeholder="admin@company.com"
              />
            </div>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.form.minThreatLevel')}</label>
              <select
                className="auto-form-select"
                value={config.min_threat_level}
                onChange={e => onConfigChange({ ...config, min_threat_level: e.target.value })}
              >
                {getCommonThreatLevels().map(option => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="auto-check-row">
            <label className="auto-check-label">
              <input
                type="checkbox"
                checked={config.notify_admin}
                onChange={e => onConfigChange({ ...config, notify_admin: e.target.checked })}
              />
              {t('automation.email.notifyAdmin')}
            </label>
            <label className="auto-check-label">
              <input
                type="checkbox"
                checked={config.notify_recipient}
                onChange={e => onConfigChange({ ...config, notify_recipient: e.target.checked })}
              />
              {t('automation.email.notifyRecipient')}
            </label>
          </div>
        </div>
      </div>

      <div className="auto-alert-footer">
        {msg && (
          <div className={`auto-msg ${msg.type === 'ok' ? 'auto-msg--ok' : 'auto-msg--err'}`}>
            {msg.text}
          </div>
        )}
        <div style={{ flex: 1 }} />
        <button
          className="sec-btn sec-btn--secondary"
          onClick={handleTest}
          disabled={testing || !config.smtp_host || !config.admin_email}
        >
          {testing ? t('automation.sending') : t('automation.email.testConnection')}
        </button>
        <button
          className="sec-btn sec-btn--primary"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? t('automation.saving') : t('automation.saveConfig')}
        </button>
      </div>
    </div>
  )
}
