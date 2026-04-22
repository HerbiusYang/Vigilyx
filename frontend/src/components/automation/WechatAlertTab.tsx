import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import i18n from '../../i18n'
import type { WechatAlertConfig, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import type { UiMessage } from './types'
import { getCommonThreatLevels } from './types'
import { parseLineList, formatLineList } from './ruleFormHelpers'

function normalizeWechatUiError(message?: string): string {
  if (!message) return i18n.t('automation.error.saveFailed')
  return message
}

interface WechatAlertTabProps {
  config: WechatAlertConfig
  onConfigChange: (config: WechatAlertConfig) => void
  onSaved: () => void
}

export default function WechatAlertTab({ config, onConfigChange, onSaved }: WechatAlertTabProps) {
  const { t } = useTranslation()
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [msg, setMsg] = useState<UiMessage | null>(null)

  const handleSave = async () => {
    setSaving(true)
    setMsg(null)
    try {
      const res = await apiFetch('/api/security/wechat-alert', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      const data: ApiResponse<{ saved: boolean }> = await res.json()
      if (data.success) {
        setMsg({ type: 'ok', text: t('automation.configSaved') })
        onSaved()
      } else {
        setMsg({ type: 'err', text: normalizeWechatUiError(data.error || i18n.t('automation.error.saveFailed')) })
      }
    } catch (e: unknown) {
      const text = e instanceof Error ? e.message : t('automation.error.networkError')
      setMsg({ type: 'err', text: normalizeWechatUiError(text) })
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setMsg(null)
    try {
      const res = await apiFetch('/api/security/wechat-alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      const data: ApiResponse<{ success: boolean; message: string }> = await res.json()
      if (data.success && data.data?.success) {
        setMsg({ type: 'ok', text: t('automation.wechat.testSent') })
      } else {
        setMsg({ type: 'err', text: normalizeWechatUiError(data.error || data.data?.message || i18n.t('automation.error.sendFailed')) })
      }
    } catch (e: unknown) {
      const text = e instanceof Error ? e.message : t('automation.error.networkError')
      setMsg({ type: 'err', text: normalizeWechatUiError(text) })
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
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
          </div>
          <div>
            <p className="auto-alert-head-title">{t('automation.wechat.title')}</p>
            <p className="auto-alert-head-desc">{t('automation.wechat.description')}</p>
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
          {t('automation.wechat.channelOnlyHint', { actionCode: 'wechat_alert' })}
        </div>
        <div className="auto-section">
          <div className="auto-section-label">Webhook</div>
          <div className="auto-form-grid">
            <div className="auto-form-group">
              <label className="auto-form-label">
                {t('automation.wechat.webhookUrl')}
                {config.webhook_url_set && <span className="auto-form-label-hint">({t('automation.alreadySet')})</span>}
              </label>
              <input
                className="auto-form-input"
                type="password"
                value={config.webhook_url}
                onChange={e => onConfigChange({ ...config, webhook_url: e.target.value })}
                placeholder={config.webhook_url_set ? t('automation.secretConfiguredPlaceholder') : 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...'}
              />
              {config.webhook_url_set && (
                <div className="auto-form-hint" style={{ marginTop: '6px' }}>
                  {t('automation.secretConfiguredHint')}
                </div>
              )}
            </div>
          </div>
          <div className="auto-form-hint" style={{ marginTop: '8px' }}>
            {t('automation.wechat.encryptHint')}
          </div>
        </div>

        <div className="auto-section">
          <div className="auto-section-label">{t('automation.alertRules')}</div>
          <div className="auto-form-grid auto-form-grid--2">
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
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.wechat.mentionedMobiles')}</label>
              <textarea
                className="auto-form-textarea"
                rows={4}
                value={formatLineList(config.mentioned_mobile_list)}
                onChange={e => onConfigChange({
                  ...config,
                  mentioned_mobile_list: parseLineList(e.target.value),
                })}
                placeholder={t('automation.wechat.mobilePlaceholder')}
              />
            </div>
          </div>
          <div className="auto-form-hint" style={{ marginTop: '8px' }}>
            {t('automation.wechat.mobileHint')}
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
          disabled={testing || (!config.webhook_url && !config.webhook_url_set)}
        >
          {testing ? t('automation.sending') : t('automation.wechat.testSendBtn')}
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
