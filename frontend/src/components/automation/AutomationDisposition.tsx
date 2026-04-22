import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { DispositionRule, EmailAlertConfig, WechatAlertConfig, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import RulesTab from './RulesTab'
import EmailAlertTab from './EmailAlertTab'
import WechatAlertTab from './WechatAlertTab'

const defaultAlertConfig: EmailAlertConfig = {
  enabled: false,
  smtp_host: '',
  smtp_port: 587,
  smtp_username: '',
  smtp_password: '',
  smtp_password_set: false,
  smtp_tls: 'starttls',
  allow_plaintext_smtp: false,
  from_address: '',
  admin_email: '',
  min_threat_level: 'medium',
  notify_recipient: false,
  notify_admin: true,
}

const defaultWechatConfig: WechatAlertConfig = {
  enabled: false,
  webhook_url: '',
  webhook_url_set: false,
  min_threat_level: 'medium',
  mentioned_mobile_list: [],
}

function AutomationDisposition() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'alert' | 'wechat' | 'rules'>('rules')
  const [pageLoading, setPageLoading] = useState(true)

  const [alertConfig, setAlertConfig] = useState<EmailAlertConfig>({ ...defaultAlertConfig })
  const [wechatConfig, setWechatConfig] = useState<WechatAlertConfig>({ ...defaultWechatConfig })
  const [rules, setRules] = useState<DispositionRule[]>([])
  const [rulesLoadError, setRulesLoadError] = useState(false)

  const fetchAlertConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/email-alert')
      const data: ApiResponse<EmailAlertConfig> = await res.json()
      if (data.success && data.data) setAlertConfig({ ...defaultAlertConfig, ...data.data })
    } catch (e) {
      console.error('Failed to fetch email alert config:', e)
    }
  }, [])

  const fetchWechatConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/wechat-alert')
      const data: ApiResponse<WechatAlertConfig> = await res.json()
      if (data.success && data.data) setWechatConfig({ ...defaultWechatConfig, ...data.data })
    } catch (e) {
      console.error('Failed to fetch WeChat alert config:', e)
    }
  }, [])

  const fetchRules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/rules')
      const data: ApiResponse<DispositionRule[]> = await res.json()
      if (data.success && data.data) {
        setRules(data.data)
        setRulesLoadError(false)
      }
    } catch (e) {
      console.error('Failed to fetch disposition rules:', e)
      setRulesLoadError(true)
    }
  }, [])

  useEffect(() => {
    setPageLoading(true)
    Promise.all([fetchAlertConfig(), fetchWechatConfig(), fetchRules()]).finally(() => setPageLoading(false))
  }, [fetchAlertConfig, fetchWechatConfig, fetchRules])

  const activeRules = rules.filter(rule => rule.enabled).length

  if (pageLoading) {
    return (
      <div className="auto-page">
        <div className="sec-loading"><div className="sec-spinner" />{t('automation.loadingConfig')}</div>
      </div>
    )
  }

  return (
    <div className="auto-page">
      <div className="auto-header">
        <div>
          <h2>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            {t('automation.title')}
          </h2>
          <p className="auto-header-sub">{t('automation.subtitle')}</p>
        </div>
      </div>

      <div className="sec-tabs">
        <button
          className={`sec-tab ${tab === 'rules' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('rules')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="9 11 12 14 22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
          {t('automation.tabRules')}
          {rules.length > 0 && <span className="sec-tab-badge">{activeRules}/{rules.length}</span>}
        </button>
        <button
          className={`sec-tab ${tab === 'alert' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('alert')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
          </svg>
          {t('automation.tabEmailAlert')}
          {alertConfig.enabled && <span className="sec-tab-badge">ON</span>}
        </button>
        <button
          className={`sec-tab ${tab === 'wechat' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('wechat')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          {t('automation.tabWechatAlert')}
          {wechatConfig.enabled && <span className="sec-tab-badge">ON</span>}
        </button>
      </div>

      {tab === 'rules' && (
        <RulesTab
          rules={rules}
          rulesLoadError={rulesLoadError}
          onRulesChanged={fetchRules}
        />
      )}

      {tab === 'alert' && (
        <EmailAlertTab
          config={alertConfig}
          onConfigChange={setAlertConfig}
          onSaved={fetchAlertConfig}
        />
      )}

      {tab === 'wechat' && (
        <WechatAlertTab
          config={wechatConfig}
          onConfigChange={setWechatConfig}
          onSaved={fetchWechatConfig}
        />
      )}
    </div>
  )
}

export default AutomationDisposition
