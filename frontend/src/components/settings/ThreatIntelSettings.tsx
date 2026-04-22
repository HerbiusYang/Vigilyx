import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'

function isMaskedSecretValue(value: string): boolean {
  return value.includes('...') || value === '****'
}

export default function ThreatIntelSettings() {
  const { t } = useTranslation()
  const [intelConfig, setIntelConfig] = useState({
    otx_enabled: true,
    vt_scrape_enabled: true,
    virustotal_api_key: '',
    virustotal_api_key_set: false,
    abuseipdb_enabled: false,
    abuseipdb_api_key: '',
    abuseipdb_api_key_set: false,
  })
  const [intelSaving, setIntelSaving] = useState(false)
  const [intelMsg, setIntelMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [intelLoaded, setIntelLoaded] = useState(false)

  // Load intel config on mount
  useEffect(() => {
    if (!intelLoaded) {
      apiFetch('/api/security/intel-config').then(r => r.json()).then(d => {
        if (d.success && d.data) {
          setIntelConfig(prev => ({
            ...prev,
            otx_enabled: d.data.otx_enabled ?? true,
            vt_scrape_enabled: d.data.vt_scrape_enabled ?? true,
            virustotal_api_key: d.data.virustotal_api_key || '',
            virustotal_api_key_set: d.data.virustotal_api_key_set ?? false,
            abuseipdb_enabled: d.data.abuseipdb_enabled ?? false,
            abuseipdb_api_key: d.data.abuseipdb_api_key || '',
            abuseipdb_api_key_set: d.data.abuseipdb_api_key_set ?? false,
          }))
          setIntelLoaded(true)
        }
      }).catch(() => {})
    }
  }, [intelLoaded])

  const handleSaveIntel = async () => {
    setIntelSaving(true)
    setIntelMsg(null)
    try {
      const payload: Record<string, unknown> = {
        otx_enabled: intelConfig.otx_enabled,
        vt_scrape_enabled: intelConfig.vt_scrape_enabled,
        abuseipdb_enabled: intelConfig.abuseipdb_enabled,
      }
      if (intelConfig.virustotal_api_key === '') {
        payload.virustotal_api_key = null
      } else if (!isMaskedSecretValue(intelConfig.virustotal_api_key)) {
        payload.virustotal_api_key = intelConfig.virustotal_api_key
      }
      if (intelConfig.abuseipdb_api_key === '') {
        payload.abuseipdb_api_key = null
      } else if (!isMaskedSecretValue(intelConfig.abuseipdb_api_key)) {
        payload.abuseipdb_api_key = intelConfig.abuseipdb_api_key
      }
      const res = await apiFetch('/api/security/intel-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (data.success) {
        setIntelMsg({ ok: true, text: t('settings.threatIntel.saveSuccess') })
        setIntelLoaded(false) // reload on next visit
      } else {
        setIntelMsg({ ok: false, text: data.error || t('settings.threatIntel.saveFailed') })
      }
    } catch {
      setIntelMsg({ ok: false, text: t('settings.threatIntel.requestFailed') })
    } finally {
      setIntelSaving(false)
    }
  }

  const IntelSourceCard = ({
    title, description, quota, icon, enabled, onToggle,
    apiKeyLabel, apiKeyPlaceholder, apiKeySet, apiKeyValue, onKeyChange,
    children,
  }: {
    title: string; description: string; quota: string; icon: React.ReactNode
    enabled: boolean; onToggle: (v: boolean) => void
    apiKeyLabel?: string; apiKeyPlaceholder?: string; apiKeySet?: boolean
    apiKeyValue?: string; onKeyChange?: (v: string) => void
    children?: React.ReactNode
  }) => (
    <div style={{
      border: '1px solid var(--border-primary)',
      borderRadius: 10,
      padding: '18px 20px',
      marginBottom: 12,
      background: 'var(--bg-secondary)',
      position: 'relative',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
        <div style={{
          width: 40, height: 40, borderRadius: 10,
          background: enabled ? 'rgba(99,102,241,0.12)' : 'rgba(148,163,184,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: enabled ? '#6366f1' : 'var(--text-tertiary)', flexShrink: 0,
        }}>
          {icon}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{title}</span>
              <span style={{
                fontSize: 11, padding: '2px 7px', borderRadius: 4, fontWeight: 500,
                background: (apiKeySet || !apiKeyLabel) && enabled
                  ? 'rgba(34,197,94,0.12)' : 'rgba(148,163,184,0.1)',
                color: (apiKeySet || !apiKeyLabel) && enabled
                  ? '#22c55e' : 'var(--text-tertiary)',
              }}>
                {!apiKeyLabel ? (enabled ? t('settings.threatIntel.enabled') : t('settings.threatIntel.disabled')) : (apiKeySet ? t('settings.threatIntel.configured') : t('settings.threatIntel.notConfigured'))}
              </span>
            </div>
            <label className="s-toggle">
              <input type="checkbox" checked={enabled} onChange={e => onToggle(e.target.checked)} />
              <span className="s-toggle-slider" />
            </label>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-tertiary)', margin: '0 0 6px 0', lineHeight: 1.5 }}>{description}</p>
          <p style={{ fontSize: 11, color: 'var(--text-tertiary)', margin: 0, opacity: 0.7 }}>{quota}</p>
        </div>
      </div>
      {apiKeyLabel && enabled && (
        <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border-primary)' }}>
          <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 6 }}>{apiKeyLabel}</div>
          <input
            type="password"
            className="s-input"
            style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12 }}
            placeholder={apiKeySet ? t('settings.threatIntel.apiKeyConfiguredPlaceholder') : (apiKeyPlaceholder || t('settings.threatIntel.apiKeyPlaceholder'))}
            value={apiKeyValue || ''}
            onChange={e => onKeyChange?.(e.target.value)}
            autoComplete="new-password"
          />
          {apiKeySet && (
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 6 }}>
              {t('settings.threatIntel.apiKeyClearHint')}
            </div>
          )}
        </div>
      )}
      {children}
    </div>
  )

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon" style={{ background: 'rgba(99,102,241,0.08)', color: '#6366f1' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
            </svg>
          </span>
          {t('settings.threatIntel.title')}
        </h2>
        <p className="s-section-subtitle">{t('settings.threatIntel.subtitle')}</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.threatIntel.freeSourcesHeader')}</div>

        <IntelSourceCard
          title="OTX AlienVault"
          description={t('settings.threatIntel.otxDescription')}
          quota={t('settings.threatIntel.otxQuota')}
          enabled={intelConfig.otx_enabled}
          onToggle={v => setIntelConfig(prev => ({ ...prev, otx_enabled: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
            </svg>
          }
        />
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.threatIntel.commercialSourcesHeader')}</div>

        <IntelSourceCard
          title="VirusTotal"
          description={t('settings.threatIntel.vtDescription')}
          quota={t('settings.threatIntel.vtQuota')}
          enabled={intelConfig.virustotal_api_key_set || intelConfig.virustotal_api_key.length > 0}
          onToggle={v => {
            if (!v) setIntelConfig(prev => ({ ...prev, virustotal_api_key: '', virustotal_api_key_set: false }))
          }}
          apiKeyLabel="API Key"
          apiKeyPlaceholder={t('settings.threatIntel.vtApiKeyPlaceholder')}
          apiKeySet={intelConfig.virustotal_api_key_set}
          apiKeyValue={intelConfig.virustotal_api_key}
          onKeyChange={v => setIntelConfig(prev => ({ ...prev, virustotal_api_key: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
          }
        />

        <IntelSourceCard
          title="AbuseIPDB"
          description={t('settings.threatIntel.abuseipdbDescription')}
          quota={t('settings.threatIntel.abuseipdbQuota')}
          enabled={intelConfig.abuseipdb_enabled}
          onToggle={v => setIntelConfig(prev => ({ ...prev, abuseipdb_enabled: v }))}
          apiKeyLabel="API Key"
          apiKeyPlaceholder={t('settings.threatIntel.abuseipdbApiKeyPlaceholder')}
          apiKeySet={intelConfig.abuseipdb_api_key_set}
          apiKeyValue={intelConfig.abuseipdb_api_key}
          onKeyChange={v => setIntelConfig(prev => ({ ...prev, abuseipdb_api_key: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          }
        />
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.threatIntel.fallbackHeader')}</div>
        <div style={{ padding: '12px 16px', background: 'rgba(99,102,241,0.05)', borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          <div style={{ fontWeight: 500, marginBottom: 6, color: 'var(--text-primary)' }}>{t('settings.threatIntel.fallbackTitle')}</div>
          <div>· <strong>{t('settings.threatIntel.fallbackVtExhausted')}</strong>{t('settings.threatIntel.fallbackVtExhaustedDesc')}</div>
          <div>· <strong>{t('settings.threatIntel.fallbackVtScrapeUnavail')}</strong>{t('settings.threatIntel.fallbackVtScrapeUnavailDesc')}</div>
          <div>· <strong>{t('settings.threatIntel.fallbackAbuseExhausted')}</strong>{t('settings.threatIntel.fallbackAbuseExhaustedDesc')}</div>
          <div>· <strong>{t('settings.threatIntel.fallback429')}</strong>{t('settings.threatIntel.fallback429Desc')}</div>
          <div>· <strong>{t('settings.threatIntel.fallbackAllDown')}</strong>{t('settings.threatIntel.fallbackAllDownDesc')}</div>
        </div>
      </div>

      <div className="s-deploy-action">
        {intelMsg && (
          <div className={intelMsg.ok ? 's-deploy-success' : ''} style={intelMsg.ok ? {} : { color: '#ef4444', fontSize: 12, marginBottom: 8 }}>
            {intelMsg.ok && <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>}
            {intelMsg.text}
          </div>
        )}
        <div className="s-deploy-action-row">
          <div className="s-deploy-action-hint">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2" style={{ flexShrink: 0 }}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>{t('settings.threatIntel.encryptionHint')}</span>
          </div>
          <button
            className="s-btn-primary"
            disabled={intelSaving}
            onClick={handleSaveIntel}
          >
            {intelSaving ? t('settings.threatIntel.saving') : t('settings.threatIntel.saveConfig')}
          </button>
        </div>
      </div>
    </div>
  )
}
