import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import { formatTime } from '../../utils/format'
import type { ApiResponse, IocEntry, SecurityStats } from '../../types'

const PAGE_SIZE = 30

function isMaskedSecretValue(value: string): boolean {
  return value.includes('...') || value === '****'
}

interface IntelConfigTabProps {
  stats: SecurityStats | null
  onNavigateToIoc: () => void
}

export default function IntelConfigTab({ stats, onNavigateToIoc }: IntelConfigTabProps) {
  const { t } = useTranslation()

  // Intel source config (VT/AbuseIPDB/OTX)
  const [intelConfig, setIntelConfig] = useState<Record<string, any> | null>(null)
  const [intelConfigDraft, setIntelConfigDraft] = useState<Record<string, any> | null>(null)
  const [savingIntelConfig, setSavingIntelConfig] = useState(false)
  const [intelConfigMsg, setIntelConfigMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Intel whitelist
  const [intelWlList, setIntelWlList] = useState<IocEntry[]>([])
  const [intelWlTotal, setIntelWlTotal] = useState(0)
  const [intelWlSearch, setIntelWlSearch] = useState('')
  const [intelWlTypeFilter, setIntelWlTypeFilter] = useState('')
  const [intelWlPage, setIntelWlPage] = useState(0)
  const [showAddIntelWl, setShowAddIntelWl] = useState(false)
  const [addingIntelWl, setAddingIntelWl] = useState(false)
  const [intelWlForm, setIntelWlForm] = useState({ indicator: '', ioc_type: 'domain', description: '' })

  const fetchIntelConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/intel-config')
      const data: ApiResponse<Record<string, any>> = await res.json()
      if (data.success && data.data) {
        setIntelConfig(data.data)
        setIntelConfigDraft(data.data)
      }
    } catch (e) {
      console.error('Failed to fetch intel config:', e)
    }
  }, [])

  const fetchIntelWhitelist = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(intelWlPage * PAGE_SIZE),
      })
      if (intelWlSearch) params.set('search', intelWlSearch)
      if (intelWlTypeFilter) params.set('ioc_type', intelWlTypeFilter)
      const res = await apiFetch(`/api/security/intel-whitelist?${params}`)
      const data: ApiResponse<{ items: IocEntry[]; total: number }> = await res.json()
      if (data.success && data.data) {
        setIntelWlList(data.data.items)
        setIntelWlTotal(data.data.total)
      }
    } catch (e) {
      console.error('Failed to fetch intel whitelist:', e)
    }
  }, [intelWlSearch, intelWlTypeFilter, intelWlPage])

  useEffect(() => {
    fetchIntelConfig()
    fetchIntelWhitelist()
  }, [fetchIntelConfig, fetchIntelWhitelist])

  const updateIntelConfigDraft = (patch: Record<string, unknown>) => {
    setIntelConfigMsg(null)
    setIntelConfigDraft(prev => (prev ? { ...prev, ...patch } : prev))
  }

  const saveIntelConfig = async () => {
    if (!intelConfigDraft) return
    setSavingIntelConfig(true)
    setIntelConfigMsg(null)
    try {
      const payload: Record<string, unknown> = {
        otx_enabled: intelConfigDraft.otx_enabled,
        vt_scrape_enabled: intelConfigDraft.vt_scrape_enabled,
        abuseipdb_enabled: intelConfigDraft.abuseipdb_enabled,
      }
      if (intelConfigDraft.virustotal_api_key === '') {
        payload.virustotal_api_key = null
      } else if (!isMaskedSecretValue(intelConfigDraft.virustotal_api_key)) {
        payload.virustotal_api_key = intelConfigDraft.virustotal_api_key
      }
      if (intelConfigDraft.abuseipdb_api_key === '') {
        payload.abuseipdb_api_key = null
      } else if (!isMaskedSecretValue(intelConfigDraft.abuseipdb_api_key)) {
        payload.abuseipdb_api_key = intelConfigDraft.abuseipdb_api_key
      }
      const res = await apiFetch('/api/security/intel-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        await fetchIntelConfig()
        setIntelConfigMsg({ ok: true, text: t('saveSuccess') })
      } else {
        setIntelConfigMsg({ ok: false, text: data.error || t('saveFailed') })
      }
    } catch (e) {
      console.error('Failed to save intel config:', e)
      setIntelConfigMsg({ ok: false, text: t('networkError') })
    } finally {
      setSavingIntelConfig(false)
    }
  }

  const handleAddIntelWl = async () => {
    if (!intelWlForm.indicator.trim()) return
    setAddingIntelWl(true)
    try {
      const res = await apiFetch('/api/security/intel-whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: intelWlForm.indicator.trim(),
          ioc_type: intelWlForm.ioc_type,
          description: intelWlForm.description || undefined,
        }),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        setIntelWlForm({ indicator: '', ioc_type: 'domain', description: '' })
        setShowAddIntelWl(false)
        fetchIntelWhitelist()
      }
    } catch (e) {
      console.error('Failed to add intel whitelist:', e)
    } finally {
      setAddingIntelWl(false)
    }
  }

  const handleDeleteIntelWl = async (id: string) => {
    try {
      const res = await apiFetch(`/api/security/intel-whitelist/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!data.success) {
        alert(data.error || t('emailSecurity.deleteFailed'))
        return
      }
      fetchIntelWhitelist()
    } catch (e) {
      console.error('Failed to delete intel whitelist:', e)
    }
  }

  return (
    <div className="intel-page">
      {/* -- Page title area -- */}
      <div className="intel-hero">
        <div className="intel-hero-text">
          <h2 className="intel-hero-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            {t('emailSecurity.intelSourcesTitle')}
          </h2>
          <p className="intel-hero-desc">{t('emailSecurity.intelSourcesDesc')}</p>
        </div>
      </div>

      {/* -- Intel-source cards -- */}
      <div className="intel-sources">
        {/* VirusTotal */}
        <div className={`intel-card ${intelConfigDraft?.vt_scrape_enabled ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(59,130,246,0.12)', color: '#3b82f6' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">VirusTotal</h3>
              <span className="intel-card-subtitle">{t('emailSecurity.vtSubtitle')}</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.vt_scrape_enabled ?? false}
                  onChange={e => updateIntelConfigDraft({ vt_scrape_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              {t('emailSecurity.vtDesc')}
            </p>
            <div className="intel-card-status-row">
              {intelConfig?.virustotal_api_key_set ? (
                <span className="intel-status-badge intel-status--configured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                  {t('emailSecurity.apiKeyConfigured')}
                </span>
              ) : (
                <span className="intel-status-badge intel-status--unconfigured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  {t('emailSecurity.notConfigured')}
                </span>
              )}
            </div>
            {intelConfigDraft && (
              <div className="intel-card-config">
                <label className="intel-config-label">API Key</label>
                <div className="intel-config-input-wrap">
                  <input
                    type="password"
                  className="intel-config-input"
                  placeholder={intelConfig?.virustotal_api_key_set ? t('emailSecurity.apiKeySetPlaceholder') : t('emailSecurity.vtApiKeyPlaceholder')}
                  value={intelConfigDraft.virustotal_api_key ?? ''}
                  onChange={e => updateIntelConfigDraft({ virustotal_api_key: e.target.value })}
                />
                </div>
                {intelConfig?.virustotal_api_key_set && (
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '8px' }}>
                    {t('emailSecurity.apiKeyClearHint')}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* AbuseIPDB */}
        <div className={`intel-card ${intelConfigDraft?.abuseipdb_enabled ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">AbuseIPDB</h3>
              <span className="intel-card-subtitle">{t('emailSecurity.abuseipdbSubtitle')}</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.abuseipdb_enabled ?? false}
                  onChange={e => updateIntelConfigDraft({ abuseipdb_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              {t('emailSecurity.abuseipdbDesc')}
            </p>
            <div className="intel-card-status-row">
              {intelConfig?.abuseipdb_api_key_set ? (
                <span className="intel-status-badge intel-status--configured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                  {t('emailSecurity.apiKeyConfigured')}
                </span>
              ) : (
                <span className="intel-status-badge intel-status--unconfigured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  {t('emailSecurity.notConfigured')}
                </span>
              )}
            </div>
            {intelConfigDraft && (
              <div className="intel-card-config">
                <label className="intel-config-label">API Key</label>
                <div className="intel-config-input-wrap">
                  <input
                    type="password"
                  className="intel-config-input"
                  placeholder={intelConfig?.abuseipdb_api_key_set ? t('emailSecurity.apiKeySetPlaceholder') : t('emailSecurity.abuseipdbApiKeyPlaceholder')}
                  value={intelConfigDraft.abuseipdb_api_key ?? ''}
                  onChange={e => updateIntelConfigDraft({ abuseipdb_api_key: e.target.value })}
                />
                </div>
                {intelConfig?.abuseipdb_api_key_set && (
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '8px' }}>
                    {t('emailSecurity.apiKeyClearHint')}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* OTX AlienVault */}
        <div className={`intel-card ${intelConfigDraft?.otx_enabled !== false ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">OTX AlienVault</h3>
              <span className="intel-card-subtitle">{t('emailSecurity.otxSubtitle')}</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.otx_enabled !== false}
                  onChange={e => updateIntelConfigDraft({ otx_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              {t('emailSecurity.otxDesc')}
            </p>
            <div className="intel-card-status-row">
              <span className="intel-status-badge intel-status--builtin">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                {t('emailSecurity.builtinNoApiKey')}
              </span>
            </div>
          </div>
        </div>

        {/* Local IOC database */}
        <div className="intel-card intel-card--active intel-card--builtin">
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(168,85,247,0.12)', color: '#a855f7' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">{t('emailSecurity.localIocTitle')}</h3>
              <span className="intel-card-subtitle">{t('emailSecurity.localIocSubtitle')}</span>
            </div>
            <span className="intel-builtin-badge">{t('emailSecurity.builtin')}</span>
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              {t('emailSecurity.localIocDesc', { count: stats?.ioc_count ?? 0 })}
            </p>
            <div className="intel-card-status-row">
              <span className="intel-status-badge intel-status--builtin">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                {t('emailSecurity.alwaysEnabled')}
              </span>
              <button
                className="sec-btn sec-btn--sm sec-btn--ghost"
                onClick={onNavigateToIoc}
                style={{ marginLeft: 'auto' }}
              >
                {t('emailSecurity.manageIoc')}
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginLeft: 4 }}><polyline points="9 18 15 12 9 6"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* -- Save button -- */}
      {intelConfigDraft && (
        <>
          {intelConfigMsg && (
            <div
              className={intelConfigMsg.ok ? 's-deploy-success' : ''}
              style={intelConfigMsg.ok ? { marginTop: 16 } : { color: '#ef4444', fontSize: 12, marginTop: 16, marginBottom: 8 }}
            >
              {intelConfigMsg.text}
            </div>
          )}
          <div className="intel-save-bar">
            <button
              className="sec-btn sec-btn--primary"
              onClick={saveIntelConfig}
              disabled={savingIntelConfig}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
              </svg>
              {savingIntelConfig ? t('emailSecurity.saving') : t('emailSecurity.saveIntelConfig')}
            </button>
            <span className="intel-save-hint">{t('emailSecurity.saveIntelConfigHint')}</span>
          </div>
        </>
      )}

      {/* -- Intel whitelist (merged into the intel-source page) -- */}
      <div className="sec-ioc" style={{ marginTop: 24 }}>
        <div className="intel-wl-header" style={{ marginBottom: 16 }}>
          <div className="intel-wl-title-group">
            <h3 className="intel-wl-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
              </svg>
              {t('emailSecurity.intelWhitelistTitle')}
            </h3>
            <span className="intel-wl-desc">{t('emailSecurity.intelWhitelistDesc')}</span>
          </div>
        </div>

        <div className="sec-ioc-toolbar">
          <div className="sec-ioc-search">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input
              type="text"
              placeholder={t('emailSecurity.searchWhitelistPlaceholder')}
              value={intelWlSearch}
              onChange={e => { setIntelWlSearch(e.target.value); setIntelWlPage(0) }}
            />
          </div>
          <select
            className="sec-ioc-select"
            value={intelWlTypeFilter}
            onChange={e => { setIntelWlTypeFilter(e.target.value); setIntelWlPage(0) }}
          >
            <option value="">{t('emailSecurity.allTypes')}</option>
            <option value="ip">IP</option>
            <option value="domain">{t('emailSecurity.typeDomain')}</option>
            <option value="url">URL</option>
            <option value="hash">{t('emailSecurity.typeHash')}</option>
          </select>
          <div className="sec-ioc-actions">
            <span className="sec-ioc-total">{t('emailSecurity.totalCount', { count: intelWlTotal })}</span>
            <button className="sec-btn sec-btn--primary sec-btn--sm" onClick={() => setShowAddIntelWl(!showAddIntelWl)}>
              {showAddIntelWl ? t('emailSecurity.cancel') : t('emailSecurity.addEntry')}
            </button>
          </div>
        </div>

        {showAddIntelWl && (
          <div className="sec-ioc-add-form">
            <div className="sec-form-row">
              <div className="sec-form-group" style={{ flex: 2 }}>
                <label className="sec-form-label">{t('emailSecurity.indicatorValue')}</label>
                <input
                  type="text"
                  className="sec-form-input"
                  placeholder={t('emailSecurity.indicatorPlaceholder')}
                  value={intelWlForm.indicator}
                  onChange={e => setIntelWlForm({ ...intelWlForm, indicator: e.target.value })}
                />
              </div>
              <div className="sec-form-group">
                <label className="sec-form-label">{t('emailSecurity.type')}</label>
                <select
                  className="sec-form-select"
                  value={intelWlForm.ioc_type}
                  onChange={e => setIntelWlForm({ ...intelWlForm, ioc_type: e.target.value })}
                >
                  <option value="domain">{t('emailSecurity.typeDomain')}</option>
                  <option value="ip">IP</option>
                  <option value="url">URL</option>
                  <option value="hash">{t('emailSecurity.typeHash')}</option>
                </select>
              </div>
              <div className="sec-form-group" style={{ flex: 2 }}>
                <label className="sec-form-label">{t('emailSecurity.description')}</label>
                <input
                  type="text"
                  className="sec-form-input"
                  placeholder={t('emailSecurity.optionalNote')}
                  value={intelWlForm.description}
                  onChange={e => setIntelWlForm({ ...intelWlForm, description: e.target.value })}
                />
              </div>
              <div className="sec-form-group" style={{ alignSelf: 'flex-end' }}>
                <button
                  className="sec-btn sec-btn--primary"
                  onClick={handleAddIntelWl}
                  disabled={addingIntelWl || !intelWlForm.indicator.trim()}
                >
                  {addingIntelWl ? t('emailSecurity.adding') : t('emailSecurity.confirmAdd')}
                </button>
              </div>
            </div>
          </div>
        )}

        {intelWlList.length === 0 ? (
          <div className="sec-empty">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <p>{t('emailSecurity.noWhitelistData')}</p>
          </div>
        ) : (
          <div className="sec-table-wrap">
            <table className="sec-table">
              <thead>
                <tr>
                  <th>{t('emailSecurity.indicatorValue')}</th>
                  <th>{t('emailSecurity.type')}</th>
                  <th>{t('emailSecurity.source')}</th>
                  <th className="sec-th-r">{t('emailSecurity.colConfidence')}</th>
                  <th className="sec-th-r">{t('emailSecurity.hitCount')}</th>
                  <th>{t('emailSecurity.expiresAt')}</th>
                  <th className="sec-th-r">{t('emailSecurity.action')}</th>
                </tr>
              </thead>
              <tbody>
                {intelWlList.map(entry => (
                  <tr key={entry.id}>
                    <td className="sec-ioc-indicator"><span className="sec-mono">{entry.indicator}</span></td>
                    <td><span className="sec-badge sec-badge--type">{entry.ioc_type}</span></td>
                    <td>
                      {entry.source === 'system' ? (
                        <span className="sec-badge sec-badge--system">{t('emailSecurity.sourceSystem')}</span>
                      ) : entry.source === 'admin_clean' ? (
                        <span className="sec-badge sec-badge--admin">{t('emailSecurity.sourceAdmin')}</span>
                      ) : (
                        <span className="sec-badge sec-badge--auto">{entry.source}</span>
                      )}
                    </td>
                    <td className="sec-td-r sec-mono">{(entry.confidence * 100).toFixed(0)}%</td>
                    <td className="sec-td-r sec-mono">{entry.hit_count}</td>
                    <td className="sec-mono">
                      {entry.expires_at ? formatTime(entry.expires_at) : t('emailSecurity.neverExpires')}
                    </td>
                    <td className="sec-td-r">
                      <button className="sec-btn-del" onClick={() => handleDeleteIntelWl(entry.id)}>
                        {t('emailSecurity.revoke')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {intelWlTotal > PAGE_SIZE && (
          <div className="sec-pagination">
            <button
              className="sec-page-btn"
              disabled={intelWlPage === 0}
              onClick={() => setIntelWlPage(p => p - 1)}
            >
              {t('emailSecurity.prevPage')}
            </button>
            <span className="sec-page-info">
              {t('emailSecurity.pageInfo', { current: intelWlPage + 1, total: Math.ceil(intelWlTotal / PAGE_SIZE) })}
            </span>
            <button
              className="sec-page-btn"
              disabled={(intelWlPage + 1) * PAGE_SIZE >= intelWlTotal}
              onClick={() => setIntelWlPage(p => p + 1)}
            >
              {t('emailSecurity.nextPage')}
            </button>
          </div>
        )}
      </div>

    </div>
  )
}
