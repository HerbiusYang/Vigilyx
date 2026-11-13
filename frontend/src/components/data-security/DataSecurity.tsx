import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import type { JSX } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { DataSecurityStats, DataSecurityEngineStatus, EmailDataSecurityStats, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import { usePrivacyPolicy } from '../../hooks/usePrivacyPolicy'
import type { TabKey } from './types'
import { OverviewTab } from './OverviewTab'
import { PolicyTab } from './PolicyTab'
import { IncidentsTab } from './IncidentsTab'
import { HttpSessionsTab } from './HttpSessionsTab'
import { OutboundEmailReviewsTab } from './OutboundEmailReviewsTab'
import { SettingsTab } from './SettingsTab'
import { TimePolicyTab } from './TimePolicyTab'

export default function DataSecurity() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()

  // Support both /data-security/* and /portal/* path prefixes
  const basePath = location.pathname.startsWith('/portal') ? '/portal' : '/data-security'

  const { activeTab, selectedId } = useMemo(() => {
    const s = location.pathname.replace(new RegExp(`^${basePath}\\/?`), '')
    if (s === 'policy') return { activeTab: 'policy' as TabKey, selectedId: undefined }
    if (s === 'privacy') return { activeTab: 'privacy' as TabKey, selectedId: undefined }
    if (s === 'outbound-emails') return { activeTab: 'outbound-emails' as TabKey, selectedId: undefined }
    if (s.startsWith('incidents/')) return { activeTab: 'incidents' as TabKey, selectedId: s.replace('incidents/', '') }
    if (s === 'incidents') return { activeTab: 'incidents' as TabKey, selectedId: undefined }
    if (s.startsWith('http-sessions/')) return { activeTab: 'http-sessions' as TabKey, selectedId: s.replace('http-sessions/', '') }
    if (s === 'http-sessions') return { activeTab: 'http-sessions' as TabKey, selectedId: undefined }
    if (s === 'settings' || s === 'time-policy') return { activeTab: 'settings' as TabKey, selectedId: undefined }
    return { activeTab: 'overview' as TabKey, selectedId: undefined }
  }, [location.pathname, basePath])

  const isPortal = basePath === '/portal'

  // Keep old bookmarks working, but make the global privacy workflow live in
  // system settings rather than inside the data-security business page.
  useEffect(() => {
    if (activeTab === 'privacy') navigate('/settings#privacy', { replace: true })
  }, [activeTab, navigate])

  const setActiveTab = useCallback((tab: TabKey) => {
    const settingsPath = isPortal ? `${basePath}/time-policy` : `${basePath}/settings`
    const routes: Record<TabKey, string> = { overview: basePath, 'outbound-emails': `${basePath}/outbound-emails`, policy: `${basePath}/policy`, privacy: `${basePath}/privacy`, incidents: `${basePath}/incidents`, 'http-sessions': `${basePath}/http-sessions`, settings: settingsPath }
    navigate(routes[tab])
  }, [navigate, basePath, isPortal])

  const { enabled: privacyMode, loading: privacyLoading, error: privacyError } = usePrivacyPolicy()
  // Portal mode enforces privacy protection regardless of the global policy.
  const effectivePrivacy = isPortal ? true : privacyMode

  const [stats, setStats] = useState<DataSecurityStats | null>(null)
  const [engineStatus, setEngineStatus] = useState<DataSecurityEngineStatus | null>(null)
  const [emailReviewStats, setEmailReviewStats] = useState<EmailDataSecurityStats | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)

  const loadStats = useCallback(async () => {
    try {
      const [sr, er] = await Promise.allSettled([
        apiFetch('/api/data-security/stats'),
        apiFetch('/api/data-security/engine-status'),
      ])
      if (sr.status !== 'fulfilled' || er.status !== 'fulfilled' || !sr.value.ok || !er.value.ok) {
        setLoadFailed(true)
        return
      }
      const sd: ApiResponse<DataSecurityStats> = await sr.value.json()
      const ed: ApiResponse<DataSecurityEngineStatus> = await er.value.json()
      if (sd.success && sd.data) { setStats(sd.data); setLoadFailed(false) }
      if (ed.success && ed.data) setEngineStatus(ed.data)
    } catch { setLoadFailed(true) }
  }, [])

  // Email reviews are the live operational feed on this page. Keep their
  // aggregate independent from the heavier HTTP/incident dashboard query so
  // the mail posture can refresh frequently without increasing the cost of
  // every other data-security metric.
  const loadEmailReviewStats = useCallback(async () => {
    try {
      const response = await apiFetch('/api/data-security/email-reviews/stats')
      if (!response.ok) return
      const body: ApiResponse<EmailDataSecurityStats> = await response.json()
      if (body.success && body.data) setEmailReviewStats(body.data)
    } catch {
      // The main dashboard remains usable if the optional email aggregate
      // request is temporarily unavailable; the next tick or WS event retries.
    }
  }, [])

  const dbRef = useRef<number | null>(null)
  const dbLoad = useCallback(() => {
    if (dbRef.current) return
    dbRef.current = window.setTimeout(() => {
      dbRef.current = null
      void loadStats()
      void loadEmailReviewStats()
    }, 3000)
  }, [loadEmailReviewStats, loadStats])

  useEffect(() => { const h = () => dbLoad(); window.addEventListener(EVENTS.DASHBOARD_REFRESH, h); return () => window.removeEventListener(EVENTS.DASHBOARD_REFRESH, h) }, [dbLoad])
  useEffect(() => {
    const h = () => {
      void loadStats()
      void loadEmailReviewStats()
    }
    window.addEventListener(EVENTS.WS_RECONNECTED, h)
    return () => window.removeEventListener(EVENTS.WS_RECONNECTED, h)
  }, [loadEmailReviewStats, loadStats])
  useEffect(() => {
    void loadStats()
    void loadEmailReviewStats()
    const statsTimer = window.setInterval(loadStats, 15000)
    const emailTimer = window.setInterval(loadEmailReviewStats, 5000)
    return () => {
      window.clearInterval(statsTimer)
      window.clearInterval(emailTimer)
    }
  }, [loadEmailReviewStats, loadStats])

  const tabs: [TabKey, string, JSX.Element, number?][] = [
    ['overview', t('dataSecurity.tabOverview'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>],
    ['outbound-emails', t('dataSecurity.tabOutboundEmails'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /><path d="M17 16h4" /></svg>, emailReviewStats?.dlp_hits],
    ['incidents', t('dataSecurity.tabIncidents'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>, stats?.total_incidents],
    ['http-sessions', t('dataSecurity.tabHttpSessions'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>],
    ['policy', t('dataSecurity.tabPolicy'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>],
    ['settings', t('dataSecurity.tabSettings'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" /></svg>],
  ]

  return (
    <div className="sec-content ds3-page">
      <div className="ds3-layout">
        <aside className="ds3-sidebar" aria-label={t('dataSecurity.tabOverview')}>
          <div className="ds3-sidebar-controls">
            <div className="ds3-tabs">
              {tabs.map(([k, l, ic, cnt]) => (
                <button key={k} className={`ds3-tab ${activeTab === k ? 'ds3-tab--active' : ''}`} onClick={() => setActiveTab(k)}>
                  <span className="ds3-tab-icon">{ic}</span>
                  <span className="ds3-tab-label">{l}</span>
                  {cnt != null && cnt > 0 && (
                    <span
                      className="ds3-tab-count"
                      title={k === 'outbound-emails' ? t('dataSecurity.outboundDlpHits') : undefined}
                    >
                      {cnt > 999 ? '999+' : cnt}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {!isPortal && <div
              className={`ds3-privacy-toggle ${privacyMode ? 'ds3-privacy-toggle--active' : ''}`}
              title={privacyMode ? t('dataSecurity.privacyOnHint') : t('dataSecurity.privacyOffHint')}
            >
              {privacyMode
                ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" /><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
                : <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>}
              <span style={{ fontSize: 12 }}>{privacyMode ? t('dataSecurity.privacyOn') : t('dataSecurity.privacyOff')}</span>
            </div>}
          </div>
        </aside>

        <div className="ds3-main">
          {activeTab === 'overview' && <OverviewTab stats={stats} engineStatus={engineStatus} emailReviewStats={emailReviewStats} onOpenOutbound={() => setActiveTab('outbound-emails')} loadFailed={loadFailed} />}
          {activeTab === 'outbound-emails' && <OutboundEmailReviewsTab privacyMode={effectivePrivacy} />}
          {activeTab === 'policy' && <PolicyTab />}
          {activeTab === 'incidents' && <IncidentsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/incidents/${id}` : `${basePath}/incidents`)} privacyMode={effectivePrivacy} />}
          {activeTab === 'http-sessions' && <HttpSessionsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/http-sessions/${id}` : `${basePath}/http-sessions`)} privacyMode={effectivePrivacy} privacyUnavailable={privacyLoading || privacyError} />}
          {activeTab === 'settings' && (isPortal ? <TimePolicyTab /> : <SettingsTab />)}
        </div>
      </div>
    </div>
  )
}
