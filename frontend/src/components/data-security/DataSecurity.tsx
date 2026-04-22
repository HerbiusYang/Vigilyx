import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { DataSecurityStats, DataSecurityEngineStatus, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import type { TabKey } from './types'
import { PRIVACY_KEY } from './constants'
import { OverviewTab } from './OverviewTab'
import { PolicyTab } from './PolicyTab'
import { IncidentsTab } from './IncidentsTab'
import { HttpSessionsTab } from './HttpSessionsTab'
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
    if (s.startsWith('incidents/')) return { activeTab: 'incidents' as TabKey, selectedId: s.replace('incidents/', '') }
    if (s === 'incidents') return { activeTab: 'incidents' as TabKey, selectedId: undefined }
    if (s.startsWith('http-sessions/')) return { activeTab: 'http-sessions' as TabKey, selectedId: s.replace('http-sessions/', '') }
    if (s === 'http-sessions') return { activeTab: 'http-sessions' as TabKey, selectedId: undefined }
    if (s === 'settings' || s === 'time-policy') return { activeTab: 'settings' as TabKey, selectedId: undefined }
    return { activeTab: 'overview' as TabKey, selectedId: undefined }
  }, [location.pathname, basePath])

  const isPortal = basePath === '/portal'

  const setActiveTab = useCallback((tab: TabKey) => {
    const settingsPath = isPortal ? `${basePath}/time-policy` : `${basePath}/settings`
    const routes: Record<TabKey, string> = { overview: basePath, policy: `${basePath}/policy`, incidents: `${basePath}/incidents`, 'http-sessions': `${basePath}/http-sessions`, settings: settingsPath }
    navigate(routes[tab])
  }, [navigate, basePath, isPortal])

  const [privacyMode, setPrivacyMode] = useState(() => localStorage.getItem(PRIVACY_KEY) !== 'false')
  const togglePrivacy = useCallback(() => {
    setPrivacyMode(prev => { const next = !prev; localStorage.setItem(PRIVACY_KEY, String(next)); return next })
  }, [])
  // Portal mode enforces privacy protection regardless of localStorage
  const effectivePrivacy = isPortal ? true : privacyMode

  const [stats, setStats] = useState<DataSecurityStats | null>(null)
  const [engineStatus, setEngineStatus] = useState<DataSecurityEngineStatus | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)

  const loadStats = useCallback(async () => {
    try {
      const [sr, er] = await Promise.all([apiFetch('/api/data-security/stats'), apiFetch('/api/data-security/engine-status')])
      if (!sr.ok || !er.ok) { setLoadFailed(true); return }
      const sd: ApiResponse<DataSecurityStats> = await sr.json()
      const ed: ApiResponse<DataSecurityEngineStatus> = await er.json()
      if (sd.success && sd.data) { setStats(sd.data); setLoadFailed(false) }
      if (ed.success && ed.data) setEngineStatus(ed.data)
    } catch { setLoadFailed(true) }
  }, [])

  const dbRef = useRef<number | null>(null)
  const dbLoad = useCallback(() => {
    if (dbRef.current) return
    dbRef.current = window.setTimeout(() => { dbRef.current = null; loadStats() }, 3000)
  }, [loadStats])

  useEffect(() => { const h = () => dbLoad(); window.addEventListener(EVENTS.DASHBOARD_REFRESH, h); return () => window.removeEventListener(EVENTS.DASHBOARD_REFRESH, h) }, [dbLoad])
  useEffect(() => { const h = () => loadStats(); window.addEventListener(EVENTS.WS_RECONNECTED, h); return () => window.removeEventListener(EVENTS.WS_RECONNECTED, h) }, [loadStats])
  useEffect(() => { loadStats(); const t = setInterval(loadStats, 15000); return () => clearInterval(t) }, [loadStats])

  const tabs: [TabKey, string, JSX.Element, number?][] = [
    ['overview', t('dataSecurity.tabOverview'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>],
    ['incidents', t('dataSecurity.tabIncidents'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>, stats?.total_incidents],
    ['http-sessions', t('dataSecurity.tabHttpSessions'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>],
    ['policy', t('dataSecurity.tabPolicy'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>],
    ['settings', t('dataSecurity.tabSettings'), <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" /></svg>],
  ]

  return (
    <div className="sec-content ds3-page">
      <div className="ds3-tabs">
        {tabs.map(([k, l, ic, cnt]) => (
          <button key={k} className={`ds3-tab ${activeTab === k ? 'ds3-tab--active' : ''}`} onClick={() => setActiveTab(k)}>
            <span className="ds3-tab-icon">{ic}</span>
            {l}
            {cnt != null && cnt > 0 && <span className="ds3-tab-count">{cnt > 999 ? '999+' : cnt}</span>}
          </button>
        ))}

        {!isPortal && <button
          className={`ds3-privacy-toggle ${privacyMode ? 'ds3-privacy-toggle--active' : ''}`}
          onClick={togglePrivacy}
          title={privacyMode ? t('dataSecurity.privacyOnHint') : t('dataSecurity.privacyOffHint')}
        >
          {privacyMode
            ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" /><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
            : <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>}
          <span style={{ fontSize: 12 }}>{privacyMode ? t('dataSecurity.privacyOn') : t('dataSecurity.privacyOff')}</span>
        </button>}
      </div>
      {activeTab === 'overview' && <OverviewTab stats={stats} engineStatus={engineStatus} loadFailed={loadFailed} />}
      {activeTab === 'policy' && <PolicyTab />}
      {activeTab === 'incidents' && <IncidentsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/incidents/${id}` : `${basePath}/incidents`)} privacyMode={effectivePrivacy} />}
      {activeTab === 'http-sessions' && <HttpSessionsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/http-sessions/${id}` : `${basePath}/http-sessions`)} privacyMode={effectivePrivacy} />}
      {activeTab === 'settings' && (isPortal ? <TimePolicyTab /> : <SettingsTab />)}
    </div>
  )
}
