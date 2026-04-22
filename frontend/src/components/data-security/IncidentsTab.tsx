import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { DataSecurityIncident, ApiResponse, PaginatedResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import { formatTimeWithSeconds, formatRelativeTime } from '../../utils/format'
import {
  SEVERITY_COLOR, SEVERITY_CN,
  INCIDENT_TYPE_COLOR,
  DLP_MATCH_CN, DLP_JRT_LEVEL, JRT_LEVEL_COLOR,
} from './constants'
import { maskIp, maskUser } from './helpers'
import { SeverityBadge, IncidentTypeBadge } from './badges'
import { IncidentDetail } from './IncidentDetail'

export function IncidentsTab({ selectedId, onSelect, privacyMode }: { selectedId?: string; onSelect: (id: string | null) => void; privacyMode: boolean }) {
  const { t } = useTranslation()
  const [incidents, setIncidents] = useState<DataSecurityIncident[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [selectedIncident, setSelectedIncident] = useState<DataSecurityIncident | null>(null)
  const [filterType, setFilterType] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [searchText, setSearchText] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const limit = 20

  useEffect(() => {
    if (!selectedId) { setSelectedIncident(null); return }
    const local = incidents.find(i => i.id === selectedId)
    if (local) { setSelectedIncident(local); return }
    let c = false
    apiFetch(`/api/data-security/incidents/${selectedId}`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<DataSecurityIncident> | null) => { if (!c && d?.success && d.data) setSelectedIncident(d.data) })
      .catch(() => {})
    return () => { c = true }
  }, [selectedId, incidents])

  const loadIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit) })
      if (filterType) params.set('incident_type', filterType)
      if (filterSeverity) params.set('severity', filterSeverity)
      if (appliedSearch) {
        if (/^\d{1,3}\./.test(appliedSearch)) params.set('client_ip', appliedSearch)
        else if (appliedSearch.includes('@')) params.set('user', appliedSearch)
        else params.set('keyword', appliedSearch)
      }
      const r = await apiFetch(`/api/data-security/incidents?${params}`)
      if (!r.ok) return
      const d: ApiResponse<PaginatedResponse<DataSecurityIncident>> = await r.json()
      if (d.success && d.data) { setIncidents(d.data.items); setTotal(d.data.total) }
    } catch (e) { console.error('Failed to load incidents:', e) }
    finally { setLoading(false) }
  }, [page, filterType, filterSeverity, appliedSearch])

  useEffect(() => { loadIncidents() }, [loadIncidents])
  useEffect(() => { const t = setInterval(() => { if (!document.hidden) loadIncidents() }, 30000); return () => clearInterval(t) }, [loadIncidents])
  useEffect(() => { const h = () => loadIncidents(); window.addEventListener(EVENTS.WS_RECONNECTED, h); return () => window.removeEventListener(EVENTS.WS_RECONNECTED, h) }, [loadIncidents])

  const tp = Math.ceil(total / limit)

  // Severity distribution of current page
  const sevStats = useMemo(() => {
    const m: Record<string, number> = {}
    incidents.forEach(inc => { m[inc.severity] = (m[inc.severity] || 0) + 1 })
    return m
  }, [incidents])

  const hasActiveFilters = filterType || filterSeverity || appliedSearch

  // Page numbers generation
  const pageNums = useMemo(() => {
    if (tp <= 7) return Array.from({ length: tp }, (_, i) => i + 1)
    const pages: (number | null)[] = [1]
    const start = Math.max(2, page - 1)
    const end = Math.min(tp - 1, page + 1)
    if (start > 2) pages.push(null) // ellipsis
    for (let i = start; i <= end; i++) pages.push(i)
    if (end < tp - 1) pages.push(null) // ellipsis
    pages.push(tp)
    return pages
  }, [page, tp])

  return (
    <div className="ds3-incidents ds3-incidents--v2">
      {/* Enhanced filter bar */}
      <div className="ds3-filter-bar ds3-filter-bar--v2">
        <div className="ds3-filters-left">
          <div className="ds3-filter-group">
            <span className="ds3-filter-label">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
              {t('dataSecurity.type')}
            </span>
            {[{ v: '', l: t('dataSecurity.all') }, { v: 'draft_box_abuse', l: t('dataSecurity.incidentType_draft_box_abuse') }, { v: 'file_transit_abuse', l: t('dataSecurity.incidentType_file_transit_abuse') }, { v: 'self_sending', l: t('dataSecurity.incidentType_self_sending') }, { v: 'jrt_compliance_violation', l: t('dataSecurity.incidentType_jrt_compliance_violation') }].map(f => (
              <button key={f.v}
                className={`ds3-filter-pill ${filterType === f.v ? 'ds3-filter-pill--active' : ''}`}
                style={f.v && filterType === f.v ? { borderColor: INCIDENT_TYPE_COLOR[f.v], color: INCIDENT_TYPE_COLOR[f.v], background: INCIDENT_TYPE_COLOR[f.v] + '10' } : undefined}
                onClick={() => { setFilterType(f.v); setPage(1) }}>{f.l}</button>
            ))}
          </div>
          <div className="ds3-filter-sep" />
          <div className="ds3-filter-group">
            <span className="ds3-filter-label">{t('dataSecurity.level')}</span>
            {[{ v: '', l: t('dataSecurity.all') }, { v: 'critical', l: t('dataSecurity.severity_critical') }, { v: 'high', l: t('dataSecurity.severity_high') }, { v: 'medium', l: t('dataSecurity.severity_medium') }, { v: 'low', l: t('dataSecurity.severity_low') }].map(f => (
              <button key={f.v}
                className={`ds3-filter-pill ${filterSeverity === f.v ? 'ds3-filter-pill--active' : ''}`}
                style={f.v && filterSeverity === f.v ? { borderColor: SEVERITY_COLOR[f.v], color: SEVERITY_COLOR[f.v], background: SEVERITY_COLOR[f.v] + '10' } : undefined}
                onClick={() => { setFilterSeverity(f.v); setPage(1) }}>{f.l}</button>
            ))}
          </div>
        </div>
        <div className="ds3-filters-right">
          <form className="ds3-search-inline" onSubmit={e => { e.preventDefault(); setAppliedSearch(searchText.trim()); setPage(1) }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)} placeholder={t('dataSecurity.searchPlaceholder')} />
            {appliedSearch && (
              <button type="button" className="ds3-search-clear" onClick={() => { setSearchText(''); setAppliedSearch(''); setPage(1) }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            )}
          </form>
        </div>
      </div>

      {/* Severity distribution ribbon + total count */}
      <div className="ds3-ribbon">
        <div className="ds3-ribbon-stats">
          {incidents.length > 0 && ['critical', 'high', 'medium', 'low', 'info'].map(sev => {
            const cnt = sevStats[sev] || 0
            if (cnt === 0) return null
            const c = SEVERITY_COLOR[sev]
            return (
              <span key={sev} className="ds3-ribbon-chip" style={{ color: c, background: c + '10', borderColor: c + '20' }}>
                <span className="ds3-ribbon-dot" style={{ background: c }} />
                {SEVERITY_CN[sev]} <b className="sec-mono">{cnt}</b>
              </span>
            )
          })}
          {hasActiveFilters && (
            <button className="ds3-ribbon-clear" onClick={() => { setFilterType(''); setFilterSeverity(''); setSearchText(''); setAppliedSearch(''); setPage(1) }}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              {t('dataSecurity.clearFilters')}
            </button>
          )}
        </div>
        <span className="ds3-ribbon-total sec-mono">
          {t('dataSecurity.totalItems', { total: total.toLocaleString() })}{tp > 1 && <> · {t('dataSecurity.pageOf', { page, totalPages: tp })}</>}
        </span>
      </div>

      {/* Master-Detail */}
      <div className="ds3-split ds3-split--v2">
        <div className="ds3-master">
          {loading ? <div className="sec-loading"><div className="sec-spinner" /></div>
            : incidents.length === 0 ? (
              <div className="ds3-empty-full ds3-empty-full--v2">
                <div className="ds3-empty-icon-wrap">
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M9 12l2 2 4-4" opacity="0.4" />
                  </svg>
                </div>
                <p className="ds3-empty-title">{t('dataSecurity.noIncidents')}</p>
                <p className="ds3-empty-sub">{hasActiveFilters ? t('dataSecurity.tryAdjustFilters') : t('dataSecurity.systemNormal')}</p>
              </div>
            ) : (
              <div className="ds3-card-list ds3-card-list--v2">
                {incidents.map(inc => {
                  const sel = selectedIncident?.id === inc.id
                  const sevC = SEVERITY_COLOR[inc.severity] || SEVERITY_COLOR.info
                  const confPct = Math.round(inc.confidence * 100)
                  return (
                    <div key={inc.id}
                      className={`ds3-card3 ${sel ? 'ds3-card3--sel' : ''}`}
                      onClick={() => onSelect(sel ? null : inc.id)}>
                      <div className="ds3-card3-stripe" style={{ background: sevC }} />
                      <div className="ds3-card3-body">
                        {/* Row 1: badges + conf + time */}
                        <div className="ds3-card3-head">
                          <SeverityBadge severity={inc.severity} />
                          <IncidentTypeBadge type={inc.incident_type} />
                          <span className="ds3-card3-conf sec-mono" style={{ color: sevC }}>{confPct}%</span>
                          <span className="ds3-card3-time sec-mono" title={formatTimeWithSeconds(inc.created_at)}>{formatRelativeTime(inc.created_at)}</span>
                        </div>
                        {/* Row 2: summary */}
                        <div className="ds3-card3-sum">{inc.summary}</div>
                        {/* Row 3: meta chips inline */}
                        <div className="ds3-card3-foot">
                          {inc.detected_user && (
                            <span className="ds3-card3-chip ds3-card3-chip--user">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                              {privacyMode ? maskUser(inc.detected_user) : inc.detected_user}
                            </span>
                          )}
                          <span className="ds3-card3-chip ds3-card3-chip--ip sec-mono">{privacyMode ? maskIp(inc.client_ip) : inc.client_ip}</span>
                          {inc.dlp_matches.length > 0 && inc.dlp_matches.slice(0, 2).map((m, i) => {
                            const jl = DLP_JRT_LEVEL[m], jc = jl ? JRT_LEVEL_COLOR[jl] : '#ef4444'
                            return <span key={i} className="ds3-card3-chip ds3-card3-chip--dlp" style={{ color: jc, borderColor: jc + '30', background: jc + '08' }}>{DLP_MATCH_CN[m] || m}</span>
                          })}
                          {inc.dlp_matches.length > 2 && <span className="ds3-card3-chip ds3-card3-chip--more">+{inc.dlp_matches.length - 2}</span>}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

        </div>

        <div className="ds3-detail-pane">
          {selectedIncident ? (
            <IncidentDetail incident={selectedIncident} onClose={() => onSelect(null)} privacyMode={privacyMode} />
          ) : (
            <div className="ds3-detail-empty ds3-detail-empty--v2">
              <div className="ds3-empty-shield">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <div className="ds3-empty-shield-pulse" />
              </div>
              <p className="ds3-empty-t">{t('dataSecurity.selectIncident')}</p>
              <p className="ds3-empty-h">{t('dataSecurity.clickIncidentHint')}</p>
            </div>
          )}
        </div>
      </div>

      {/* Pagination — outside ds3-split so it centers across full width */}
      {tp > 1 && (
        <div className="ds3-pagination ds3-pagination--v2">
          <button className="ds3-pg-btn" disabled={page <= 1} onClick={() => setPage(1)} title={t('dataSecurity.firstPage')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>
          </button>
          <button className="ds3-pg-btn" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))} title={t('dataSecurity.prevPage')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="15 18 9 12 15 6"/></svg>
          </button>
          <div className="ds3-pg-nums">
            {pageNums.map((pn, i) => pn === null
              ? <span key={`e${i}`} className="ds3-pg-ellipsis">...</span>
              : <button key={pn} className={`ds3-pg-num ${page === pn ? 'ds3-pg-num--active' : ''}`} onClick={() => setPage(pn)}>{pn}</button>
            )}
          </div>
          <button className="ds3-pg-btn" disabled={page >= tp} onClick={() => setPage(p => p + 1)} title={t('dataSecurity.nextPage')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          </button>
          <button className="ds3-pg-btn" disabled={page >= tp} onClick={() => setPage(tp)} title={t('dataSecurity.lastPage')}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/></svg>
          </button>
        </div>
      )}
    </div>
  )
}
