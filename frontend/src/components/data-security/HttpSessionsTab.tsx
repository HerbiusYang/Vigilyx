import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { HttpSessionItem, ApiResponse, PaginatedResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import { usePrivacyAccess } from '../../hooks/usePrivacyAccess'
import { EVENTS } from '../../utils/events'
import { formatTimeWithSeconds, formatSize } from '../../utils/format'
import { METHOD_COLOR, getMaskedBody } from './constants'
import { maskIp, maskUser, maskUrl } from './helpers'
import { MethodBadge } from './badges'

export function HttpSessionsTab({ selectedId, onSelect, privacyMode, privacyUnavailable = false }: { selectedId?: string; onSelect: (id: string | null) => void; privacyMode: boolean; privacyUnavailable?: boolean }) {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<HttpSessionItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const expandedId = selectedId || null
  const privacyAccess = usePrivacyAccess(expandedId ? { resource_type: 'http_session', resource_id: expandedId } : null)
  const privacyHeaders = useMemo(() => privacyAccess.leaseHeaders('http_body'), [privacyAccess.leaseHeaders])
  const effectivePrivacyMode = privacyMode || privacyUnavailable || Boolean(privacyAccess.error)
  const canRevealBody = !privacyUnavailable && !privacyAccess.error && (!privacyMode || Boolean(privacyAccess.lease?.scopes.includes('http_body')))
  const authorizationKey = JSON.stringify([
    expandedId, privacyMode, privacyUnavailable, privacyAccess.error, privacyAccess.lease?.lease_handle,
    privacyAccess.lease?.expires_at, privacyAccess.lease?.scopes,
  ])
  const [detailSnapshot, setDetailSession] = useState<{ key: string; data: HttpSessionItem } | null>(null)
  const detailSession = detailSnapshot?.key === authorizationKey ? detailSnapshot.data : null
  const [detailLoading, setDetailLoading] = useState(false)
  const [searchText, setSearchText] = useState('')
  const [filterMethod, setFilterMethod] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const limit = 20

  const loadSessions = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit) })
      if (filterMethod) params.set('method', filterMethod)
      if (appliedSearch) {
        if (/^\d{1,3}\./.test(appliedSearch)) params.set('client_ip', appliedSearch)
        else if (appliedSearch.includes('@')) params.set('user', appliedSearch)
        else params.set('keyword', appliedSearch)
      }
      const r = await apiFetch(`/api/data-security/http-sessions?${params}`)
      if (!r.ok) return
      const d: ApiResponse<PaginatedResponse<HttpSessionItem>> = await r.json()
      if (d.success && d.data) { setSessions(d.data.items); setTotal(d.data.total) }
    } catch (e) { console.error('Failed to load HTTP sessions:', e) }
    finally { setLoading(false) }
  }, [page, filterMethod, appliedSearch])

  useEffect(() => { loadSessions() }, [loadSessions])
  useEffect(() => { const t = setInterval(() => { if (!document.hidden) loadSessions() }, 30000); return () => clearInterval(t) }, [loadSessions])
  useEffect(() => { const h = () => loadSessions(); window.addEventListener(EVENTS.WS_RECONNECTED, h); return () => window.removeEventListener(EVENTS.WS_RECONNECTED, h) }, [loadSessions])

  useEffect(() => {
    setDetailSession(null)
    setDetailLoading(false)
    if (!expandedId || privacyUnavailable) return
    const controller = new AbortController()
    setDetailLoading(true)
    apiFetch(`/api/data-security/http-sessions/${expandedId}`, { headers: privacyHeaders, signal: controller.signal })
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<HttpSessionItem> | null) => {
        if (!controller.signal.aborted && d?.success && d.data) setDetailSession({ key: authorizationKey, data: d.data })
      })
      .catch(() => { if (!controller.signal.aborted) setDetailSession(null) })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(false) })
    return () => controller.abort()
  }, [expandedId, authorizationKey])

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="ds3-http">
      {/* Filter bar */}
      <div className="ds3-filter-bar">
        <div className="ds3-filter-group">
          <span className="ds3-filter-label">{t('dataSecurity.method')}</span>
          {[{ v: '', l: t('dataSecurity.all') }, { v: 'POST', l: 'POST' }, { v: 'GET', l: 'GET' }, { v: 'PUT', l: 'PUT' }].map(f => (
            <button key={f.v}
              className={`ds3-filter-pill ${filterMethod === f.v ? 'ds3-filter-pill--active' : ''}`}
              style={f.v && filterMethod === f.v ? { borderColor: METHOD_COLOR[f.v], color: METHOD_COLOR[f.v], background: METHOD_COLOR[f.v] + '10' } : undefined}
              onClick={() => { setFilterMethod(f.v); setPage(1) }}>{f.l}</button>
          ))}
        </div>
        <form className="ds3-search-form" onSubmit={e => { e.preventDefault(); setAppliedSearch(searchText.trim()); setPage(1) }}>
          <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)}
            placeholder={t('dataSecurity.searchPlaceholder')} className="ds3-search-input" />
          <button type="submit" className="ds3-filter-pill">{t('dataSecurity.search')}</button>
          {(appliedSearch || filterMethod) && <button type="button" className="ds3-filter-pill" style={{ fontSize: 11 }} onClick={() => { setSearchText(''); setAppliedSearch(''); setFilterMethod(''); setPage(1) }}>{t('dataSecurity.clear')}</button>}
        </form>
        <span className="sec-mono" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-tertiary)' }}>{t('dataSecurity.totalCount', { count: total })}</span>
      </div>

      {/* Expanded details */}
      {expandedId && (() => {
        const listedSession = sessions.find(x => x.id === expandedId)
        // List snapshots are never a fallback source for a sensitive body.
        const s = detailSession || (listedSession ? { ...listedSession, request_body: null } : null)
        if (!s) return null
        return (
          <div className="ds3-http-detail">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{t('dataSecurity.httpSessionDetail')}</div>
              <button className="ds3-close-btn" onClick={() => onSelect(null)}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
              </button>
            </div>
            <div className="ds3-http-detail-grid">
              {[
                [t('dataSecurity.method'), <span style={{ color: METHOD_COLOR[s.method] || 'var(--text-primary)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{s.method}</span>],
                [t('dataSecurity.statusCode'), <span className="sec-mono">{s.response_status ?? '—'}</span>],
                [t('dataSecurity.client'), <span className="sec-mono">{effectivePrivacyMode ? maskIp(s.client_ip) + ':***' : s.client_ip + ':' + s.client_port}</span>],
                [t('dataSecurity.server'), <span className="sec-mono">{effectivePrivacyMode ? maskIp(s.server_ip) + ':***' : s.server_ip + ':' + s.server_port}</span>],
              ].map(([l, v], i) => <div key={i} className="ds3-http-field"><span className="ds3-http-field-label">{l as string}</span>{v}</div>)}
              <div className="ds3-http-field" style={{ gridColumn: 'span 2' }}><span className="ds3-http-field-label">Content-Type</span><span className="sec-mono" style={{ fontSize: 11 }}>{s.content_type || '—'}</span></div>
              <div className="ds3-http-field"><span className="ds3-http-field-label">{t('dataSecurity.bodySize')}</span><span className="sec-mono">{formatSize(s.request_body_size)}{s.body_is_binary ? ` (${t('dataSecurity.binary')})` : ''}</span></div>
              <div className="ds3-http-field"><span className="ds3-http-field-label">{t('dataSecurity.user')}</span><span className="sec-mono">{effectivePrivacyMode ? maskUser(s.detected_user || '') || '—' : s.detected_user || '—'}</span></div>
              <div className="ds3-http-field" style={{ gridColumn: '1 / -1' }}>
                <span className="ds3-http-field-label">URL</span>
                <span className="sec-mono" style={{ color: '#22d3ee', wordBreak: 'break-all', fontSize: 11 }}>{s.host && <span style={{ color: 'var(--text-tertiary)' }}>{s.host}</span>}{effectivePrivacyMode ? maskUrl(s.uri) : s.uri}</span>
              </div>
              {s.uploaded_filename && (
                <div className="ds3-http-field" style={{ gridColumn: '1 / -1' }}>
                  <span className="ds3-http-field-label">{t('dataSecurity.uploadedFile')}</span>
                  <span style={{ color: '#f97316' }} className="sec-mono">{effectivePrivacyMode ? '***' + (s.uploaded_filename.includes('.') ? '.' + s.uploaded_filename.split('.').pop() : '') : s.uploaded_filename}</span>
                  {s.file_type_mismatch && <span style={{ fontSize: 10, color: '#f97316', marginLeft: 8 }}>⚠ {s.file_type_mismatch}</span>}
                </div>
              )}
            </div>
            {detailLoading ? <div style={{ padding: 12, color: 'var(--text-tertiary)', fontSize: 12 }}>{t('dataSecurity.loading')}</div>
              : s.request_body ? <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 4 }}>{t('dataSecurity.requestBody')}</div>
                <pre className="ds3-code-block">{canRevealBody ? s.request_body : getMaskedBody()}</pre>
              </div> : null}
          </div>
        )
      })()}

      {/* Table */}
      <div className="ds3-table-wrap">
        <table className="ds3-table">
          <thead><tr>
            <th style={{ width: 120 }}>{t('dataSecurity.time')}</th>
            <th>{t('dataSecurity.clientIp')}</th>
            <th>{t('dataSecurity.user')}</th>
            <th style={{ width: 60 }}>{t('dataSecurity.method')}</th>
            <th>URL</th>
            <th style={{ width: 80 }}>Body</th>
            <th>{t('dataSecurity.uploadedFile')}</th>
          </tr></thead>
          <tbody>
            {loading ? <tr><td colSpan={7}><div className="sec-loading"><div className="sec-spinner" /></div></td></tr>
              : sessions.length === 0 ? <tr><td colSpan={7}><div className="ds3-empty-full" style={{ padding: '3rem' }}><p>{t('dataSecurity.noHttpSessions')}</p></div></td></tr>
                : sessions.map(s => (
                  <tr key={s.id} className={expandedId === s.id ? 'ds3-row--active' : ''} onClick={() => onSelect(expandedId === s.id ? null : s.id)}>
                    <td className="sec-mono" style={{ fontSize: 11 }}>{formatTimeWithSeconds(s.timestamp)}</td>
                    <td className="sec-mono" style={{ fontSize: 12 }}>{effectivePrivacyMode ? maskIp(s.client_ip) : s.client_ip}</td>
                    <td style={{ fontSize: 12 }}>{s.detected_user ? (effectivePrivacyMode ? maskUser(s.detected_user) : s.detected_user) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}</td>
                    <td><MethodBadge method={s.method} /></td>
                    <td className="sec-mono ds3-url-cell">{effectivePrivacyMode ? maskUrl(s.uri) : s.uri}</td>
                    <td className="sec-mono" style={{ fontSize: 12 }}>{s.request_body_size > 0 ? formatSize(s.request_body_size) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}</td>
                    <td style={{ fontSize: 12 }}>
                      {s.uploaded_filename ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ color: '#f97316', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{effectivePrivacyMode ? '***' + (s.uploaded_filename.includes('.') ? '.' + s.uploaded_filename.split('.').pop() : '') : s.uploaded_filename}</span>
                          {s.file_type_mismatch && <span style={{ fontSize: 9, padding: '1px 4px', borderRadius: 3, background: 'rgba(239,68,68,0.1)', color: '#ef4444', fontWeight: 600 }}>{t('dataSecurity.disguised')}</span>}
                        </span>
                      ) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="ds3-pagination">
          <button className="sec-page-btn" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>{t('dataSecurity.prevPage')}</button>
          <span className="sec-mono" style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>{t('dataSecurity.pageInfo', { page, totalPages })}</span>
          <button className="sec-page-btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>{t('dataSecurity.nextPage')}</button>
        </div>
      )}
    </div>
  )
}
