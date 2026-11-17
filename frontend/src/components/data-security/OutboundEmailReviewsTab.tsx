import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import type {
  ApiResponse,
  EmailDataSecurityReview,
  EmailDataSecurityStats,
  EmailAuditClass,
  EmailDlpResult,
  EmailInspectionStatus,
  EmailReviewAction,
  EmailReviewSource,
  PaginatedResponse,
} from '../../types'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'

type FilterState = {
  source: '' | EmailReviewSource
  direction: '' | 'outbound' | 'unknown'
  audit_class: '' | EmailAuditClass
  inspection_status: '' | EmailInspectionStatus
  dlp_result: '' | EmailDlpResult
  action: '' | EmailReviewAction
}

const EMPTY_FILTERS: FilterState = {
  source: '',
  direction: '',
  audit_class: '',
  inspection_status: '',
  dlp_result: '',
  action: '',
}

// Keep the review queue scannable and ensure pagination is available for
// operationally useful result sets instead of waiting for 26+ records.
const PAGE_SIZE = 10

const sourceOptions: Array<['' | EmailReviewSource, string]> = [
  ['', 'sourceAll'],
  ['sniffer', 'sourceMirror'],
  ['mta_proxy', 'sourceMta'],
  ['import', 'sourceImport'],
]

const inspectionOptions: Array<['' | EmailInspectionStatus, string]> = [
  ['', 'statusAll'],
  ['inspected', 'statusInspected'],
  ['encrypted', 'statusEncrypted'],
  ['incomplete', 'statusIncomplete'],
  ['failed', 'statusFailed'],
]

const directionOptions: Array<['' | 'outbound' | 'unknown', string]> = [
  ['', 'directionAll'],
  ['outbound', 'directionOutbound'],
  ['unknown', 'directionUnknown'],
]

const auditClassOptions: Array<['' | EmailAuditClass, string]> = [
  ['', 'auditClassAll'],
  ['confirmed_outbound', 'auditClassConfirmed'],
  ['outbound_candidate', 'auditClassCandidate'],
  ['attribution_pending', 'auditClassPending'],
  ['legacy', 'auditClassLegacy'],
]

const dlpOptions: Array<['' | EmailDlpResult, string]> = [
  ['', 'resultAll'],
  ['hit', 'resultHit'],
  ['clean', 'resultClean'],
  ['unknown', 'resultUnknown'],
]

const actionOptions: Array<['' | EmailReviewAction, string]> = [
  ['', 'actionAll'],
  ['audit', 'actionAudit'],
  ['allow', 'actionAllow'],
  ['alert', 'actionAlert'],
  ['quarantine', 'actionQuarantine'],
  ['block', 'actionBlock'],
  ['reject', 'actionReject'],
  ['tempfail', 'actionTempfail'],
]

type FilterFieldProps<T extends string> = {
  label: string
  value: T
  active: boolean
  options: ReadonlyArray<readonly [T, string]>
  onChange: (value: T) => void
}

function FilterField<T extends string>({ label, value, active, options, onChange }: FilterFieldProps<T>) {
  return (
    <label className={`ds3-filter-field${active ? ' ds3-filter-field--active' : ''}`}>
      <span className="ds3-filter-field-label">{label}</span>
      <select className="ds3-filter-field-select" value={value} onChange={event => onChange(event.target.value as T)}>
        {options.map(([optionValue, optionLabel]) => <option key={optionValue || 'all'} value={optionValue}>{optionLabel}</option>)}
      </select>
    </label>
  )
}

function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function maskIp(value: string, privacyMode: boolean) {
  if (!privacyMode) return value
  const parts = value.split('.')
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.•••.•••` : '••••••'
}

function maskMailbox(value: string | null | undefined, privacyMode: boolean) {
  if (!value) return '—'
  if (!privacyMode) return value
  const at = value.lastIndexOf('@')
  if (at <= 0) return '••••••'
  return `${value.slice(0, 1)}****@${value.slice(at + 1)}`
}

const REDACTED_SUBJECT_VALUE = '[REDACTED]'

type LoadOptions = {
  background?: boolean
}

function isRedactedSubject(value: string | null | undefined) {
  return value?.trim().toLowerCase() === REDACTED_SUBJECT_VALUE.toLowerCase()
}

function SubjectSummary({
  value,
  privacyMode,
  t,
}: {
  value: string | null | undefined
  privacyMode: boolean
  t: (key: string) => string
}) {
  const redacted = isRedactedSubject(value)
  const privacyHidden = privacyMode && Boolean(value) && !redacted

  if (!redacted && !privacyHidden) {
    return <div className="ds3-detail-summary ds3-detail-summary--subject">
      <span className="ds3-detail-summary-label">{t('dataSecurity.outboundSubject')}</span>
      <span className="ds3-detail-summary-value">{value?.trim() || t('dataSecurity.outboundNoSubject')}</span>
    </div>
  }

  return <div className="ds3-redacted-field" role="status">
    <div className="ds3-redacted-field-icon" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="10" width="16" height="10" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        <path d="M12 14v2" />
      </svg>
    </div>
    <div className="ds3-redacted-field-body">
      <div className="ds3-redacted-field-head">
        <span className="ds3-redacted-field-label">{t('dataSecurity.outboundSubject')}</span>
        <span className="ds3-redacted-field-badge">{t(redacted ? 'dataSecurity.outboundSubjectRedacted' : 'dataSecurity.outboundSubjectPrivacy')}</span>
      </div>
      <strong className="ds3-redacted-field-value">{t('dataSecurity.outboundSubjectHidden')}</strong>
      <p className="ds3-redacted-field-hint">{t(redacted ? 'dataSecurity.outboundSubjectRedactedHint' : 'dataSecurity.outboundSubjectPrivacyHint')}</p>
    </div>
  </div>
}

function badgeClass(value: string) {
  return `ds3-outbound-badge ds3-outbound-badge--${value}`
}

function sourceLabel(t: (key: string) => string, source: EmailReviewSource) {
  return t(`dataSecurity.${source === 'sniffer' ? 'sourceMirror' : source === 'mta_proxy' ? 'sourceMta' : 'sourceImport'}`)
}

function auditClassLabel(t: (key: string) => string, value: EmailAuditClass) {
  return t(`dataSecurity.${value === 'confirmed_outbound' ? 'auditClassConfirmed' : value === 'outbound_candidate' ? 'auditClassCandidate' : value === 'attribution_pending' ? 'auditClassPending' : 'auditClassLegacy'}`)
}

function inspectionReasonLabel(t: (key: string) => string, code: string) {
  const suffix = code.split('_').map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('')
  const key = `dataSecurity.inspectionReason${suffix}`
  const translated = t(key)
  return translated === key ? code : translated
}

function inspectionReasonCodes(value: string | null | undefined, fallback: string) {
  const codes = (value ?? '')
    .split(/[;,]/)
    .map(part => part.trim())
    .filter(part => part && !part.startsWith('prior:'))
    .map(part => part.startsWith('inspection:') ? part.slice('inspection:'.length) : part)
    .map(part => part.split(':')[0].replace(/[^a-zA-Z0-9_]/g, ''))
    .filter(Boolean)
  return [...new Set(codes.length > 0 ? codes : [fallback])]
}

function dlpEvidenceCount(review: EmailDataSecurityReview, match: string) {
  const detail = review.dlp_details?.[match]
  if (Array.isArray(detail)) return detail.length
  if (detail && Number.isInteger(detail.count) && (detail.count ?? 0) >= 0) return detail.count
  return undefined
}

function dlpEvidenceLabel(t: (key: string) => string, match: string) {
  const key = `dataSecurity.dlpMatch_${match}`
  const translated = t(key)
  return translated === key ? match : translated
}

export function OutboundEmailReviewsTab({ privacyMode }: { privacyMode: boolean }) {
  const { t } = useTranslation()
  const [stats, setStats] = useState<EmailDataSecurityStats | null>(null)
  const [items, setItems] = useState<EmailDataSecurityReview[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(0)
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS)
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<EmailDataSecurityReview | null>(null)
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [loadFailed, setLoadFailed] = useState(false)
  const requestInFlightRef = useRef(false)

  const loadReviews = useCallback(async ({ background = false }: LoadOptions = {}) => {
    // WebSocket events and the fallback timer can arrive together. Avoid
    // overlapping list/stat requests and let the next event/tick retry.
    if (requestInFlightRef.current) return
    requestInFlightRef.current = true
    if (!background) setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) })
      for (const [key, value] of Object.entries(filters)) {
        if (value) params.set(key, value)
      }
      if (keyword) params.set('keyword', keyword)

      const [statsResponse, listResponse] = await Promise.all([
        apiFetch('/api/data-security/email-reviews/stats'),
        apiFetch(`/api/data-security/email-reviews?${params.toString()}`),
      ])
      const statsBody: ApiResponse<EmailDataSecurityStats> = await statsResponse.json()
      const listBody: ApiResponse<PaginatedResponse<EmailDataSecurityReview>> = await listResponse.json()
      if (!statsBody.success || !listBody.success || !listBody.data) throw new Error('load failed')
      setStats(statsBody.data)
      setItems(listBody.data.items)
      setTotal(listBody.data.total)
      setTotalPages(listBody.data.total_pages)
      setLoadFailed(false)
    } catch {
      setLoadFailed(true)
    } finally {
      requestInFlightRef.current = false
      if (!background) setLoading(false)
    }
  }, [filters, keyword, page])

  useEffect(() => { void loadReviews() }, [loadReviews])

  useEffect(() => {
    const refreshInBackground = () => { void loadReviews({ background: true }) }
    window.addEventListener(EVENTS.DASHBOARD_REFRESH, refreshInBackground)
    window.addEventListener(EVENTS.WS_RECONNECTED, refreshInBackground)
    // Clean Webmail sends do not necessarily emit a threat/incident event;
    // this bounded fallback keeps the list live even when the socket is quiet.
    const timer = window.setInterval(refreshInBackground, 5000)
    return () => {
      window.removeEventListener(EVENTS.DASHBOARD_REFRESH, refreshInBackground)
      window.removeEventListener(EVENTS.WS_RECONNECTED, refreshInBackground)
      window.clearInterval(timer)
    }
  }, [loadReviews])

  useEffect(() => {
    if (!selectedId) {
      setDetail(null)
      return
    }
    let cancelled = false
    setDetailLoading(true)
    apiFetch(`/api/data-security/email-reviews/${selectedId}`)
      .then(response => response.json() as Promise<ApiResponse<EmailDataSecurityReview>>)
      .then(body => { if (!cancelled && body.success && body.data) setDetail(body.data) })
      .catch(() => { if (!cancelled) setDetail(null) })
      .finally(() => { if (!cancelled) setDetailLoading(false) })
    return () => { cancelled = true }
  }, [selectedId])

  useEffect(() => {
    if (!selectedId) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSelectedId(null)
    }
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.body.style.overflow = previousOverflow
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [selectedId])

  const coverage = useMemo(() => {
    if (!stats || stats.total === 0) return 0
    return Math.round((stats.inspected / stats.total) * 100)
  }, [stats])

  const setFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters(previous => ({ ...previous, [key]: value }))
    setPage(1)
  }

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setKeyword(keywordInput.trim())
    setPage(1)
  }

  const clearFilters = () => {
    setFilters(EMPTY_FILTERS)
    setKeywordInput('')
    setKeyword('')
    setPage(1)
  }

  const openDetail = (id: string) => {
    setDetail(null)
    setSelectedId(id)
  }

  const enforcementCount = (stats?.quarantined ?? 0) + (stats?.blocked ?? 0) + (stats?.rejected ?? 0)

  return (
    <div className="ds3-outbound">
      <div className="ds3-outbound-heading">
        <div>
          <h2>{t('dataSecurity.outboundTitle')}</h2>
          <p>{t('dataSecurity.outboundSubtitle')}</p>
        </div>
        <span className="ds3-outbound-scope">{t('dataSecurity.outboundScope')}</span>
      </div>

      <div className="ds3-outbound-stats">
        <div className="ds3-outbound-stat"><span>{t('dataSecurity.outboundTotal')}</span><strong>{stats?.total.toLocaleString() ?? '—'}</strong><small>{t('dataSecurity.outboundTotalHint')}</small></div>
        <div className="ds3-outbound-stat ds3-outbound-stat--cyan"><span>{t('dataSecurity.outboundInspected')}</span><strong>{stats?.inspected.toLocaleString() ?? '—'}</strong><small>{t('dataSecurity.outboundCoverage', { pct: coverage })}</small></div>
        <div className="ds3-outbound-stat ds3-outbound-stat--red"><span>{t('dataSecurity.outboundDlpHits')}</span><strong>{stats?.dlp_hits.toLocaleString() ?? '—'}</strong><small>{t('dataSecurity.outboundDlpHitsHint')}</small></div>
        <div className="ds3-outbound-stat ds3-outbound-stat--orange"><span>{t('dataSecurity.outboundEnforcement')}</span><strong>{enforcementCount.toLocaleString()}</strong><small>{t('dataSecurity.outboundEnforcementHint', { quarantine: stats?.quarantined ?? 0, block: (stats?.blocked ?? 0) + (stats?.rejected ?? 0) })}</small></div>
      </div>
      <div className="ds3-outbound-class-breakdown" aria-label={t('dataSecurity.auditClassBreakdown')}>
        <span className="ds3-outbound-class-breakdown__label">{t('dataSecurity.auditClassBreakdown')}</span>
        <span className="ds3-outbound-class-chip ds3-outbound-class-chip--confirmed">{t('dataSecurity.auditClassConfirmed')} <b>{stats?.confirmed_outbound ?? 0}</b></span>
        <span className="ds3-outbound-class-chip ds3-outbound-class-chip--candidate">{t('dataSecurity.auditClassCandidate')} <b>{stats?.outbound_candidates ?? 0}</b></span>
        <span className="ds3-outbound-class-chip ds3-outbound-class-chip--pending">{t('dataSecurity.auditClassPending')} <b>{stats?.attribution_pending ?? 0}</b></span>
        <span className="ds3-outbound-class-chip ds3-outbound-class-chip--coverage">{t('dataSecurity.auditClassIncomplete')} <b>{stats?.incomplete_sessions ?? 0}</b></span>
      </div>

      <div className="ds3-filter-bar ds3-filter-bar--v2 ds3-outbound-filters">
        <div className="ds3-filters-left">
          <FilterField
            label={t('dataSecurity.outboundSource')}
            value={filters.source}
            active={filters.source !== ''}
            options={sourceOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('source', value)}
          />
          <FilterField
            label={t('dataSecurity.outboundDirection')}
            value={filters.direction}
            active={filters.direction !== ''}
            options={directionOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('direction', value)}
          />
          <FilterField
            label={t('dataSecurity.outboundAuditClass')}
            value={filters.audit_class}
            active={filters.audit_class !== ''}
            options={auditClassOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('audit_class', value)}
          />
          <FilterField
            label={t('dataSecurity.outboundInspection')}
            value={filters.inspection_status}
            active={filters.inspection_status !== ''}
            options={inspectionOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('inspection_status', value)}
          />
          <FilterField
            label="DLP"
            value={filters.dlp_result}
            active={filters.dlp_result !== ''}
            options={dlpOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('dlp_result', value)}
          />
          <FilterField
            label={t('dataSecurity.outboundAction')}
            value={filters.action}
            active={filters.action !== ''}
            options={actionOptions.map(([value, label]) => [value, t(`dataSecurity.${label}`)] as const)}
            onChange={value => setFilter('action', value)}
          />
        </div>
        <div className="ds3-filters-right">
          <form className="ds3-search-inline" onSubmit={submitSearch}>
            <svg className="ds3-search-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>
            <input value={keywordInput} onChange={event => setKeywordInput(event.target.value)} placeholder={t('dataSecurity.outboundSearchPlaceholder')} />
            {keywordInput && <button type="button" className="ds3-search-clear" onClick={() => { setKeywordInput(''); setKeyword(''); setPage(1) }}>×</button>}
            <button type="submit" className="ds3-outbound-search">{t('dataSecurity.search')}</button>
          </form>
          {(keyword || Object.values(filters).some(Boolean)) && <button type="button" className="ds3-ribbon-clear" onClick={clearFilters}>{t('dataSecurity.clearFilters')}</button>}
        </div>
      </div>

      {loadFailed && <div className="ds3-settings-msg ds3-settings-msg--err">{t('dataSecurity.failedToLoad')}</div>}

      <div className="ds3-outbound-body">
        <div className="ds3-outbound-list">
          <div className="ds3-outbound-list-head"><span>{t('dataSecurity.outboundRecords')}</span><b>{t('dataSecurity.totalItems', { total })}</b></div>
          {loading ? <div className="ds3-empty-full"><p>{t('dataSecurity.loading')}</p></div> : items.length === 0 ? (
            <div className="ds3-empty-full"><svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /><path d="M8 18h8" /></svg><p>{t('dataSecurity.outboundNoRecords')}</p></div>
          ) : (
            <div className="ds3-table-wrap ds3-outbound-table-wrap">
              <table className="ds3-table ds3-outbound-table">
                <thead><tr><th>{t('dataSecurity.time')}</th><th>{t('dataSecurity.outboundSource')}</th><th>{t('dataSecurity.outboundSender')}</th><th>{t('dataSecurity.outboundRecipients')}</th><th>{t('dataSecurity.outboundAuditClass')}</th><th>{t('dataSecurity.outboundInspection')}</th><th>DLP</th><th>{t('dataSecurity.outboundAction')}</th></tr></thead>
                <tbody>{items.map(item => (
                  <tr
                    key={item.id}
                    className={selectedId === item.id ? 'ds3-row--active' : ''}
                    onClick={() => openDetail(item.id)}
                    onKeyDown={event => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        openDetail(item.id)
                      }
                    }}
                    tabIndex={0}
                  >
                    <td className="ds3-inc-time">{formatTime(item.created_at)}</td>
                    <td><span className="ds3-outbound-source">{sourceLabel(t, item.source)}</span></td>
                    <td><div className="ds3-outbound-mailbox">{maskMailbox(item.mail_from, privacyMode)}<small>{maskIp(item.client_ip, privacyMode)}</small></div></td>
                    <td><div className="ds3-outbound-recipient">{privacyMode ? t('dataSecurity.outboundDomainCount', { count: item.external_recipient_domains.length }) : item.external_recipient_domains.join(', ') || '—'}<small>{t('dataSecurity.outboundRecipientCount', { count: item.recipient_count })}</small></div></td>
                    <td><span className={badgeClass(item.audit_class)}>{auditClassLabel(t, item.audit_class)}</span></td>
                    <td><span className={badgeClass(item.inspection_status)}>{t(`dataSecurity.status${item.inspection_status.charAt(0).toUpperCase()}${item.inspection_status.slice(1)}`)}</span></td>
                    <td><span className={badgeClass(item.dlp_result)}>{t(`dataSecurity.result${item.dlp_result.charAt(0).toUpperCase()}${item.dlp_result.slice(1)}`)}</span></td>
                    <td><span className={badgeClass(item.action)}>{t(`dataSecurity.action${item.action.charAt(0).toUpperCase()}${item.action.slice(1)}`)}</span></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
          {totalPages > 1 && <div className="ds3-pagination ds3-outbound-pagination">
            <button type="button" className="ds3-ribbon-clear" disabled={page <= 1} onClick={() => setPage(value => Math.max(1, value - 1))}>{t('dataSecurity.prevPage')}</button>
            <span className="ds3-inc-time ds3-outbound-pagination-info">{t('dataSecurity.pageInfo', { page, totalPages })}</span>
            <button type="button" className="ds3-ribbon-clear" disabled={page >= totalPages} onClick={() => setPage(value => Math.min(totalPages, value + 1))}>{t('dataSecurity.nextPage')}</button>
          </div>}
        </div>

      </div>

      {selectedId && createPortal(<div
        className="ds3-outbound-modal-overlay"
        role="presentation"
        onMouseDown={event => {
          if (event.target === event.currentTarget) setSelectedId(null)
        }}
      >
        <section
          className="ds3-outbound-modal"
          role="dialog"
          aria-modal="true"
          aria-label={t('dataSecurity.outboundDetail')}
          aria-busy={detailLoading}
          onMouseDown={event => event.stopPropagation()}
        >
          {!detail && detailLoading ? <div className="ds3-detail-empty"><p>{t('dataSecurity.loading')}</p></div> : !detail ? <div className="ds3-detail-empty"><p>{t('dataSecurity.outboundNoDetail')}</p></div> : (
            <div className="ds3-detail">
              <div className="ds3-detail-accent" style={{ background: detail.dlp_result === 'hit' ? '#ef4444' : '#22d3ee' }} />
              <div className="ds3-detail-header"><div><div className="ds3-section-label" style={{ padding: 0 }}>{t('dataSecurity.outboundDetail')}</div><div className="ds3-inc-time">{formatTime(detail.created_at)}</div></div><button type="button" className="ds3-close-btn" aria-label={t('dataSecurity.outboundCloseDetail')} onClick={() => setSelectedId(null)}>×</button></div>
              <SubjectSummary value={detail.subject} privacyMode={privacyMode} t={t} />
              <div className="ds3-detail-section">
                <div className="ds3-meta-grid">
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundSource')}</span><span className="ds3-meta-value">{sourceLabel(t, detail.source)}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundDirection')}</span><span className="ds3-meta-value">{t(`dataSecurity.direction${detail.direction.charAt(0).toUpperCase()}${detail.direction.slice(1)}`)}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundAuditClass')}</span><span className="ds3-meta-value">{auditClassLabel(t, detail.audit_class)}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundClient')}</span><span className="ds3-meta-value">{maskIp(detail.client_ip, privacyMode)}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundSender')}</span><span className="ds3-meta-value">{maskMailbox(detail.mail_from, privacyMode)}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundRecipients')}</span><span className="ds3-meta-value">{privacyMode ? t('dataSecurity.outboundDomainCount', { count: detail.external_recipient_domains.length }) : detail.external_recipient_domains.join(', ') || '—'}</span></div>
                  <div className="ds3-meta-cell"><span className="ds3-meta-label">{t('dataSecurity.outboundDelivery')}</span><span className="ds3-meta-value">{detail.delivery_status || '—'}</span></div>
                </div>
                {detail.audit_class === 'outbound_candidate' && <div className="ds3-outbound-inspection-reason" role="status">
                  <h4 className="ds3-outbound-detail-title">{t('dataSecurity.outboundAttributionPending')}</h4>
                  <p className="ds3-outbound-reason">{t('dataSecurity.outboundAttributionPendingDesc')}</p>
                </div>}
                <div className="ds3-outbound-detail-badges"><span className={badgeClass(detail.inspection_status)}>{t(`dataSecurity.status${detail.inspection_status.charAt(0).toUpperCase()}${detail.inspection_status.slice(1)}`)}</span><span className={badgeClass(detail.dlp_result)}>{t(`dataSecurity.result${detail.dlp_result.charAt(0).toUpperCase()}${detail.dlp_result.slice(1)}`)}</span><span className={badgeClass(detail.action)}>{t(`dataSecurity.action${detail.action.charAt(0).toUpperCase()}${detail.action.slice(1)}`)}</span>{detail.max_jrt_level != null && <span className="ds3-jrt-tag">{t('dataSecurity.levelNumber', { level: detail.max_jrt_level })}</span>}</div>
                {(detail.inspection_reason || detail.inspection_status === 'incomplete' || detail.inspection_status === 'failed') && (() => {
                  const codes = inspectionReasonCodes(detail.inspection_reason, detail.inspection_status === 'failed' ? 'content_scan_not_run' : 'capture_incomplete')
                  return <div className="ds3-outbound-inspection-reason">
                    <h4 className="ds3-outbound-detail-title">{t('dataSecurity.outboundInspectionReason')}</h4>
                    <ul>{codes.map(code => <li key={code}>{inspectionReasonLabel(t, code)}</li>)}</ul>
                  </div>
                })()}
                <h4 className="ds3-outbound-detail-title">{t('dataSecurity.outboundDlpEvidence')}</h4>
                {detail.dlp_matches.length === 0 ? <div className="ds3-inc-time">{t('dataSecurity.outboundNoDlp')}</div> : <>
                  <div className="ds3-aux-chips">{detail.dlp_matches.map(match => {
                    const count = dlpEvidenceCount(detail, match)
                    return <span className="ds3-aux-chip" key={match}>{dlpEvidenceLabel(t, match)}{count == null ? '' : ` ×${count}`}</span>
                  })}</div>
                  <p className="ds3-outbound-reason">{t('dataSecurity.outboundDlpEvidenceRedacted')}</p>
                </>}
                <div className="ds3-outbound-coverage"><span>{t('dataSecurity.outboundAttachmentCoverage')}</span><b>{detail.attachment_count === 0 ? t('dataSecurity.outboundNoAttachments') : `${detail.attachments_scanned}/${detail.attachment_count}`}</b></div>
                {detail.direction_reason && <p className="ds3-outbound-reason">{detail.direction_reason}</p>}
                {detail.session_id && <div className="ds3-outbound-session-detail">
                  <p>{t('dataSecurity.outboundDetailSourceHint')}</p>
                  <a href={`/emails/${detail.session_id}`} className="ds3-outbound-detail-link">{t('dataSecurity.outboundViewEmailDetail')} <span aria-hidden="true">→</span></a>
                </div>}
              </div>
            </div>
          )}
        </section>
      </div>, document.body)}
    </div>
  )
}
