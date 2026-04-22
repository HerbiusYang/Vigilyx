import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { EmailSession, Protocol, SessionStatus, ApiResponse, PaginatedResponse } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatDate, getRelativeTime, getServerNowMs, isEncryptedPort } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'

// ========================================
// Types
// ========================================

/** Read the enabled protocol list from localStorage. */
function getEnabledProtocols(): Protocol[] {
  const smtp = localStorage.getItem('vigilyx-capture-smtp') !== 'false'
  const pop3 = localStorage.getItem('vigilyx-capture-pop3') !== 'false'
  const imap = localStorage.getItem('vigilyx-capture-imap') !== 'false'
  const enabled: Protocol[] = []
  if (smtp) enabled.push('SMTP')
  if (pop3) enabled.push('POP3')
  if (imap) enabled.push('IMAP')
  return enabled
}

type TimeFilter = 'ALL' | '30m' | '1h' | '6h' | '24h'
type ContentFilter = 'ALL' | 'WITH_CONTENT'
type AuthFilter = 'ALL' | 'WITH_AUTH' | 'AUTH_SUCCESS' | 'AUTH_FAILED'
type DirectionFilter = 'ALL' | 'inbound' | 'outbound'
type SessionDirection = 'inbound' | 'outbound' | null

function readEnumParam<T extends string>(
  params: URLSearchParams,
  key: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const value = params.get(key)
  return value && allowed.includes(value as T) ? value as T : fallback
}

function readNumberParam(
  params: URLSearchParams,
  key: string,
  fallback: number,
  allowed?: readonly number[],
): number {
  const raw = Number(params.get(key) || fallback)
  if (!Number.isFinite(raw)) return fallback
  if (allowed && !allowed.includes(raw)) return fallback
  return raw
}

/**
 * Determine session direction from the rules configured in Settings.
 * The source IP matches client_ip (TCP initiator), and the destination IP matches server_ip (TCP target).
 * This matches the backend logic of source_ips -> client_ip and dest_ips -> server_ip.
 * Leaving either side empty means that side is unrestricted.
 */
function detectDirection(clientIp: string, serverIp: string): SessionDirection {
  const parse = (key: string): string[] =>
    (localStorage.getItem(key) || '').split(',').map(s => s.trim()).filter(Boolean)

  const inSrc = parse('vigilyx-inbound-src')
  const inDst = parse('vigilyx-inbound-dst')
  const outSrc = parse('vigilyx-outbound-src')
  const outDst = parse('vigilyx-outbound-dst')

  // Inbound: source IP (client_ip) is in the inbound source list and destination IP (server_ip) is in the inbound destination list
  if (inSrc.length > 0 || inDst.length > 0) {
    const srcOk = inSrc.length === 0 || inSrc.includes(clientIp)
    const dstOk = inDst.length === 0 || inDst.includes(serverIp)
    if (srcOk && dstOk) return 'inbound'
  }

  // Outbound: source IP (client_ip) is in the outbound source list and destination IP (server_ip) is in the outbound destination list
  if (outSrc.length > 0 || outDst.length > 0) {
    const srcOk = outSrc.length === 0 || outSrc.includes(clientIp)
    const dstOk = outDst.length === 0 || outDst.includes(serverIp)
    if (srcOk && dstOk) return 'outbound'
  }

  return null
}

// ========================================
// Skeleton loading component
// ========================================

const SkeletonCard = () => (
  <div className="email-card skeleton-card">
    <div className="skeleton-line wide" />
    <div className="skeleton-line medium" />
    <div className="skeleton-line narrow" />
    <div className="skeleton-line wide" />
  </div>
)

const SkeletonRow = () => (
  <tr className="skeleton-row">
    {Array.from({ length: 11 }, (_, i) => (
      <td key={i}><div className="skeleton-line narrow" /></td>
    ))}
  </tr>
)

// ========================================
// Memo sub-components: Card view
// ========================================

const DirectionBadge = ({ clientIp, serverIp }: { clientIp: string; serverIp: string }) => {
  const { t } = useTranslation()
  const dir = detectDirection(clientIp, serverIp)
  if (!dir) return <span className="direction-badge none">-</span>
  return (
    <span className={`direction-badge ${dir}`}>
      {dir === 'inbound' ? t('emailSecurity.inbound') : t('emailSecurity.outbound')}
    </span>
  )
}

const EmailCard = React.memo(({ session, detailHref }: { session: EmailSession; detailHref: string }) => {
  const { t } = useTranslation()
  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  const hasContent = session.content?.body_text || session.content?.body_html
  const attachmentCount = session.content?.attachments?.length || 0
  const linkCount = session.content?.links?.length || 0
  const suspiciousLinkCount = session.content?.links?.filter(l => l.suspicious).length || 0
  const decodedSubject = decodeMimeWord(session.subject)

  return (
    <div className={`email-card ${isEncrypted ? 'encrypted' : ''}`}>
      <div className="email-card-header">
        <div className="email-card-badges">
          <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>
            {session.protocol}
          </span>
          {isEncrypted && (
            <span className="encrypted-badge" title={t('emailSecurity.encryptedTransmission')}>
              TLS
            </span>
          )}
          <span className={`status-badge ${session.status}`}>
            {session.status === 'active' && t('emailSecurity.statusActive')}
            {session.status === 'completed' && t('emailSecurity.statusCompleted')}
            {session.status === 'timeout' && t('emailSecurity.statusTimeout')}
            {session.status === 'error' && t('emailSecurity.statusError')}
          </span>
          <DirectionBadge clientIp={session.client_ip} serverIp={session.server_ip} />
          {session.auth_info && (
            <span className={`auth-badge ${session.auth_info.auth_success === true ? 'success' : session.auth_info.auth_success === false ? 'failed' : ''}`}
              title={`${session.auth_info.auth_method} ${t('emailSecurity.auth')}${session.auth_info.username ? ': ' + session.auth_info.username : ''}`}>
              {session.auth_info.auth_method}
            </span>
          )}
        </div>
        <span className="email-card-time" title={formatDate(session.started_at)}>
          {getRelativeTime(session.started_at)}
        </span>
      </div>

      <div className="email-card-subject">
        {decodedSubject || (isEncrypted ? t('emailSecurity.encrypted') : t('emailSecurity.noSubject'))}
      </div>

      <div className="email-card-participants">
        <div className="participant from">
          <span className="label">{t('emailSecurity.sender')}</span>
          <span className="value">{session.mail_from || t('emailSecurity.unknown')}</span>
        </div>
        <div className="participant to">
          <span className="label">{t('emailSecurity.recipient')}</span>
          <span className="value">
            {session.rcpt_to.length > 0
              ? session.rcpt_to.length > 2
                ? t('emailSecurity.recipientOverflow', { first: session.rcpt_to[0], count: session.rcpt_to.length - 1 })
                : session.rcpt_to.join(', ')
              : t('emailSecurity.unknown')}
          </span>
        </div>
        {session.auth_info?.username && (
          <div className="participant auth">
            <span className="label">{t('emailSecurity.loginAccount')}</span>
            <span className="value auth-value">{session.auth_info.username}</span>
          </div>
        )}
      </div>

      {!isEncrypted && hasContent && (
        <div className="email-card-preview">
          {session.content?.body_text?.slice(0, 150) ||
           session.content?.body_html?.replace(/<[^>]*>/g, '').slice(0, 150)}
          {(session.content?.body_text?.length || 0) > 150 && '...'}
        </div>
      )}

      <div className="email-card-footer">
        <div className="email-card-stats">
          <span className="stat" title={t('emailSecurity.packets')}>
            {t('emailSecurity.packetCount', { count: session.packet_count })}
          </span>
          <span className="stat" title={t('emailSecurity.size')}>
            {formatBytes(session.total_bytes)}
          </span>
          {attachmentCount > 0 && (
            <span className="stat attachment" title={t('emailSecurity.attachments')}>
              {t('emailSecurity.attachmentCount', { count: attachmentCount })}
            </span>
          )}
          {linkCount > 0 && (
            <span className={`stat link ${suspiciousLinkCount > 0 ? 'suspicious' : ''}`} title={t('emailSecurity.links')}>
              {t('emailSecurity.linkCount', { count: linkCount })}
              {suspiciousLinkCount > 0 && ` (${t('emailSecurity.suspiciousCount', { count: suspiciousLinkCount })})`}
            </span>
          )}
        </div>

        <div className="email-card-connection">
          <span className="ip">{session.client_ip}</span>
          <span className="arrow">→</span>
          <span className="ip">{session.server_ip}:{session.server_port}</span>
        </div>

        <div className="cell-actions">
          {!isEncrypted ? (
            <Link to={detailHref} className="email-card-action">
              {t('emailSecurity.viewDetails')}
            </Link>
          ) : (
            <span className="email-card-action disabled" title={t('emailSecurity.cannotViewEncrypted')}>
              {t('emailSecurity.encryptedShort')}
            </span>
          )}
          <RescanButton sessionId={session.id} disabled={isEncrypted} />
        </div>
      </div>
    </div>
  )
})

// ========================================
// Memo sub-components: Table row
// ========================================

const RescanButton = ({ sessionId, disabled }: { sessionId: string; disabled?: boolean }) => {
  const { t } = useTranslation()
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')

  const handleRescan = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (state === 'loading') return
    setState('loading')
    try {
      const res = await apiFetch(`/api/sessions/${sessionId}/rescan`, { method: 'POST' })
      if (!res.ok) { setState('error'); return }
      const data = await res.json()
      setState(data.success ? 'done' : 'error')
    } catch {
      setState('error')
    }
    setTimeout(() => setState('idle'), 2000)
  }

  if (disabled) return null

  return (
    <button
      className={`table-action rescan-btn rescan-btn--${state}`}
      onClick={handleRescan}
      disabled={state === 'loading'}
      title={t('emailSecurity.rescanTitle')}
    >
      {state === 'idle' && t('emailSecurity.rescanIdle')}
      {state === 'loading' && '...'}
      {state === 'done' && t('emailSecurity.rescanDone')}
      {state === 'error' && t('emailSecurity.rescanError')}
    </button>
  )
}

const EmailRow = React.memo(({ session, detailHref }: { session: EmailSession; detailHref: string }) => {
  const { t } = useTranslation()
  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  const attachmentCount = session.content?.attachments?.length || 0
  const decodedSubject = decodeMimeWord(session.subject)
  const navigate = useNavigate()

  return (
    <tr
      className={`clickable-row ${isEncrypted ? 'encrypted-row' : ''}`}
      onClick={(e) => {
        // Do not intercept button or link clicks
        if ((e.target as HTMLElement).closest('a, button')) return
        if (!isEncrypted) navigate(detailHref)
      }}
      style={{ cursor: isEncrypted ? 'default' : 'pointer' }}
    >
      <td>
        <div className="cell-badges">
          <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>
            {session.protocol}
          </span>
          {isEncrypted && <span className="encrypted-badge small">TLS</span>}
          {session.auth_info && (
            <span className={`auth-badge small ${session.auth_info.auth_success === true ? 'success' : session.auth_info.auth_success === false ? 'failed' : ''}`}
              title={`${session.auth_info.auth_method}${session.auth_info.username ? ': ' + session.auth_info.username : ''}`}>
              {session.auth_info.auth_method}
            </span>
          )}
        </div>
      </td>
      <td>
        <DirectionBadge clientIp={session.client_ip} serverIp={session.server_ip} />
      </td>
      <td>
        <span className={`status-badge ${session.status}`}>
          {session.status === 'active' && t('emailSecurity.statusActive')}
          {session.status === 'completed' && t('emailSecurity.statusCompleted')}
          {session.status === 'timeout' && t('emailSecurity.statusTimeout')}
          {session.status === 'error' && t('emailSecurity.statusError')}
        </span>
      </td>
      <td>
        {session.threat_level ? (
          <span className={`threat-badge threat-badge--${session.threat_level}`}>
            {session.threat_level === 'safe' && t('emailSecurity.threatSafe')}
            {session.threat_level === 'low' && t('emailSecurity.threatLow')}
            {session.threat_level === 'medium' && t('emailSecurity.threatMedium')}
            {session.threat_level === 'high' && t('emailSecurity.threatHigh')}
            {session.threat_level === 'critical' && t('emailSecurity.threatCritical')}
          </span>
        ) : (
          <span className="threat-badge threat-badge--none">-</span>
        )}
      </td>
      <td className="subject-cell" title={decodedSubject || undefined}>
        {decodedSubject || (isEncrypted ? t('emailSecurity.encrypted') : t('emailSecurity.noSubject'))}
      </td>
      <td className="col-sender" title={session.mail_from || undefined}>{session.mail_from || t('emailSecurity.unknown')}</td>
      <td className="col-recipient" title={session.rcpt_to.join(', ') || undefined}>
        {session.rcpt_to.length > 0
          ? session.rcpt_to.length > 1
            ? `${session.rcpt_to[0]} +${session.rcpt_to.length - 1}`
            : session.rcpt_to[0]
          : t('emailSecurity.unknown')}
      </td>
      <td className="num-cell">{formatBytes(session.total_bytes)}</td>
      <td className="num-cell">
        {attachmentCount > 0 ? `${attachmentCount}` : '-'}
      </td>
      <td title={formatDate(session.started_at)}>
        {getRelativeTime(session.started_at)}
      </td>
      <td>
        <div className="cell-actions">
          {!isEncrypted ? (
            <Link to={detailHref} className="table-action">
              {t('emailSecurity.details')}
            </Link>
          ) : (
            <span className="table-action disabled">{t('emailSecurity.encryptedShort')}</span>
          )}
          <RescanButton sessionId={session.id} disabled={isEncrypted} />
        </div>
      </td>
    </tr>
  )
})

// ========================================
// Component: TrafficList with Pagination
// ========================================

// Lazy-load the quarantine component
const Quarantine = React.lazy(() => import('../quarantine/Quarantine'))

export default function TrafficList() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const initialParamsRef = useRef(new URLSearchParams(location.search))
  const initialParams = initialParamsRef.current

  // Tabs: mail list | quarantine
  const [activeTab, setActiveTab] = useState<'list' | 'quarantine'>('list')

  // Filter state
  const [protocolFilter, setProtocolFilter] = useState<Protocol | 'ALL'>(() =>
    readEnumParam(initialParams, 'protocol_filter', ['ALL', 'SMTP', 'POP3', 'IMAP'], 'ALL')
  )
  const [statusFilter, setStatusFilter] = useState<SessionStatus | 'ALL'>(() =>
    readEnumParam(initialParams, 'status_filter', ['ALL', 'active', 'completed', 'timeout', 'error'], 'ALL')
  )
  const [contentFilter, setContentFilter] = useState<ContentFilter>(() =>
    readEnumParam(initialParams, 'content_filter_mode', ['ALL', 'WITH_CONTENT'], 'WITH_CONTENT')
  )
  const [timeFilter, setTimeFilter] = useState<TimeFilter>(() =>
    readEnumParam(initialParams, 'time_filter', ['ALL', '30m', '1h', '6h', '24h'], 'ALL')
  )
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>(() =>
    readEnumParam(initialParams, 'direction_filter', ['ALL', 'inbound', 'outbound'], 'ALL')
  )
  const [authFilter, setAuthFilter] = useState<AuthFilter>(() =>
    readEnumParam(initialParams, 'auth_filter_mode', ['ALL', 'WITH_AUTH', 'AUTH_SUCCESS', 'AUTH_FAILED'], 'ALL')
  )
  const [viewMode, setViewMode] = useState<'table' | 'card'>(() =>
    readEnumParam(initialParams, 'view', ['table', 'card'], 'table')
  )
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(() =>
    readNumberParam(initialParams, 'refresh', 0, [0, 1000, 3000, 5000])
  ) // 0=off, 1000/3000/5000

  // Display settings: enabled protocols (read from localStorage)
  const [enabledProtocols, setEnabledProtocols] = useState<Protocol[]>(getEnabledProtocols)

  // Listen for localStorage changes because the Settings page may update them
  useEffect(() => {
    const onStorage = () => setEnabledProtocols(getEnabledProtocols())
    window.addEventListener('storage', onStorage)
    // Also listen for custom events for Settings changes within the same tab
    window.addEventListener(EVENTS.DISPLAY_SETTINGS_CHANGED, onStorage)
    return () => {
      window.removeEventListener('storage', onStorage)
      window.removeEventListener(EVENTS.DISPLAY_SETTINGS_CHANGED, onStorage)
    }
  }, [])

  // Data state - pagination
  const [sessions, setSessions] = useState<EmailSession[]>([])
  const [page, setPage] = useState(() => Math.max(1, readNumberParam(initialParams, 'page', 1)))
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(true) // Show the skeleton screen on first load
  const [fetching, setFetching] = useState(false) // Loading indicator for pagination/filter changes
  const [total, setTotal] = useState(0)
  const [pageSize, setPageSize] = useState(() => readNumberParam(initialParams, 'page_size', 20, [10, 20, 50]))
  const [jumpInput, setJumpInput] = useState('')

  // Refs
  const abortRef = useRef<AbortController | null>(null)
  const refreshAbortRef = useRef<AbortController | null>(null)
  const isInitialLoad = useRef(true)
  const fetchingPageRef = useRef(false) // Marks an in-flight pagination request so WS/polling writes can be suppressed
  const refreshingRef = useRef(false) // Marks an in-flight background refresh to avoid stacking interval/event requests
  const pageRef = useRef(page) // Always store the latest page number to avoid stale values inside WS/polling closures

  // Keep pageRef in sync
  useEffect(() => { pageRef.current = page }, [page])

  const listStateSearch = useMemo(() => {
    const params = new URLSearchParams()
    if (protocolFilter !== 'ALL') params.set('protocol_filter', protocolFilter)
    if (statusFilter !== 'ALL') params.set('status_filter', statusFilter)
    if (contentFilter !== 'WITH_CONTENT') params.set('content_filter_mode', contentFilter)
    if (timeFilter !== 'ALL') params.set('time_filter', timeFilter)
    if (directionFilter !== 'ALL') params.set('direction_filter', directionFilter)
    if (authFilter !== 'ALL') params.set('auth_filter_mode', authFilter)
    if (viewMode !== 'table') params.set('view', viewMode)
    if (autoRefreshInterval > 0) params.set('refresh', String(autoRefreshInterval))
    if (page > 1) params.set('page', String(page))
    if (pageSize !== 20) params.set('page_size', String(pageSize))
    return params.toString()
  }, [protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter, authFilter, viewMode, autoRefreshInterval, page, pageSize])

  const detailSearch = useMemo(
    () => (listStateSearch ? `?from=${encodeURIComponent(`?${listStateSearch}`)}` : ''),
    [listStateSearch],
  )

  // ========================================
  // WebSocket: real-time session changes (using lastMessage passed down from App)
  // ========================================
  const wsRefreshTimerRef = useRef(0)

  // ========================================
  // Build query string (does NOT depend on page for filter-based reset)
  // ========================================

  const buildQueryString = useCallback((pageNum: number, skipCount = false) => {
    const params = new URLSearchParams({
      page: String(pageNum),
      limit: String(pageSize),
    })
    // Performance optimization: skip COUNT queries during auto-refresh/WS refreshes (~4.5s -> 0),
    // and reuse the last total/totalPages values because they change slowly in the short term.
    // Only query COUNT on the initial load and when the user manually changes pages.
    if (skipCount) params.set('skip_count', 'true')
    if (protocolFilter !== 'ALL') {
      // The user manually selected a protocol
      params.set('protocol', protocolFilter)
    } else if (enabledProtocols.length > 0 && enabledProtocols.length < 3) {
      // If "All" is selected but some protocols are disabled, show only enabled protocols
      params.set('protocol', enabledProtocols.join(','))
    }
    if (statusFilter !== 'ALL') params.set('status', statusFilter)
    params.set('content_filter', contentFilter === 'WITH_CONTENT' ? 'WITH_CONTENT' : 'NON_ENCRYPTED')
    if (authFilter !== 'ALL') params.set('auth_filter', authFilter)
    if (timeFilter !== 'ALL') {
      const ms: Record<string, number> = {
        '30m': 30 * 60_000,
        '1h': 60 * 60_000,
        '6h': 6 * 60 * 60_000,
        '24h': 24 * 60 * 60_000,
      }
      const since = new Date(getServerNowMs() - ms[timeFilter]).toISOString()
      params.set('since', since)
    }
    // Traffic-direction filtering: read the inbound/outbound rules configured in Settings
    if (directionFilter !== 'ALL') {
      const srcKey = directionFilter === 'inbound' ? 'vigilyx-inbound-src' : 'vigilyx-outbound-src'
      const dstKey = directionFilter === 'inbound' ? 'vigilyx-inbound-dst' : 'vigilyx-outbound-dst'
      const srcIps = localStorage.getItem(srcKey) || ''
      const dstIps = localStorage.getItem(dstKey) || ''
      if (srcIps) params.set('source_ips', srcIps)
      if (dstIps) params.set('dest_ips', dstIps)
    }
    return params.toString()
  }, [protocolFilter, statusFilter, contentFilter, authFilter, timeFilter, directionFilter, enabledProtocols, pageSize])

  const applyPageData = useCallback((
    data: ApiResponse<PaginatedResponse<EmailSession>>,
    pageNum: number,
    skipCount: boolean,
  ) => {
    if (!data.success || !data.data) return

    setSessions(data.data.items)
    setPage(pageNum)

    if (!skipCount || data.data.total > 0) {
      setTotal(data.data.total)
      setTotalPages(data.data.total_pages)
    }
  }, [])

  // ========================================
  // Fetch: load page data
  // ========================================

  const fetchPage = useCallback(async (pageNum: number) => {
    abortRef.current?.abort()
    refreshAbortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    fetchingPageRef.current = true

    // Show the skeleton only on first load; keep existing data during pagination/filter changes and show a loading indicator
    if (isInitialLoad.current) setLoading(true)
    else setFetching(true)

    try {
      const qs = buildQueryString(pageNum)
      const res = await apiFetch(`/api/sessions?${qs}`, { signal: controller.signal })
      const data: ApiResponse<PaginatedResponse<EmailSession>> = await res.json()
      applyPageData(data, pageNum, false)
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      console.error('Failed to fetch sessions:', e)
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false)
        setFetching(false)
        isInitialLoad.current = false
        fetchingPageRef.current = false
      }
    }
  }, [applyPageData, buildQueryString])

  const refreshPage = useCallback(async (pageNum: number) => {
    if (fetchingPageRef.current || refreshingRef.current) return

    const controller = new AbortController()
    refreshAbortRef.current?.abort()
    refreshAbortRef.current = controller
    refreshingRef.current = true

    try {
      const qs = buildQueryString(pageNum, true)
      const res = await apiFetch(`/api/sessions?${qs}`, { signal: controller.signal })
      const data: ApiResponse<PaginatedResponse<EmailSession>> = await res.json()
      if (!controller.signal.aborted) {
        applyPageData(data, pageNum, true)
      }
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      console.error('Failed to refresh sessions:', e)
    } finally {
      if (refreshAbortRef.current === controller) {
        refreshAbortRef.current = null
      }
      refreshingRef.current = false
    }
  }, [applyPageData, buildQueryString])

  // ========================================
  // Effect: Initial load & filter changes (reset to page 1)
  // ========================================

  useEffect(() => {
    const nextSearch = listStateSearch ? `?${listStateSearch}` : ''
    if (location.search !== nextSearch) {
      navigate({ pathname: '/emails', search: nextSearch }, { replace: true })
    }
  }, [listStateSearch, location.search, navigate])

  const filterSignature = useMemo(
    () => JSON.stringify({
      protocolFilter,
      statusFilter,
      contentFilter,
      timeFilter,
      directionFilter,
      authFilter,
      enabledProtocols,
      pageSize,
    }),
    [protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter, authFilter, enabledProtocols, pageSize],
  )
  const initialPageRef = useRef(page)
  const lastFilterSignatureRef = useRef<string | null>(null)

  useEffect(() => {
    const pageToLoad = lastFilterSignatureRef.current === null ? initialPageRef.current : 1
    lastFilterSignatureRef.current = filterSignature
    fetchPage(pageToLoad)
  }, [fetchPage, filterSignature])

  // ========================================
  // WebSocket-driven refresh: insert new items at top
  // ========================================

  // Listen for dashboard-refresh events from App instead of relying on lastMessage props to avoid pointless re-renders
  useEffect(() => {
    const onRefresh = () => {
      if (autoRefreshInterval > 0) return
      if (!wsRefreshTimerRef.current) {
        wsRefreshTimerRef.current = window.setTimeout(() => {
          wsRefreshTimerRef.current = 0
          void refreshPage(pageRef.current)
        }, 1500)
      }
    }
    window.addEventListener(EVENTS.DASHBOARD_REFRESH, onRefresh)
    return () => {
      window.removeEventListener(EVENTS.DASHBOARD_REFRESH, onRefresh)
      if (wsRefreshTimerRef.current) {
        clearTimeout(wsRefreshTimerRef.current)
        wsRefreshTimerRef.current = 0
      }
    }
  }, [autoRefreshInterval, refreshPage])

  // Auto-refresh polling: only run when explicitly enabled; pause when the page is hidden.
  useEffect(() => {
    if (autoRefreshInterval <= 0) return

    void refreshPage(pageRef.current)

    const timer = setInterval(() => {
      if (document.hidden) return
      void refreshPage(pageRef.current)
    }, autoRefreshInterval)
    return () => clearInterval(timer)
  }, [autoRefreshInterval, refreshPage])

  // Perform a full refresh after WebSocket reconnection to compensate for messages lost while disconnected
  useEffect(() => {
    const handler = () => fetchPage(pageRef.current)
    window.addEventListener(EVENTS.WS_RECONNECTED, handler)
    return () => window.removeEventListener(EVENTS.WS_RECONNECTED, handler)
  }, [fetchPage])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
      refreshAbortRef.current?.abort()
      if (wsRefreshTimerRef.current) clearTimeout(wsRefreshTimerRef.current)
    }
  }, [])

  // ========================================
  // Filter change handlers (reset to page 1)
  // ========================================

  const changeProtocol = (v: Protocol | 'ALL') => { setProtocolFilter(v); setPage(1) }
  const changeStatus = (v: SessionStatus | 'ALL') => { setStatusFilter(v); setPage(1) }
  const changeContent = (v: ContentFilter) => { setContentFilter(v); setPage(1) }
  const changeTime = (v: TimeFilter) => { setTimeFilter(v); setPage(1) }
  const changeDirection = (v: DirectionFilter) => { setDirectionFilter(v); setPage(1) }
  const changeAuth = (v: AuthFilter) => { setAuthFilter(v); setPage(1) }

  // ========================================
  // Derived data
  // ========================================

  const isEmailFullyRestored = useCallback((session: EmailSession): boolean => {
    if (session.content?.is_encrypted || isEncryptedPort(session.server_port)) return false
    return session.content?.is_complete === true
  }, [])

  const displaySessions = useMemo(() => {
    // No more client-side content filtering; encrypted filtering is already handled on the server so totals/pagination stay consistent
    // Always sort with restored mail shown first
    return [...sessions]
      .sort((a, b) => {
        const ar = isEmailFullyRestored(a) ? 1 : 0
        const br = isEmailFullyRestored(b) ? 1 : 0
        return br - ar
      })
  }, [sessions, isEmailFullyRestored])

  const { restoredCount } = useMemo(() => ({
    restoredCount: displaySessions.filter(isEmailFullyRestored).length,
  }), [displaySessions, isEmailFullyRestored])

  // ========================================
  // Render
  // ========================================

  return (
    <div className="traffic-list">
      {/* Tab switch: mail list | quarantine */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        <button
          onClick={() => setActiveTab('list')}
          style={{
            padding: '10px 20px', fontSize: 14, fontWeight: activeTab === 'list' ? 600 : 400,
            cursor: 'pointer', border: 'none', background: 'none',
            color: activeTab === 'list' ? 'var(--accent-primary)' : 'var(--text-secondary)',
            borderBottom: activeTab === 'list' ? '2px solid var(--accent-primary)' : '2px solid transparent',
            marginBottom: -1,
          }}
        >
          {t('emailSecurity.emailList')}
        </button>
        <button
          onClick={() => setActiveTab('quarantine')}
          style={{
            padding: '10px 20px', fontSize: 14, fontWeight: activeTab === 'quarantine' ? 600 : 400,
            cursor: 'pointer', border: 'none', background: 'none',
            color: activeTab === 'quarantine' ? 'var(--accent-primary)' : 'var(--text-secondary)',
            borderBottom: activeTab === 'quarantine' ? '2px solid var(--accent-primary)' : '2px solid transparent',
            marginBottom: -1,
          }}
        >
          {t('emailSecurity.quarantine')}
        </button>
      </div>

      {activeTab === 'quarantine' ? (
        <React.Suspense fallback={<div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>{t('emailSecurity.loading')}</div>}>
          <Quarantine />
        </React.Suspense>
      ) : (
      <>
      <div className="traffic-list-header">
        <div className="header-left">
          <h1>{t('emailSecurity.emailTraffic')}</h1>
          <div className="email-stats">
            <span className="email-count">
              {t('emailSecurity.totalCount', { count: total })}{fetching && ` · ${t('emailSecurity.refreshing')}`}
            </span>
            {contentFilter === 'ALL' && restoredCount > 0 && (
              <span className="email-hint">
                {t('emailSecurity.restoredCount', { count: restoredCount })}
              </span>
            )}
          </div>
        </div>
        <div className="header-right">
          <div className="auto-refresh-control">
            <select
              className="filter-select"
              value={autoRefreshInterval}
              onChange={e => setAutoRefreshInterval(Number(e.target.value))}
            >
              <option value={0}>{t('emailSecurity.manualRefresh')}</option>
              <option value={1000}>{t('emailSecurity.autoRefresh1s')}</option>
              <option value={3000}>{t('emailSecurity.autoRefresh3s')}</option>
              <option value={5000}>{t('emailSecurity.autoRefresh5s')}</option>
            </select>
            {autoRefreshInterval > 0 && <span className="refresh-indicator" />}
          </div>
          <div className="view-toggle">
            <button
              className={`toggle-btn ${viewMode === 'card' ? 'active' : ''}`}
              onClick={() => setViewMode('card')}
              title={t('emailSecurity.cardView')}
            >
              ▦
            </button>
            <button
              className={`toggle-btn ${viewMode === 'table' ? 'active' : ''}`}
              onClick={() => setViewMode('table')}
              title={t('emailSecurity.tableView')}
            >
              ≡
            </button>
          </div>
          <div className="filters">
            <div className="filter-group">
              <select
                className="filter-select"
                value={directionFilter}
                onChange={(e) => changeDirection(e.target.value as DirectionFilter)}
              >
                <option value="ALL">{t('emailSecurity.allDirections')}</option>
                <option value="inbound">{t('emailSecurity.inbound')}</option>
                <option value="outbound">{t('emailSecurity.outbound')}</option>
              </select>
              <select
                className="filter-select"
                value={authFilter}
                onChange={(e) => changeAuth(e.target.value as AuthFilter)}
              >
                <option value="ALL">{t('emailSecurity.allAuth')}</option>
                <option value="WITH_AUTH">{t('emailSecurity.withAuth')}</option>
                <option value="AUTH_SUCCESS">{t('emailSecurity.authSuccess')}</option>
                <option value="AUTH_FAILED">{t('emailSecurity.authFailed')}</option>
              </select>
            </div>
            <div className="filter-divider" />
            <div className="filter-group">
              <select
                className="filter-select"
                value={contentFilter}
                onChange={(e) => changeContent(e.target.value as ContentFilter)}
              >
                <option value="ALL">{t('emailSecurity.allTraffic')}</option>
                <option value="WITH_CONTENT">{t('emailSecurity.restoredEmails')}</option>
              </select>
              <select
                className="filter-select"
                value={timeFilter}
                onChange={(e) => changeTime(e.target.value as TimeFilter)}
              >
                <option value="ALL">{t('emailSecurity.allTime')}</option>
                <option value="30m">{t('emailSecurity.last30m')}</option>
                <option value="1h">{t('emailSecurity.last1h')}</option>
                <option value="6h">{t('emailSecurity.last6h')}</option>
                <option value="24h">{t('emailSecurity.last24h')}</option>
              </select>
              <select
                className="filter-select"
                value={protocolFilter}
                onChange={(e) => changeProtocol(e.target.value as Protocol | 'ALL')}
              >
                <option value="ALL">{t('emailSecurity.allProtocols')}</option>
                {enabledProtocols.includes('SMTP') && <option value="SMTP">SMTP</option>}
                {enabledProtocols.includes('POP3') && <option value="POP3">POP3</option>}
                {enabledProtocols.includes('IMAP') && <option value="IMAP">IMAP</option>}
              </select>
              <select
                className="filter-select"
                value={statusFilter}
                onChange={(e) => changeStatus(e.target.value as SessionStatus | 'ALL')}
              >
                <option value="ALL">{t('emailSecurity.allStatuses')}</option>
                <option value="active">{t('emailSecurity.statusActive')}</option>
                <option value="completed">{t('emailSecurity.statusDone')}</option>
                <option value="timeout">{t('emailSecurity.statusTimeout')}</option>
                <option value="error">{t('emailSecurity.statusError')}</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Initial loading skeleton */}
      {loading ? (
        viewMode === 'card' ? (
          <div className="email-card-grid">
            {[1, 2, 3, 4].map(i => <SkeletonCard key={i} />)}
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th className="col-protocol">{t('emailSecurity.colProtocol')}</th>
                  <th className="col-direction">{t('emailSecurity.colDirection')}</th>
                  <th className="col-status">{t('emailSecurity.colStatus')}</th>
                  <th className="col-security">{t('emailSecurity.colSecurity')}</th>
                  <th>{t('emailSecurity.colSubject')}</th>
                  <th className="col-sender">{t('emailSecurity.sender')}</th>
                  <th className="col-recipient">{t('emailSecurity.recipient')}</th>
                  <th className="col-size num-cell">{t('emailSecurity.colSize')}</th>
                  <th className="col-attach num-cell">{t('emailSecurity.colAttachments')}</th>
                  <th className="col-time">{t('emailSecurity.colTime')}</th>
                  <th className="col-actions">{t('emailSecurity.colActions')}</th>
                </tr>
              </thead>
              <tbody>
                {[1, 2, 3, 4].map(i => <SkeletonRow key={i} />)}
              </tbody>
            </table>
          </div>
        )
      ) : displaySessions.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: '#6e7681' }}>
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>
            </svg>
          </div>
          {contentFilter === 'WITH_CONTENT' ? (
            <>
              <h3>{t('emailSecurity.noRestoredEmails')}</h3>
              <p>
                {t('emailSecurity.noRestoredEmailsHint')}
                {timeFilter !== 'ALL' && ` ${t('emailSecurity.tryExpandTimeRange')}`}
              </p>
              <button
                className="view-all-btn"
                onClick={() => changeContent('ALL')}
              >
                {t('emailSecurity.viewAllTraffic')}
              </button>
            </>
          ) : (
            <>
              <h3>{t('emailSecurity.noEmails')}</h3>
              <p>{t('emailSecurity.noEmailsHint')}</p>
            </>
          )}
        </div>
      ) : viewMode === 'card' ? (
        <div className="email-card-grid">
            {displaySessions.map(session => (
            <EmailCard key={session.id} session={session} detailHref={`/emails/${session.id}${detailSearch}`} />
            ))}
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th className="col-protocol">{t('emailSecurity.colProtocol')}</th>
                <th className="col-direction">{t('emailSecurity.colDirection')}</th>
                <th className="col-status">{t('emailSecurity.colStatus')}</th>
                <th className="col-security">{t('emailSecurity.colSecurity')}</th>
                <th>{t('emailSecurity.colSubject')}</th>
                <th>{t('emailSecurity.sender')}</th>
                <th>{t('emailSecurity.recipient')}</th>
                <th className="col-size num-cell">{t('emailSecurity.colSize')}</th>
                <th className="col-attach num-cell">{t('emailSecurity.colAttachments')}</th>
                <th className="col-time">{t('emailSecurity.colTime')}</th>
                <th className="col-actions">{t('emailSecurity.colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {displaySessions.map(session => (
                <EmailRow key={session.id} session={session} detailHref={`/emails/${session.id}${detailSearch}`} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination controls */}
      {!loading && total > 0 && (
        <div className="pagination-controls">
          <div className="pagination-info">
            <span className="pagination-text">
              {t('emailSecurity.paginationInfo', { page, totalPages, total })}
            </span>
            <select
              className="pagination-size-select"
              value={pageSize}
              onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
            >
              <option value={10}>{t('emailSecurity.perPage', { count: 10 })}</option>
              <option value={20}>{t('emailSecurity.perPage', { count: 20 })}</option>
              <option value={50}>{t('emailSecurity.perPage', { count: 50 })}</option>
            </select>
          </div>

          {totalPages > 1 && (
            <div className="pagination-buttons">
              <button className="pagination-btn" disabled={page <= 1} onClick={() => fetchPage(1)} title={t('emailSecurity.firstPage')}>&laquo;</button>
              <button className="pagination-btn" disabled={page <= 1} onClick={() => fetchPage(page - 1)} title={t('emailSecurity.prevPage')}>&lsaquo;</button>

              {(() => {
                const items: (number | '...')[] = []
                if (totalPages <= 7) {
                  for (let i = 1; i <= totalPages; i++) items.push(i)
                } else {
                  items.push(1)
                  if (page > 3) items.push('...')
                  const start = Math.max(2, page - 1)
                  const end = Math.min(totalPages - 1, page + 1)
                  for (let i = start; i <= end; i++) items.push(i)
                  if (page < totalPages - 2) items.push('...')
                  items.push(totalPages)
                }
                return items.map((item, idx) =>
                  item === '...' ? (
                    <span key={`e${idx}`} className="pagination-ellipsis">...</span>
                  ) : (
                    <button
                      key={item}
                      className={`pagination-btn ${item === page ? 'active' : ''}`}
                      onClick={() => item !== page && fetchPage(item)}
                    >
                      {item}
                    </button>
                  )
                )
              })()}

              <button className="pagination-btn" disabled={page >= totalPages} onClick={() => fetchPage(page + 1)} title={t('emailSecurity.nextPage')}>&rsaquo;</button>
              <button className="pagination-btn" disabled={page >= totalPages} onClick={() => fetchPage(totalPages)} title={t('emailSecurity.lastPage')}>&raquo;</button>
            </div>
          )}

          {totalPages > 5 && (
            <div className="pagination-jump">
              <span className="pagination-jump-label">{t('emailSecurity.jumpTo')}</span>
              <input
                type="text"
                className="pagination-jump-input"
                value={jumpInput}
                onChange={e => setJumpInput(e.target.value.replace(/\D/g, ''))}
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    const p = parseInt(jumpInput)
                    if (p >= 1 && p <= totalPages) { fetchPage(p); setJumpInput('') }
                  }
                }}
                placeholder={`1-${totalPages}`}
              />
              <span className="pagination-jump-label">{t('emailSecurity.pageUnit')}</span>
            </div>
          )}
        </div>
      )}
      </>
      )}
    </div>
  )
}
