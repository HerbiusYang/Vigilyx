import React, { useState, useEffect, useCallback, useLayoutEffect, useMemo, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { EmailSession, Protocol, SessionStatus, ApiResponse, PaginatedResponse, SessionCountResponse } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatDate, getRelativeTime, getServerNowMs, isEncryptedPort } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import { getSensitiveSetting } from '../../utils/sensitiveStorage'
import { usePrivacyPolicy } from '../../hooks/usePrivacyPolicy'
import { threatTypeLabel } from './categoryLabels'

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

const TRAFFIC_LIST_STATE_KEY = 'vigilyx-email-list-state'
const RELATIVE_FILTER_SNAPSHOT_MS = 60_000

/** `auto` fills the visible table height; the numbers are fixed page sizes. */
type PageSizeChoice = 'auto' | 20 | 50 | 100
const FIXED_PAGE_SIZES = [20, 50, 100] as const
/** Rows are single-line (`td` is nowrap); this matches the fit layout's padded row. */
const FIT_ROW_HEIGHT_PX = 37
const FIT_MIN_ROWS = 5
const FIT_MAX_ROWS = 200
/** Cards have no fixed height, so the automatic size uses a fixed batch there. */
const CARD_AUTO_PAGE_SIZE = 24

function readPageSizeChoice(
  params: URLSearchParams,
  storedState: Record<string, string | number>,
): PageSizeChoice {
  const stored = storedState.page_size
  const value = Number(params.get('page_size') ?? (stored !== undefined ? stored : 'auto'))
  return (FIXED_PAGE_SIZES as readonly number[]).includes(value) ? value as PageSizeChoice : 'auto'
}

function readDirectionRules() {
  return {
    inboundSrc: getSensitiveSetting('vigilyx-inbound-src') || '',
    inboundDst: getSensitiveSetting('vigilyx-inbound-dst') || '',
    outboundSrc: getSensitiveSetting('vigilyx-outbound-src') || '',
    outboundDst: getSensitiveSetting('vigilyx-outbound-dst') || '',
  }
}

interface SessionListSnapshot {
  query: string
  capturedAt: number
  relativeTime: boolean
}

function pageQuery(snapshot: SessionListSnapshot, page: number, after?: string): string {
  const params = new URLSearchParams(snapshot.query)
  params.set('page', String(page))
  params.set('skip_count', 'true')
  if (after) params.set('after', after)
  return params.toString()
}

/**
 * Keep list subjects useful without exposing their plaintext. The API already
 * applies this projection; repeating it here keeps older API responses safe
 * during a rolling deployment and is idempotent for already-masked values.
 */
function maskEmailListSubject(subject: string): string {
  const SUBJECT_MASK = '******'
  const chars = Array.from(subject.trim())
  if (chars.length === 0) return ''
  if (chars.every(char => char === '*')) return SUBJECT_MASK
  if (chars.length >= SUBJECT_MASK.length + 2 && chars.slice(1, -1).every(char => char === '*')) {
    return subject.trim()
  }
  if (chars.length < 2) return SUBJECT_MASK
  return `${chars[0]}${SUBJECT_MASK}${chars[chars.length - 1]}`
}

export function getEmailListSubject(
  subject: string | null,
  isEncrypted: boolean,
  noSubjectLabel: string,
  encryptedLabel: string,
  privacyEnabled = true,
): string {
  const trimmedSubject = subject?.trim()
  return trimmedSubject
    ? (privacyEnabled ? maskEmailListSubject(trimmedSubject) : trimmedSubject)
    : (isEncrypted ? encryptedLabel : noSubjectLabel)
}

/** Keep the list filters when navigating away and returning to the mail list. */
function readTrafficListState(): Record<string, string | number> {
  try {
    const raw = localStorage.getItem(TRAFFIC_LIST_STATE_KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    return Object.entries(parsed as Record<string, unknown>).reduce<Record<string, string | number>>((state, [key, value]) => {
      if (typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) {
        state[key] = value
      }
      return state
    }, {})
  } catch {
    return {}
  }
}

function readEnumParam<T extends string>(
  params: URLSearchParams,
  key: string,
  allowed: readonly T[],
  fallback: T,
  storedState?: Record<string, string | number>,
): T {
  const value = params.get(key) ?? (storedState?.[key] !== undefined ? String(storedState[key]) : null)
  return value && allowed.includes(value as T) ? value as T : fallback
}

function readNumberParam(
  params: URLSearchParams,
  key: string,
  fallback: number,
  allowed?: readonly number[],
  storedState?: Record<string, string | number>,
): number {
  const storedValue = storedState?.[key]
  const raw = Number(params.get(key) ?? (storedValue !== undefined ? storedValue : fallback))
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
    (getSensitiveSetting(key) || '').split(',').map(s => s.trim()).filter(Boolean)

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

const TRAFFIC_TABLE_COLUMNS = 10

const SkeletonRow = () => (
  <tr className="skeleton-row">
    {Array.from({ length: TRAFFIC_TABLE_COLUMNS }, (_, i) => (
      <td key={i}><div className="skeleton-line narrow" /></td>
    ))}
  </tr>
)

/**
 * Fixed-layout column plan: short columns get compact widths and the subject
 * absorbs the remaining space. Session status is a dot in the protocol column
 * and threat type shares the risk column with the security level.
 */
const TrafficTableHead = () => {
  const { t } = useTranslation()
  return (
    <>
      <colgroup>
        <col className="tcol-protocol" />
        <col className="tcol-direction" />
        <col className="tcol-risk" />
        <col />
        <col className="tcol-party" />
        <col className="tcol-party" />
        <col className="tcol-size" />
        <col className="tcol-attach" />
        <col className="tcol-time" />
        <col className="tcol-actions" />
      </colgroup>
      <thead>
        <tr>
          <th>{t('emailSecurity.colProtocol')}</th>
          <th title={t('emailSecurity.colDirection')}>{t('emailSecurity.colDirection')}</th>
          <th>{t('emailSecurity.colRisk')}</th>
          <th>{t('emailSecurity.colSubject')}</th>
          <th>{t('emailSecurity.sender')}</th>
          <th>{t('emailSecurity.recipient')}</th>
          <th className="num-cell">{t('emailSecurity.colSize')}</th>
          <th className="num-cell" title={t('emailSecurity.colAttachments')}>{t('emailSecurity.colAttachments')}</th>
          <th>{t('emailSecurity.colTime')}</th>
          <th>{t('emailSecurity.colActions')}</th>
        </tr>
      </thead>
    </>
  )
}

const MutedDash = ({ title }: { title?: string }) => (
  <span className="cell-muted" title={title}>–</span>
)

// ========================================
// Memo sub-components: Card view
// ========================================

const DirectionBadge = ({ clientIp, serverIp }: { clientIp: string; serverIp: string }) => {
  const { t } = useTranslation()
  const dir = detectDirection(clientIp, serverIp)
  if (!dir) {
    return <span className="direction-badge none" title={t('emailSecurity.directionUnknownTitle')}>–</span>
  }
  return (
    <span className={`direction-badge ${dir}`}>
      {dir === 'inbound' ? t('emailSecurity.inbound') : t('emailSecurity.outbound')}
    </span>
  )
}

const SESSION_STATUS_KEYS: Record<SessionStatus, string> = {
  active: 'emailSecurity.statusActive',
  completed: 'emailSecurity.statusCompleted',
  timeout: 'emailSecurity.statusTimeout',
  error: 'emailSecurity.statusError',
}

/** Most sessions are completed, so the status is a dot with its text on hover. */
const StatusDot = ({ status }: { status: SessionStatus }) => {
  const { t } = useTranslation()
  const label = t('emailSecurity.statusTitle', { status: t(SESSION_STATUS_KEYS[status] ?? status) })
  return <span className={`status-dot status-dot--${status}`} role="img" aria-label={label} title={label} />
}

const THREAT_LEVEL_KEYS: Record<string, string> = {
  safe: 'emailSecurity.threatSafe',
  low: 'emailSecurity.threatLow',
  medium: 'emailSecurity.threatMedium',
  high: 'emailSecurity.threatHigh',
  critical: 'emailSecurity.threatCritical',
}

const EmailCard = React.memo(({ session, detailHref, privacyEnabled }: { session: EmailSession; detailHref: string; privacyEnabled: boolean }) => {
  const { t } = useTranslation()
  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  const hasContent = session.content?.body_text || session.content?.body_html
  const attachmentCount = session.content?.attachments?.length || 0
  const linkCount = session.content?.links?.length || 0
  const suspiciousLinkCount = session.content?.links?.filter(l => l.suspicious).length || 0
  const decodedSubject = decodeMimeWord(session.subject)
  const subjectLabel = getEmailListSubject(
    decodedSubject,
    isEncrypted,
    t('emailSecurity.noSubject'),
    t('emailSecurity.encrypted'),
    privacyEnabled,
  )

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
        {subjectLabel}
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
          <WhitelistButton
            sessionId={session.id}
            disabled={isEncrypted}
          />
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
  const [state, setState] = useState<'idle' | 'loading' | 'analyzing' | 'done' | 'error'>('idle')
  const resetTimerRef = useRef<number | null>(null)
  const completedRef = useRef(false)
  const activeRef = useRef(false)

  useEffect(() => {
    const onSecurityVerdict = (event: Event) => {
      const detail = (event as CustomEvent<{ session_id?: unknown }>).detail
      if (detail?.session_id !== sessionId || !activeRef.current) return
      completedRef.current = true
      activeRef.current = false
      setState(() => {
        if (resetTimerRef.current) window.clearTimeout(resetTimerRef.current)
        resetTimerRef.current = window.setTimeout(() => setState('idle'), 2500)
        return 'done'
      })
    }
    window.addEventListener(EVENTS.SECURITY_VERDICT, onSecurityVerdict)
    return () => {
      window.removeEventListener(EVENTS.SECURITY_VERDICT, onSecurityVerdict)
      if (resetTimerRef.current) window.clearTimeout(resetTimerRef.current)
    }
  }, [sessionId])

  const handleRescan = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (state === 'loading' || state === 'analyzing') return
    if (resetTimerRef.current) window.clearTimeout(resetTimerRef.current)
    completedRef.current = false
    activeRef.current = true
    setState('loading')
    try {
      const res = await apiFetch(`/api/sessions/${sessionId}/rescan`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      if (!data.success) throw new Error(data.error || 'Rescan rejected')
      // The API acknowledges queueing only. The matching SecurityVerdict
      // event marks the actual completion and triggers the list refresh.
      if (completedRef.current) return
      setState('analyzing')
      resetTimerRef.current = window.setTimeout(() => {
        activeRef.current = false
        setState(current => current === 'analyzing' ? 'error' : current)
        resetTimerRef.current = window.setTimeout(() => setState('idle'), 2500)
      }, 15_000)
    } catch {
      activeRef.current = false
      setState('error')
      resetTimerRef.current = window.setTimeout(() => setState('idle'), 2500)
    }
  }

  if (disabled) return null

  return (
    <button
      className={`table-action rescan-btn rescan-btn--${state}`}
      onClick={handleRescan}
      disabled={state === 'loading' || state === 'analyzing'}
      title={t('emailSecurity.rescanTitle')}
    >
      {state === 'idle' && t('emailSecurity.rescanIdle')}
      {state === 'loading' && t('emailSecurity.rescanSubmitting')}
      {state === 'analyzing' && t('emailSecurity.rescanAnalyzing')}
      {state === 'done' && t('emailSecurity.rescanDone')}
      {state === 'error' && t('emailSecurity.rescanError')}
    </button>
  )
}

export const WhitelistButton = ({
  sessionId,
  disabled,
}: {
  sessionId: string
  disabled?: boolean
}) => {
  const { t } = useTranslation()
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const [iocCleanup, setIocCleanup] = useState<{ deleted: number; preserved: number } | null>(null)

  const handleWhitelist = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (state === 'loading' || state === 'done') return
    setState('loading')
    setIocCleanup(null)
    try {
      const res = await apiFetch(`/api/sessions/${sessionId}/whitelist`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: ApiResponse<{
        ioc_cleanup?: { deleted?: number; preserved_shared?: number }
      }> = await res.json()
      if (!data.success) throw new Error(data.error || 'Whitelist rejected')
      const cleanup = data.data?.ioc_cleanup
      if (cleanup && typeof cleanup === 'object') {
        setIocCleanup({
          deleted: typeof cleanup.deleted === 'number' ? cleanup.deleted : 0,
          preserved: typeof cleanup.preserved_shared === 'number' ? cleanup.preserved_shared : 0,
        })
      }
      setState('done')
    } catch (error) {
      console.error('Whitelist failed:', error)
      setState('error')
      window.setTimeout(() => setState('idle'), 2000)
    }
  }

  if (disabled) return null

  return (
    <button
      className={`table-action whitelist-btn whitelist-btn--${state}`}
      onClick={handleWhitelist}
      disabled={state === 'loading' || state === 'done'}
      title={t('emailSecurity.whitelistDesc')}
    >
      {state === 'idle' && t('emailSecurity.whitelistListAction')}
      {state === 'loading' && '...'}
      {state === 'done' && (iocCleanup
        ? t('emailSecurity.whitelistListDoneWithIoc', iocCleanup)
        : t('emailSecurity.whitelistListDone'))}
      {state === 'error' && t('emailSecurity.whitelistListError')}
    </button>
  )
}

const EmailRow = React.memo(({ session, detailHref, privacyEnabled }: { session: EmailSession; detailHref: string; privacyEnabled: boolean }) => {
  const { t } = useTranslation()
  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  const attachmentCount = session.content?.attachments?.length || 0
  const decodedSubject = decodeMimeWord(session.subject)
  const subjectLabel = getEmailListSubject(
    decodedSubject,
    isEncrypted,
    t('emailSecurity.noSubject'),
    t('emailSecurity.encrypted'),
    privacyEnabled,
  )
  const navigate = useNavigate()
  const threatLevelKey = session.threat_level ? THREAT_LEVEL_KEYS[session.threat_level] : undefined
  const threatLevelText = threatLevelKey ? t(threatLevelKey) : ''
  const threatTypeText = threatTypeLabel(session.threat_type) ?? ''
  const riskTitle = [threatLevelText, threatTypeText].filter(Boolean).join(' · ')

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
          <StatusDot status={session.status} />
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
      <td title={riskTitle || undefined}>
        {threatLevelText || threatTypeText ? (
          <span className="risk-cell">
            {threatLevelText && (
              <span className={`threat-badge threat-badge--${session.threat_level}`}>{threatLevelText}</span>
            )}
            {threatTypeText && <span className="threat-type-badge">{threatTypeText}</span>}
          </span>
        ) : (
          <MutedDash />
        )}
      </td>
      <td className="subject-cell" title={subjectLabel || undefined}>
        {subjectLabel}
      </td>
      <td title={session.mail_from || undefined}>
        {session.mail_from || <span className="cell-muted">{t('emailSecurity.unknown')}</span>}
      </td>
      <td title={session.rcpt_to.join(', ') || undefined}>
        {session.rcpt_to.length > 0
          ? session.rcpt_to.length > 1
            ? `${session.rcpt_to[0]} +${session.rcpt_to.length - 1}`
            : session.rcpt_to[0]
          : <span className="cell-muted">{t('emailSecurity.unknown')}</span>}
      </td>
      <td className="num-cell">{formatBytes(session.total_bytes)}</td>
      <td className="num-cell">
        {attachmentCount > 0 ? `${attachmentCount}` : <MutedDash />}
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
          <WhitelistButton
            sessionId={session.id}
            disabled={isEncrypted}
          />
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
  const { enabled: privacyEnabled } = usePrivacyPolicy()
  const location = useLocation()
  const navigate = useNavigate()
  const initialParamsRef = useRef(new URLSearchParams(location.search))
  const initialParams = initialParamsRef.current
  const storedStateRef = useRef(readTrafficListState())
  const storedState = storedStateRef.current

  // Tabs: mail list | quarantine
  const [activeTab, setActiveTab] = useState<'list' | 'quarantine'>('list')

  // Filter state
  const [protocolFilter, setProtocolFilter] = useState<Protocol | 'ALL'>(() =>
    readEnumParam(initialParams, 'protocol_filter', ['ALL', 'SMTP', 'POP3', 'IMAP'], 'ALL', storedState)
  )
  const [statusFilter, setStatusFilter] = useState<SessionStatus | 'ALL'>(() =>
    readEnumParam(initialParams, 'status_filter', ['ALL', 'active', 'completed', 'timeout', 'error'], 'ALL', storedState)
  )
  const [contentFilter, setContentFilter] = useState<ContentFilter>(() =>
    readEnumParam(initialParams, 'content_filter_mode', ['ALL', 'WITH_CONTENT'], 'WITH_CONTENT', storedState)
  )
  const [timeFilter, setTimeFilter] = useState<TimeFilter>(() =>
    readEnumParam(initialParams, 'time_filter', ['ALL', '30m', '1h', '6h', '24h'], 'ALL', storedState)
  )
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>(() =>
    readEnumParam(initialParams, 'direction_filter', ['ALL', 'inbound', 'outbound'], 'ALL', storedState)
  )
  const [authFilter, setAuthFilter] = useState<AuthFilter>(() =>
    readEnumParam(initialParams, 'auth_filter_mode', ['ALL', 'WITH_AUTH', 'AUTH_SUCCESS', 'AUTH_FAILED'], 'ALL', storedState)
  )
  const [viewMode, setViewMode] = useState<'table' | 'card'>(() =>
    readEnumParam(initialParams, 'view', ['table', 'card'], 'table', storedState)
  )
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(() =>
    readNumberParam(initialParams, 'refresh', 0, [0, 1000, 3000, 5000], storedState)
  ) // 0=off, 1000/3000/5000
  // Authentication and session-status filters are folded away by default; an
  // active value restored from the URL or storage keeps them visible.
  const [showMoreFilters, setShowMoreFilters] = useState(() => authFilter !== 'ALL' || statusFilter !== 'ALL')

  // Display settings: enabled protocols (read from localStorage)
  const [enabledProtocols, setEnabledProtocols] = useState<Protocol[]>(getEnabledProtocols)
  const [directionRules, setDirectionRules] = useState(readDirectionRules)

  // Listen for localStorage changes because the Settings page may update them
  useEffect(() => {
    const onStorage = () => {
      const protocols = getEnabledProtocols()
      setEnabledProtocols(previous => previous.join(',') === protocols.join(',') ? previous : protocols)
      const rules = readDirectionRules()
      setDirectionRules(previous => JSON.stringify(previous) === JSON.stringify(rules) ? previous : rules)
    }
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
  const [totalPages, setTotalPages] = useState<number | null>(null)
  const [loading, setLoading] = useState(true) // Show the skeleton screen on first load
  const [fetching, setFetching] = useState(false) // Loading indicator for pagination/filter changes
  const [loadError, setLoadError] = useState<string | null>(null)
  const [pageLoadError, setPageLoadError] = useState<string | null>(null)
  const [total, setTotal] = useState<number | null>(null)
  // A timed-out exact count falls back to a labelled database estimate.
  const [totalExact, setTotalExact] = useState(true)
  const [hasMore, setHasMore] = useState(false)
  const [countLoading, setCountLoading] = useState(false)
  const [countError, setCountError] = useState(false)
  const [refreshError, setRefreshError] = useState(false)
  const [snapshotVersion, setSnapshotVersion] = useState(0)
  // By default a page holds as many rows as the visible table fits. An explicit
  // page_size URL parameter or a remembered fixed choice overrides this.
  const [pageSizeChoice, setPageSizeChoice] = useState<PageSizeChoice>(() =>
    readPageSizeChoice(initialParams, storedState)
  )
  const [fitRows, setFitRows] = useState<number | null>(null)
  const autoFitTable = pageSizeChoice === 'auto' && viewMode === 'table'
  const pageSize = pageSizeChoice !== 'auto' ? pageSizeChoice
    : viewMode === 'card' ? CARD_AUTO_PAGE_SIZE : (fitRows ?? FIT_MIN_ROWS)
  // The first list request waits for the measured row count.
  const waitingForFit = autoFitTable && fitRows === null
  const tableContainerRef = useRef<HTMLDivElement | null>(null)
  const [jumpInput, setJumpInput] = useState('')

  // Refs
  const abortRef = useRef<AbortController | null>(null)
  const refreshAbortRef = useRef<AbortController | null>(null)
  const countAbortRef = useRef<AbortController | null>(null)
  const snapshotRef = useRef<SessionListSnapshot | null>(null)
  const pageCursorsRef = useRef(new Map<number, string>())
  const hasRowsRef = useRef(false)
  const rowsSnapshotRef = useRef<SessionListSnapshot | null>(null)
  const isInitialLoad = useRef(true)
  const fetchingPageRef = useRef(false) // Marks an in-flight pagination request so WS/polling writes can be suppressed
  const refreshingRef = useRef(false) // Marks an in-flight background refresh to avoid stacking interval/event requests
  const pageRef = useRef(page) // Always store the latest page number to avoid stale values inside WS/polling closures
  const requestedPageRef = useRef(page)

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
    if (pageSizeChoice !== 'auto') params.set('page_size', String(pageSizeChoice))
    return params.toString()
  }, [protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter, authFilter, viewMode, autoRefreshInterval, page, pageSizeChoice])

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

  const sourceIps = directionFilter === 'inbound' ? directionRules.inboundSrc
    : directionFilter === 'outbound' ? directionRules.outboundSrc : ''
  const destIps = directionFilter === 'inbound' ? directionRules.inboundDst
    : directionFilter === 'outbound' ? directionRules.outboundDst : ''
  const protocolsKey = enabledProtocols.join(',')
  const filterSignature = useMemo(() => JSON.stringify({
    protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter,
    authFilter, protocolsKey, pageSize, sourceIps, destIps,
  }), [protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter, authFilter, protocolsKey, pageSize, sourceIps, destIps])

  // A list/count pair shares the exact same time cutoff and direction rules.
  // Page changes reuse this snapshot and its count; relative windows renew at
  // most once per minute when another refresh or page request is made.
  const frozenSnapshot = useMemo<SessionListSnapshot>(() => {
    const params = new URLSearchParams({ limit: String(pageSize) })
    if (protocolFilter !== 'ALL') params.set('protocol', protocolFilter)
    else if (protocolsKey && protocolsKey.split(',').length < 3) params.set('protocol', protocolsKey)
    if (statusFilter !== 'ALL') params.set('status', statusFilter)
    params.set('content_filter', contentFilter === 'WITH_CONTENT' ? 'WITH_CONTENT' : 'NON_ENCRYPTED')
    if (authFilter !== 'ALL') params.set('auth_filter', authFilter)
    if (timeFilter !== 'ALL') {
      const ms = { '30m': 30 * 60_000, '1h': 60 * 60_000, '6h': 6 * 60 * 60_000, '24h': 24 * 60 * 60_000 }
      params.set('since', new Date(getServerNowMs() - ms[timeFilter]).toISOString())
    }
    if (sourceIps) params.set('source_ips', sourceIps)
    if (destIps) params.set('dest_ips', destIps)
    return { query: params.toString(), capturedAt: Date.now(), relativeTime: timeFilter !== 'ALL' }
  }, [protocolFilter, statusFilter, contentFilter, authFilter, timeFilter, directionFilter, protocolsKey, pageSize, sourceIps, destIps, snapshotVersion])

  const translateRef = useRef(t)
  useEffect(() => { translateRef.current = t }, [t])

  const applyPageData = useCallback((data: PaginatedResponse<EmailSession>, pageNum: number) => {
    // Earlier page refreshes invalidate later boundaries, including cached
    // cursors from before a new insertion at the head of the list.
    for (const knownPage of pageCursorsRef.current.keys()) {
      if (knownPage > pageNum) pageCursorsRef.current.delete(knownPage)
    }
    if (data.has_more !== false && data.next_cursor) {
      pageCursorsRef.current.set(pageNum + 1, data.next_cursor)
    }
    setSessions(data.items)
    hasRowsRef.current = data.items.length > 0
    rowsSnapshotRef.current = snapshotRef.current
    setHasMore(data.has_more ?? data.items.length >= data.limit)
    setPage(pageNum)
    pageRef.current = pageNum
    // A skipped count's compatibility total=0 is not an empty result.
    // Only the independent count request updates total and totalPages.
  }, [])

  const fetchCount = useCallback(async (snapshot: SessionListSnapshot) => {
    countAbortRef.current?.abort()
    const controller = new AbortController()
    countAbortRef.current = controller
    const isCurrent = () => !controller.signal.aborted
      && countAbortRef.current === controller && snapshotRef.current === snapshot
    setCountLoading(true)
    setCountError(false)
    try {
      const res = await apiFetch(`/api/sessions/count?${snapshot.query}`, { signal: controller.signal })
      const data: ApiResponse<SessionCountResponse> = await res.json()
      if (!isCurrent()) return
      if (!data.success || !data.data
        || !Number.isSafeInteger(data.data.total) || data.data.total < 0
        || !Number.isSafeInteger(data.data.total_pages) || data.data.total_pages < 0) {
        throw new Error('session_count_invalid')
      }
      // An estimate is shown as such; its page count could point past the real
      // last page, so estimated totals keep the previous/next navigation.
      const exact = data.data.exact !== false
      setTotal(data.data.total)
      setTotalExact(exact)
      setTotalPages(exact ? data.data.total_pages : null)
    } catch (e: unknown) {
      if (!isCurrent()) return
      if (e instanceof DOMException && e.name === 'AbortError') return
      setCountError(true)
    } finally {
      if (isCurrent()) {
        setCountLoading(false)
        countAbortRef.current = null
      }
    }
  }, [])

  const fetchPage = useCallback(async (pageNum: number, background = false) => {
    const snapshot = snapshotRef.current
    if (!snapshot) return
    if (!background) requestedPageRef.current = pageNum
    if (snapshot.relativeTime && Date.now() - snapshot.capturedAt >= RELATIVE_FILTER_SNAPSHOT_MS) {
      setSnapshotVersion(version => version + 1)
      return
    }
    abortRef.current?.abort()
    refreshAbortRef.current?.abort()
    refreshAbortRef.current = null
    refreshingRef.current = false
    const controller = new AbortController()
    abortRef.current = controller
    fetchingPageRef.current = true
    const isCurrent = () => !controller.signal.aborted
      && abortRef.current === controller && snapshotRef.current === snapshot

    if (isInitialLoad.current) setLoading(true)
    else setFetching(true)
    setLoadError(null)
    if (!background) setPageLoadError(null)

    try {
      const res = await apiFetch(`/api/sessions?${pageQuery(snapshot, pageNum, pageCursorsRef.current.get(pageNum))}`, { signal: controller.signal })
      const data: ApiResponse<PaginatedResponse<EmailSession>> = await res.json()
      if (!isCurrent()) return
      if (!data.success || !data.data) throw new Error(data.error || translateRef.current('emailSecurity.sessionListLoadFailed'))
      applyPageData(data.data, pageNum)
      if (pageNum === requestedPageRef.current) setPageLoadError(null)
      setRefreshError(false)
    } catch (e: unknown) {
      if (!isCurrent()) return
      if (e instanceof DOMException && e.name === 'AbortError') return
      const message = e instanceof Error && e.message ? e.message : translateRef.current('emailSecurity.sessionListLoadFailed')
      if (hasRowsRef.current && background) setRefreshError(true)
      else if (hasRowsRef.current && rowsSnapshotRef.current === snapshot) setPageLoadError(message)
      else setLoadError(message)
    } finally {
      if (isCurrent()) {
        setLoading(false)
        setFetching(false)
        isInitialLoad.current = false
        fetchingPageRef.current = false
        abortRef.current = null
      }
    }
  }, [applyPageData])

  const refreshPage = useCallback(async (pageNum: number) => {
    const snapshot = snapshotRef.current
    if (!snapshot || fetchingPageRef.current || refreshingRef.current) return
    if (snapshot.relativeTime && Date.now() - snapshot.capturedAt >= RELATIVE_FILTER_SNAPSHOT_MS) {
      setSnapshotVersion(version => version + 1)
      return
    }
    const controller = new AbortController()
    refreshAbortRef.current = controller
    refreshingRef.current = true
    const isCurrent = () => !controller.signal.aborted
      && refreshAbortRef.current === controller && snapshotRef.current === snapshot

    try {
      const res = await apiFetch(`/api/sessions?${pageQuery(snapshot, pageNum, pageCursorsRef.current.get(pageNum))}`, { signal: controller.signal })
      const data: ApiResponse<PaginatedResponse<EmailSession>> = await res.json()
      if (!isCurrent()) return
      if (!data.success || !data.data) throw new Error('session_list_refresh_failed')
      applyPageData(data.data, pageNum)
      setLoadError(null)
      setRefreshError(false)
    } catch (e: unknown) {
      if (!isCurrent()) return
      if (e instanceof DOMException && e.name === 'AbortError') return
      // A refresh failure must not replace usable rows with the empty/error view.
      setRefreshError(true)
    } finally {
      if (isCurrent()) {
        refreshAbortRef.current = null
        refreshingRef.current = false
      }
    }
  }, [applyPageData])

  // ========================================
  // Effect: Initial load & filter changes (reset to page 1)
  // ========================================

  useEffect(() => {
    const nextSearch = listStateSearch ? `?${listStateSearch}` : ''
    if (location.search !== nextSearch) {
      navigate({ pathname: '/emails', search: nextSearch }, { replace: true })
    }
  }, [listStateSearch, location.search, navigate])

  // URL parameters take precedence for shareable links; once changed, remember the
  // user's filters so returning to /emails restores the same view automatically.
  useEffect(() => {
    try {
      localStorage.setItem(TRAFFIC_LIST_STATE_KEY, JSON.stringify({
        protocol_filter: protocolFilter,
        status_filter: statusFilter,
        content_filter_mode: contentFilter,
        time_filter: timeFilter,
        direction_filter: directionFilter,
        auth_filter_mode: authFilter,
        view: viewMode,
        refresh: autoRefreshInterval,
        page_size: pageSizeChoice,
      }))
    } catch {
      // Storage may be unavailable in private browsing; the list still works normally.
    }
  }, [protocolFilter, statusFilter, contentFilter, timeFilter, directionFilter, authFilter, viewMode, autoRefreshInterval, pageSizeChoice])

  const initialPageRef = useRef(page)
  const lastFilterSignatureRef = useRef<string | null>(null)

  useEffect(() => {
    if (waitingForFit) return
    const previousSignature = lastFilterSignatureRef.current
    const pageToLoad = previousSignature === null ? initialPageRef.current
      : previousSignature !== filterSignature ? 1 : requestedPageRef.current
    lastFilterSignatureRef.current = filterSignature
    snapshotRef.current = frozenSnapshot
    pageCursorsRef.current.clear()
    setTotal(null)
    setTotalExact(true)
    setTotalPages(null)
    setHasMore(false)
    setRefreshError(false)
    setPageLoadError(null)
    setJumpInput('')
    void fetchPage(pageToLoad, previousSignature === filterSignature)
    void fetchCount(frozenSnapshot)
    return () => {
      abortRef.current?.abort()
      refreshAbortRef.current?.abort()
      countAbortRef.current?.abort()
      snapshotRef.current = null
      refreshAbortRef.current = null
      refreshingRef.current = false
    }
  }, [fetchPage, fetchCount, filterSignature, frozenSnapshot, waitingForFit])

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
    const handler = () => { void fetchPage(pageRef.current, true) }
    window.addEventListener(EVENTS.WS_RECONNECTED, handler)
    return () => window.removeEventListener(EVENTS.WS_RECONNECTED, handler)
  }, [fetchPage])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
      refreshAbortRef.current?.abort()
      countAbortRef.current?.abort()
      snapshotRef.current = null
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
  const resetFilters = () => {
    setProtocolFilter('ALL')
    setStatusFilter('ALL')
    setContentFilter('WITH_CONTENT')
    setTimeFilter('ALL')
    setDirectionFilter('ALL')
    setAuthFilter('ALL')
    setPage(1)
  }
  const hiddenFilterCount = (authFilter !== 'ALL' ? 1 : 0) + (statusFilter !== 'ALL' ? 1 : 0)
  const activeFilterCount = hiddenFilterCount
    + (protocolFilter !== 'ALL' ? 1 : 0)
    + (contentFilter !== 'WITH_CONTENT' ? 1 : 0)
    + (timeFilter !== 'ALL' ? 1 : 0)
    + (directionFilter !== 'ALL' ? 1 : 0)

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
  // Automatic page size: as many rows as the visible table body holds
  // ========================================

  const measureFitRows = useCallback(() => {
    const container = tableContainerRef.current
    if (!container) return
    const headHeight = container.querySelector('thead')?.getBoundingClientRect().height ?? 0
    // Prefer a real row once data is shown; skeleton rows are shorter.
    const rowHeight = Math.ceil(
      container.querySelector('tbody tr:not(.skeleton-row)')?.getBoundingClientRect().height || FIT_ROW_HEIGHT_PX
    )
    const rows = Math.floor((container.clientHeight - headHeight) / rowHeight)
    const next = Math.min(FIT_MAX_ROWS, Math.max(FIT_MIN_ROWS, Number.isFinite(rows) ? rows : FIT_MIN_ROWS))
    setFitRows(previous => previous === next ? previous : next)
  }, [])

  useLayoutEffect(() => {
    if (autoFitTable) measureFitRows()
  }, [autoFitTable, loading, displaySessions, measureFitRows])

  // The table container is re-created between skeleton, rows and empty state.
  const hasRows = displaySessions.length > 0
  useEffect(() => {
    const container = tableContainerRef.current
    if (!autoFitTable || !container || typeof ResizeObserver === 'undefined') return
    let timer = 0
    const observer = new ResizeObserver(() => {
      window.clearTimeout(timer)
      timer = window.setTimeout(measureFitRows, 150)
    })
    observer.observe(container)
    return () => {
      observer.disconnect()
      window.clearTimeout(timer)
    }
  }, [autoFitTable, loading, loadError, hasRows, measureFitRows])

  // ========================================
  // Render
  // ========================================

  return (
    <div className={`traffic-list ${activeTab === 'list' ? 'traffic-list--fit' : ''}`}>
      {/* Tab switch: mail list | quarantine */}
      <div className="traffic-list-tabs">
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
            {countLoading && <span className="email-hint" role="status">{t('emailSecurity.totalLoading')}</span>}
            {countError && <span className="email-hint" role="status">{t('emailSecurity.totalUnavailable')}</span>}
            {refreshError && <span className="email-hint" role="status">{t('emailSecurity.sessionListRefreshFailed')}</span>}
            {contentFilter === 'ALL' && restoredCount > 0 && (
              <span className="email-hint">
                {t('emailSecurity.restoredCount', { count: restoredCount })}
              </span>
            )}
          </div>
        </div>
        <div className="header-right">
          <button
            type="button"
            className="pagination-btn"
            disabled={countLoading}
            onClick={() => setSnapshotVersion(version => version + 1)}
          >
            {t('emailSecurity.recountTotal')}
          </button>
          <div className="auto-refresh-control">
            <select
              className="filter-select"
              value={autoRefreshInterval}
              aria-label={t('emailSecurity.autoRefreshLabel')}
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
        </div>
      </div>

      <div className="traffic-filterbar">
        <div className="filters">
          <select
            className="filter-select"
            value={contentFilter}
            aria-label={t('emailSecurity.allTraffic')}
            onChange={(e) => changeContent(e.target.value as ContentFilter)}
          >
            <option value="ALL">{t('emailSecurity.allTraffic')}</option>
            <option value="WITH_CONTENT">{t('emailSecurity.restoredEmails')}</option>
          </select>
          <select
            className="filter-select"
            value={timeFilter}
            aria-label={t('emailSecurity.allTime')}
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
            aria-label={t('emailSecurity.colProtocol')}
            onChange={(e) => changeProtocol(e.target.value as Protocol | 'ALL')}
          >
            <option value="ALL">{t('emailSecurity.allProtocols')}</option>
            {enabledProtocols.includes('SMTP') && <option value="SMTP">SMTP</option>}
            {enabledProtocols.includes('POP3') && <option value="POP3">POP3</option>}
            {enabledProtocols.includes('IMAP') && <option value="IMAP">IMAP</option>}
          </select>
          <select
            className="filter-select"
            value={directionFilter}
            aria-label={t('emailSecurity.allDirections')}
            onChange={(e) => changeDirection(e.target.value as DirectionFilter)}
          >
            <option value="ALL">{t('emailSecurity.allDirections')}</option>
            <option value="inbound">{t('emailSecurity.inbound')}</option>
            <option value="outbound">{t('emailSecurity.outbound')}</option>
          </select>
          {showMoreFilters && (
            <>
              <div className="filter-divider" />
              <select
                className="filter-select"
                value={authFilter}
                aria-label={t('emailSecurity.allAuth')}
                onChange={(e) => changeAuth(e.target.value as AuthFilter)}
              >
                <option value="ALL">{t('emailSecurity.allAuth')}</option>
                <option value="WITH_AUTH">{t('emailSecurity.withAuth')}</option>
                <option value="AUTH_SUCCESS">{t('emailSecurity.authSuccess')}</option>
                <option value="AUTH_FAILED">{t('emailSecurity.authFailed')}</option>
              </select>
              <select
                className="filter-select"
                value={statusFilter}
                aria-label={t('emailSecurity.colStatus')}
                onChange={(e) => changeStatus(e.target.value as SessionStatus | 'ALL')}
              >
                <option value="ALL">{t('emailSecurity.allStatuses')}</option>
                <option value="active">{t('emailSecurity.statusActive')}</option>
                <option value="completed">{t('emailSecurity.statusDone')}</option>
                <option value="timeout">{t('emailSecurity.statusTimeout')}</option>
                <option value="error">{t('emailSecurity.statusError')}</option>
              </select>
            </>
          )}
          <button
            type="button"
            className={`filter-more-btn ${showMoreFilters ? 'active' : ''}`}
            aria-expanded={showMoreFilters}
            onClick={() => setShowMoreFilters(open => !open)}
          >
            {showMoreFilters ? t('emailSecurity.lessFilters') : t('emailSecurity.moreFilters')}
            {!showMoreFilters && hiddenFilterCount > 0 && (
              <span className="filter-count" aria-hidden="true">{hiddenFilterCount}</span>
            )}
          </button>
        </div>
        {activeFilterCount > 0 && (
          <button type="button" className="filter-reset-btn" onClick={resetFilters}>
            {t('emailSecurity.resetFilters')}
          </button>
        )}
      </div>

      {pageLoadError && !loadError && (
        <div className="email-stats" role="alert" aria-live="polite">
          <span className="email-hint">{pageLoadError}</span>
          <button className="pagination-btn" type="button" disabled={fetching} onClick={() => { void fetchPage(requestedPageRef.current) }}>
            {t('emailSecurity.retry')}
          </button>
        </div>
      )}

      {/* Initial loading skeleton */}
      {loading ? (
        viewMode === 'card' ? (
          <div className="email-card-grid">
            {[1, 2, 3, 4].map(i => <SkeletonCard key={i} />)}
          </div>
        ) : (
          <div className="table-container" ref={tableContainerRef}>
            <table className="traffic-table">
              <TrafficTableHead />
              <tbody>
                {[1, 2, 3, 4].map(i => <SkeletonRow key={i} />)}
              </tbody>
            </table>
          </div>
        )
      ) : loadError ? (
        <div className="empty-state" role="alert" aria-live="polite">
          <h3>{t('emailSecurity.loadFailedTitle')}</h3>
          <p>{loadError}</p>
          <button className="view-all-btn" type="button" onClick={() => { void fetchPage(requestedPageRef.current) }}>
            {t('emailSecurity.retry')}
          </button>
        </div>
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
            <EmailCard key={session.id} session={session} detailHref={`/emails/${session.id}${detailSearch}`} privacyEnabled={privacyEnabled} />
            ))}
        </div>
      ) : (
        <div className="table-container" ref={tableContainerRef}>
          <table className="traffic-table">
            <TrafficTableHead />
            <tbody>
              {displaySessions.map(session => (
                <EmailRow key={session.id} session={session} detailHref={`/emails/${session.id}${detailSearch}`} privacyEnabled={privacyEnabled} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination controls */}
      {!loading && (
        <div className="pagination-controls traffic-pagination" aria-busy={fetching}>
          {totalPages === null ? (
            <div className="pagination-buttons">
              <button className="pagination-btn" disabled={fetching || page <= 1} onClick={() => { void fetchPage(page - 1) }} title={t('emailSecurity.prevPage')} aria-label={t('emailSecurity.prevPage')}>&lsaquo;</button>
              <span className="pagination-text">{t('emailSecurity.currentPage', { page })}</span>
              <button className="pagination-btn" disabled={fetching || !hasMore} onClick={() => { void fetchPage(page + 1) }} title={t('emailSecurity.nextPage')} aria-label={t('emailSecurity.nextPage')}>&rsaquo;</button>
            </div>
          ) : (totalPages > 1 || hasMore || page > 1) && (
            <div className="pagination-buttons">
              <button className="pagination-btn" disabled={fetching || page <= 1} onClick={() => { void fetchPage(1) }} title={t('emailSecurity.firstPage')} aria-label={t('emailSecurity.firstPage')}>&laquo;</button>
              <button className="pagination-btn" disabled={fetching || page <= 1} onClick={() => { void fetchPage(page - 1) }} title={t('emailSecurity.prevPage')} aria-label={t('emailSecurity.prevPage')}>&lsaquo;</button>

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
                      disabled={fetching}
                      onClick={() => { if (item !== page) void fetchPage(item) }}
                    >
                      {item}
                    </button>
                  )
                )
              })()}

              <button className="pagination-btn" disabled={fetching || !hasMore} onClick={() => { void fetchPage(page + 1) }} title={t('emailSecurity.nextPage')} aria-label={t('emailSecurity.nextPage')}>&rsaquo;</button>
              <button className="pagination-btn" disabled={fetching || page >= totalPages} onClick={() => { void fetchPage(totalPages) }} title={t('emailSecurity.lastPage')} aria-label={t('emailSecurity.lastPage')}>&raquo;</button>
            </div>
          )}

          <div className="pagination-actions">
            {totalPages !== null && totalPages > 5 && (
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
                      if (!fetching && p >= 1 && p <= totalPages) { void fetchPage(p); setJumpInput('') }
                    }
                  }}
                  placeholder={`1-${totalPages}`}
                />
                <span className="pagination-jump-label">{t('emailSecurity.pageUnit')}</span>
              </div>
            )}

            <div className="pagination-info">
              {totalPages !== null && <span className="pagination-text">{t('emailSecurity.currentPage', { page })}</span>}
              {/* While counting or after a failed count the header hint explains the state. */}
              {total !== null && (
                totalExact ? (
                  <span className="pagination-text">{t('emailSecurity.paginationInfo', { page, totalPages, total })}</span>
                ) : (
                  <span className="pagination-text" title={t('emailSecurity.totalEstimatedTitle')}>
                    {t('emailSecurity.paginationInfoEstimated', { total: total.toLocaleString() })}
                  </span>
                )
              )}
              <select
                className="pagination-size-select"
                aria-label={t('emailSecurity.pageSizeLabel')}
                value={String(pageSizeChoice)}
                onChange={e => {
                  const value = e.target.value
                  setPageSizeChoice(value === 'auto' ? 'auto' : Number(value) as PageSizeChoice)
                  setPage(1)
                }}
              >
                <option value="auto">{t('emailSecurity.perPageAuto', { count: pageSize })}</option>
                {FIXED_PAGE_SIZES.map(size => (
                  <option key={size} value={size}>{t('emailSecurity.perPage', { count: size })}</option>
                ))}
              </select>
            </div>
          </div>
        </div>
      )}
      </>
      )}
    </div>
  )
}
