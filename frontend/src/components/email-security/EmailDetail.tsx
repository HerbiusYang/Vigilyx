import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useLocation, useParams, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { EmailSession, ApiResponse, SecurityVerdict, ModuleResult } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatClockTime, formatDateFull, getFileIcon, isEncryptedPort } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { PRIVACY_LEASE_HEADER, usePrivacyAccess } from '../../hooks/usePrivacyAccess'
import { usePrivacyPolicy } from '../../hooks/usePrivacyPolicy'
import { PrivacyAccessPanel } from '../privacy/PrivacyAccessPanel'
import { EVENTS } from '../../utils/events'
import { buildEmailPreviewDoc } from '../../utils/emailHtml'
import SecurityAnalysisView, { RadarChart, isModuleUnavailable } from './SecurityAnalysisView'
import FeedbackPanel from './FeedbackPanel'
import { categoryLabel, classificationLabel, threatTypeLabel } from './categoryLabels'

const EMAIL_PRIVACY_SCOPES = ['body', 'html', 'headers', 'verdict', 'attachment_download', 'eml_download'] as const

const MAX_ATTACHMENT_DOWNLOAD_BYTES = 25 * 1024 * 1024
const RESCAN_POLL_INTERVAL_MS = 500
const RESCAN_MAX_WAIT_MS = 15_000

type EmailSecurityData = {
  verdict: SecurityVerdict | null
  results: ModuleResult[]
}

/**
 * A rescan is queued asynchronously. Keep the two read paths independent so
 * a temporarily unavailable legacy verdict cannot hide fresh module results.
 */
async function fetchEmailSecurity(
  id: string,
  headers?: HeadersInit,
  signal?: AbortSignal,
): Promise<EmailSecurityData> {
  const fetchVerdict = async (): Promise<SecurityVerdict | null> => {
    try {
      const response = await apiFetch(`/api/sessions/${id}/verdict`, { signal, headers })
      const data: ApiResponse<SecurityVerdict> = await response.json()
      return data.success && data.data ? data.data : null
    } catch { return null }
  }

  const fetchResults = async (): Promise<ModuleResult[]> => {
    try {
      const response = await apiFetch(`/api/sessions/${id}/security-results`, { signal, headers })
      const data: ApiResponse<ModuleResult[]> = await response.json()
      return data.success ? normalizeModuleResults(data.data) : []
    } catch { return [] }
  }

  const [verdict, results] = await Promise.all([fetchVerdict(), fetchResults()])
  return { verdict, results }
}

/**
 * Keep the security view renderable when an older API or a partial response
 * omits optional module fields. Privacy mode no longer redacts this endpoint,
 * but normalizing at the response boundary keeps the detail page resilient.
 */
export function normalizeModuleResults(value: unknown): ModuleResult[] {
  if (!Array.isArray(value)) return []

  return value
    .filter((item): item is Record<string, unknown> => (
      Boolean(item) && typeof item === 'object' && !Array.isArray(item)
    ))
    .map(item => ({
      ...item,
      categories: Array.isArray(item.categories)
        ? item.categories.filter((category): category is string => typeof category === 'string')
        : [],
      evidence: Array.isArray(item.evidence) ? item.evidence : [],
      details: item.details && typeof item.details === 'object' && !Array.isArray(item.details)
        ? item.details
        : {},
    }) as ModuleResult)
}

export default function EmailDetail() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const location = useLocation()
  const [sessionSnapshot, setSession] = useState<{ key: string; data: EmailSession } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'content' | 'headers' | 'attachments' | 'smtp-dialog' | 'security'>('content')
  const [relatedSessions, setRelatedSessions] = useState<EmailSession[]>([])
  const [expandedModules, setExpandedModules] = useState<Set<string> | null>(null)
  const [verdict, setVerdict] = useState<SecurityVerdict | null>(null)
  const [moduleResults, setModuleResults] = useState<ModuleResult[]>([])
  const [feedbackOpen, setFeedbackOpen] = useState(false)
  const [rescanStatus, setRescanStatus] = useState<'idle' | 'loading' | 'analyzing' | 'done' | 'error'>('idle')
  const [whitelistStatus, setWhitelistStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const [copiedLinkIndex, setCopiedLinkIndex] = useState<number | null>(null)
  const privacyAccess = usePrivacyAccess(id ? { resource_type: 'session', resource_id: id } : null)
  const privacyPolicy = usePrivacyPolicy()
  const authorizationKey = JSON.stringify([
    id, privacyPolicy.enabled, privacyPolicy.loading, privacyPolicy.error,
    privacyAccess.error, privacyAccess.lease?.lease_handle,
    privacyAccess.lease?.expires_at, privacyAccess.lease?.scopes,
  ])
  // Hide the old DOM in this render, before an effect or replacement request
  // can run. A failed refresh must not leave a previous plaintext snapshot.
  const session = sessionSnapshot?.key === authorizationKey ? sessionSnapshot.data : null
  const currentAuthorizationKey = useRef(authorizationKey)
  currentAuthorizationKey.current = authorizationKey
  const privacyHeaders = useMemo(
    () => privacyAccess.lease?.lease_handle
      ? { [PRIVACY_LEASE_HEADER]: privacyAccess.lease.lease_handle }
      : undefined,
    [privacyAccess.lease?.lease_handle],
  )
  const rescanStatusRef = useRef(rescanStatus)
  const rescanRunRef = useRef(0)
  const rescanCompletedRef = useRef(false)
  const rescanPreviousVerdictIdRef = useRef<string | undefined>(undefined)
  const rescanActiveRef = useRef(false)
  const rescanResetTimerRef = useRef<number | null>(null)
  const mountedRef = useRef(true)
  const fromSearch = new URLSearchParams(location.search).get('from') || ''
  const listSearch = fromSearch.startsWith('?') ? fromSearch : fromSearch ? `?${fromSearch}` : ''
  const backToList = `/emails${listSearch}`
  const detailLink = (sessionId: string) =>
    `/emails/${sessionId}${fromSearch ? `?from=${encodeURIComponent(listSearch)}` : ''}`

  useEffect(() => {
    rescanStatusRef.current = rescanStatus
  }, [rescanStatus])

  useEffect(() => () => {
    mountedRef.current = false
    rescanRunRef.current += 1
    if (rescanResetTimerRef.current) window.clearTimeout(rescanResetTimerRef.current)
  }, [])

  const refreshSecurity = useCallback(async (signal?: AbortSignal) => {
    if (!id) return null
    const security = await fetchEmailSecurity(id, privacyHeaders, signal)
    if (!mountedRef.current || signal?.aborted || currentAuthorizationKey.current !== authorizationKey) return null
    if (security.verdict) setVerdict(security.verdict)
    setModuleResults(security.results)
    return security
  }, [id, privacyHeaders, authorizationKey])

  const reportRescanStatus = useCallback((status: 'done' | 'error', runId: number) => {
    if (!mountedRef.current || runId !== rescanRunRef.current) return
    rescanActiveRef.current = false
    setRescanStatus(status)
    if (rescanResetTimerRef.current) window.clearTimeout(rescanResetTimerRef.current)
    rescanResetTimerRef.current = window.setTimeout(() => {
      if (mountedRef.current && rescanRunRef.current === runId) setRescanStatus('idle')
      rescanResetTimerRef.current = null
    }, 2500)
  }, [])

  const THREAT_CN: Record<string, string> = {
    safe: t('emailSecurity.threat_safe'), low: t('emailSecurity.threat_low'), medium: t('emailSecurity.threat_medium'), high: t('emailSecurity.threat_high'), critical: t('emailSecurity.threat_critical'),
  }

  useEffect(() => {
    if (!id) return

    setSession(null)
    setVerdict(null)
    setModuleResults([])
    setRelatedSessions([])
    setError(null)
    setLoading(true)
    if (privacyPolicy.loading) return
    if (privacyPolicy.error) {
      setError(t('emailSecurity.networkError'))
      setLoading(false)
      return
    }

    const controller = new AbortController()
    const signal = controller.signal

    const fetchData = async () => {
      try {
        // 1. Fetch session details first because they determine whether the page can render
        const sessionRes = await apiFetch(`/api/sessions/${id}`, { signal, headers: privacyHeaders })
        const sessionData: ApiResponse<EmailSession> = await sessionRes.json()
        if (signal.aborted || currentAuthorizationKey.current !== authorizationKey) return

        if (!sessionData.success || !sessionData.data) {
          setError(t('emailSecurity.cannotLoadSession'))
          return
        }
        setSession({ key: authorizationKey, data: sessionData.data })
        // End the loading state as early as possible so the page can render sooner
        setLoading(false)

        if (signal.aborted || currentAuthorizationKey.current !== authorizationKey) return

        // 2. Load the remaining data in parallel without blocking the main page render
        const fetchRelated = async () => {
          try {
            const res = await apiFetch(`/api/sessions/${id}/related`, { signal })
            const data: ApiResponse<EmailSession[]> = await res.json()
            return data.success && data.data ? data.data : []
          } catch { return [] }
        }

        const [related, security] = await Promise.all([
          fetchRelated(),
          fetchEmailSecurity(id, privacyHeaders, signal),
        ])
        if (signal.aborted || currentAuthorizationKey.current !== authorizationKey) return
        setRelatedSessions(related)
        if (security.verdict) setVerdict(security.verdict)
        setModuleResults(security.results)
      } catch (err) {
        if (signal.aborted || currentAuthorizationKey.current !== authorizationKey || (err instanceof DOMException && err.name === 'AbortError')) return
        setSession(null)
        setError(t('emailSecurity.networkError'))
      } finally {
        if (!signal.aborted && currentAuthorizationKey.current === authorizationKey) setLoading(false)
      }
    }

    fetchData()

    return () => controller.abort()
  }, [id, authorizationKey, t])

  // The engine emits a compact verdict only after the new result is persisted.
  // Use it as the fast path, then reload the full verdict and module evidence.
  useEffect(() => {
    if (!id) return

    const onSecurityVerdict = (event: Event) => {
      const detail = (event as CustomEvent<{ session_id?: unknown }>).detail
      if (!detail || detail.session_id !== id) return
      const wasRescanning = rescanActiveRef.current
        || rescanStatusRef.current === 'loading'
        || rescanStatusRef.current === 'analyzing'
      const eventRunId = rescanRunRef.current
      void refreshSecurity().then(security => {
        const isFreshVerdict = Boolean(
          security?.verdict && security.verdict.id !== rescanPreviousVerdictIdRef.current,
        )
        if (wasRescanning && isFreshVerdict && eventRunId === rescanRunRef.current) {
          rescanCompletedRef.current = true
          reportRescanStatus('done', eventRunId)
        }
      })
    }

    window.addEventListener(EVENTS.SECURITY_VERDICT, onSecurityVerdict)
    return () => window.removeEventListener(EVENTS.SECURITY_VERDICT, onSecurityVerdict)
  }, [id, refreshSecurity, reportRescanStatus])

  // Accordion: expand alert modules by default
  useEffect(() => {
    if (moduleResults.length > 0 && expandedModules === null) {
      const flagged = new Set<string>()
      moduleResults.forEach(m => {
        if (m.threat_level !== 'safe' || isModuleUnavailable(m)) flagged.add(m.module_id)
      })
      setExpandedModules(flagged)
    }
  }, [moduleResults, expandedModules])

  const toggleModuleExpand = (id: string) => {
    setExpandedModules(prev => {
      const next = new Set(prev ?? [])
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const copyLinkUrl = async (url: string, idx: number) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url)
      } else {
        const textarea = document.createElement('textarea')
        textarea.value = url
        textarea.setAttribute('readonly', 'true')
        textarea.style.position = 'fixed'
        textarea.style.left = '-9999px'
        document.body.appendChild(textarea)
        textarea.select()
        document.execCommand('copy')
        document.body.removeChild(textarea)
      }
      setCopiedLinkIndex(idx)
      window.setTimeout(() => {
        setCopiedLinkIndex(current => (current === idx ? null : current))
      }, 1500)
    } catch {
      setCopiedLinkIndex(null)
    }
  }

  const openOriginalLink = (url: string) => {
    if (!/^https?:\/\//i.test(url)) return
    if (!window.confirm(t('emailSecurity.confirmOpenOriginalLink'))) return
    const opened = window.open(url, '_blank', 'noopener,noreferrer')
    if (opened) opened.opener = null
  }

  const handleRescan = async () => {
    if (!id || rescanStatus === 'loading' || rescanStatus === 'analyzing') return
    const runId = rescanRunRef.current + 1
    rescanRunRef.current = runId
    rescanCompletedRef.current = false
    rescanActiveRef.current = true
    const previousVerdictId = verdict?.id
    rescanPreviousVerdictIdRef.current = previousVerdictId
    setRescanStatus('loading')
    try {
      const res = await apiFetch(`/api/sessions/${id}/rescan`, { method: 'POST' })
      const data: ApiResponse<{ status?: string }> = await res.json()
      if (!data.success) throw new Error(data.error || 'Rescan rejected')

      // POST only means that Redis accepted the job. Do not claim completion
      // until a newer verdict is visible in the database.
      // A very fast engine can publish the verdict before this POST returns.
      // Preserve the terminal state instead of overwriting it with analyzing.
      if (rescanCompletedRef.current) {
        reportRescanStatus('done', runId)
        return
      }
      setRescanStatus('analyzing')
      const deadline = Date.now() + RESCAN_MAX_WAIT_MS
      while (Date.now() < deadline && !rescanCompletedRef.current) {
        await new Promise(resolve => window.setTimeout(resolve, RESCAN_POLL_INTERVAL_MS))
        if (runId !== rescanRunRef.current || !mountedRef.current) return
        const security = await refreshSecurity()
        if (security?.verdict && security.verdict.id !== previousVerdictId) {
          rescanCompletedRef.current = true
          reportRescanStatus('done', runId)
          return
        }
      }
      if (!rescanCompletedRef.current) reportRescanStatus('error', runId)
    } catch (err) {
      console.error('Rescan failed:', err)
      reportRescanStatus('error', runId)
    }
  }

  const downloadAttachment = async (index: number, filename: string) => {
    if (!id) return
    try {
      const res = await apiFetch(`/api/sessions/${id}/attachments/${index}`, { headers: privacyHeaders })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      if (currentAuthorizationKey.current !== authorizationKey) return
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = decodeMimeWord(filename) || filename || `attachment-${index + 1}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Attachment download failed:', e)
    }
  }

  if (loading || (!session && !error)) {
    return (
      <div className="email-detail-loading">
        <div className="spinner"></div>
        <p>{t('emailSecurity.loadingEmailDetail')}</p>
      </div>
    )
  }

  if (error || !session) {
    return (
      <div className="email-detail-error">
        <div className="error-icon">⚠️</div>
        <h2>{t('emailSecurity.loadFailedTitle')}</h2>
        <p>{error || t('emailSecurity.sessionNotExist')}</p>
        <Link to={backToList} className="back-btn">{t('emailSecurity.backToList')}</Link>
      </div>
    )
  }

  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  if (isEncrypted) {
    return (
      <div className="email-detail-error">
        <div className="error-icon">🔒</div>
        <h2>{t('emailSecurity.encryptedEmailNotDisplayed')}</h2>
        <p>{t('emailSecurity.encryptedEmailHint')}</p>
        <Link to={backToList} className="back-btn">{t('emailSecurity.backToList')}</Link>
      </div>
    )
  }

  const smtpDialog = session.content?.smtp_dialog ?? []
  const displayContent = session.content
  const hasContent = displayContent?.body_text || displayContent?.body_html
  const attachmentCount = displayContent?.attachments?.length || 0
  const headerCount = session.content?.headers?.length || 0
  const linkCount = displayContent?.links?.length || 0
  const suspiciousLinkCount = displayContent?.links?.filter(l => l.suspicious).length || 0
  const inspectionIncomplete = verdict?.inspection_coverage === 'limited'
    || verdict?.categories.some(category =>
      ['inspection_incomplete', 'inspection_coverage_incomplete', 'inspection_execution_incomplete', 'inspection_quarantine_required', 'inspection_dependency_unavailable'].includes(category),
    )
    || (session.status === 'completed' && displayContent?.is_complete === false)
  const operationalAlert = moduleResults.some(
    module => module.module_id === 'link_scan' && module.details?.operational_alert === true,
  )
  const fallbackRiskByThreat: Record<string, number> = {
    safe: 0,
    low: 0.2,
    medium: 0.5,
    high: 0.75,
    critical: 0.95,
  }
  const riskPct = verdict
    ? Math.round((verdict.fusion_details?.risk_single ?? fallbackRiskByThreat[verdict.threat_level] ?? 0) * 100)
    : 0
  // Safe verdicts can still carry auditable observation categories (for
  // example invoice_spam, first_contact, or random_sender). Keep these
  // visible at the top of the detail page so "safe" is not mistaken for
  // "nothing was inspected"; the copy explicitly avoids changing threat
  // semantics or disposition.
  const observationCategories = verdict?.threat_level === 'safe'
    ? verdict.categories.filter(category => category.trim().length > 0)
    : []
  const safeHtmlPreview = displayContent?.body_html
    ? buildEmailPreviewDoc(displayContent.body_html)
    : ''

  // Mask SMTP AUTH credentials in dialog display
  const maskAuthCredentials = (cmd: string): string => {
    if (cmd.startsWith('AUTH PLAIN ')) return 'AUTH PLAIN ****'
    if (cmd === 'AUTH PLAIN') return cmd
    if (cmd.startsWith('AUTH LOGIN')) return cmd
    return cmd
  }

  return (
    <div className="email-detail-page">
      {/* === Two-column layout === */}
      <div className="ed-layout">

        {/* -- Left column: mail info + security badges -- */}
        <div className="ed-sidebar-wrap">
        <aside className={`ed-sidebar ${verdict ? `ed-sidebar--${verdict.threat_level}` : ''}`}>
          {/* Radar chart - pillar-score visualization */}
          {verdict && Object.keys(verdict.pillar_scores).length > 0 && (
            <div style={{ display: 'flex', justifyContent: 'center', margin: '0 0 -6px' }}>
              <RadarChart
                pillarPcts={Object.fromEntries(
                  Object.entries(verdict.pillar_scores).map(([k, v]) => [k, Math.round(v * 100)])
                )}
                riskPct={riskPct}
                threatLevel={verdict.threat_level}
                size={210}
              />
            </div>
          )}

          <h2 className="ed-subject" title={decodeMimeWord(session.subject) || t('emailSecurity.noSubject')}>
            {decodeMimeWord(session.subject) || t('emailSecurity.noSubject')}
          </h2>

          <div className="ed-badges">
            {verdict && (
              <>
                <span className={`ed-threat-tag ed-threat--${verdict.threat_level}`}>
                  {verdict.threat_level === 'safe' && (inspectionIncomplete || verdict.fusion_details?.primary_result?.epistemic_state === 'unknown') ? t('emailSecurity.threatUncertain') : THREAT_CN[verdict.threat_level] || verdict.threat_level}
                </span>
                <span className="ed-risk-tag">
                  {t('emailSecurity.overallRisk')} {riskPct}%
                </span>
                {threatTypeLabel(verdict.threat_type) && (
                  <span className="ed-risk-tag">
                    {t('emailSecurity.threatTypeLabel')}: {threatTypeLabel(verdict.threat_type)}
                  </span>
                )}
                {classificationLabel(verdict.classification) && (
                  <span className="ed-risk-tag">
                    {t('emailSecurity.classificationLabel')}: {classificationLabel(verdict.classification)}
                  </span>
                )}
              </>
            )}
            <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>{session.protocol}</span>
            <span className={`status-badge ${session.status}`}>
              {session.status === 'active' ? t('emailSecurity.statusActive') : session.status === 'completed' ? t('emailSecurity.statusCompleted') : session.status === 'timeout' ? t('emailSecurity.statusTimeout') : t('emailSecurity.statusError')}
            </span>
          </div>

          {observationCategories.length > 0 && (
            <div
              data-testid="observation-signals"
              style={{
                marginTop: 10,
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid rgba(96,165,250,0.28)',
                background: 'rgba(59,130,246,0.07)',
                color: 'rgba(255,255,255,0.58)',
                fontSize: 11,
                lineHeight: 1.5,
              }}
            >
              <div style={{ color: '#93c5fd', fontWeight: 600 }}>
                {t('emailSecurity.observationSignalsTitle')}
              </div>
              <div style={{ marginTop: 3 }}>
                {observationCategories.map(categoryLabel).join('、')}
              </div>
              <div style={{ marginTop: 3, color: 'rgba(255,255,255,0.38)' }}>
                {t('emailSecurity.observationSignalsAdvisory')}
              </div>
            </div>
          )}

          <div className="ed-meta-list">
            <div className="ed-meta-item">
              <span className="ed-meta-label">{t('emailSecurity.sender')}</span>
              <span className="ed-meta-value ed-mono">{session.mail_from || t('emailSecurity.unknown')}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">{t('emailSecurity.recipient')}</span>
              <span className="ed-meta-value ed-mono">{session.rcpt_to.length > 0 ? session.rcpt_to.join('; ') : t('emailSecurity.unknown')}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">{t('emailSecurity.time')}</span>
              <span className="ed-meta-value">{formatDateFull(session.started_at)}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">{t('emailSecurity.size')}</span>
              <span className="ed-meta-value">{formatBytes(session.total_bytes)}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">{t('emailSecurity.packets')}</span>
              <span className="ed-meta-value">{session.packet_count}</span>
            </div>
            {linkCount > 0 && (
              <div className="ed-meta-item">
                <span className="ed-meta-label">{t('emailSecurity.links')}</span>
                <span className={`ed-meta-value ${suspiciousLinkCount > 0 ? 'ed-meta-warn' : ''}`}>
                  {t('emailSecurity.linkCount', { count: linkCount })}{suspiciousLinkCount > 0 && ` (${t('emailSecurity.suspiciousCount', { count: suspiciousLinkCount })})`}
                </span>
              </div>
            )}
          </div>

          <div className="ed-conn">
            <span className="ed-conn-val ed-mono">
              {session.client_ip}:{session.client_port} → {session.server_ip}:{session.server_port}
            </span>
            {isEncrypted && <span className="ed-conn-tag ed-conn-tls">TLS</span>}
            {!isEncrypted && session.protocol === 'SMTP' && <span className="ed-conn-tag ed-conn-plain">{t('emailSecurity.plaintext')}</span>}
          </div>

          {/* SMTP authentication info */}
          {session.auth_info && (
            <div className="ed-auth">
              <span className="ed-meta-label">{t('emailSecurity.smtpAuth')}</span>
              <code className="ed-mono">{session.auth_info.auth_method}</code>
              {session.auth_info.username && <span className="ed-mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{session.auth_info.username}</span>}
            </div>
          )}

          {/* Encryption/plaintext warning */}
          {isEncrypted && (
            <div className="ed-banner ed-banner--tls">{t('emailSecurity.tlsEncryptedBanner')}</div>
          )}
          {!isEncrypted && session.protocol === 'SMTP' && !session.server_ip.startsWith('10.') && !session.server_ip.startsWith('192.168.') && (
            <div className="ed-banner ed-banner--warn">{t('emailSecurity.plaintextBanner')}</div>
          )}
          {inspectionIncomplete && (
            <div className="ed-banner ed-banner--warn" role="status">
              <strong>{t('emailSecurity.inspectionIncompleteTitle')}</strong>
              <div>{t('emailSecurity.inspectionIncompleteMessage')}</div>
            </div>
          )}
          {operationalAlert && (
            <div className="ed-banner ed-banner--info" role="status">
              <strong>{t('emailSecurity.operationalAlertTitle')}</strong>
              <div>{t('emailSecurity.operationalAlertMessage')}</div>
            </div>
          )}

          {/* Content navigation */}
          <nav className="ed-nav">
            {[
              { key: 'content', label: t('emailSecurity.tabBody'), count: 0 },
              { key: 'headers', label: t('emailSecurity.tabHeaders'), count: headerCount },
              { key: 'attachments', label: t('emailSecurity.tabAttachments'), count: attachmentCount },
              { key: 'smtp-dialog', label: t('emailSecurity.tabSmtpDialog'), count: smtpDialog.length },
              { key: 'security', label: t('emailSecurity.tabSecurityAnalysis'), count: 0 },
            ].map(item => (
              <button
                key={item.key}
                className={`ed-nav-item ${activeTab === item.key ? 'ed-nav-item--active' : ''}`}
                onClick={() => setActiveTab(item.key as typeof activeTab)}
              >
                <span>{item.label}</span>
                {item.count > 0 && <span className="ed-nav-count">{item.count}</span>}
              </button>
            ))}
          </nav>

          {/* Related sessions */}
          {relatedSessions.length > 0 && (
            <div className="ed-related">
              <span className="ed-meta-label">{t('emailSecurity.originalSource')}</span>
              {relatedSessions.map(rel => (
                <Link key={rel.id} to={detailLink(rel.id)} className="ed-related-link">
                  {rel.client_ip} → {rel.server_ip}:{rel.server_port}
                  {rel.content?.is_encrypted && ' 🔒'}
                </Link>
              ))}
            </div>
          )}
        </aside>
        </div>{/* ed-sidebar-wrap */}

        {/* -- Right side: tabs + content -- */}
        <div className="ed-main">

      {session.privacy?.state === 'redacted' && id && (
        <PrivacyAccessPanel
          resource={{ resource_type: 'session', resource_id: id }}
          defaultScopes={[...EMAIL_PRIVACY_SCOPES]}
          onLeaseReady={() => void privacyAccess.refresh()}
        />
      )}

      {/* Tab navigation */}
      <div className="detail-tabs">
        <button
          className={`detail-tab ${activeTab === 'content' ? 'active' : ''}`}
          onClick={() => setActiveTab('content')}
        >
          {t('emailSecurity.tabBody')}
        </button>
        <button
          className={`detail-tab ${activeTab === 'headers' ? 'active' : ''}`}
          onClick={() => setActiveTab('headers')}
        >
          {t('emailSecurity.tabHeaders')} ({headerCount})
        </button>
        <button
          className={`detail-tab ${activeTab === 'attachments' ? 'active' : ''}`}
          onClick={() => setActiveTab('attachments')}
        >
          {t('emailSecurity.tabAttachments')} ({attachmentCount})
        </button>
        <button
          className={`detail-tab ${activeTab === 'smtp-dialog' ? 'active' : ''}`}
          onClick={() => setActiveTab('smtp-dialog')}
        >
          {t('emailSecurity.tabSmtpDialog')} ({smtpDialog.length})
        </button>
        <button
          className={`detail-tab ${activeTab === 'security' ? 'active' : ''} ${verdict ? (verdict.threat_level === 'high' || verdict.threat_level === 'critical' ? 'tab-danger' : '') : ''}`}
          onClick={() => setActiveTab('security')}
        >
          {t('emailSecurity.tabSecurityAnalysis')} {verdict && (
            <span style={{
              marginLeft: 4,
              padding: '1px 6px',
              borderRadius: 8,
              fontSize: '0.75rem',
              backgroundColor: threatLevelBg(verdict.threat_level),
              color: '#fff',
            }}>
              {verdict.threat_level}
            </span>
          )}
        </button>
        {/* Divider */}
        <div className="detail-tabs-sep" />
        {/* Right-side actions */}
        <div className="detail-tab-actions">
          <button className="ed-fb-btn" onClick={() => setFeedbackOpen(true)}>
            {t('emailSecurity.feedbackReviewAction')}
          </button>
          <button
            className={`ed-rescan-btn ed-rescan-btn--${rescanStatus}`}
            disabled={rescanStatus === 'loading'}
            onClick={handleRescan}
            title={t('emailSecurity.rescanTitle')}
          >
            {rescanStatus === 'idle' && t('emailSecurity.rescanIdle')}
            {rescanStatus === 'loading' && t('emailSecurity.rescanSubmitting')}
            {rescanStatus === 'analyzing' && t('emailSecurity.rescanAnalyzing')}
            {rescanStatus === 'done' && t('emailSecurity.rescanDone')}
            {rescanStatus === 'error' && t('emailSecurity.rescanError')}
          </button>
          {/* Whitelist false-positive button */}
          {session && session.mail_from && (
            <button
              className={`ed-wl-btn ed-wl-btn--${whitelistStatus}`}
              disabled={whitelistStatus === 'loading' || whitelistStatus === 'done'}
              title={t('emailSecurity.whitelistTitle', { email: session.mail_from, ip: session.client_ip })}
              onClick={async () => {
                setWhitelistStatus('loading')
                try {
                  const res = await apiFetch(`/api/sessions/${id}/whitelist`, { method: 'POST' })
                  const data: ApiResponse<{ session_id: string }> = await res.json()
                  if (!data.success) throw new Error(data.error || 'Whitelist rejected')
                  setWhitelistStatus('done')
                } catch (e) {
                  console.error('Whitelist failed:', e)
                  setWhitelistStatus('error')
                  window.setTimeout(() => setWhitelistStatus('idle'), 2500)
                }
              }}
            >
              {whitelistStatus === 'loading' ? '...' : whitelistStatus === 'done' ? t('emailSecurity.whitelistDone') : whitelistStatus === 'error' ? t('emailSecurity.whitelistError') : t('emailSecurity.whitelistAction')}
            </button>
          )}
          <button
            className="detail-tab ed-eml-btn"
            onClick={async () => {
              try {
                const res = await apiFetch(`/api/sessions/${id}/eml`, { headers: privacyHeaders })
                if (!res.ok) throw new Error(`HTTP ${res.status}`)
                const blob = await res.blob()
                if (currentAuthorizationKey.current !== authorizationKey) return
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `${id}.eml`
                a.click()
                URL.revokeObjectURL(url)
              } catch (e) {
                console.error('EML download failed:', e)
              }
            }}
            title={t('emailSecurity.downloadEml')}
          >
            📥 EML
          </button>
        </div>
      </div>

      {id && <FeedbackPanel key={id} sessionId={id} verdict={verdict} open={feedbackOpen}
        onClose={() => setFeedbackOpen(false)} onRefreshVerdict={refreshSecurity} />}

      {/* Content area */}
      <div className="detail-content">
        {/* Message body */}
        {activeTab === 'content' && (
          <div className="content-section">
            {isEncrypted ? (
              <div className="no-content-notice">
                <div className="notice-icon">🔒</div>
                <h3>{t('emailSecurity.encryptedNoBody')}</h3>
                <p>{t('emailSecurity.encryptedNoBodyHint')}</p>
              </div>
            ) : !hasContent ? (
              <div className="no-content-notice">
                <div className="notice-icon">📄</div>
                <h3>{t('emailSecurity.noBodyYet')}</h3>
                <p>{t('emailSecurity.noBodyHint')}</p>
              </div>
            ) : (
              <>
                {displayContent?.body_html ? (
                  <div className="email-body-container">
                    <div className="body-header">
                      <span className="body-type-badge html">{t('emailSecurity.htmlSafePreview')}</span>
                      {displayContent?.body_text && (
                        <span className="body-type-hint">{t('emailSecurity.alsoHasPlaintext')}</span>
                      )}
                    </div>
                    <div className="email-html-body">
                      {/* SEC: sandbox="" uses the strictest mode - no scripts, same-origin access, forms, or popups
                          Do not use allow-same-origin, or malicious mail CSS could read data from the parent page */}
                      <iframe
                        srcDoc={safeHtmlPreview}
                        sandbox=""
                        title={t('emailSecurity.emailContent')}
                        referrerPolicy="no-referrer"
                      />
                    </div>
                  </div>
                ) : displayContent?.body_text ? (
                  <div className="email-body-container">
                    <div className="body-header">
                      <span className="body-type-badge text">{t('emailSecurity.plainTextFormat')}</span>
                    </div>
                    <div className="email-text-body">
                      <pre>{displayContent.body_text}</pre>
                    </div>
                  </div>
                ) : null}

                {/* Links inside the message */}
                {displayContent?.links && displayContent.links.length > 0 && (
                  <div className="email-links-section">
                    <h3 className="section-title">
                      {t('emailSecurity.linksInEmail', { count: displayContent.links.length })}
                      {suspiciousLinkCount > 0 && (
                        <span className="warning-badge">{t('emailSecurity.suspiciousLinks', { count: suspiciousLinkCount })}</span>
                      )}
                    </h3>
                    <div className="links-list">
                      {displayContent.links.map((link, idx) => (
                        <div key={idx} className={`link-item ${link.suspicious ? 'suspicious' : ''}`}>
                          {link.suspicious && <span className="suspicious-icon">⚠️</span>}
                          <div className="link-content">
                            <span className="link-url" title={link.url}>
                              {link.url}
                            </span>
                            {link.text && link.text !== link.url && (
                              <span className="link-text">{t('emailSecurity.displayText')}: {link.text}</span>
                            )}
                          </div>
                          <div className="link-actions">
                            <button
                              type="button"
                              className="link-action-btn"
                              onClick={() => copyLinkUrl(link.url, idx)}
                            >
                              {copiedLinkIndex === idx ? t('emailSecurity.copiedLink') : t('emailSecurity.copyLink')}
                            </button>
                            {/^https?:\/\//i.test(link.url) && (
                              <button
                                type="button"
                                className="link-action-btn link-action-btn--danger"
                                onClick={() => openOriginalLink(link.url)}
                              >
                                {t('emailSecurity.openOriginalLink')}
                              </button>
                            )}
                          </div>
                          {link.suspicious && (
                            <span className="suspicious-badge">{t('emailSecurity.suspiciousLink')}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Message headers */}
        {activeTab === 'headers' && (
          <div className="headers-section">
            {session.content?.headers && session.content.headers.length > 0 ? (
              <div className="headers-list">
                {session.content.headers.map(([name, value], idx) => (
                  <div key={idx} className="header-item">
                    <span className="header-name">{name}</span>
                    <span className="header-value">{value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-data-notice">
                <p>{t('emailSecurity.noHeaders')}</p>
              </div>
            )}
          </div>
        )}

        {/* Attachments */}
        {activeTab === 'attachments' && (
          <div className="attachments-section">
            {displayContent?.attachments && displayContent.attachments.length > 0 ? (
              <div className="attachments-grid">
                {displayContent.attachments.map((att, idx) => (
                  <div key={idx} className="attachment-card">
                    <div className="attachment-icon">
                      {getFileIcon(att.content_type)}
                    </div>
                    <div className="attachment-details">
                      <div className="attachment-name">{decodeMimeWord(att.filename) || att.filename}</div>
                      <div className="attachment-meta">
                        <span className="attachment-type">{att.content_type}</span>
                        <span className="attachment-size">{formatBytes(att.size)}</span>
                      </div>
                      <div className="attachment-hash" title={att.hash}>
                        SHA256: {att.hash.substring(0, 32)}...
                      </div>
                      {att.size <= MAX_ATTACHMENT_DOWNLOAD_BYTES ? (
                        <button
                          className="attachment-download-btn"
                          onClick={() => downloadAttachment(idx, att.filename)}
                        >
                          {t('emailSecurity.downloadAttachment')}
                        </button>
                      ) : (
                        <span className="attachment-no-data">{t('emailSecurity.attachmentUnavailable')}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-data-notice">
                <div className="notice-icon">📎</div>
                <p>{t('emailSecurity.noAttachments')}</p>
              </div>
            )}
          </div>
        )}

        {/* SMTP dialogue */}
        {activeTab === 'smtp-dialog' && (
          <div className="smtp-dialog-section">
            {smtpDialog.length > 0 ? (
              <div className="smtp-dialog-timeline">
                {smtpDialog.map((entry, idx) => {
                  const isClient = entry.direction === 'outbound'
                  const command = entry.command
                  const isEhlo = /^EHLO/i.test(command)
                  const isStartTls = /^STARTTLS/i.test(command)
                  const isData = /^\[DATA/.test(command)

                  return (
                    <div
                      key={idx}
                      className={`smtp-dialog-item ${isClient ? 'client' : 'server'} ${isStartTls ? 'starttls' : ''} ${isEhlo ? 'ehlo' : ''}`}
                    >
                      <div className="dialog-meta">
                        <span className={`dialog-role ${isClient ? 'client' : 'server'}`}>
                          {isClient ? 'C' : 'S'}
                        </span>
                        <span className="dialog-time">
                          {formatClockTime(entry.timestamp)}
                        </span>
                        <span className="dialog-size">{formatBytes(entry.size)}</span>
                      </div>
                      <div className="dialog-content">
                        {command && !isData && (
                          <div className={`dialog-command ${isStartTls ? 'highlight-starttls' : ''}`}>
                            <code>{maskAuthCredentials(command)}</code>
                          </div>
                        )}
                        {isData && (
                          <div className="dialog-command data-indicator">
                            <code>{maskAuthCredentials(command)}</code>
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}

                {/* STARTTLS analysis summary */}
                {session.protocol === 'SMTP' && (
                  <div className="smtp-analysis-summary">
                    <h4>{t('emailSecurity.smtpSecurityAnalysis')}</h4>
                    <div className="analysis-items">
                      {(() => {
                        const ehloResponse = smtpDialog.find(p =>
                          p.direction === 'inbound' && /^250/.test(p.command)
                        )
                        const hasStartTlsCap = ehloResponse?.command?.toUpperCase().includes('STARTTLS') ?? false
                        const clientSentStartTls = smtpDialog.some(p =>
                          p.direction === 'outbound' && /^STARTTLS/i.test(p.command)
                        )
                        return (
                          <>
                            <div className={`analysis-item ${hasStartTlsCap ? 'good' : 'warn'}`}>
                              <span className="analysis-icon">{hasStartTlsCap ? '✓' : '✗'}</span>
                              <span>{hasStartTlsCap ? t('emailSecurity.serverSupportsStarttls') : t('emailSecurity.serverNoStarttls')}</span>
                            </div>
                            <div className={`analysis-item ${clientSentStartTls ? 'good' : isEncrypted ? 'good' : 'warn'}`}>
                              <span className="analysis-icon">
                                {clientSentStartTls ? '✓' : isEncrypted ? '✓' : '✗'}
                              </span>
                              <span>
                                {clientSentStartTls
                                  ? t('emailSecurity.clientInitiatedStarttls')
                                  : isEncrypted
                                    ? t('emailSecurity.implicitTls')
                                    : hasStartTlsCap
                                      ? t('emailSecurity.clientSkippedStarttls')
                                      : t('emailSecurity.connectionUnencrypted')}
                              </span>
                            </div>
                            <div className={`analysis-item ${isEncrypted ? 'good' : 'warn'}`}>
                              <span className="analysis-icon">{isEncrypted ? '🔒' : '⚠️'}</span>
                              <span>{isEncrypted ? t('emailSecurity.emailEncryptedTransmit') : t('emailSecurity.emailPlaintextTransmit')}</span>
                            </div>
                            {session.auth_info && (
                              <div className={`analysis-item ${session.auth_info.auth_success ? 'good' : 'warn'}`}>
                                <span className="analysis-icon">&#128273;</span>
                                <span>
                                  SMTP AUTH {session.auth_info.auth_method} {t('emailSecurity.login')}
                                  {session.auth_info.username ? ` (${session.auth_info.username})` : ''}
                                  {!isEncrypted && ` - ${t('emailSecurity.credentialsPlaintext')}`}
                                </span>
                              </div>
                            )}
                          </>
                        )
                      })()}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="no-data-notice">
                <p>{t('emailSecurity.noSmtpDialog')}</p>
              </div>
            )}
          </div>
        )}

        {/* Security analysis - use the new visualization components */}
        {activeTab === 'security' && (
          <SecurityAnalysisView
            verdict={verdict}
            moduleResults={moduleResults}
            expandedModules={expandedModules}
            toggleModuleExpand={toggleModuleExpand}
            onOpenFeedback={() => setFeedbackOpen(true)}
          />
        )}
        {/* old security analysis code removed */}
        </div>{/* detail-content */}
        </div>{/* ed-main */}
      </div>{/* ed-layout */}
    </div>
  )
}

function threatLevelBg(level: string): string {
  switch (level) {
    case 'critical': return '#dc2626'
    case 'high': return '#ea580c'
    case 'medium': return '#ca8a04'
    case 'low': return '#2563eb'
    case 'safe': return '#16a34a'
    default: return '#6b7280'
  }
}
