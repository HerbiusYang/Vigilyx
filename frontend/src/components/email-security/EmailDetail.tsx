import { useState, useEffect } from 'react'
import { useLocation, useParams, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { EmailSession, ApiResponse, SecurityVerdict, ModuleResult } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatClockTime, formatDateFull, getFileIcon, isEncryptedPort } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { buildEmailPreviewDoc } from '../../utils/emailHtml'
import SecurityAnalysisView, { RadarChart } from './SecurityAnalysisView'

export default function EmailDetail() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const location = useLocation()
  const [session, setSession] = useState<EmailSession | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'content' | 'headers' | 'attachments' | 'smtp-dialog' | 'security'>('content')
  const [relatedSessions, setRelatedSessions] = useState<EmailSession[]>([])
  const [expandedModules, setExpandedModules] = useState<Set<string> | null>(null)
  const [verdict, setVerdict] = useState<SecurityVerdict | null>(null)
  const [moduleResults, setModuleResults] = useState<ModuleResult[]>([])
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false)
  const [feedbackDone, setFeedbackDone] = useState(false)
  const [feedbackType, setFeedbackType] = useState<'legitimate' | 'phishing' | 'spoofing' | 'social_engineering' | 'other_threat' | null>(null)
  const [feedbackComment, setFeedbackComment] = useState('')
  const [whitelistStatus, setWhitelistStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const fromSearch = new URLSearchParams(location.search).get('from') || ''
  const listSearch = fromSearch.startsWith('?') ? fromSearch : fromSearch ? `?${fromSearch}` : ''
  const backToList = `/emails${listSearch}`
  const detailLink = (sessionId: string) =>
    `/emails/${sessionId}${fromSearch ? `?from=${encodeURIComponent(listSearch)}` : ''}`

  const THREAT_CN: Record<string, string> = {
    safe: t('emailSecurity.threat_safe'), low: t('emailSecurity.threat_low'), medium: t('emailSecurity.threat_medium'), high: t('emailSecurity.threat_high'), critical: t('emailSecurity.threat_critical'),
  }

  useEffect(() => {
    if (!id) return

    const controller = new AbortController()
    const signal = controller.signal

    const fetchData = async () => {
      try {
        // 1. Fetch session details first because they determine whether the page can render
        const sessionRes = await apiFetch(`/api/sessions/${id}`, { signal })
        const sessionData: ApiResponse<EmailSession> = await sessionRes.json()

        if (!sessionData.success || !sessionData.data) {
          setError(t('emailSecurity.cannotLoadSession'))
          return
        }
        setSession(sessionData.data)
        // End the loading state as early as possible so the page can render sooner
        setLoading(false)

        if (signal.aborted) return

        // 2. Load the remaining data in parallel without blocking the main page render
        const fetchRelated = async () => {
          try {
            const res = await apiFetch(`/api/sessions/${id}/related`, { signal })
            const data: ApiResponse<EmailSession[]> = await res.json()
            return data.success && data.data ? data.data : []
          } catch { return [] }
        }

        const fetchSecurity = async () => {
          try {
            const [vRes, rRes] = await Promise.all([
              apiFetch(`/api/sessions/${id}/verdict`, { signal }),
              apiFetch(`/api/sessions/${id}/security-results`, { signal }),
            ])
            const vData: ApiResponse<SecurityVerdict> = await vRes.json()
            const rData: ApiResponse<ModuleResult[]> = await rRes.json()
            return {
              verdict: vData.success && vData.data ? vData.data : null,
              results: rData.success && rData.data ? rData.data : [],
            }
          } catch { return { verdict: null, results: [] as ModuleResult[] } }
        }

        const [related, security] = await Promise.all([fetchRelated(), fetchSecurity()])
        if (signal.aborted) return
        setRelatedSessions(related)
        if (security.verdict) setVerdict(security.verdict)
        if (security.results.length > 0) setModuleResults(security.results)
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return
        setError(t('emailSecurity.networkError'))
      } finally {
        if (!signal.aborted) setLoading(false)
      }
    }

    fetchData()

    return () => controller.abort()
  }, [id, t])

  // Accordion: expand alert modules by default
  useEffect(() => {
    if (moduleResults.length > 0 && expandedModules === null) {
      const flagged = new Set<string>()
      moduleResults.forEach(m => {
        if (m.threat_level !== 'safe') flagged.add(m.module_id)
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

  if (loading) {
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
  const riskPct = verdict
    ? Math.round((verdict.fusion_details?.risk_single ?? verdict.confidence) * 100)
    : 0
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

  const senderShort = (session.mail_from || t('emailSecurity.unknown')).split('@')[0]

  return (
    <div className="email-detail-page">
      {/* Breadcrumb navigation */}
      <nav className="ed-breadcrumb">
        <Link to={backToList} className="ed-bc-link">{t('emailSecurity.breadcrumbSecurity')}</Link>
        <span className="ed-bc-sep">/</span>
        <Link to={backToList} className="ed-bc-link">{t('emailSecurity.breadcrumbList')}</Link>
        <span className="ed-bc-sep">/</span>
        <span className="ed-bc-current" title={session.mail_from || ''}>{senderShort}</span>
      </nav>

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
                  {THREAT_CN[verdict.threat_level] || verdict.threat_level}
                </span>
                <span className="ed-risk-tag">
                  {t('emailSecurity.overallRisk')} {riskPct}%
                </span>
              </>
            )}
            <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>{session.protocol}</span>
            <span className={`status-badge ${session.status}`}>
              {session.status === 'active' ? t('emailSecurity.statusActive') : session.status === 'completed' ? t('emailSecurity.statusCompleted') : session.status === 'timeout' ? t('emailSecurity.statusTimeout') : t('emailSecurity.statusError')}
            </span>
          </div>

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
          {/* Feedback button group - click once to submit */}
          {!feedbackDone && (
            <div className="ed-fb-inline">
              {([
                ['legitimate', t('emailSecurity.feedbackLegitimate')],
                ['phishing', t('emailSecurity.feedbackPhishing')],
                ['spoofing', t('emailSecurity.feedbackSpoofing')],
                ['social_engineering', t('emailSecurity.feedbackSocialEng')],
                ['other_threat', t('emailSecurity.feedbackOther')],
              ] as const).map(([val, label]) => (
                <button
                  key={val}
                  className={`ed-fb-btn ${feedbackType === val ? 'ed-fb-btn--active' : ''}`}
                  disabled={feedbackSubmitting}
                  onClick={async () => {
                    setFeedbackType(val)
                    setFeedbackSubmitting(true)
                    try {
                      const resp = await apiFetch(`/api/sessions/${id}/feedback`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ feedback_type: val, comment: feedbackComment || null }),
                      })
                      if (resp.ok) setFeedbackDone(true)
                    } catch (e) {
                      console.error('Failed to submit feedback:', e)
                    } finally {
                      setFeedbackSubmitting(false)
                    }
                  }}
                >{label}</button>
              ))}
            </div>
          )}
          {feedbackDone && <span className="ed-fb-done">{t('emailSecurity.feedbackDone')}: {feedbackType === 'legitimate' ? t('emailSecurity.feedbackLegitimate') : feedbackType === 'phishing' ? t('emailSecurity.feedbackPhishing') : feedbackType === 'spoofing' ? t('emailSecurity.feedbackSpoofing') : feedbackType === 'social_engineering' ? t('emailSecurity.feedbackSocialEng') : t('emailSecurity.feedbackOther')}</span>}
          {/* Whitelist false-positive button */}
          {session && session.mail_from && (
            <button
              className={`ed-wl-btn ${whitelistStatus === 'done' ? 'ed-wl-btn--done' : ''}`}
              disabled={whitelistStatus === 'loading' || whitelistStatus === 'done'}
              title={t('emailSecurity.whitelistTitle', { domain: session.mail_from?.split('@')[1], ip: session.client_ip })}
              onClick={async () => {
                setWhitelistStatus('loading')
                const domain = session.mail_from?.split('@')[1]
                const ip = session.client_ip
                try {
                  const promises: Promise<Response>[] = []
                  if (domain) {
                    promises.push(apiFetch('/api/security/whitelist', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ entry_type: 'domain', value: domain, description: t('emailSecurity.whitelistDesc', { id }) }),
                    }))
                  }
                  if (ip) {
                    promises.push(apiFetch('/api/security/whitelist', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ entry_type: 'ip', value: ip, description: t('emailSecurity.whitelistDesc', { id }) }),
                    }))
                  }
                  await Promise.all(promises)
                  setWhitelistStatus('done')
                } catch (e) {
                  console.error('Whitelist failed:', e)
                  setWhitelistStatus('error')
                }
              }}
            >
              {whitelistStatus === 'loading' ? '...' : whitelistStatus === 'done' ? t('emailSecurity.whitelistDone') : t('emailSecurity.whitelistAction')}
            </button>
          )}
          <button
            className="detail-tab ed-eml-btn"
            onClick={async () => {
              try {
                const res = await fetch(`/api/sessions/${id}/eml`, {
                  credentials: 'same-origin',
                })
                if (!res.ok) throw new Error(`HTTP ${res.status}`)
                const blob = await res.blob()
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
                            <a href={/^https?:\/\//i.test(link.url) ? link.url : '#'} target="_blank" rel="noopener noreferrer" className="link-url">
                              {link.url}
                            </a>
                            {link.text && link.text !== link.url && (
                              <span className="link-text">{t('emailSecurity.displayText')}: {link.text}</span>
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
                      {att.content_base64 ? (
                        <button
                          className="attachment-download-btn"
                          onClick={() => {
                            const byteChars = atob(att.content_base64!)
                            const byteArray = new Uint8Array(byteChars.length)
                            for (let i = 0; i < byteChars.length; i++) {
                              byteArray[i] = byteChars.charCodeAt(i)
                            }
                            const blob = new Blob([byteArray], { type: att.content_type })
                            const url = URL.createObjectURL(blob)
                            const a = document.createElement('a')
                            a.href = url
                            a.download = decodeMimeWord(att.filename) || att.filename
                            a.click()
                            URL.revokeObjectURL(url)
                          }}
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
            feedbackDone={feedbackDone}
            feedbackType={feedbackType}
            feedbackComment={feedbackComment}
            feedbackSubmitting={feedbackSubmitting}
            setFeedbackType={setFeedbackType}
            setFeedbackComment={setFeedbackComment}
            submitFeedback={async () => {
              setFeedbackSubmitting(true)
              try {
                const resp = await apiFetch(`/api/sessions/${id}/feedback`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ feedback_type: feedbackType, comment: feedbackComment || null }),
                })
                if (resp.ok) setFeedbackDone(true)
              } catch (e) {
                console.error('Failed to submit feedback:', e)
              } finally {
                setFeedbackSubmitting(false)
              }
            }}
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
