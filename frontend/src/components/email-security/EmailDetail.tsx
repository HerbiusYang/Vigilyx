import { useState, useEffect } from 'react'
import { useLocation, useParams, Link } from 'react-router-dom'
import type { EmailSession, ApiResponse, SecurityVerdict, ModuleResult } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatDateFull, isEncryptedPort, getFileIcon } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { buildEmailPreviewDoc } from '../../utils/emailHtml'
import SecurityAnalysisView, { RadarChart } from './SecurityAnalysisView'

const THREAT_CN: Record<string, string> = {
  safe: '安全', low: '低危', medium: '中危', high: '高危', critical: '危急',
}

export default function EmailDetail() {
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
          setError('无法加载会话信息')
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
        setError('网络错误')
      } finally {
        if (!signal.aborted) setLoading(false)
      }
    }

    fetchData()

    return () => controller.abort()
  }, [id])

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
        <p>加载邮件详情...</p>
      </div>
    )
  }

  if (error || !session) {
    return (
      <div className="email-detail-error">
        <div className="error-icon">⚠️</div>
        <h2>加载失败</h2>
        <p>{error || '会话不存在'}</p>
        <Link to={backToList} className="back-btn">返回列表</Link>
      </div>
    )
  }

  const isEncrypted = session.content?.is_encrypted || isEncryptedPort(session.server_port)
  if (isEncrypted) {
    return (
      <div className="email-detail-error">
        <div className="error-icon">🔒</div>
        <h2>加密邮件不在页面展示</h2>
        <p>TLS 加密会话仅在日志中提示，不在 Web 页面展示邮件内容与详情。</p>
        <Link to={backToList} className="back-btn">返回列表</Link>
      </div>
    )
  }

  const smtpDialog = session.content?.smtp_dialog ?? []
  const hasContent = session.content?.body_text || session.content?.body_html
  const attachmentCount = session.content?.attachments?.length || 0
  const headerCount = session.content?.headers?.length || 0
  const linkCount = session.content?.links?.length || 0
  const suspiciousLinkCount = session.content?.links?.filter(l => l.suspicious).length || 0
  const riskPct = verdict
    ? Math.round((verdict.fusion_details?.risk_single ?? verdict.confidence) * 100)
    : 0
  const safeHtmlPreview = session.content?.body_html
    ? buildEmailPreviewDoc(session.content.body_html)
    : ''

  // Mask SMTP AUTH credentials in dialog display
  const maskAuthCredentials = (cmd: string): string => {
    if (cmd.startsWith('AUTH PLAIN ')) return 'AUTH PLAIN ****'
    if (cmd === 'AUTH PLAIN') return cmd
    if (cmd.startsWith('AUTH LOGIN')) return cmd
    return cmd
  }

  const senderShort = (session.mail_from || '未知').split('@')[0]

  return (
    <div className="email-detail-page">
      {/* Breadcrumb navigation */}
      <nav className="ed-breadcrumb">
        <Link to={backToList} className="ed-bc-link">邮件安全</Link>
        <span className="ed-bc-sep">/</span>
        <Link to={backToList} className="ed-bc-link">邮件列表</Link>
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

          <h2 className="ed-subject" title={decodeMimeWord(session.subject) || '(无主题)'}>
            {decodeMimeWord(session.subject) || '(无主题)'}
          </h2>

          <div className="ed-badges">
            {verdict && (
              <span className={`ed-threat-tag ed-threat--${verdict.threat_level}`}>
                {THREAT_CN[verdict.threat_level] || verdict.threat_level} {riskPct}%
              </span>
            )}
            <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>{session.protocol}</span>
            <span className={`status-badge ${session.status}`}>
              {session.status === 'active' ? '进行中' : session.status === 'completed' ? '已完成' : session.status === 'timeout' ? '超时' : '错误'}
            </span>
          </div>

          <div className="ed-meta-list">
            <div className="ed-meta-item">
              <span className="ed-meta-label">发件人</span>
              <span className="ed-meta-value ed-mono">{session.mail_from || '未知'}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">收件人</span>
              <span className="ed-meta-value ed-mono">{session.rcpt_to.length > 0 ? session.rcpt_to.join('; ') : '未知'}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">时间</span>
              <span className="ed-meta-value">{formatDateFull(session.started_at)}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">大小</span>
              <span className="ed-meta-value">{formatBytes(session.total_bytes)}</span>
            </div>
            <div className="ed-meta-item">
              <span className="ed-meta-label">数据包</span>
              <span className="ed-meta-value">{session.packet_count}</span>
            </div>
            {linkCount > 0 && (
              <div className="ed-meta-item">
                <span className="ed-meta-label">链接</span>
                <span className={`ed-meta-value ${suspiciousLinkCount > 0 ? 'ed-meta-warn' : ''}`}>
                  {linkCount} 个{suspiciousLinkCount > 0 && ` (${suspiciousLinkCount} 可疑)`}
                </span>
              </div>
            )}
          </div>

          <div className="ed-conn">
            <span className="ed-conn-val ed-mono">
              {session.client_ip}:{session.client_port} → {session.server_ip}:{session.server_port}
            </span>
            {isEncrypted && <span className="ed-conn-tag ed-conn-tls">TLS</span>}
            {!isEncrypted && session.protocol === 'SMTP' && <span className="ed-conn-tag ed-conn-plain">明文</span>}
          </div>

          {/* SMTP authentication info */}
          {session.auth_info && (
            <div className="ed-auth">
              <span className="ed-meta-label">SMTP 认证</span>
              <code className="ed-mono">{session.auth_info.auth_method}</code>
              {session.auth_info.username && <span className="ed-mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{session.auth_info.username}</span>}
            </div>
          )}

          {/* Encryption/plaintext warning */}
          {isEncrypted && (
            <div className="ed-banner ed-banner--tls">🔒 TLS 加密，内容无法解析</div>
          )}
          {!isEncrypted && session.protocol === 'SMTP' && !session.server_ip.startsWith('10.') && !session.server_ip.startsWith('192.168.') && (
            <div className="ed-banner ed-banner--warn">⚠ 明文传输</div>
          )}

          {/* Content navigation */}
          <nav className="ed-nav">
            {[
              { key: 'content', label: '邮件正文', count: 0 },
              { key: 'headers', label: '邮件头', count: headerCount },
              { key: 'attachments', label: '附件', count: attachmentCount },
              { key: 'smtp-dialog', label: 'SMTP 对话', count: smtpDialog.length },
              { key: 'security', label: '安全分析', count: 0 },
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
              <span className="ed-meta-label">原始来源</span>
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
          邮件正文
        </button>
        <button
          className={`detail-tab ${activeTab === 'headers' ? 'active' : ''}`}
          onClick={() => setActiveTab('headers')}
        >
          邮件头 ({headerCount})
        </button>
        <button
          className={`detail-tab ${activeTab === 'attachments' ? 'active' : ''}`}
          onClick={() => setActiveTab('attachments')}
        >
          附件 ({attachmentCount})
        </button>
        <button
          className={`detail-tab ${activeTab === 'smtp-dialog' ? 'active' : ''}`}
          onClick={() => setActiveTab('smtp-dialog')}
        >
          SMTP 对话 ({smtpDialog.length})
        </button>
        <button
          className={`detail-tab ${activeTab === 'security' ? 'active' : ''} ${verdict ? (verdict.threat_level === 'high' || verdict.threat_level === 'critical' ? 'tab-danger' : '') : ''}`}
          onClick={() => setActiveTab('security')}
        >
          安全分析 {verdict && (
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
                ['legitimate', '正常'],
                ['phishing', '钓鱼'],
                ['spoofing', '仿冒'],
                ['social_engineering', '社工'],
                ['other_threat', '其他'],
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
          {feedbackDone && <span className="ed-fb-done">已反馈: {feedbackType === 'legitimate' ? '正常' : feedbackType === 'phishing' ? '钓鱼' : feedbackType === 'spoofing' ? '仿冒' : feedbackType === 'social_engineering' ? '社工' : '其他'}</span>}
          {/* Whitelist false-positive button */}
          {session && session.mail_from && (
            <button
              className={`ed-wl-btn ${whitelistStatus === 'done' ? 'ed-wl-btn--done' : ''}`}
              disabled={whitelistStatus === 'loading' || whitelistStatus === 'done'}
              title={`将 ${session.mail_from?.split('@')[1]} 和发件 IP ${session.client_ip} 加入整封白名单，后续同域名+IP 邮件将直接跳过安全检测`}
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
                      body: JSON.stringify({ entry_type: 'domain', value: domain, description: `详情页整封加白 (session ${id})` }),
                    }))
                  }
                  if (ip) {
                    promises.push(apiFetch('/api/security/whitelist', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ entry_type: 'ip', value: ip, description: `详情页整封加白 (session ${id})` }),
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
              {whitelistStatus === 'loading' ? '...' : whitelistStatus === 'done' ? '已整封加白' : '整封加白'}
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
            title="下载 EML 文件"
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
                <h3>加密邮件不显示正文</h3>
                <p>TLS 加密会话仅保留日志与元数据，页面不展示邮件正文内容。</p>
              </div>
            ) : !hasContent ? (
              <div className="no-content-notice">
                <div className="notice-icon">📄</div>
                <h3>暂无邮件正文</h3>
                <p>邮件正文可能正在接收中，或者邮件没有正文内容</p>
              </div>
            ) : (
              <>
                {session.content?.body_html ? (
                  <div className="email-body-container">
                    <div className="body-header">
                      <span className="body-type-badge html">HTML 安全预览</span>
                      {session.content?.body_text && (
                        <span className="body-type-hint">同时包含纯文本版本</span>
                      )}
                    </div>
                    <div className="email-html-body">
                      {/* SEC: sandbox="" uses the strictest mode - no scripts, same-origin access, forms, or popups
                          Do not use allow-same-origin, or malicious mail CSS could read data from the parent page */}
                      <iframe
                        srcDoc={safeHtmlPreview}
                        sandbox=""
                        title="邮件内容"
                        referrerPolicy="no-referrer"
                      />
                    </div>
                  </div>
                ) : session.content?.body_text ? (
                  <div className="email-body-container">
                    <div className="body-header">
                      <span className="body-type-badge text">纯文本格式</span>
                    </div>
                    <div className="email-text-body">
                      <pre>{session.content.body_text}</pre>
                    </div>
                  </div>
                ) : null}

                {/* Links inside the message */}
                {session.content?.links && session.content.links.length > 0 && (
                  <div className="email-links-section">
                    <h3 className="section-title">
                      邮件中的链接 ({session.content.links.length})
                      {suspiciousLinkCount > 0 && (
                        <span className="warning-badge">{suspiciousLinkCount} 个可疑链接</span>
                      )}
                    </h3>
                    <div className="links-list">
                      {session.content.links.map((link, idx) => (
                        <div key={idx} className={`link-item ${link.suspicious ? 'suspicious' : ''}`}>
                          {link.suspicious && <span className="suspicious-icon">⚠️</span>}
                          <div className="link-content">
                            <a href={/^https?:\/\//i.test(link.url) ? link.url : '#'} target="_blank" rel="noopener noreferrer" className="link-url">
                              {link.url}
                            </a>
                            {link.text && link.text !== link.url && (
                              <span className="link-text">显示文本: {link.text}</span>
                            )}
                          </div>
                          {link.suspicious && (
                            <span className="suspicious-badge">可疑链接</span>
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
                <p>暂无邮件头信息</p>
              </div>
            )}
          </div>
        )}

        {/* Attachments */}
        {activeTab === 'attachments' && (
          <div className="attachments-section">
            {session.content?.attachments && session.content.attachments.length > 0 ? (
              <div className="attachments-grid">
                {session.content.attachments.map((att, idx) => (
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
                          下载附件
                        </button>
                      ) : (
                        <span className="attachment-no-data">附件数据不可用</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-data-notice">
                <div className="notice-icon">📎</div>
                <p>此邮件没有附件</p>
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
                          {new Date(entry.timestamp).toLocaleTimeString('zh-CN', {
                            hour: '2-digit', minute: '2-digit', second: '2-digit'
                          })}
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
                    <h4>SMTP 安全分析</h4>
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
                              <span>服务器{hasStartTlsCap ? '支持' : '未声明'} STARTTLS</span>
                            </div>
                            <div className={`analysis-item ${clientSentStartTls ? 'good' : isEncrypted ? 'good' : 'warn'}`}>
                              <span className="analysis-icon">
                                {clientSentStartTls ? '✓' : isEncrypted ? '✓' : '✗'}
                              </span>
                              <span>
                                {clientSentStartTls
                                  ? '客户端已发起 STARTTLS'
                                  : isEncrypted
                                    ? '连接使用隐式 TLS (端口 465)'
                                    : hasStartTlsCap
                                      ? '客户端未发起 STARTTLS (服务器支持但未使用)'
                                      : '连接未加密'}
                              </span>
                            </div>
                            <div className={`analysis-item ${isEncrypted ? 'good' : 'warn'}`}>
                              <span className="analysis-icon">{isEncrypted ? '🔒' : '⚠️'}</span>
                              <span>{isEncrypted ? '邮件通过加密通道传输' : '邮件以明文传输'}</span>
                            </div>
                            {session.auth_info && (
                              <div className={`analysis-item ${session.auth_info.auth_success ? 'good' : 'warn'}`}>
                                <span className="analysis-icon">&#128273;</span>
                                <span>
                                  SMTP AUTH {session.auth_info.auth_method} 登录
                                  {session.auth_info.username ? ` (${session.auth_info.username})` : ''}
                                  {!isEncrypted && ' - 凭据以明文传输!'}
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
                <p>暂无 SMTP 对话数据</p>
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
