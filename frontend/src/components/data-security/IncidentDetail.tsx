import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import type { DataSecurityIncident, HttpSessionItem, ApiResponse, Evidence } from '../../types'
import { apiFetch } from '../../utils/api'
import { formatRelativeTime, formatSize } from '../../utils/format'
import {
  SEVERITY_COLOR, SEVERITY_CN,
  DLP_MATCH_CN, DLP_JRT_LEVEL, JRT_LEVEL_COLOR, JRT_LEVEL_LABEL,
  getMaskedBody, getMaskedSnippet,
} from './constants'
import { maskIp, maskUser, maskUrl, getDownloadName } from './helpers'
import { IncidentTypeBadge, MethodBadge } from './badges'

export function IncidentDetail({ incident, onClose, privacyMode }: { incident: DataSecurityIncident; onClose: () => void; privacyMode: boolean }) {
  const { t } = useTranslation()
  const [rs, setRs] = useState<HttpSessionItem | null>(null)
  const [rl, setRl] = useState(false)
  const [showBody, setShowBody] = useState(false)
  const sc = SEVERITY_COLOR[incident.severity] || SEVERITY_COLOR.info
  const confPct = Math.round(incident.confidence * 100)

  useEffect(() => {
    if (!incident.http_session_id) return
    let c = false
    setRl(true)
    apiFetch(`/api/data-security/http-sessions/${incident.http_session_id}`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<HttpSessionItem> | null) => { if (!c && d?.success && d.data) setRs(d.data) })
      .catch(() => {})
      .finally(() => { if (!c) setRl(false) })
    return () => { c = true }
  }, [incident.http_session_id])

  return (
    <div className="ds3-detail ds3-detail--v2">
      {/* Severity-themed hero header */}
      <div className="ds3-dtl-hero" style={{ '--sev-color': sc } as React.CSSProperties}>
        <div className="ds3-dtl-hero-glow" />
        <div className="ds3-dtl-hero-content">
          <div className="ds3-dtl-hero-left">
            <div className="ds3-dtl-sev-ring" style={{ borderColor: sc, boxShadow: `0 0 12px ${sc}33` }}>
              <span style={{ color: sc, fontWeight: 800, fontSize: 11, textTransform: 'uppercase' }}>{SEVERITY_CN[incident.severity]}</span>
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4, flexWrap: 'wrap' }}>
                <IncidentTypeBadge type={incident.incident_type} />
              </div>
              <div className="ds3-dtl-id sec-mono">
                {incident.id.slice(0, 8)} · {formatRelativeTime(incident.created_at)}
              </div>
            </div>
          </div>
          <div className="ds3-dtl-hero-right">
            {/* Confidence gauge */}
            <div className="ds3-conf-gauge" title={t('dataSecurity.confidencePercent', { pct: confPct })}>
              <svg viewBox="0 0 44 44" width="44" height="44">
                <circle cx="22" cy="22" r="18" fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="3" />
                <circle cx="22" cy="22" r="18" fill="none" stroke={sc} strokeWidth="3"
                  strokeDasharray={`${confPct * 1.131} ${113.1 - confPct * 1.131}`}
                  strokeDashoffset="28.3" strokeLinecap="round"
                  style={{ transition: 'stroke-dasharray 0.6s ease' }} />
              </svg>
              <span className="ds3-conf-val sec-mono" style={{ color: sc }}>{confPct}</span>
            </div>
            <button className="ds3-close-btn" onClick={onClose}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
            </button>
          </div>
        </div>
      </div>

      {/* Summary */}
      <div className="ds3-dtl-summary">{incident.summary}</div>

      {/* Metadata */}
      <div className="ds3-detail-section">
        <div className="ds3-section-label">{t('dataSecurity.relatedInfo')}</div>
        <div className="ds3-dtl-meta">
          {([
            [t('dataSecurity.clientIp'), privacyMode ? maskIp(incident.client_ip) : incident.client_ip,
              <svg key="ip" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" /></svg>],
            [t('dataSecurity.user'), privacyMode ? maskUser(incident.detected_user || '') || '—' : incident.detected_user || '—',
              <svg key="user" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>],
            [t('dataSecurity.host'), incident.host || '—',
              <svg key="host" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>],
          ] as [string, string, JSX.Element][]).map(([l, v, icon], i) => (
            <div key={i} className="ds3-dtl-meta-item">
              <span className="ds3-dtl-meta-icon">{icon}</span>
              <div className="ds3-dtl-meta-text">
                <span className="ds3-dtl-meta-k">{l}</span>
                <span className="ds3-dtl-meta-v sec-mono">{v}</span>
              </div>
            </div>
          ))}
        </div>
        {incident.request_url && (
          <div className="ds3-dtl-url">
            {incident.method && <MethodBadge method={incident.method} />}
            <span className="sec-mono" style={{ fontSize: 11, color: 'var(--text-secondary)', wordBreak: 'break-all', flex: 1 }}>{privacyMode ? maskUrl(incident.request_url) : incident.request_url}</span>
          </div>
        )}
      </div>

      {/* DLP Matches */}
      {incident.dlp_matches.length > 0 && (
        <div className="ds3-detail-section">
          <div className="ds3-section-label">
            {t('dataSecurity.sensitiveDataHit')}
            <span className="ds3-section-cnt">{incident.dlp_matches.length}</span>
          </div>
          <div className="ds3-dtl-dlp-grid">
            {incident.dlp_matches.map((m, i) => {
              const jl = DLP_JRT_LEVEL[m], jc = jl ? JRT_LEVEL_COLOR[jl] : '#ef4444'
              return (
                <div key={i} className="ds3-dtl-dlp-chip" style={{ '--dlp-c': jc } as React.CSSProperties}>
                  {jl && <span className="ds3-dtl-dlp-lv" style={{ background: jc }}>{JRT_LEVEL_LABEL[jl]}</span>}
                  <span className="ds3-dtl-dlp-name">{DLP_MATCH_CN[m] || m}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Evidence Chain */}
      {incident.evidence.length > 0 && (
        <div className="ds3-detail-section">
          <div className="ds3-section-label">
            {t('dataSecurity.evidenceChain')}
            <span className="ds3-section-cnt">{incident.evidence.length}</span>
          </div>
          <div className="ds3-dtl-evidence">
            {incident.evidence.map((ev: Evidence, i: number) => (
              <div key={i} className="ds3-evi-row">
                <div className="ds3-evi-gutter">
                  <div className="ds3-evi-num">{i + 1}</div>
                  {i < incident.evidence.length - 1 && <div className="ds3-evi-line" />}
                </div>
                <div className="ds3-evi-content">
                  <div className="ds3-evi-desc">{ev.description}</div>
                  {ev.location && <div className="ds3-evi-loc">{ev.location}</div>}
                  {ev.snippet && <pre className="ds3-evi-snippet sec-mono">{privacyMode ? getMaskedSnippet() : ev.snippet}</pre>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Redacted request body */}
      <div className="ds3-detail-section" style={{ paddingBottom: 20 }}>
        <button className="ds3-collapse-btn ds3-collapse-btn--v2" onClick={() => setShowBody(!showBody)}>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ transform: showBody ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s ease' }}>
            <polyline points="9 18 15 12 9 6" />
          </svg>
          <span>{t('dataSecurity.requestBody')}</span>
          {rs && rs.request_body_size > 0 && <span className="ds3-body-sz">{formatSize(rs.request_body_size)}</span>}
        </button>
        {showBody && (
          <div className="ds3-collapse-content">
            {rl ? <div className="ds3-inline-msg">{t('dataSecurity.loading')}</div>
              : rs?.request_body ? <pre className="ds3-code-block">{privacyMode ? getMaskedBody() : rs.request_body}</pre>
                : rs?.uploaded_filename ? (
                  privacyMode ? (
                    <div className="ds3-privacy-notice">{t('dataSecurity.privacyEnabledFileDisabled')}</div>
                  ) : (
                  <div className="ds3-dtl-file">
                    <div className="ds3-dtl-file-info">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                      <span className="sec-mono" style={{ color: 'var(--text-primary)' }}>{rs.uploaded_filename}</span>
                      {rs.uploaded_file_size != null && <span className="ds3-dtl-file-sz">{formatSize(rs.uploaded_file_size)}</span>}
                    </div>
                    <div className="ds3-inline-msg" style={{ color: 'var(--text-secondary)', marginBottom: 10 }}>
                      {rs.body_is_binary ? t('dataSecurity.binaryBodyMetadataOnly') : t('dataSecurity.exportRedactedCopy')}
                    </div>
                    <button
                      className="ds3-dl-btn ds3-dl-btn--v2"
                      disabled={rs.body_is_binary}
                      style={rs.body_is_binary ? { opacity: 0.55, cursor: 'not-allowed' } : undefined}
                      onClick={async () => {
                      if (rs.body_is_binary) return
                      try {
                        const r = await apiFetch(`/api/data-security/http-sessions/${rs.id}/body`)
                        if (!r.ok) {
                          const message = (await r.text().catch(() => t('dataSecurity.exportFailed'))).trim()
                          alert(message || t('dataSecurity.exportFailed'))
                          return
                        }
                        const b = await r.blob(), u = URL.createObjectURL(b), a = document.createElement('a')
                        a.href = u
                        a.download = getDownloadName(r.headers, rs.uploaded_filename || 'http-request-body.redacted.txt')
                        a.click()
                        URL.revokeObjectURL(u)
                      } catch { alert(t('dataSecurity.downloadFailed')) }
                    }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                      {t('dataSecurity.exportRedactedContent')}
                    </button>
                  </div>)
                ) : <div className="ds3-inline-msg" style={{ color: 'var(--text-tertiary)' }}>{!rs ? t('dataSecurity.failedToLoad') : rs.request_body_size === 0 ? t('dataSecurity.requestBodyEmpty') : t('dataSecurity.requestBodyNotStored')}</div>}
          </div>
        )}
      </div>
    </div>
  )
}
