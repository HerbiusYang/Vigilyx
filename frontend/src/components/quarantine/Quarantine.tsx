import { Fragment, useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import { formatTimeFull, formatSize } from '../../utils/format'

interface QuarantineEntry {
  id: string
  session_id: string
  verdict_id: string | null
  mail_from: string | null
  rcpt_to: string[]
  subject: string | null
  threat_level: string
  reason: string | null
  status: string
  created_at: string
  released_at: string | null
  released_by: string | null
  ttl_days: number
  raw_eml_size: number
}

interface QuarantineStats {
  quarantined: number
  releasing: number
  released: number
  total: number
}

interface QuarantinePreview {
  body_text: string | null
  body_html_source: string | null
  attachments: Array<{
    filename: string
    content_type: string
    size: number
    hash: string
  }>
  parse_warning: string | null
}

type PendingAction = { id: string; kind: 'release' | 'delete' } | null

async function getApiError(response: Response, fallback: string): Promise<string> {
  try {
    const data = await response.json() as { error?: string; message?: string }
    return data.error || data.message || fallback
  } catch {
    return fallback
  }
}

const THREAT_COLORS: Record<string, string> = {
  safe: 'var(--accent-emerald)',
  low: 'var(--accent-blue)',
  medium: 'var(--accent-yellow)',
  high: 'var(--accent-orange, #f97316)',
  critical: 'var(--accent-red, #ef4444)',
}

export default function Quarantine() {
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [deployMode, setDeployMode] = useState<string>(
    () => localStorage.getItem('vigilyx-deploy-mode') || 'mirror'
  )
  const [entries, setEntries] = useState<QuarantineEntry[]>([])
  const [stats, setStats] = useState<QuarantineStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [pendingAction, setPendingAction] = useState<PendingAction>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [previewById, setPreviewById] = useState<Record<string, QuarantinePreview>>({})
  const [previewLoadingId, setPreviewLoadingId] = useState<string | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('quarantined')
  const [page, setPage] = useState(0)
  const limit = 30
  const pendingCount = (stats?.quarantined ?? 0) + (stats?.releasing ?? 0)

  // Load the deployment mode from the API
  useEffect(() => {
    apiFetch('/api/config/deployment-mode')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.data?.mode) {
          setDeployMode(data.data.mode)
        }
      })
      .catch(() => {})
  }, [])

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) })
      if (statusFilter) params.set('status', statusFilter)

      const [listRes, statsRes] = await Promise.all([
        apiFetch(`/api/security/quarantine?${params}`),
        apiFetch('/api/security/quarantine/stats'),
      ])
      if (!listRes.ok) throw new Error(await getApiError(listRes, t('quarantine.loadFailed')))
      if (!statsRes.ok) throw new Error(await getApiError(statsRes, t('quarantine.loadFailed')))

      const [listData, statsData] = await Promise.all([listRes.json(), statsRes.json()])
      if (!listData.success || !listData.data) throw new Error(listData.error || t('quarantine.loadFailed'))
      if (!statsData.success || !statsData.data) throw new Error(statsData.error || t('quarantine.loadFailed'))

      setEntries(listData.data.items || [])
      setStats(statsData.data)
      setActionError(null)
      setExpandedId(null)
      setPreviewById({})
      setPreviewError(null)
    } catch (e) {
      console.error('Failed to fetch quarantine data:', e)
      setError(e instanceof Error && e.message ? e.message : t('quarantine.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [statusFilter, page, t])

  useEffect(() => {
    if (deployMode === 'mta') fetchData()
  }, [deployMode, fetchData])

  // Mirror mode - show the guidance page. Keep this return after all hooks so
  // an asynchronous deployment-mode refresh cannot change hook ordering.
  if (deployMode !== 'mta') {
    return (
      <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>{t('quarantine.title')}</h2>
        </div>
        <div style={{
          textAlign: 'center', padding: '80px 40px',
          border: '1px dashed var(--border)', borderRadius: 12,
          background: 'var(--bg-secondary)',
        }}>
          <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.3 }}>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
          </div>
          <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: 'var(--text-primary)' }}>
            {t('quarantine.mirrorModeTitle')}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 24, maxWidth: 460, margin: '0 auto 24px' }}>
            {t('quarantine.mirrorModeDesc')}
          </div>
          <button
            onClick={() => {
              navigate('/settings')
              setTimeout(() => window.location.hash = 'deployment', 100)
            }}
            style={{
              padding: '8px 20px', borderRadius: 8, fontSize: 13, fontWeight: 600,
              cursor: 'pointer', border: 'none',
              background: 'var(--accent-primary)', color: '#fff',
            }}
          >
            {t('quarantine.goToSettings')}
          </button>
        </div>
      </div>
    )
  }

  const handleRelease = async (entry: QuarantineEntry) => {
    if (pendingAction) return
    if (!confirm(t('quarantine.confirmRelease', {
      subject: entry.subject || t('quarantine.noSubject'),
      sender: entry.mail_from || '<>',
      reason: entry.reason || t('quarantine.reasonUnavailable'),
    }))) return
    setActionError(null)
    setPendingAction({ id: entry.id, kind: 'release' })
    try {
      const res = await apiFetch(`/api/security/quarantine/${entry.id}/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // The API derives the operator from the authenticated session.
        body: JSON.stringify({}),
      })
      if (!res.ok) throw new Error(await getApiError(res, t('quarantine.releaseFailed')))
      await fetchData()
    } catch (e) {
      console.error('Release failed:', e)
      setActionError(e instanceof Error && e.message ? e.message : t('quarantine.releaseFailed'))
    } finally {
      setPendingAction(null)
    }
  }

  const handleDelete = async (entry: QuarantineEntry) => {
    if (pendingAction) return
    if (!confirm(t('quarantine.confirmDelete', {
      subject: entry.subject || t('quarantine.noSubject'),
      sender: entry.mail_from || '<>',
    }))) return
    setActionError(null)
    setPendingAction({ id: entry.id, kind: 'delete' })
    try {
      const res = await apiFetch(`/api/security/quarantine/${entry.id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await getApiError(res, t('quarantine.deleteFailed')))
      await fetchData()
    } catch (e) {
      console.error('Delete failed:', e)
      setActionError(e instanceof Error && e.message ? e.message : t('quarantine.deleteFailed'))
    } finally {
      setPendingAction(null)
    }
  }

  const handlePreview = async (entry: QuarantineEntry) => {
    if (expandedId === entry.id) {
      setExpandedId(null)
      return
    }

    setExpandedId(entry.id)
    setPreviewError(null)
    if (previewById[entry.id]) return

    setPreviewLoadingId(entry.id)
    try {
      const response = await apiFetch(`/api/security/quarantine/${entry.id}/preview`)
      if (!response.ok) {
        throw new Error(await getApiError(response, t('quarantine.previewFailed')))
      }
      const data = await response.json()
      if (!data.success || !data.data) {
        throw new Error(data.error || t('quarantine.previewFailed'))
      }
      setPreviewById(current => ({ ...current, [entry.id]: data.data }))
    } catch (previewFailure) {
      setPreviewError(
        previewFailure instanceof Error && previewFailure.message
          ? previewFailure.message
          : t('quarantine.previewFailed')
      )
    } finally {
      setPreviewLoadingId(null)
    }
  }

  return (
    <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>
          {t('quarantine.title')}
          <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-secondary)', marginLeft: 8 }}>
            {t('quarantine.mtaMode')}
          </span>
        </h2>
        <button
          onClick={fetchData}
          disabled={loading || pendingAction !== null}
          style={{
            padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 13,
          }}
        >
          {t('quarantine.refresh')}
        </button>
      </div>

      {(error || actionError) && (
        <div
          role="alert"
          aria-live="polite"
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
            padding: '10px 14px', marginBottom: 16, borderRadius: 8,
            border: '1px solid rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.08)',
            color: 'var(--accent-red, #ef4444)', fontSize: 13,
          }}
        >
          <span>{actionError || error}</span>
          {error && (
            <button type="button" onClick={fetchData} disabled={loading}>
              {t('quarantine.retry')}
            </button>
          )}
        </div>
      )}

      {/* Stat cards */}
      {stats && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
          {[
            { label: t('quarantine.pending'), value: pendingCount, color: 'var(--accent-yellow)' },
            { label: t('quarantine.releasing'), value: stats.releasing ?? 0, color: 'var(--accent-orange, #f97316)' },
            { label: t('quarantine.released'), value: stats.released, color: 'var(--accent-emerald)' },
            { label: t('quarantine.total'), value: stats.total, color: 'var(--text-secondary)' },
          ].map(s => (
            <div key={s.label} style={{
              flex: 1, padding: '14px 18px', borderRadius: 10,
              border: '1px solid var(--border)', background: 'var(--bg-secondary)',
            }}>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>{s.label}</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {['quarantined', 'releasing', 'release_blocked', 'released', ''].map(s => (
          <button
            key={s || 'all'}
            onClick={() => { setStatusFilter(s); setPage(0) }}
            style={{
              padding: '5px 12px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
              border: statusFilter === s ? '1px solid var(--accent-primary)' : '1px solid var(--border)',
              background: statusFilter === s ? 'var(--accent-primary)' : 'var(--bg-secondary)',
              color: statusFilter === s ? '#fff' : 'var(--text-primary)',
            }}
          >
            {s === 'quarantined'
              ? t('quarantine.pending')
              : s === 'releasing'
                ? t('quarantine.releasing')
                : s === 'release_blocked'
                  ? t('quarantine.statusReleaseBlocked')
                  : s === 'released'
                    ? t('quarantine.released')
                    : t('quarantine.all')}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>{t('quarantine.loading')}</div>
      ) : error && entries.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
          {t('quarantine.unavailable')}
        </div>
      ) : entries.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
          {t('quarantine.empty')}
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colTime')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colFrom')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colTo')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colSubject')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colThreat')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colSize')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colStatus')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('quarantine.colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(entry => (
                <Fragment key={entry.id}>
                <tr style={{ borderBottom: '1px solid var(--border-light, var(--border))' }}>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {formatTimeFull(entry.created_at)}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.mail_from || '<>'}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.rcpt_to.join(', ')}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    <div>{entry.subject || t('quarantine.noSubject')}</div>
                    <div style={{ marginTop: 4, color: 'var(--text-secondary)', fontSize: 11, whiteSpace: 'normal' }}>
                      <strong>{t('quarantine.reason')}:</strong>{' '}
                      {entry.reason || t('quarantine.reasonUnavailable')}
                    </div>
                    <button
                      type="button"
                      onClick={() => { void handlePreview(entry) }}
                      aria-expanded={expandedId === entry.id}
                      aria-controls={`quarantine-preview-${entry.id}`}
                      style={{
                        marginTop: 4, padding: 0, border: 0, background: 'transparent',
                        color: 'var(--accent-primary)', cursor: 'pointer', fontSize: 11,
                      }}
                    >
                      {expandedId === entry.id ? t('quarantine.hidePreview') : t('quarantine.preview')}
                    </button>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                      background: `${THREAT_COLORS[entry.threat_level] || '#888'}20`,
                      color: THREAT_COLORS[entry.threat_level] || '#888',
                    }}>
                      {entry.threat_level.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {formatSize(entry.raw_eml_size)}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    {(() => {
                      const statusColor =
                        entry.status === 'released'
                          ? 'var(--accent-emerald)'
                          : entry.status === 'release_blocked'
                            ? 'var(--accent-red, #ef4444)'
                            : entry.status === 'releasing'
                              ? 'var(--accent-orange, #f97316)'
                              : 'var(--accent-yellow)'
                      const statusLabel =
                        entry.status === 'released'
                          ? t('quarantine.statusReleased')
                          : entry.status === 'release_blocked'
                            ? t('quarantine.statusReleaseBlocked')
                            : entry.status === 'releasing'
                              ? t('quarantine.statusReleasing')
                              : t('quarantine.statusQuarantined')

                      return (
                        <span
                          style={{ fontSize: 11, fontWeight: 500, color: statusColor }}
                          title={entry.status === 'release_blocked'
                            ? t('quarantine.releaseBlockedHint')
                            : undefined}
                        >
                          {statusLabel}
                        </span>
                      )
                    })()}
                    {entry.status === 'release_blocked' && (
                      <div style={{
                        marginTop: 4, fontSize: 11, lineHeight: 1.4,
                        color: 'var(--text-secondary)', whiteSpace: 'normal', maxWidth: 220,
                      }}>
                        {t('quarantine.releaseBlockedHint')}
                      </div>
                    )}
                    {entry.released_by && (
                      <span style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 4 }}>
                        ({entry.released_by})
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {entry.status === 'quarantined' && (
                      <>
                        <button
                          onClick={() => handleRelease(entry)}
                          disabled={pendingAction !== null || !previewById[entry.id]}
                          aria-busy={pendingAction?.id === entry.id && pendingAction.kind === 'release'}
                          title={!previewById[entry.id] ? t('quarantine.reviewBeforeRelease') : undefined}
                          style={{
                            padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                            border: '1px solid var(--accent-emerald)', background: 'transparent',
                            color: 'var(--accent-emerald)', marginRight: 6,
                          }}
                        >
                          {pendingAction?.id === entry.id && pendingAction.kind === 'release'
                            ? t('quarantine.releasingAction')
                            : t('quarantine.release')}
                        </button>
                        <button
                          onClick={() => handleDelete(entry)}
                          disabled={pendingAction !== null}
                          aria-busy={pendingAction?.id === entry.id && pendingAction.kind === 'delete'}
                          style={{
                            padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                            border: '1px solid var(--accent-red, #ef4444)', background: 'transparent',
                            color: 'var(--accent-red, #ef4444)',
                          }}
                        >
                          {pendingAction?.id === entry.id && pendingAction.kind === 'delete'
                            ? t('quarantine.deletingAction')
                            : t('quarantine.delete')}
                        </button>
                      </>
                    )}
                    {entry.status === 'release_blocked' && (
                      <button
                        onClick={() => handleDelete(entry)}
                        disabled={pendingAction !== null}
                        aria-busy={pendingAction?.id === entry.id && pendingAction.kind === 'delete'}
                        title={t('quarantine.releaseBlockedHint')}
                        style={{
                          padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                          border: '1px solid var(--accent-red, #ef4444)', background: 'transparent',
                          color: 'var(--accent-red, #ef4444)',
                        }}
                      >
                        {pendingAction?.id === entry.id && pendingAction.kind === 'delete'
                          ? t('quarantine.deletingAction')
                          : t('quarantine.delete')}
                      </button>
                    )}
                  </td>
                </tr>
                {expandedId === entry.id && (
                  <tr id={`quarantine-preview-${entry.id}`}>
                    <td colSpan={8} style={{ padding: 0 }}>
                      <div style={{
                        padding: 16, margin: '0 12px 12px', borderRadius: 8,
                        border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                      }}>
                        {previewLoadingId === entry.id ? (
                          <div role="status" style={{ color: 'var(--text-secondary)' }}>
                            {t('quarantine.previewLoading')}
                          </div>
                        ) : previewError ? (
                          <div role="alert" style={{ color: 'var(--accent-red, #ef4444)' }}>
                            {previewError}
                          </div>
                        ) : previewById[entry.id] ? (
                          <>
                            {previewById[entry.id].parse_warning && (
                              <div role="alert" style={{ marginBottom: 12, color: 'var(--accent-yellow)' }}>
                                {t('quarantine.previewParseWarning')}
                              </div>
                            )}
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                              <strong>{t('quarantine.reason')}:</strong>{' '}
                              {entry.reason || t('quarantine.reasonUnavailable')}
                            </div>
                            <pre style={{
                              margin: 0, padding: 12, maxHeight: 280, overflow: 'auto',
                              whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12,
                              borderRadius: 6, background: 'var(--bg-primary)', color: 'var(--text-primary)',
                            }}>
                              {previewById[entry.id].body_text
                                || previewById[entry.id].body_html_source
                                || t('quarantine.previewBodyUnavailable')}
                            </pre>
                            <div style={{ marginTop: 12, fontSize: 12 }}>
                              <strong>{t('quarantine.attachments')}:</strong>{' '}
                              {previewById[entry.id].attachments.length === 0
                                ? t('quarantine.noAttachments')
                                : previewById[entry.id].attachments.map(attachment => (
                                    <span key={`${attachment.hash}:${attachment.filename}`} style={{ display: 'block', marginTop: 4 }}>
                                      {attachment.filename} · {attachment.content_type} · {formatSize(attachment.size)}
                                    </span>
                                  ))}
                            </div>
                            <button
                              type="button"
                              onClick={() => navigate(`/emails/${entry.session_id}`)}
                              style={{
                                marginTop: 12, padding: 0, border: 0, background: 'transparent',
                                color: 'var(--accent-primary)', cursor: 'pointer', fontSize: 12,
                              }}
                            >
                              {t('quarantine.viewEvidence')}
                            </button>
                          </>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {(page > 0 || entries.length >= limit) && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button
            disabled={page === 0 || loading}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            {t('quarantine.prevPage')}
          </button>
          <span style={{ padding: '4px 8px', fontSize: 13, color: 'var(--text-secondary)' }}>
            {t('quarantine.pageNum', { page: page + 1 })}
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={entries.length < limit || loading}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            {t('quarantine.nextPage')}
          </button>
        </div>
      )}

    </div>
  )
}
