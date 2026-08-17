import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import { formatTimeFull } from '../../utils/format'
import { EVENTS } from '../../utils/events'
import type { AlertLevel, AlertRecord } from '../../types'

async function getApiError(response: Response, fallback: string): Promise<string> {
  try {
    const data = await response.json() as { error?: string; message?: string }
    return data.error || data.message || fallback
  } catch {
    return fallback
  }
}

const LEVEL_COLORS: Record<AlertLevel, string> = {
  P0: 'var(--accent-red, #ef4444)',
  P1: 'var(--accent-orange, #f97316)',
  P2: 'var(--accent-yellow)',
  P3: 'var(--accent-blue)',
}

const LEVELS: AlertLevel[] = ['P0', 'P1', 'P2', 'P3']

export default function AlertCenter() {
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [ackingId, setAckingId] = useState<string | null>(null)
  const [levelFilter, setLevelFilter] = useState<string>('')
  const [ackFilter, setAckFilter] = useState<string>('')
  const [page, setPage] = useState(0)
  const limit = 30

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) })
      if (levelFilter) params.set('alert_level', levelFilter)
      if (ackFilter) params.set('acknowledged', ackFilter)

      const res = await apiFetch(`/api/security/alerts?${params}`)
      if (!res.ok) throw new Error(await getApiError(res, t('alerts.loadFailed')))
      const json = await res.json()
      if (json.success === false) throw new Error(json.error || t('alerts.loadFailed'))
      // Tolerate both a raw {alerts,total} body and the {success,data} envelope
      const payload = json.data ?? json
      setAlerts(payload.alerts || [])
      setTotal(payload.total ?? 0)
      setActionError(null)
    } catch (e) {
      console.error('Failed to fetch alerts:', e)
      setError(e instanceof Error && e.message ? e.message : t('alerts.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [levelFilter, ackFilter, page, t])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Refresh the list when a new alert arrives over WebSocket
  useEffect(() => {
    const handler = () => { void fetchData() }
    window.addEventListener(EVENTS.ALERT, handler)
    return () => window.removeEventListener(EVENTS.ALERT, handler)
  }, [fetchData])

  const handleAcknowledge = async (alert: AlertRecord) => {
    if (ackingId) return
    setActionError(null)
    setAckingId(alert.id)
    try {
      const res = await apiFetch(`/api/security/alerts/${alert.id}/acknowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      if (!res.ok) throw new Error(await getApiError(res, t('alerts.ackFailed')))
      await fetchData()
    } catch (e) {
      console.error('Acknowledge failed:', e)
      setActionError(e instanceof Error && e.message ? e.message : t('alerts.ackFailed'))
    } finally {
      setAckingId(null)
    }
  }

  return (
    <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>
          {t('alerts.title')}
          <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-secondary)', marginLeft: 8 }}>
            {t('alerts.total', { count: total })}
          </span>
        </h2>
        <button
          onClick={fetchData}
          disabled={loading || ackingId !== null}
          style={{
            padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 13,
          }}
        >
          {t('alerts.refresh')}
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
              {t('alerts.retry')}
            </button>
          )}
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{t('alerts.level')}</span>
          {['', ...LEVELS].map(level => (
            <button
              key={level || 'all'}
              onClick={() => { setLevelFilter(level); setPage(0) }}
              style={{
                padding: '5px 12px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
                border: levelFilter === level ? '1px solid var(--accent-primary)' : '1px solid var(--border)',
                background: levelFilter === level ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                color: levelFilter === level ? '#fff' : 'var(--text-primary)',
              }}
            >
              {level || t('alerts.all')}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{t('alerts.ackStatus')}</span>
          {[['', 'alerts.all'], ['false', 'alerts.unacknowledged'], ['true', 'alerts.acknowledged']].map(([value, key]) => (
            <button
              key={value || 'all'}
              onClick={() => { setAckFilter(value); setPage(0) }}
              style={{
                padding: '5px 12px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
                border: ackFilter === value ? '1px solid var(--accent-primary)' : '1px solid var(--border)',
                background: ackFilter === value ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                color: ackFilter === value ? '#fff' : 'var(--text-primary)',
              }}
            >
              {t(key)}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>{t('alerts.loading')}</div>
      ) : error && alerts.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
          {t('alerts.unavailable')}
        </div>
      ) : alerts.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
          {t('alerts.empty')}
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colLevel')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colRationale')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colExpectedLoss')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colRisk')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colTime')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colStatus')}</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>{t('alerts.colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr
                  key={alert.id}
                  onClick={() => navigate(`/emails/${alert.session_id}`)}
                  style={{ borderBottom: '1px solid var(--border-light, var(--border))', cursor: 'pointer' }}
                  title={t('alerts.viewEmail')}
                >
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                      background: `${LEVEL_COLORS[alert.alert_level] || '#888'}20`,
                      color: LEVEL_COLORS[alert.alert_level] || '#888',
                    }}>
                      {alert.alert_level}
                    </span>
                    {alert.cusum_alarm && (
                      <span style={{
                        marginLeft: 6, padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                        background: 'rgba(239,68,68,0.12)', color: 'var(--accent-red, #ef4444)',
                      }}>
                        {t('alerts.cusumAlarm')}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {alert.rationale}
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {alert.expected_loss.toFixed(2)}
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {alert.risk_final.toFixed(3)}
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {formatTimeFull(alert.created_at)}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    {alert.acknowledged ? (
                      <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--accent-emerald)' }}>
                        {t('alerts.acknowledged')}
                        {alert.acknowledged_by && (
                          <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>
                            ({alert.acknowledged_by})
                          </span>
                        )}
                      </span>
                    ) : (
                      <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--accent-yellow)' }}>
                        {t('alerts.unacknowledged')}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {!alert.acknowledged && (
                      <button
                        onClick={e => { e.stopPropagation(); void handleAcknowledge(alert) }}
                        disabled={ackingId !== null}
                        aria-busy={ackingId === alert.id}
                        style={{
                          padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                          border: '1px solid var(--accent-emerald)', background: 'transparent',
                          color: 'var(--accent-emerald)',
                        }}
                      >
                        {ackingId === alert.id ? t('alerts.acknowledging') : t('alerts.acknowledge')}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {(page > 0 || alerts.length >= limit) && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button
            disabled={page === 0 || loading}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            {t('alerts.prevPage')}
          </button>
          <span style={{ padding: '4px 8px', fontSize: 13, color: 'var(--text-secondary)' }}>
            {t('alerts.pageNum', { page: page + 1 })}
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={alerts.length < limit || loading}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            {t('alerts.nextPage')}
          </button>
        </div>
      )}
    </div>
  )
}
