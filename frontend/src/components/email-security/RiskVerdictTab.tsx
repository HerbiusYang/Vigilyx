import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '../../utils/api'
import { formatTime } from '../../utils/format'
import type { ApiResponse, VerdictWithMeta } from '../../types'

const THREAT_LEVEL_COLORS: Record<string, string> = {
  safe: '#22c55e',
  low: '#3b82f6',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

function threatColor(level: string): string {
  return THREAT_LEVEL_COLORS[level] ?? 'var(--text-secondary)'
}

const PAGE_SIZE = 30

export default function RiskVerdictTab() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [verdicts, setVerdicts] = useState<VerdictWithMeta[]>([])
  const [verdictTotal, setVerdictTotal] = useState(0)
  const [verdictFilter, setVerdictFilter] = useState('')
  const [verdictPage, setVerdictPage] = useState(0)

  const THREAT_CN: Record<string, string> = {
    safe: t('emailSecurity.threatSafe'), low: t('emailSecurity.threatLow'), medium: t('emailSecurity.threatMedium'), high: t('emailSecurity.threatHigh'), critical: t('emailSecurity.threatCritical'),
  }

  const fetchVerdicts = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(verdictPage * PAGE_SIZE),
      })
      if (verdictFilter) params.set('threat_level', verdictFilter)
      const res = await apiFetch(`/api/security/verdicts?${params}`)
      const data: ApiResponse<{ items: VerdictWithMeta[]; total: number }> = await res.json()
      if (data.success && data.data) {
        setVerdicts(data.data.items)
        setVerdictTotal(data.data.total)
      }
    } catch (e) {
      console.error('Failed to fetch verdicts:', e)
    }
  }, [verdictFilter, verdictPage])

  useEffect(() => {
    fetchVerdicts()
  }, [fetchVerdicts])

  return (
    <div className="sec-risk">
      <div className="sec-risk-toolbar">
        <div className="sec-risk-filters">
          {['', 'critical', 'high', 'medium', 'low'].map(level => (
            <button
              key={level}
              className={`sec-filter-btn ${verdictFilter === level ? 'sec-filter-btn--active' : ''}`}
              onClick={() => { setVerdictFilter(level); setVerdictPage(0) }}
              style={level && verdictFilter === level ? { borderColor: threatColor(level), color: threatColor(level) } : undefined}
            >
              {level ? THREAT_CN[level] : t('emailSecurity.filterAll')}
            </button>
          ))}
        </div>
        <span className="sec-risk-total">{t('emailSecurity.totalCount', { count: verdictTotal })}</span>
      </div>

      {verdicts.length === 0 ? (
        <div className="sec-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <p>{t('emailSecurity.noRiskEmails')}</p>
        </div>
      ) : (
        <>
          <div className="sec-table-wrap">
            <table className="sec-table sec-table--hover">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>{t('emailSecurity.colThreat')}</th>
                  <th>{t('emailSecurity.colSender')}</th>
                  <th>{t('emailSecurity.colSubject')}</th>
                  <th style={{ width: 90 }}>{t('emailSecurity.colConfidence')}</th>
                  <th style={{ width: 160 }}>{t('emailSecurity.colTime')}</th>
                </tr>
              </thead>
              <tbody>
                {verdicts.map(v => (
                  <tr
                    key={v.verdict_id}
                    className="sec-risk-row"
                    onClick={() => navigate(`/emails/${v.session_id}`)}
                  >
                    <td>
                      <span className="sec-threat-tag" style={{ backgroundColor: threatColor(v.threat_level) + '20', color: threatColor(v.threat_level), borderColor: threatColor(v.threat_level) + '40' }}>
                        {THREAT_CN[v.threat_level] || v.threat_level}
                      </span>
                    </td>
                    <td className="sec-risk-from">{v.mail_from || '-'}</td>
                    <td className="sec-risk-subject">{v.subject || t('emailSecurity.noSubject')}</td>
                    <td className="sec-td-r sec-mono">{(v.confidence * 100).toFixed(0)}%</td>
                    <td className="sec-risk-time">{formatTime(v.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {verdictTotal > PAGE_SIZE && (
            <div className="sec-pagination">
              <button
                className="sec-page-btn"
                disabled={verdictPage === 0}
                onClick={() => setVerdictPage(p => p - 1)}
              >
                {t('emailSecurity.prevPage')}
              </button>
              <span className="sec-page-info">
                {t('emailSecurity.pageInfo', { current: verdictPage + 1, total: Math.ceil(verdictTotal / PAGE_SIZE) })}
              </span>
              <button
                className="sec-page-btn"
                disabled={(verdictPage + 1) * PAGE_SIZE >= verdictTotal}
                onClick={() => setVerdictPage(p => p + 1)}
              >
                {t('emailSecurity.nextPage')}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
