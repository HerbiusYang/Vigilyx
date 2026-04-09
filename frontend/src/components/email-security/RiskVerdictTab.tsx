import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '../../utils/api'
import type { ApiResponse, VerdictWithMeta } from '../../types'

const THREAT_LEVELS = [
  { key: 'safe', label: '安全', color: '#22c55e' },
  { key: 'low', label: '低危', color: '#3b82f6' },
  { key: 'medium', label: '中危', color: '#eab308' },
  { key: 'high', label: '高危', color: '#f97316' },
  { key: 'critical', label: '严重', color: '#ef4444' },
]

const THREAT_CN: Record<string, string> = {
  safe: '安全', low: '低危', medium: '中危', high: '高危', critical: '严重',
}

function threatColor(level: string): string {
  return THREAT_LEVELS.find(l => l.key === level)?.color ?? 'var(--text-secondary)'
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  } catch {
    return iso
  }
}

const PAGE_SIZE = 30

export default function RiskVerdictTab() {
  const navigate = useNavigate()
  const [verdicts, setVerdicts] = useState<VerdictWithMeta[]>([])
  const [verdictTotal, setVerdictTotal] = useState(0)
  const [verdictFilter, setVerdictFilter] = useState('')
  const [verdictPage, setVerdictPage] = useState(0)

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
              {level ? THREAT_CN[level] : '全部'}
            </button>
          ))}
        </div>
        <span className="sec-risk-total">共 {verdictTotal} 条</span>
      </div>

      {verdicts.length === 0 ? (
        <div className="sec-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <p>暂无风险邮件</p>
        </div>
      ) : (
        <>
          <div className="sec-table-wrap">
            <table className="sec-table sec-table--hover">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>威胁</th>
                  <th>发件人</th>
                  <th>主题</th>
                  <th style={{ width: 90 }}>置信度</th>
                  <th style={{ width: 160 }}>时间</th>
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
                    <td className="sec-risk-subject">{v.subject || '(无主题)'}</td>
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
                上一页
              </button>
              <span className="sec-page-info">
                第 {verdictPage + 1} / {Math.ceil(verdictTotal / PAGE_SIZE)} 页
              </span>
              <button
                className="sec-page-btn"
                disabled={(verdictPage + 1) * PAGE_SIZE >= verdictTotal}
                onClick={() => setVerdictPage(p => p + 1)}
              >
                下一页
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
