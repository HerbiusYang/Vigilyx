import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '../../utils/api'

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
  released: number
  total: number
}

const THREAT_COLORS: Record<string, string> = {
  safe: 'var(--accent-emerald)',
  low: 'var(--accent-blue)',
  medium: 'var(--accent-yellow)',
  high: 'var(--accent-orange, #f97316)',
  critical: 'var(--accent-red, #ef4444)',
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

export default function Quarantine() {
  const navigate = useNavigate()
  const [deployMode, setDeployMode] = useState<string>(
    () => localStorage.getItem('vigilyx-deploy-mode') || 'mirror'
  )
  const [entries, setEntries] = useState<QuarantineEntry[]>([])
  const [stats, setStats] = useState<QuarantineStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState<string>('quarantined')
  const [page, setPage] = useState(0)
  const limit = 30

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

  // Mirror mode - show the guidance page
  if (deployMode !== 'mta') {
    return (
      <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>邮件隔离区</h2>
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
            当前为旁路镜像模式
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 24, maxWidth: 460, margin: '0 auto 24px' }}>
            旁路镜像模式下，系统通过网络抓包被动监控邮件流量，无法拦截或隔离邮件。
            切换到 <strong>MTA 代理模式</strong> 后，系统将作为 SMTP 中继部署，
            可在投递前实时检测并拦截恶意邮件，支持隔离区管理。
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
            前往设置切换到 MTA 模式
          </button>
        </div>
      </div>
    )
  }

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(page * limit) })
      if (statusFilter) params.set('status', statusFilter)

      const [listRes, statsRes] = await Promise.all([
        apiFetch(`/api/security/quarantine?${params}`),
        apiFetch('/api/security/quarantine/stats'),
      ])
      if (listRes.ok) {
        const data = await listRes.json()
        setEntries(data.data?.items || [])
      }
      if (statsRes.ok) {
        const data = await statsRes.json()
        setStats(data.data || null)
      }
    } catch (e) {
      console.error('Failed to fetch quarantine data:', e)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, page])

  useEffect(() => { fetchData() }, [fetchData])

  const handleRelease = async (id: string) => {
    if (!confirm('确认释放此邮件？释放后将转发到收件人。')) return
    try {
      const res = await apiFetch(`/api/security/quarantine/${id}/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ released_by: 'admin' }),
      })
      if (res.ok) fetchData()
    } catch (e) {
      console.error('Release failed:', e)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('确认永久删除此隔离邮件？此操作不可恢复。')) return
    try {
      const res = await apiFetch(`/api/security/quarantine/${id}`, { method: 'DELETE' })
      if (res.ok) fetchData()
    } catch (e) {
      console.error('Delete failed:', e)
    }
  }

  return (
    <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>
          邮件隔离区
          <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-secondary)', marginLeft: 8 }}>
            MTA 代理模式
          </span>
        </h2>
        <button
          onClick={fetchData}
          style={{
            padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', cursor: 'pointer', fontSize: 13,
          }}
        >
          刷新
        </button>
      </div>

      {/* Stat cards */}
      {stats && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
          {[
            { label: '待审核', value: stats.quarantined, color: 'var(--accent-yellow)' },
            { label: '已释放', value: stats.released, color: 'var(--accent-emerald)' },
            { label: '总计', value: stats.total, color: 'var(--text-secondary)' },
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
        {['quarantined', 'released', ''].map(s => (
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
            {s === 'quarantined' ? '待审核' : s === 'released' ? '已释放' : '全部'}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>加载中...</div>
      ) : entries.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-secondary)' }}>
          暂无隔离邮件
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>时间</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>发件人</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>收件人</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>主题</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>威胁</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>大小</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>状态</th>
                <th style={{ padding: '8px 12px', fontWeight: 500 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(entry => (
                <tr key={entry.id} style={{ borderBottom: '1px solid var(--border-light, var(--border))' }}>
                  <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                    {formatTime(entry.created_at)}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.mail_from || '<>'}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.rcpt_to.join(', ')}
                  </td>
                  <td style={{ padding: '8px 12px', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.subject || '(no subject)'}
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
                    <span style={{
                      fontSize: 11, fontWeight: 500,
                      color: entry.status === 'quarantined' ? 'var(--accent-yellow)' : 'var(--accent-emerald)',
                    }}>
                      {entry.status === 'quarantined' ? '隔离中' : '已释放'}
                    </span>
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
                          onClick={() => handleRelease(entry.id)}
                          style={{
                            padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                            border: '1px solid var(--accent-emerald)', background: 'transparent',
                            color: 'var(--accent-emerald)', marginRight: 6,
                          }}
                        >
                          释放
                        </button>
                        <button
                          onClick={() => handleDelete(entry.id)}
                          style={{
                            padding: '3px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                            border: '1px solid var(--accent-red, #ef4444)', background: 'transparent',
                            color: 'var(--accent-red, #ef4444)',
                          }}
                        >
                          删除
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {entries.length >= limit && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button
            disabled={page === 0}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            上一页
          </button>
          <span style={{ padding: '4px 8px', fontSize: 13, color: 'var(--text-secondary)' }}>
            第 {page + 1} 页
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            style={{ padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', cursor: 'pointer' }}
          >
            下一页
          </button>
        </div>
      )}

      {/* Quarantine reason */}
      {entries.length > 0 && entries.some(e => e.reason) && (
        <div style={{ marginTop: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
          <strong>隔离原因示例:</strong> {entries.find(e => e.reason)?.reason}
        </div>
      )}
    </div>
  )
}
