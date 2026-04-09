import { useState, useEffect, useCallback } from 'react'
import type { ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'

interface WhitelistEntry {
  id: string
  entry_type: string
  value: string
  description?: string
  created_at: string
  created_by: string
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

export default function WhitelistTab() {
  const [wlEntries, setWlEntries] = useState<WhitelistEntry[]>([])
  const [wlSaving, setWlSaving] = useState(false)
  const [wlNewType, setWlNewType] = useState<'domain' | 'ip'>('domain')
  const [wlNewValue, setWlNewValue] = useState('')
  const [wlNewDesc, setWlNewDesc] = useState('')

  const fetchWhitelist = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/whitelist')
      const data: ApiResponse<WhitelistEntry[]> = await res.json()
      if (data.success && data.data) setWlEntries(data.data)
    } catch (e) {
      console.error('Failed to fetch whitelist:', e)
    }
  }, [])

  useEffect(() => {
    fetchWhitelist()
  }, [fetchWhitelist])

  const addWhitelistEntry = async () => {
    if (!wlNewValue.trim()) return
    setWlSaving(true)
    try {
      const res = await apiFetch('/api/security/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entry_type: wlNewType,
          value: wlNewValue.trim(),
          description: wlNewDesc.trim() || undefined,
        }),
      })
      const data: ApiResponse<WhitelistEntry> = await res.json()
      if (data.success) {
        await fetchWhitelist()
        setWlNewValue('')
        setWlNewDesc('')
      }
    } catch (e) {
      console.error('Failed to add whitelist entry:', e)
    } finally {
      setWlSaving(false)
    }
  }

  const deleteWhitelistEntry = async (id: string) => {
    setWlSaving(true)
    try {
      const res = await apiFetch(`/api/security/whitelist/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!data.success) {
        alert(data.error || '删除失败')
        return
      }
      await fetchWhitelist()
    } catch (e) {
      console.error('Failed to delete whitelist entry:', e)
    } finally {
      setWlSaving(false)
    }
  }

  return (
    <div className="sec-whitelist">
      <div className="sec-section">
        <div className="sec-section-header">
          <h2 className="sec-section-title">整封白名单管理</h2>
          <span className="sec-section-badge">{wlEntries.length} 条</span>
        </div>
        <p style={{ color: 'var(--text-tertiary)', fontSize: '13px', margin: '0 0 16px' }}>
          同时命中域名 + IP 白名单的邮件将跳过安全检测。建议成对添加发件域名和发件 IP。
        </p>

        {/* Add form */}
        <div className="sec-wl-add" style={{ display: 'flex', gap: '8px', marginBottom: '16px', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>类型</label>
            <select
              className="sec-form-input"
              value={wlNewType}
              onChange={e => setWlNewType(e.target.value as 'domain' | 'ip')}
              style={{ width: '100px' }}
            >
              <option value="domain">域名</option>
              <option value="ip">IP</option>
            </select>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
            <label style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>值</label>
            <input
              className="sec-form-input"
              placeholder={wlNewType === 'domain' ? 'example.com' : '192.168.1.1'}
              value={wlNewValue}
              onChange={e => setWlNewValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addWhitelistEntry()}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
            <label style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>备注</label>
            <input
              className="sec-form-input"
              placeholder="可选备注"
              value={wlNewDesc}
              onChange={e => setWlNewDesc(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addWhitelistEntry()}
            />
          </div>
          <button
            className="sec-btn sec-btn--primary"
            onClick={addWhitelistEntry}
            disabled={wlSaving || !wlNewValue.trim()}
            style={{ whiteSpace: 'nowrap' }}
          >
            {wlSaving ? '保存中...' : '添加'}
          </button>
        </div>

        {/* Whitelist list */}
        {wlEntries.length === 0 ? (
          <div className="sec-empty">暂无白名单条目</div>
        ) : (
          <table className="sec-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>类型</th>
                <th>值</th>
                <th>备注</th>
                <th style={{ width: '140px' }}>添加时间</th>
                <th style={{ width: '60px' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {wlEntries.map(entry => (
                <tr key={entry.id}>
                  <td>
                    <span
                      className="sec-ioc-type-badge"
                      style={{
                        background: entry.entry_type === 'domain'
                          ? 'rgba(59,130,246,0.15)' : 'rgba(168,85,247,0.15)',
                        color: entry.entry_type === 'domain'
                          ? 'var(--accent-blue)' : 'var(--accent-purple)',
                      }}
                    >
                      {entry.entry_type === 'domain' ? '域名' : 'IP'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}>{entry.value}</td>
                  <td style={{ color: 'var(--text-tertiary)', fontSize: '13px' }}>{entry.description || '—'}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>{formatTime(entry.created_at)}</td>
                  <td>
                    <button
                      className="sec-btn-icon sec-btn-icon--danger"
                      title="删除"
                      onClick={() => deleteWhitelistEntry(entry.id)}
                      disabled={wlSaving}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="3 6 5 6 21 6" />
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
