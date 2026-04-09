import { useState, useEffect, useCallback } from 'react'
import { apiFetch } from '../../utils/api'
import type { ApiResponse, IocEntry } from '../../types'

const PAGE_SIZE = 30

export default function IocTab() {
  const [iocList, setIocList] = useState<IocEntry[]>([])
  const [iocTotal, setIocTotal] = useState(0)
  const [iocSearch, setIocSearch] = useState('')
  const [iocTypeFilter, setIocTypeFilter] = useState('')
  const [showAddIoc, setShowAddIoc] = useState(false)
  const [addingIoc, setAddingIoc] = useState(false)
  const [iocForm, setIocForm] = useState({ indicator: '', ioc_type: 'ip', verdict: 'suspicious', confidence: 0.8, attack_type: 'unknown', description: '' })
  const [iocPage, setIocPage] = useState(0)

  const fetchIoc = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(iocPage * PAGE_SIZE),
      })
      if (iocSearch) params.set('search', iocSearch)
      if (iocTypeFilter) params.set('ioc_type', iocTypeFilter)
      const res = await apiFetch(`/api/security/ioc?${params}`)
      const data: ApiResponse<{ items: IocEntry[]; total: number }> = await res.json()
      if (data.success && data.data) {
        setIocList(data.data.items)
        setIocTotal(data.data.total)
      }
    } catch (e) {
      console.error('Failed to fetch IOC:', e)
    }
  }, [iocSearch, iocTypeFilter, iocPage])

  useEffect(() => {
    fetchIoc()
  }, [fetchIoc])

  const handleAddIoc = async () => {
    if (!iocForm.indicator.trim()) return
    setAddingIoc(true)
    try {
      const res = await apiFetch('/api/security/ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: iocForm.indicator.trim(),
          ioc_type: iocForm.ioc_type,
          verdict: iocForm.verdict,
          confidence: iocForm.confidence,
          attack_type: iocForm.attack_type,
          description: iocForm.description || undefined,
        }),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        setIocForm({ indicator: '', ioc_type: 'ip', verdict: 'suspicious', confidence: 0.8, attack_type: 'unknown', description: '' })
        setShowAddIoc(false)
        fetchIoc()
      }
    } catch (e) {
      console.error('Failed to add IOC:', e)
    } finally {
      setAddingIoc(false)
    }
  }

  const handleDeleteIoc = async (id: string) => {
    try {
      const res = await apiFetch(`/api/security/ioc/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!data.success) {
        alert(data.error || '删除失败')
        return
      }
      fetchIoc()
    } catch (e) {
      console.error('Failed to delete IOC:', e)
    }
  }

  const handleExtendIoc = async (id: string, days: number = 30) => {
    try {
      const res = await apiFetch(`/api/security/ioc/${id}/extend`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days }),
      })
      if (!res.ok) { console.error('Failed to extend IOC:', res.status); return }
      fetchIoc()
    } catch (e) {
      console.error('Failed to extend IOC:', e)
    }
  }

  const exportIoc = (verdictFilter?: string) => {
    const params = verdictFilter ? `?verdict=${verdictFilter}` : ''
    const url = `/api/security/ioc/export${params}`
    fetch(url, { credentials: 'same-origin' })
      .then(res => res.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `vigilyx-ioc-${verdictFilter || 'all'}-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(a.href)
      })
      .catch(e => console.error('Export failed:', e))
  }

  const importIocFile = async (file: File) => {
    try {
      const text = await file.text()
      const res = await apiFetch('/api/security/ioc/import', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: text,
      })
      const data: ApiResponse<{ imported: number; skipped: number }> = await res.json()
      if (data.success && data.data) {
        alert(`导入完成: ${data.data.imported} 条成功, ${data.data.skipped} 条跳过`)
        fetchIoc()
      } else {
        alert(`导入失败: ${data.error || '未知错误'}`)
      }
    } catch (e) {
      console.error('Import failed:', e)
      alert('导入失败')
    }
  }

  return (
    <div className="sec-ioc">
      <div className="sec-ioc-toolbar">
        <div className="sec-ioc-search">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input
            type="text"
            placeholder="搜索 IOC 指标..."
            value={iocSearch}
            onChange={e => { setIocSearch(e.target.value); setIocPage(0) }}
          />
        </div>
        <select
          className="sec-ioc-select"
          value={iocTypeFilter}
          onChange={e => { setIocTypeFilter(e.target.value); setIocPage(0) }}
        >
          <option value="">全部类型</option>
          <option value="ip">IP 地址</option>
          <option value="domain">域名</option>
          <option value="url">URL</option>
          <option value="hash">文件哈希</option>
          <option value="email">邮箱地址</option>
          <option value="subject">邮件主题</option>
        </select>
        <div className="sec-ioc-actions">
          <span className="sec-ioc-total">共 {iocTotal} 条</span>
          <button className="sec-btn sec-btn--sm sec-btn--ghost" onClick={() => exportIoc('malicious,suspicious')} title="导出恶意+可疑 IOC 为 CSV">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            导出
          </button>
          <label className="sec-btn sec-btn--sm sec-btn--ghost sec-btn-upload" title="从 CSV 导入 IOC">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            导入
            <input type="file" accept=".csv" style={{ display: 'none' }} onChange={e => {
              const file = e.target.files?.[0]
              if (file) { importIocFile(file); e.target.value = '' }
            }} />
          </label>
          <button className="sec-btn sec-btn--primary sec-btn--sm" onClick={() => setShowAddIoc(!showAddIoc)}>
            {showAddIoc ? '取消' : '+ 添加'}
          </button>
        </div>
      </div>

      {showAddIoc && (
        <div className="sec-ioc-add-form">
          <div className="sec-form-row">
            <div className="sec-form-group" style={{ flex: 2 }}>
              <label className="sec-form-label">指标值</label>
              <input
                type="text"
                className="sec-form-input"
                value={iocForm.indicator}
                onChange={e => setIocForm({ ...iocForm, indicator: e.target.value })}
                placeholder="如 192.168.1.1、evil.com、hash..."
              />
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">类型</label>
              <select className="sec-form-select" value={iocForm.ioc_type} onChange={e => setIocForm({ ...iocForm, ioc_type: e.target.value })}>
                <option value="ip">IP 地址</option>
                <option value="domain">域名</option>
                <option value="url">URL</option>
                <option value="hash">文件哈希</option>
                <option value="email">邮箱地址</option>
                <option value="subject">邮件主题</option>
              </select>
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">判定</label>
              <select className="sec-form-select" value={iocForm.verdict} onChange={e => setIocForm({ ...iocForm, verdict: e.target.value })}>
                <option value="malicious">恶意</option>
                <option value="suspicious">可疑</option>
                <option value="safe">安全</option>
              </select>
            </div>
          </div>
          <div className="sec-form-row">
            <div className="sec-form-group">
              <label className="sec-form-label">攻击类型</label>
              <select className="sec-form-select" value={iocForm.attack_type} onChange={e => setIocForm({ ...iocForm, attack_type: e.target.value })}>
                <option value="phishing">钓鱼</option>
                <option value="spoofing">伪造</option>
                <option value="malware">恶意软件</option>
                <option value="bec">BEC 诈骗</option>
                <option value="spam">垃圾邮件</option>
                <option value="unknown">未知</option>
              </select>
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">置信度</label>
              <input
                type="number"
                className="sec-form-input"
                value={iocForm.confidence}
                onChange={e => setIocForm({ ...iocForm, confidence: Math.min(1, Math.max(0, parseFloat(e.target.value) || 0)) })}
                min={0} max={1} step={0.1}
              />
            </div>
            <div className="sec-form-group" style={{ flex: 2 }}>
              <label className="sec-form-label">描述 (可选)</label>
              <input
                type="text"
                className="sec-form-input"
                value={iocForm.description}
                onChange={e => setIocForm({ ...iocForm, description: e.target.value })}
                placeholder="备注说明"
              />
            </div>
            <div className="sec-form-group" style={{ alignSelf: 'flex-end' }}>
              <button className="sec-btn sec-btn--primary" onClick={handleAddIoc} disabled={addingIoc || !iocForm.indicator.trim()}>
                {addingIoc ? '添加中...' : '确认添加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {iocList.length === 0 ? (
        <div className="sec-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          <p>暂无 IOC 数据</p>
        </div>
      ) : (
        <div className="sec-table-wrap">
          <table className="sec-table">
            <thead>
              <tr>
                <th>指标值</th>
                <th>类型</th>
                <th>来源</th>
                <th>判定</th>
                <th className="sec-th-r">置信度</th>
                <th className="sec-th-r">命中</th>
                <th>过期时间</th>
                <th className="sec-th-r">操作</th>
              </tr>
            </thead>
            <tbody>
              {iocList.map(ioc => {
                const isExpired = ioc.expires_at && new Date(ioc.expires_at) < new Date()
                const expiresLabel = !ioc.expires_at ? '永不过期'
                  : isExpired ? '已过期'
                  : new Date(ioc.expires_at).toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit', year: 'numeric' })
                return (
                  <tr key={ioc.id} style={isExpired ? { opacity: 0.5 } : undefined}>
                    <td className="sec-ioc-indicator" title={ioc.indicator}>
                      <span className="sec-mono">{ioc.indicator}</span>
                    </td>
                    <td><span className="sec-badge sec-badge--type">{ioc.ioc_type}</span></td>
                    <td>
                      {ioc.source === 'system' ? (
                        <span className="sec-badge sec-badge--system">系统内置</span>
                      ) : ioc.source === 'admin_clean' ? (
                        <span className="sec-badge sec-badge--admin">管理员</span>
                      ) : ioc.source === 'admin' ? (
                        <span className="sec-badge sec-badge--admin">管理员</span>
                      ) : (
                        <span className="sec-badge sec-badge--auto">{ioc.source}</span>
                      )}
                    </td>
                    <td>
                      <span className={`sec-verdict-tag sec-verdict--${ioc.verdict}`}>
                        {ioc.verdict === 'malicious' ? '恶意' : ioc.verdict === 'suspicious' ? '可疑' : '安全'}
                      </span>
                    </td>
                    <td className="sec-td-r sec-mono">{(ioc.confidence * 100).toFixed(0)}%</td>
                    <td className="sec-td-r sec-mono">{ioc.hit_count}</td>
                    <td className={isExpired ? 'sec-text-warn' : ''}>
                      {expiresLabel}
                    </td>
                    <td className="sec-td-r" style={{ whiteSpace: 'nowrap' }}>
                      {ioc.source !== 'system' && ioc.expires_at && (
                        <button className="sec-btn-extend" onClick={() => handleExtendIoc(ioc.id, 30)} title="延期 30 天">+30d</button>
                      )}
                      <button className="sec-btn-del" onClick={() => handleDeleteIoc(ioc.id)}>删除</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {iocTotal > PAGE_SIZE && (
        <div className="sec-pagination">
          <button
            className="sec-page-btn"
            disabled={iocPage === 0}
            onClick={() => setIocPage(p => p - 1)}
          >
            上一页
          </button>
          <span className="sec-page-info">
            第 {iocPage + 1} / {Math.ceil(iocTotal / PAGE_SIZE)} 页
          </span>
          <button
            className="sec-page-btn"
            disabled={(iocPage + 1) * PAGE_SIZE >= iocTotal}
            onClick={() => setIocPage(p => p + 1)}
          >
            下一页
          </button>
        </div>
      )}
    </div>
  )
}
