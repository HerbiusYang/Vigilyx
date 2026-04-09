import { useState, useEffect, useCallback } from 'react'
import { apiFetch } from '../../utils/api'
import type { ApiResponse, IocEntry, SecurityStats } from '../../types'

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

interface IntelConfigTabProps {
  stats: SecurityStats | null
  onNavigateToIoc: () => void
}

export default function IntelConfigTab({ stats, onNavigateToIoc }: IntelConfigTabProps) {
  // Intel source config (VT/AbuseIPDB/OTX)
  const [intelConfig, setIntelConfig] = useState<Record<string, any> | null>(null)
  const [intelConfigDraft, setIntelConfigDraft] = useState<Record<string, any> | null>(null)
  const [savingIntelConfig, setSavingIntelConfig] = useState(false)

  // Intel whitelist
  const [intelWlList, setIntelWlList] = useState<IocEntry[]>([])
  const [intelWlTotal, setIntelWlTotal] = useState(0)
  const [intelWlSearch, setIntelWlSearch] = useState('')
  const [intelWlTypeFilter, setIntelWlTypeFilter] = useState('')
  const [intelWlPage, setIntelWlPage] = useState(0)
  const [showAddIntelWl, setShowAddIntelWl] = useState(false)
  const [addingIntelWl, setAddingIntelWl] = useState(false)
  const [intelWlForm, setIntelWlForm] = useState({ indicator: '', ioc_type: 'domain', description: '' })

  const fetchIntelConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/intel-config')
      const data: ApiResponse<Record<string, any>> = await res.json()
      if (data.success && data.data) {
        setIntelConfig(data.data)
        setIntelConfigDraft(data.data)
      }
    } catch (e) {
      console.error('Failed to fetch intel config:', e)
    }
  }, [])

  const fetchIntelWhitelist = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(intelWlPage * PAGE_SIZE),
      })
      if (intelWlSearch) params.set('search', intelWlSearch)
      if (intelWlTypeFilter) params.set('ioc_type', intelWlTypeFilter)
      const res = await apiFetch(`/api/security/intel-whitelist?${params}`)
      const data: ApiResponse<{ items: IocEntry[]; total: number }> = await res.json()
      if (data.success && data.data) {
        setIntelWlList(data.data.items)
        setIntelWlTotal(data.data.total)
      }
    } catch (e) {
      console.error('Failed to fetch intel whitelist:', e)
    }
  }, [intelWlSearch, intelWlTypeFilter, intelWlPage])

  useEffect(() => {
    fetchIntelConfig()
    fetchIntelWhitelist()
  }, [fetchIntelConfig, fetchIntelWhitelist])

  const saveIntelConfig = async () => {
    if (!intelConfigDraft) return
    setSavingIntelConfig(true)
    try {
      const payload: Record<string, unknown> = {
        otx_enabled: intelConfigDraft.otx_enabled,
        vt_scrape_enabled: intelConfigDraft.vt_scrape_enabled,
        abuseipdb_enabled: intelConfigDraft.abuseipdb_enabled,
      }
      if (intelConfigDraft.virustotal_api_key && !intelConfigDraft.virustotal_api_key.includes('...') && intelConfigDraft.virustotal_api_key !== '****') {
        payload.virustotal_api_key = intelConfigDraft.virustotal_api_key
      }
      if (intelConfigDraft.abuseipdb_api_key && !intelConfigDraft.abuseipdb_api_key.includes('...') && intelConfigDraft.abuseipdb_api_key !== '****') {
        payload.abuseipdb_api_key = intelConfigDraft.abuseipdb_api_key
      }
      const res = await apiFetch('/api/security/intel-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        fetchIntelConfig()
      }
    } catch (e) {
      console.error('Failed to save intel config:', e)
    } finally {
      setSavingIntelConfig(false)
    }
  }

  const handleAddIntelWl = async () => {
    if (!intelWlForm.indicator.trim()) return
    setAddingIntelWl(true)
    try {
      const res = await apiFetch('/api/security/intel-whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: intelWlForm.indicator.trim(),
          ioc_type: intelWlForm.ioc_type,
          description: intelWlForm.description || undefined,
        }),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        setIntelWlForm({ indicator: '', ioc_type: 'domain', description: '' })
        setShowAddIntelWl(false)
        fetchIntelWhitelist()
      }
    } catch (e) {
      console.error('Failed to add intel whitelist:', e)
    } finally {
      setAddingIntelWl(false)
    }
  }

  const handleDeleteIntelWl = async (id: string) => {
    try {
      const res = await apiFetch(`/api/security/intel-whitelist/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!data.success) {
        alert(data.error || '删除失败')
        return
      }
      fetchIntelWhitelist()
    } catch (e) {
      console.error('Failed to delete intel whitelist:', e)
    }
  }

  return (
    <div className="intel-page">
      {/* -- Page title area -- */}
      <div className="intel-hero">
        <div className="intel-hero-text">
          <h2 className="intel-hero-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            威胁情报源
          </h2>
          <p className="intel-hero-desc">接入外部威胁情报以增强邮件安全检测能力，情报数据用于 IP/域名/URL/哈希信誉查询</p>
        </div>
      </div>

      {/* -- Intel-source cards -- */}
      <div className="intel-sources">
        {/* VirusTotal */}
        <div className={`intel-card ${intelConfigDraft?.vt_scrape_enabled ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(59,130,246,0.12)', color: '#3b82f6' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">VirusTotal</h3>
              <span className="intel-card-subtitle">文件 / URL / 域名 / IP 多引擎扫描</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.vt_scrape_enabled ?? false}
                  onChange={e => setIntelConfigDraft({ ...intelConfigDraft, vt_scrape_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              聚合 70+ 安全厂商检测结果，查询 URL/域名/IP/文件哈希的恶意评判。
              每分钟 4 次免费查询配额。
            </p>
            <div className="intel-card-status-row">
              {intelConfig?.virustotal_api_key_set ? (
                <span className="intel-status-badge intel-status--configured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                  API Key 已配置
                </span>
              ) : (
                <span className="intel-status-badge intel-status--unconfigured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  未配置
                </span>
              )}
            </div>
            {intelConfigDraft && (
              <div className="intel-card-config">
                <label className="intel-config-label">API Key</label>
                <div className="intel-config-input-wrap">
                  <input
                    type="password"
                    className="intel-config-input"
                    placeholder={intelConfig?.virustotal_api_key_set ? '已设置（留空保持不变）' : '输入 VirusTotal API Key'}
                    value={intelConfigDraft.virustotal_api_key ?? ''}
                    onChange={e => setIntelConfigDraft({ ...intelConfigDraft, virustotal_api_key: e.target.value })}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* AbuseIPDB */}
        <div className={`intel-card ${intelConfigDraft?.abuseipdb_enabled ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">AbuseIPDB</h3>
              <span className="intel-card-subtitle">IP 地址信誉评分与滥用举报</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.abuseipdb_enabled ?? false}
                  onChange={e => setIntelConfigDraft({ ...intelConfigDraft, abuseipdb_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              基于社区举报的 IP 信誉数据库，返回 0-100 滥用置信度评分和历史举报详情。
              每日 1000 次免费查询。
            </p>
            <div className="intel-card-status-row">
              {intelConfig?.abuseipdb_api_key_set ? (
                <span className="intel-status-badge intel-status--configured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                  API Key 已配置
                </span>
              ) : (
                <span className="intel-status-badge intel-status--unconfigured">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  未配置
                </span>
              )}
            </div>
            {intelConfigDraft && (
              <div className="intel-card-config">
                <label className="intel-config-label">API Key</label>
                <div className="intel-config-input-wrap">
                  <input
                    type="password"
                    className="intel-config-input"
                    placeholder={intelConfig?.abuseipdb_api_key_set ? '已设置（留空保持不变）' : '输入 AbuseIPDB API Key'}
                    value={intelConfigDraft.abuseipdb_api_key ?? ''}
                    onChange={e => setIntelConfigDraft({ ...intelConfigDraft, abuseipdb_api_key: e.target.value })}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* OTX AlienVault */}
        <div className={`intel-card ${intelConfigDraft?.otx_enabled !== false ? 'intel-card--active' : ''}`}>
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(34,197,94,0.12)', color: '#22c55e' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">OTX AlienVault</h3>
              <span className="intel-card-subtitle">开放威胁情报交换平台</span>
            </div>
            {intelConfigDraft && (
              <label className="intel-toggle">
                <input
                  type="checkbox"
                  checked={intelConfigDraft.otx_enabled !== false}
                  onChange={e => setIntelConfigDraft({ ...intelConfigDraft, otx_enabled: e.target.checked })}
                />
                <span className="intel-toggle-track">
                  <span className="intel-toggle-thumb" />
                </span>
              </label>
            )}
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              社区驱动的威胁情报平台，提供 IP/域名的 Pulse 关联数据。
              内置集成，无需 API Key 即可使用。
            </p>
            <div className="intel-card-status-row">
              <span className="intel-status-badge intel-status--builtin">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                内置（无需 API Key）
              </span>
            </div>
          </div>
        </div>

        {/* Local IOC database */}
        <div className="intel-card intel-card--active intel-card--builtin">
          <div className="intel-card-header">
            <div className="intel-card-icon" style={{ background: 'rgba(168,85,247,0.12)', color: '#a855f7' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
              </svg>
            </div>
            <div className="intel-card-title-group">
              <h3 className="intel-card-title">本地 IOC 库</h3>
              <span className="intel-card-subtitle">自建威胁指标数据库</span>
            </div>
            <span className="intel-builtin-badge">内置</span>
          </div>
          <div className="intel-card-body">
            <p className="intel-card-desc">
              引擎自动记录和管理员手动添加的 IOC 指标，包含 IP/域名/URL/哈希/邮箱。
              当前 {(stats?.ioc_count ?? 0).toLocaleString()} 条。
            </p>
            <div className="intel-card-status-row">
              <span className="intel-status-badge intel-status--builtin">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                始终启用
              </span>
              <button
                className="sec-btn sec-btn--sm sec-btn--ghost"
                onClick={onNavigateToIoc}
                style={{ marginLeft: 'auto' }}
              >
                管理 IOC
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginLeft: 4 }}><polyline points="9 18 15 12 9 6"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* -- Save button -- */}
      {intelConfigDraft && (
        <div className="intel-save-bar">
          <button
            className="sec-btn sec-btn--primary"
            onClick={saveIntelConfig}
            disabled={savingIntelConfig}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
            </svg>
            {savingIntelConfig ? '保存中...' : '保存情报源配置'}
          </button>
          <span className="intel-save-hint">修改 API Key 或启用状态后需保存，重启引擎生效</span>
        </div>
      )}

      {/* -- Intel whitelist (merged into the intel-source page) -- */}
      <div className="sec-ioc" style={{ marginTop: 24 }}>
        <div className="intel-wl-header" style={{ marginBottom: 16 }}>
          <div className="intel-wl-title-group">
            <h3 className="intel-wl-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
              </svg>
              情报白名单
            </h3>
            <span className="intel-wl-desc">仅展示系统/管理员情报白名单；命中后跳过外部情报查询，避免误报。</span>
          </div>
        </div>

        <div className="sec-ioc-toolbar">
          <div className="sec-ioc-search">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input
              type="text"
              placeholder="搜索白名单指标..."
              value={intelWlSearch}
              onChange={e => { setIntelWlSearch(e.target.value); setIntelWlPage(0) }}
            />
          </div>
          <select
            className="sec-ioc-select"
            value={intelWlTypeFilter}
            onChange={e => { setIntelWlTypeFilter(e.target.value); setIntelWlPage(0) }}
          >
            <option value="">全部类型</option>
            <option value="ip">IP</option>
            <option value="domain">域名</option>
            <option value="url">URL</option>
            <option value="hash">哈希</option>
          </select>
          <div className="sec-ioc-actions">
            <span className="sec-ioc-total">共 {intelWlTotal} 条</span>
            <button className="sec-btn sec-btn--primary sec-btn--sm" onClick={() => setShowAddIntelWl(!showAddIntelWl)}>
              {showAddIntelWl ? '取消' : '+ 添加'}
            </button>
          </div>
        </div>

        {showAddIntelWl && (
          <div className="sec-ioc-add-form">
            <div className="sec-form-row">
              <div className="sec-form-group" style={{ flex: 2 }}>
                <label className="sec-form-label">指标值</label>
                <input
                  type="text"
                  className="sec-form-input"
                  placeholder="如: example.com / 1.2.3.4"
                  value={intelWlForm.indicator}
                  onChange={e => setIntelWlForm({ ...intelWlForm, indicator: e.target.value })}
                />
              </div>
              <div className="sec-form-group">
                <label className="sec-form-label">类型</label>
                <select
                  className="sec-form-select"
                  value={intelWlForm.ioc_type}
                  onChange={e => setIntelWlForm({ ...intelWlForm, ioc_type: e.target.value })}
                >
                  <option value="domain">域名</option>
                  <option value="ip">IP</option>
                  <option value="url">URL</option>
                  <option value="hash">哈希</option>
                </select>
              </div>
              <div className="sec-form-group" style={{ flex: 2 }}>
                <label className="sec-form-label">说明</label>
                <input
                  type="text"
                  className="sec-form-input"
                  placeholder="可选备注"
                  value={intelWlForm.description}
                  onChange={e => setIntelWlForm({ ...intelWlForm, description: e.target.value })}
                />
              </div>
              <div className="sec-form-group" style={{ alignSelf: 'flex-end' }}>
                <button
                  className="sec-btn sec-btn--primary"
                  onClick={handleAddIntelWl}
                  disabled={addingIntelWl || !intelWlForm.indicator.trim()}
                >
                  {addingIntelWl ? '添加中...' : '确认添加'}
                </button>
              </div>
            </div>
          </div>
        )}

        {intelWlList.length === 0 ? (
          <div className="sec-empty">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <p>暂无白名单数据</p>
          </div>
        ) : (
          <div className="sec-table-wrap">
            <table className="sec-table">
              <thead>
                <tr>
                  <th>指标值</th>
                  <th>类型</th>
                  <th>来源</th>
                  <th className="sec-th-r">置信度</th>
                  <th className="sec-th-r">命中</th>
                  <th>过期时间</th>
                  <th className="sec-th-r">操作</th>
                </tr>
              </thead>
              <tbody>
                {intelWlList.map(entry => (
                  <tr key={entry.id}>
                    <td className="sec-ioc-indicator"><span className="sec-mono">{entry.indicator}</span></td>
                    <td><span className="sec-badge sec-badge--type">{entry.ioc_type}</span></td>
                    <td>
                      {entry.source === 'system' ? (
                        <span className="sec-badge sec-badge--system">系统内置</span>
                      ) : entry.source === 'admin_clean' ? (
                        <span className="sec-badge sec-badge--admin">管理员</span>
                      ) : (
                        <span className="sec-badge sec-badge--auto">{entry.source}</span>
                      )}
                    </td>
                    <td className="sec-td-r sec-mono">{(entry.confidence * 100).toFixed(0)}%</td>
                    <td className="sec-td-r sec-mono">{entry.hit_count}</td>
                    <td className="sec-mono">
                      {entry.expires_at ? formatTime(entry.expires_at) : '永不过期'}
                    </td>
                    <td className="sec-td-r">
                      <button className="sec-btn-del" onClick={() => handleDeleteIntelWl(entry.id)}>
                        撤销
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {intelWlTotal > PAGE_SIZE && (
          <div className="sec-pagination">
            <button
              className="sec-page-btn"
              disabled={intelWlPage === 0}
              onClick={() => setIntelWlPage(p => p - 1)}
            >
              上一页
            </button>
            <span className="sec-page-info">
              第 {intelWlPage + 1} / {Math.ceil(intelWlTotal / PAGE_SIZE)} 页
            </span>
            <button
              className="sec-page-btn"
              disabled={(intelWlPage + 1) * PAGE_SIZE >= intelWlTotal}
              onClick={() => setIntelWlPage(p => p + 1)}
            >
              下一页
            </button>
          </div>
        )}
      </div>

    </div>
  )
}
