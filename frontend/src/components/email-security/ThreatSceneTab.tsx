import { useState, useEffect, useCallback } from 'react'
import type { ThreatScene, ThreatSceneStats, ThreatSceneRule } from '../../types'
import { apiFetch } from '../../utils/api'

const THREAT_CN: Record<string, string> = {
  safe: '安全', low: '低危', medium: '中危', high: '高危', critical: '严重',
}

export default function ThreatSceneTab() {
  const [sceneList, setSceneList] = useState<ThreatScene[]>([])
  const [sceneTotal, setSceneTotal] = useState(0)
  const [sceneStats, setSceneStats] = useState<ThreatSceneStats | null>(null)
  const [sceneTypeFilter, setSceneTypeFilter] = useState('')
  const [sceneStatusFilter, setSceneStatusFilter] = useState('')
  const [sceneExpanded, setSceneExpanded] = useState<string | null>(null)
  const [sceneRules, setSceneRules] = useState<ThreatSceneRule[]>([])
  const [showSceneConfig, setShowSceneConfig] = useState(false)
  const [sceneSaving, setSceneSaving] = useState(false)

  const fetchScenes = useCallback(async () => {
    try {
      const params = new URLSearchParams()
      if (sceneTypeFilter) params.set('scene_type', sceneTypeFilter)
      if (sceneStatusFilter) params.set('status', sceneStatusFilter)
      params.set('limit', '100')
      const [listRes, statsRes] = await Promise.all([
        apiFetch(`/api/security/threat-scenes?${params}`),
        apiFetch('/api/security/threat-scenes/stats'),
      ])
      if (listRes.ok) {
        const d = await listRes.json()
        setSceneList(d.items || [])
        setSceneTotal(d.total ?? 0)
      }
      if (statsRes.ok) {
        setSceneStats(await statsRes.json())
      }
    } catch (e) { console.error('Failed to fetch scenes:', e) }
  }, [sceneTypeFilter, sceneStatusFilter])

  const fetchSceneRules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/scene-rules')
      if (res.ok) setSceneRules(await res.json())
    } catch (e) { console.error('Failed to fetch scene rules:', e) }
  }, [])

  const handleSceneAction = async (id: string, action: 'acknowledge' | 'block' | 'resolve') => {
    setSceneSaving(true)
    try {
      const res = await apiFetch(`/api/security/threat-scenes/${id}/${action}`, { method: 'POST' })
      if (res.ok) await fetchScenes()
      else alert('操作失败')
    } catch (e) { console.error(`Scene ${action} failed:`, e) }
    finally { setSceneSaving(false) }
  }

  const handleDeleteScene = async (id: string) => {
    if (!confirm('确认删除此场景记录？')) return
    try {
      const res = await apiFetch(`/api/security/threat-scenes/${id}`, { method: 'DELETE' })
      if (res.ok) await fetchScenes()
    } catch (e) { console.error('Scene delete failed:', e) }
  }

  const handleSaveSceneRules = async () => {
    setSceneSaving(true)
    try {
      const res = await apiFetch('/api/security/scene-rules', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sceneRules),
      })
      if (res.ok) { setShowSceneConfig(false); await fetchScenes() }
      else alert('保存失败')
    } catch (e) { console.error('Save scene rules failed:', e) }
    finally { setSceneSaving(false) }
  }

  useEffect(() => {
    fetchScenes()
    fetchSceneRules()
  }, [fetchScenes, fetchSceneRules])

  return (
    <div className="sec-scene">
      {/* Stats cards */}
      <div className="sec-scene-cards">
        {([
          { type: 'bulk_mailing' as const, label: '群发邮件攻击', icon: '\u{1F4E7}', desc: '外部域名向内部收件人群发邮件' },
          { type: 'bounce_harvest' as const, label: '退信扫描攻击', icon: '\u{1F4E8}', desc: '退信涌入 = 攻击者在枚举邮箱地址' },
        ] as const).map(card => {
          const s = sceneStats?.[card.type]
          return (
            <div key={card.type} className="sec-scene-card">
              <div className="sec-scene-card-header">
                <span className="sec-scene-card-icon">{card.icon}</span>
                <span className="sec-scene-card-title">{card.label}</span>
              </div>
              <p className="sec-scene-card-desc">{card.desc}</p>
              <div className="sec-scene-card-metrics">
                <span data-active={!!s?.active}>活跃: <b>{s?.active ?? 0}</b></span>
                <span>已封禁: <b>{s?.auto_blocked ?? 0}</b></span>
                <span>24h 新增: <b>{s?.total_24h ?? 0}</b></span>
              </div>
              <div className="sec-scene-card-status" data-ok={String(sceneRules.find(r => r.scene_type === card.type)?.enabled !== false)}>
                <span className="sec-status-dot" data-ok={String(sceneRules.find(r => r.scene_type === card.type)?.enabled !== false)} />
                {sceneRules.find(r => r.scene_type === card.type)?.enabled !== false ? '检测已启用' : '检测已关闭'}
              </div>
            </div>
          )
        })}
      </div>

      {/* Toolbar */}
      <div className="sec-scene-toolbar">
        <div className="sec-scene-filters">
          <select value={sceneTypeFilter} onChange={e => setSceneTypeFilter(e.target.value)}>
            <option value="">全部类型</option>
            <option value="bulk_mailing">群发邮件</option>
            <option value="bounce_harvest">退信扫描</option>
          </select>
          <select value={sceneStatusFilter} onChange={e => setSceneStatusFilter(e.target.value)}>
            <option value="">全部状态</option>
            <option value="active">活跃</option>
            <option value="acknowledged">已确认</option>
            <option value="auto_blocked">已封禁</option>
            <option value="resolved">已解除</option>
          </select>
        </div>
        <div className="sec-scene-actions">
          <span className="sec-risk-total">共 {sceneTotal} 条</span>
          <button className="sec-btn sec-btn--outline" onClick={() => { fetchSceneRules(); setShowSceneConfig(true) }}>配置</button>
          <button className="sec-btn sec-btn--outline" onClick={fetchScenes}>刷新</button>
        </div>
      </div>

      {/* Scene list */}
      {sceneList.length === 0 ? (
        <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          暂无威胁场景
        </div>
      ) : (
        <table className="sec-table sec-table--hover">
          <thead>
            <tr>
              <th style={{width:'70px'}}>威胁等级</th>
              <th style={{width:'90px'}}>场景类型</th>
              <th>攻击者</th>
              <th style={{width:'70px'}}>邮件数</th>
              <th style={{width:'70px'}}>收件人</th>
              <th style={{width:'70px'}}>退信数</th>
              <th style={{width:'90px'}}>状态</th>
              <th style={{width:'130px'}}>检测时间</th>
              <th style={{width:'120px'}}>操作</th>
            </tr>
          </thead>
          <tbody>
            {sceneList.map(sc => (
              <>
                <tr key={sc.id} className="sec-risk-row" onClick={() => setSceneExpanded(sceneExpanded === sc.id ? null : sc.id)}>
                  <td><span className="sec-threat-tag" data-level={sc.threat_level}>{THREAT_CN[sc.threat_level] || sc.threat_level}</span></td>
                  <td>{sc.scene_type === 'bulk_mailing' ? '群发邮件' : '退信扫描'}</td>
                  <td className="sec-risk-from">{sc.actor}</td>
                  <td>{sc.email_count || '-'}</td>
                  <td>{sc.unique_recipients || '-'}</td>
                  <td>{sc.bounce_count || '-'}</td>
                  <td><span className="sec-scene-status" data-status={sc.status}>
                    {{active:'活跃',acknowledged:'已确认',auto_blocked:'已封禁',resolved:'已解除'}[sc.status] || sc.status}
                  </span></td>
                  <td className="sec-risk-time">{new Date(sc.created_at).toLocaleString('zh-CN', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' })}</td>
                  <td className="sec-scene-ops" onClick={e => e.stopPropagation()}>
                    {sc.status === 'active' && (
                      <>
                        <button className="sec-btn-sm" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'acknowledge')} title="确认">确认</button>
                        <button className="sec-btn-sm sec-btn-sm--danger" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'block')} title="封禁">封禁</button>
                      </>
                    )}
                    {sc.status === 'acknowledged' && (
                      <button className="sec-btn-sm sec-btn-sm--danger" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'block')} title="封禁">封禁</button>
                    )}
                    {(sc.status === 'active' || sc.status === 'acknowledged' || sc.status === 'auto_blocked') && (
                      <button className="sec-btn-sm" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'resolve')} title="解除">解除</button>
                    )}
                    <button className="sec-btn-sm" onClick={() => handleDeleteScene(sc.id)} title="删除">删除</button>
                  </td>
                </tr>
                {sceneExpanded === sc.id && (
                  <tr key={`${sc.id}-detail`} className="sec-scene-detail-row">
                    <td colSpan={9}>
                      <div className="sec-scene-detail">
                        <div className="sec-scene-detail-grid">
                          <div>
                            <h4>攻击者</h4>
                            <p>{sc.actor} ({sc.actor_type === 'domain' ? '域名' : '邮箱'})</p>
                          </div>
                          {sc.target_domain && (
                            <div>
                              <h4>目标域名</h4>
                              <p>{sc.target_domain}</p>
                            </div>
                          )}
                          <div>
                            <h4>时间窗口</h4>
                            <p>{new Date(sc.time_window_start).toLocaleString('zh-CN')} — {new Date(sc.time_window_end).toLocaleString('zh-CN')}</p>
                          </div>
                          <div>
                            <h4>统计</h4>
                            <p>邮件: {sc.email_count} 封 · 收件人: {sc.unique_recipients} 人{sc.bounce_count > 0 ? ` · 退信: ${sc.bounce_count} 封` : ''}</p>
                          </div>
                        </div>
                        {sc.sample_subjects.length > 0 && (
                          <div className="sec-scene-detail-section">
                            <h4>示例主题</h4>
                            <ul>{sc.sample_subjects.map((s, i) => <li key={i}>{s}</li>)}</ul>
                          </div>
                        )}
                        {sc.sample_recipients.length > 0 && (
                          <div className="sec-scene-detail-section">
                            <h4>涉及收件人</h4>
                            <p className="sec-scene-recipients">{sc.sample_recipients.join(', ')}</p>
                          </div>
                        )}
                        {sc.ioc_id && <p style={{marginTop:8,fontSize:12,color:'var(--text-tertiary)'}}>关联 IOC: {sc.ioc_id}</p>}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      )}

      {/* Config modal */}
      {showSceneConfig && (
        <div className="sec-modal-overlay" onClick={() => setShowSceneConfig(false)}>
          <div className="sec-modal" onClick={e => e.stopPropagation()} style={{maxWidth:560}}>
            <h3>威胁场景配置</h3>
            {sceneRules.map((rule, ri) => {
              const isBulk = rule.scene_type === 'bulk_mailing'
              const cfg = rule.config as Record<string, number | boolean | string[]>
              const setField = (key: string, val: number | boolean) => {
                const updated = [...sceneRules]
                updated[ri] = { ...rule, config: { ...cfg, [key]: val } }
                setSceneRules(updated)
              }
              return (
                <div key={rule.scene_type} className="sec-scene-cfg-block">
                  <div className="sec-scene-cfg-header">
                    <span>{isBulk ? '群发邮件检测' : '退信扫描检测'}</span>
                    <label className="sec-toggle">
                      <input type="checkbox" checked={rule.enabled} onChange={e => {
                        const updated = [...sceneRules]
                        updated[ri] = { ...rule, enabled: e.target.checked }
                        setSceneRules(updated)
                      }} />
                      <span className="sec-toggle-slider" />
                    </label>
                  </div>
                  <div className="sec-scene-cfg-fields">
                    <label>时间窗口 (小时)<input type="number" value={(cfg.time_window_hours as number) || 24} onChange={e => setField('time_window_hours', +e.target.value)} /></label>
                    {isBulk ? (
                      <>
                        <label>最少邮件数<input type="number" value={(cfg.min_emails as number) || 5} onChange={e => setField('min_emails', +e.target.value)} /></label>
                        <label>最少唯一收件人<input type="number" value={(cfg.min_unique_internal_recipients as number) || 3} onChange={e => setField('min_unique_internal_recipients', +e.target.value)} /></label>
                        <label className="sec-scene-cfg-check"><input type="checkbox" checked={cfg.auto_block_enabled as boolean || false} onChange={e => setField('auto_block_enabled', e.target.checked)} /> 自动封禁</label>
                        {cfg.auto_block_enabled && (
                          <>
                            <label>封禁阈值 (唯一收件人)<input type="number" value={(cfg.auto_block_recipient_threshold as number) || 10} onChange={e => setField('auto_block_recipient_threshold', +e.target.value)} /></label>
                            <label>封禁时长 (小时)<input type="number" value={(cfg.auto_block_duration_hours as number) || 48} onChange={e => setField('auto_block_duration_hours', +e.target.value)} /></label>
                          </>
                        )}
                      </>
                    ) : (
                      <>
                        <label>最少退信数<input type="number" value={(cfg.min_bounces as number) || 10} onChange={e => setField('min_bounces', +e.target.value)} /></label>
                        <label>最少唯一目标<input type="number" value={(cfg.min_unique_targets as number) || 5} onChange={e => setField('min_unique_targets', +e.target.value)} /></label>
                        <label className="sec-scene-cfg-check"><input type="checkbox" checked={cfg.auto_block_enabled as boolean || false} onChange={e => setField('auto_block_enabled', e.target.checked)} /> 自动封禁</label>
                        {cfg.auto_block_enabled && (
                          <>
                            <label>封禁阈值 (退信数)<input type="number" value={(cfg.auto_block_bounce_threshold as number) || 20} onChange={e => setField('auto_block_bounce_threshold', +e.target.value)} /></label>
                            <label>封禁时长 (小时)<input type="number" value={(cfg.auto_block_duration_hours as number) || 72} onChange={e => setField('auto_block_duration_hours', +e.target.value)} /></label>
                          </>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )
            })}
            <div className="sec-modal-footer">
              <button className="sec-btn sec-btn--outline" onClick={() => setShowSceneConfig(false)}>取消</button>
              <button className="sec-btn sec-btn--primary" disabled={sceneSaving} onClick={handleSaveSceneRules}>
                {sceneSaving ? '保存中...' : '保存'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
