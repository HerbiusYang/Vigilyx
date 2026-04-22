import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { ThreatScene, ThreatSceneStats, ThreatSceneRule } from '../../types'
import { apiFetch } from '../../utils/api'
import { formatDateFull, formatTime } from '../../utils/format'

export default function ThreatSceneTab() {
  const { t } = useTranslation()

  const THREAT_CN: Record<string, string> = {
    safe: t('emailSecurity.threatSafe'), low: t('emailSecurity.threatLow'), medium: t('emailSecurity.threatMedium'), high: t('emailSecurity.threatHigh'), critical: t('emailSecurity.threatCritical'),
  }

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
      else alert(t('emailSecurity.operationFailed'))
    } catch (e) { console.error(`Scene ${action} failed:`, e) }
    finally { setSceneSaving(false) }
  }

  const handleDeleteScene = async (id: string) => {
    if (!confirm(t('emailSecurity.confirmDeleteScene'))) return
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
      else alert(t('emailSecurity.saveFailed'))
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
          { type: 'bulk_mailing' as const, label: t('emailSecurity.bulkMailingAttack'), icon: '\u{1F4E7}', desc: t('emailSecurity.bulkMailingDesc') },
          { type: 'bounce_harvest' as const, label: t('emailSecurity.bounceHarvestAttack'), icon: '\u{1F4E8}', desc: t('emailSecurity.bounceHarvestDesc') },
          { type: 'internal_domain_impersonation' as const, label: t('emailSecurity.internalDomainImpersonation'), icon: '\u{1F3AD}', desc: t('emailSecurity.internalDomainImpersonationDesc') },
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
                <span data-active={!!s?.active}>{t('emailSecurity.active')}: <b>{s?.active ?? 0}</b></span>
                <span>{t('emailSecurity.blocked')}: <b>{s?.auto_blocked ?? 0}</b></span>
                <span>{t('emailSecurity.new24h')}: <b>{s?.total_24h ?? 0}</b></span>
              </div>
              <div className="sec-scene-card-status" data-ok={String(sceneRules.find(r => r.scene_type === card.type)?.enabled !== false)}>
                <span className="sec-status-dot" data-ok={String(sceneRules.find(r => r.scene_type === card.type)?.enabled !== false)} />
                {sceneRules.find(r => r.scene_type === card.type)?.enabled !== false ? t('emailSecurity.detectionEnabled') : t('emailSecurity.detectionDisabled')}
              </div>
            </div>
          )
        })}
      </div>

      {/* Toolbar */}
      <div className="sec-scene-toolbar">
        <div className="sec-scene-filters">
          <select value={sceneTypeFilter} onChange={e => setSceneTypeFilter(e.target.value)}>
            <option value="">{t('emailSecurity.allTypes')}</option>
            <option value="bulk_mailing">{t('emailSecurity.bulkMailing')}</option>
            <option value="bounce_harvest">{t('emailSecurity.bounceHarvest')}</option>
            <option value="internal_domain_impersonation">{t('emailSecurity.internalDomainImpersonation')}</option>
          </select>
          <select value={sceneStatusFilter} onChange={e => setSceneStatusFilter(e.target.value)}>
            <option value="">{t('emailSecurity.allStatuses')}</option>
            <option value="active">{t('emailSecurity.statusActive')}</option>
            <option value="acknowledged">{t('emailSecurity.statusAcknowledged')}</option>
            <option value="auto_blocked">{t('emailSecurity.statusBlocked')}</option>
            <option value="resolved">{t('emailSecurity.statusResolved')}</option>
          </select>
        </div>
        <div className="sec-scene-actions">
          <span className="sec-risk-total">{t('emailSecurity.totalItems', { count: sceneTotal })}</span>
          <button className="sec-btn sec-btn--outline" onClick={() => { fetchSceneRules(); setShowSceneConfig(true) }}>{t('emailSecurity.configure')}</button>
          <button className="sec-btn sec-btn--outline" onClick={fetchScenes}>{t('emailSecurity.refresh')}</button>
        </div>
      </div>

      {/* Scene list */}
      {sceneList.length === 0 ? (
        <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          {t('emailSecurity.noThreatScenes')}
        </div>
      ) : (
        <table className="sec-table sec-table--hover">
          <thead>
            <tr>
              <th style={{width:'70px'}}>{t('emailSecurity.threatLevel')}</th>
              <th style={{width:'90px'}}>{t('emailSecurity.sceneType')}</th>
              <th>{t('emailSecurity.attacker')}</th>
              <th style={{width:'70px'}}>{t('emailSecurity.emailCount')}</th>
              <th style={{width:'70px'}}>{t('emailSecurity.recipients')}</th>
              <th style={{width:'70px'}}>{t('emailSecurity.bounceCount')}</th>
              <th style={{width:'90px'}}>{t('emailSecurity.status')}</th>
              <th style={{width:'130px'}}>{t('emailSecurity.detectionTime')}</th>
              <th style={{width:'120px'}}>{t('emailSecurity.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {sceneList.map(sc => (
              <>
                <tr key={sc.id} className="sec-risk-row" onClick={() => setSceneExpanded(sceneExpanded === sc.id ? null : sc.id)}>
                  <td><span className="sec-threat-tag" data-level={sc.threat_level}>{THREAT_CN[sc.threat_level] || sc.threat_level}</span></td>
                  <td>{sc.scene_type === 'bulk_mailing' ? t('emailSecurity.bulkMailing') : sc.scene_type === 'bounce_harvest' ? t('emailSecurity.bounceHarvest') : t('emailSecurity.internalDomainImpersonation')}</td>
                  <td className="sec-risk-from">{sc.actor}</td>
                  <td>{sc.email_count || '-'}</td>
                  <td>{sc.unique_recipients || '-'}</td>
                  <td>{sc.bounce_count || '-'}</td>
                  <td><span className="sec-scene-status" data-status={sc.status}>
                    {{active: t('emailSecurity.statusActive'), acknowledged: t('emailSecurity.statusAcknowledged'), auto_blocked: t('emailSecurity.statusBlocked'), resolved: t('emailSecurity.statusResolved')}[sc.status] || sc.status}
                  </span></td>
                  <td className="sec-risk-time">{formatTime(sc.created_at)}</td>
                  <td className="sec-scene-ops" onClick={e => e.stopPropagation()}>
                    {sc.status === 'active' && (
                      <>
                        <button className="sec-btn-sm" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'acknowledge')} title={t('emailSecurity.acknowledge')}>{t('emailSecurity.acknowledge')}</button>
                        <button className="sec-btn-sm sec-btn-sm--danger" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'block')} title={t('emailSecurity.block')}>{t('emailSecurity.block')}</button>
                      </>
                    )}
                    {sc.status === 'acknowledged' && (
                      <button className="sec-btn-sm sec-btn-sm--danger" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'block')} title={t('emailSecurity.block')}>{t('emailSecurity.block')}</button>
                    )}
                    {(sc.status === 'active' || sc.status === 'acknowledged' || sc.status === 'auto_blocked') && (
                      <button className="sec-btn-sm" disabled={sceneSaving} onClick={() => handleSceneAction(sc.id, 'resolve')} title={t('emailSecurity.resolve')}>{t('emailSecurity.resolve')}</button>
                    )}
                    <button className="sec-btn-sm" onClick={() => handleDeleteScene(sc.id)} title={t('emailSecurity.delete')}>{t('emailSecurity.delete')}</button>
                  </td>
                </tr>
                {sceneExpanded === sc.id && (
                  <tr key={`${sc.id}-detail`} className="sec-scene-detail-row">
                    <td colSpan={9}>
                      <div className="sec-scene-detail">
                        <div className="sec-scene-detail-grid">
                          <div>
                            <h4>{t('emailSecurity.attacker')}</h4>
                            <p>{sc.actor} ({sc.actor_type === 'domain' ? t('emailSecurity.domain') : t('emailSecurity.email')})</p>
                          </div>
                          {sc.target_domain && (
                            <div>
                              <h4>{t('emailSecurity.targetDomain')}</h4>
                              <p>{sc.target_domain}</p>
                            </div>
                          )}
                          {typeof sc.details?.similarity_type === 'string' && (
                            <div>
                              <h4>{t('emailSecurity.similarityType')}</h4>
                              <p>{({
                                tld_swap: t('emailSecurity.simTldSwap'),
                                subdomain_prefix: t('emailSecurity.simSubdomainPrefix'),
                                typosquatting: t('emailSecurity.simTyposquatting'),
                                homoglyph: t('emailSecurity.simHomoglyph'),
                              } as Record<string, string>)[sc.details.similarity_type] ?? sc.details.similarity_type}</p>
                            </div>
                          )}
                          <div>
                            <h4>{t('emailSecurity.timeWindow')}</h4>
                            <p>{formatDateFull(sc.time_window_start)} — {formatDateFull(sc.time_window_end)}</p>
                          </div>
                          <div>
                            <h4>{t('emailSecurity.statistics')}</h4>
                            <p>{t('emailSecurity.statsEmails', { count: sc.email_count })} · {t('emailSecurity.statsRecipients', { count: sc.unique_recipients })}{sc.bounce_count > 0 ? ` · ${t('emailSecurity.statsBounces', { count: sc.bounce_count })}` : ''}</p>
                          </div>
                        </div>
                        {sc.sample_subjects.length > 0 && (
                          <div className="sec-scene-detail-section">
                            <h4>{t('emailSecurity.sampleSubjects')}</h4>
                            <ul>{sc.sample_subjects.map((s, i) => <li key={i}>{s}</li>)}</ul>
                          </div>
                        )}
                        {sc.sample_recipients.length > 0 && (
                          <div className="sec-scene-detail-section">
                            <h4>{t('emailSecurity.involvedRecipients')}</h4>
                            <p className="sec-scene-recipients">{sc.sample_recipients.join(', ')}</p>
                          </div>
                        )}
                        {sc.ioc_id && <p style={{marginTop:8,fontSize:12,color:'var(--text-tertiary)'}}>{t('emailSecurity.relatedIoc')}: {sc.ioc_id}</p>}
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
            <h3>{t('emailSecurity.threatSceneConfig')}</h3>
            {sceneRules.map((rule, ri) => {
              const isBulk = rule.scene_type === 'bulk_mailing'
              const isBounce = rule.scene_type === 'bounce_harvest'
              const isImpersonation = rule.scene_type === 'internal_domain_impersonation'
              const cfg = rule.config as Record<string, number | boolean | string[]>
              const setField = (key: string, val: number | boolean) => {
                const updated = [...sceneRules]
                updated[ri] = { ...rule, config: { ...cfg, [key]: val } }
                setSceneRules(updated)
              }
              const ruleLabel = isBulk ? t('emailSecurity.bulkMailingDetection')
                : isBounce ? t('emailSecurity.bounceHarvestDetection')
                : t('emailSecurity.internalDomainImpersonationDetection')
              return (
                <div key={rule.scene_type} className="sec-scene-cfg-block">
                  <div className="sec-scene-cfg-header">
                    <span>{ruleLabel}</span>
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
                    <label>{t('emailSecurity.timeWindowHours')}<input type="number" value={(cfg.time_window_hours as number) || 24} onChange={e => setField('time_window_hours', +e.target.value)} /></label>
                    {isBulk && (
                      <>
                        <label>{t('emailSecurity.minEmails')}<input type="number" value={(cfg.min_emails as number) || 5} onChange={e => setField('min_emails', +e.target.value)} /></label>
                        <label>{t('emailSecurity.minUniqueRecipients')}<input type="number" value={(cfg.min_unique_internal_recipients as number) || 3} onChange={e => setField('min_unique_internal_recipients', +e.target.value)} /></label>
                        <label className="sec-scene-cfg-check"><input type="checkbox" checked={cfg.auto_block_enabled as boolean || false} onChange={e => setField('auto_block_enabled', e.target.checked)} /> {t('emailSecurity.autoBlock')}</label>
                        {cfg.auto_block_enabled && (
                          <>
                            <label>{t('emailSecurity.blockThresholdRecipients')}<input type="number" value={(cfg.auto_block_recipient_threshold as number) || 10} onChange={e => setField('auto_block_recipient_threshold', +e.target.value)} /></label>
                            <label>{t('emailSecurity.blockDurationHours')}<input type="number" value={(cfg.auto_block_duration_hours as number) || 48} onChange={e => setField('auto_block_duration_hours', +e.target.value)} /></label>
                          </>
                        )}
                      </>
                    )}
                    {isBounce && (
                      <>
                        <label>{t('emailSecurity.minBounces')}<input type="number" value={(cfg.min_bounces as number) || 10} onChange={e => setField('min_bounces', +e.target.value)} /></label>
                        <label>{t('emailSecurity.minUniqueTargets')}<input type="number" value={(cfg.min_unique_targets as number) || 5} onChange={e => setField('min_unique_targets', +e.target.value)} /></label>
                        <label className="sec-scene-cfg-check"><input type="checkbox" checked={cfg.auto_block_enabled as boolean || false} onChange={e => setField('auto_block_enabled', e.target.checked)} /> {t('emailSecurity.autoBlock')}</label>
                        {cfg.auto_block_enabled && (
                          <>
                            <label>{t('emailSecurity.blockThresholdBounces')}<input type="number" value={(cfg.auto_block_bounce_threshold as number) || 20} onChange={e => setField('auto_block_bounce_threshold', +e.target.value)} /></label>
                            <label>{t('emailSecurity.blockDurationHours')}<input type="number" value={(cfg.auto_block_duration_hours as number) || 72} onChange={e => setField('auto_block_duration_hours', +e.target.value)} /></label>
                          </>
                        )}
                      </>
                    )}
                    {isImpersonation && (
                      <>
                        <label>{t('emailSecurity.minEmails')}<input type="number" value={(cfg.min_emails as number) || 3} onChange={e => setField('min_emails', +e.target.value)} /></label>
                        <label className="sec-scene-cfg-check"><input type="checkbox" checked={cfg.auto_block_enabled as boolean || false} onChange={e => setField('auto_block_enabled', e.target.checked)} /> {t('emailSecurity.autoBlock')}</label>
                        {cfg.auto_block_enabled && (
                          <label>{t('emailSecurity.blockDurationHours')}<input type="number" value={(cfg.auto_block_duration_hours as number) || 48} onChange={e => setField('auto_block_duration_hours', +e.target.value)} /></label>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )
            })}
            <div className="sec-modal-footer">
              <button className="sec-btn sec-btn--outline" onClick={() => setShowSceneConfig(false)}>{t('emailSecurity.cancel')}</button>
              <button className="sec-btn sec-btn--primary" disabled={sceneSaving} onClick={handleSaveSceneRules}>
                {sceneSaving ? t('emailSecurity.saving') : t('emailSecurity.save')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
