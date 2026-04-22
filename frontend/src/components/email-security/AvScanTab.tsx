import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { ModuleMetadata, PipelineConfig, EngineStatus, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'

type ActiveEngine = 'clamav' | 'yara'

interface AvScanTabProps {
  /** Which sub-tab was active when parent mounted this component */
  initialEngine: ActiveEngine
  modules: ModuleMetadata[]
  engineStatus: EngineStatus | null
  pipelineConfig: PipelineConfig | null
  onToggleModule: (moduleId: string) => void
  /** Notify parent when sub-tab changes so URL can update */
  onEngineChange: (engine: ActiveEngine) => void
}

export default function AvScanTab({
  initialEngine,
  modules,
  engineStatus,
  pipelineConfig,
  onToggleModule,
  onEngineChange,
}: AvScanTabProps) {
  const { t } = useTranslation()
  const [activeEngine, setActiveEngine] = useState<ActiveEngine>(initialEngine)

  // Sync if parent changes the prop (e.g. URL navigation)
  useEffect(() => { setActiveEngine(initialEngine) }, [initialEngine])

  // YARA state
  const [yaraRules, setYaraRules] = useState<any[]>([])
  const [yaraSearch, setYaraSearch] = useState('')
  const [showYaraEditor, setShowYaraEditor] = useState(false)
  const [editingYaraRule, setEditingYaraRule] = useState<any>(null)
  const [yaraForm, setYaraForm] = useState({ rule_name: '', category: 'custom', severity: 'high', rule_source: '', description: '' })
  const [yaraValidation, setYaraValidation] = useState<{ valid: boolean; error?: string } | null>(null)
  const [yaraSaving, setYaraSaving] = useState(false)
  const [expandedYaraCats, setExpandedYaraCats] = useState<Set<string>>(new Set())

  // -- Fetch YARA rules --
  const fetchYaraRules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/yara-rules')
      const data: ApiResponse<{ items: any[]; total: number }> = await res.json()
      if (data.success && data.data) setYaraRules(data.data.items)
    } catch (e) {
      console.error('Failed to fetch YARA rules:', e)
    }
  }, [])

  useEffect(() => {
    if (activeEngine === 'yara') fetchYaraRules()
  }, [activeEngine, fetchYaraRules])

  // -- YARA CRUD --
  const saveYaraRule = async () => {
    if (!yaraForm.rule_name.trim() || !yaraForm.rule_source.trim()) return
    setYaraSaving(true)
    try {
      const method = editingYaraRule ? 'PUT' : 'POST'
      const url = editingYaraRule ? `/api/security/yara-rules/${editingYaraRule.id}` : '/api/security/yara-rules'
      const res = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(yaraForm),
      })
      const data = await res.json()
      if (data.success) {
        setShowYaraEditor(false)
        setEditingYaraRule(null)
        setYaraForm({ rule_name: '', category: 'custom', severity: 'high', rule_source: '', description: '' })
        setYaraValidation(null)
        fetchYaraRules()
      } else {
        alert(data.error || t('emailSecurity.saveFailed'))
      }
    } catch (e) {
      console.error('Failed to save YARA rule:', e)
    } finally {
      setYaraSaving(false)
    }
  }

  const deleteYaraRule = async (id: string, source: string) => {
    if (source === 'builtin') { alert(t('emailSecurity.builtinRuleCannotDelete')); return }
    if (!confirm(t('emailSecurity.confirmDeleteRule'))) return
    try {
      const res = await apiFetch(`/api/security/yara-rules/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (data.success) fetchYaraRules()
      else alert(data.error || t('emailSecurity.deleteFailed'))
    } catch (e) { console.error('Failed to delete:', e) }
  }

  const toggleYaraRule = async (id: string, enabled: boolean) => {
    try {
      await apiFetch(`/api/security/yara-rules/${id}/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      })
      fetchYaraRules()
    } catch (e) { console.error('Failed to toggle:', e) }
  }

  const validateYaraRule = async () => {
    if (!yaraForm.rule_source.trim()) { setYaraValidation({ valid: false, error: t('emailSecurity.ruleSourceEmpty') }); return }
    try {
      const res = await apiFetch('/api/security/yara-rules/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_source: yaraForm.rule_source }),
      })
      const data = await res.json()
      if (data.success && data.data) setYaraValidation(data.data)
    } catch { setYaraValidation({ valid: false, error: t('emailSecurity.validationRequestFailed') }) }
  }

  // -- Tab switch helper --
  const switchEngine = (engine: ActiveEngine) => {
    setActiveEngine(engine)
    onEngineChange(engine)
  }

  // -- Category constants --
  const catColors: Record<string, string> = { malicious_document: '#f59e0b', executable_disguise: '#dc2626', malware_family: '#a855f7', webshell: '#3b82f6', advanced_threat: '#f43f5e', evasion_technique: '#8b5cf6', custom: '#22d3ee' }
  const catNames: Record<string, string> = { malicious_document: t('emailSecurity.catMaliciousDocument'), executable_disguise: t('emailSecurity.catExecutableDisguise'), malware_family: t('emailSecurity.catMalwareFamily'), webshell: t('emailSecurity.catWebshell'), advanced_threat: t('emailSecurity.catAdvancedThreat'), evasion_technique: t('emailSecurity.catEvasionTechnique'), custom: t('emailSecurity.catCustom') }
  const catIcons: Record<string, JSX.Element> = {
    malicious_document: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6"/><path d="M9 15l3 3 3-3"/></svg>,
    executable_disguise: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><circle cx="12" cy="16" r="1"/></svg>,
    malware_family: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/><path d="M19 10a7 7 0 0 1-14 0"/><path d="M12 14v8"/><path d="M8 18h8"/></svg>,
    webshell: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/><line x1="12" y1="2" x2="12" y2="22" strokeDasharray="2 3"/></svg>,
    advanced_threat: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    evasion_technique: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/><line x1="1" y1="1" x2="23" y2="23" strokeWidth="2"/></svg>,
    custom: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
  }
  const catOrder = ['malicious_document', 'executable_disguise', 'malware_family', 'webshell', 'advanced_threat', 'evasion_technique', 'custom']

  return (
    <>
      {/* Segmented control */}
      <div className="av-seg">
        <button className={`av-seg-btn ${activeEngine === 'clamav' ? 'av-seg-btn--active' : ''}`} data-engine="clamav" onClick={() => switchEngine('clamav')}>
          <span className={`av-seg-dot ${
            engineStatus?.module_metrics?.some(m => m.module_id === 'av_eml_scan' && m.total_runs > 0)
              ? 'av-seg-dot--online'
              : pipelineConfig?.modules.some(m => m.id === 'av_eml_scan' && m.enabled)
                ? 'av-seg-dot--pending'
                : 'av-seg-dot--offline'
          }`} />
          {t('emailSecurity.clamavSignatureEngine')}
          <span className="av-seg-count">{t('emailSecurity.moduleCount', { count: 2 })}</span>
        </button>
        <button className={`av-seg-btn ${activeEngine === 'yara' ? 'av-seg-btn--active' : ''}`} data-engine="yara" onClick={() => switchEngine('yara')}>
          <span className={`av-seg-dot ${
            engineStatus?.module_metrics?.some(m => m.module_id === 'yara_scan' && m.total_runs > 0)
              ? 'av-seg-dot--online'
              : 'av-seg-dot--pending'
          }`} />
          {t('emailSecurity.yaraCustomRules')}
          <span className="av-seg-count">{t('emailSecurity.ruleCount', { count: yaraRules.length || 28 })}</span>
        </button>
      </div>

      {/* ═══ ClamAV ═══ */}
      {activeEngine === 'clamav' && (() => {
        const avEmlMetric = engineStatus?.module_metrics?.find(m => m.module_id === 'av_eml_scan')
        const avAttMetric = engineStatus?.module_metrics?.find(m => m.module_id === 'av_attach_scan')
        const totalScans = (avEmlMetric?.total_runs ?? 0) + (avAttMetric?.total_runs ?? 0)
        const avEnabled = pipelineConfig?.modules.some(m => m.id === 'av_eml_scan' && m.enabled)
        const isOnline = avEnabled && (totalScans > 0 || modules.some(m => m.id === 'av_eml_scan'))
        return (
        <div className="av-panel">
          <div className="sec-card" style={{ padding: '14px 20px', marginBottom: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: isOnline ? '#10b981' : avEnabled ? '#f59e0b' : '#6b7280', boxShadow: isOnline ? '0 0 6px #10b981' : 'none' }} />
              <span style={{ fontSize: 13, fontWeight: 500, color: 'rgba(255,255,255,0.7)' }}>{isOnline ? t('emailSecurity.onlineRunning') : avEnabled ? t('emailSecurity.awaitingFirstScan') : t('emailSecurity.notEnabled')}</span>
              <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)' }}>v1.4 / TCP INSTREAM / 3310</span>
            </div>
            {totalScans > 0 && (
              <div style={{ display: 'flex', gap: 20, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'rgba(255,255,255,0.5)' }}>
                <span><strong style={{ color: 'rgba(255,255,255,0.85)' }}>{totalScans.toLocaleString()}</strong> {t('emailSecurity.scans')}</span>
                <span><strong style={{ color: '#10b981' }}>{((((avEmlMetric?.success_rate ?? 1) + (avAttMetric?.success_rate ?? 1)) / 2) * 100).toFixed(0)}%</strong> {t('emailSecurity.successRate')}</span>
                <span><strong style={{ color: 'rgba(255,255,255,0.85)' }}>{(((avEmlMetric?.avg_duration_ms ?? 0) + (avAttMetric?.avg_duration_ms ?? 0)) / 2).toFixed(0)}ms</strong> {t('emailSecurity.average')}</span>
              </div>
            )}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            {[
              { id: 'av_eml_scan', name: t('emailSecurity.emlVirusScan'), desc: t('emailSecurity.emlVirusScanDesc') },
              { id: 'av_attach_scan', name: t('emailSecurity.attachVirusScan'), desc: t('emailSecurity.attachVirusScanDesc') },
            ].map(mod => {
              const cfg = pipelineConfig?.modules.find(m => m.id === mod.id)
              const enabled = cfg?.enabled ?? true
              const metric = mod.id === 'av_eml_scan' ? avEmlMetric : avAttMetric
              return (
                <div key={mod.id} className="sec-card" style={{ padding: 18 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.85)' }}>{mod.name}</div>
                    <label className="sec-toggle sec-toggle--sm"><input type="checkbox" checked={enabled} onChange={() => onToggleModule(mod.id)} /><span className="sec-toggle-slider" /></label>
                  </div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', lineHeight: 1.6, marginBottom: metric && metric.total_runs > 0 ? 12 : 0 }}>{mod.desc}</div>
                  {metric && metric.total_runs > 0 && (
                    <div style={{ display: 'flex', gap: 16, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'rgba(255,255,255,0.4)', padding: '8px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.02)' }}>
                      <span>{metric.total_runs.toLocaleString()} {t('emailSecurity.times')}</span>
                      <span>{metric.avg_duration_ms.toFixed(0)}ms</span>
                      <span style={{ color: metric.success_rate >= 0.95 ? '#10b981' : '#f59e0b' }}>{(metric.success_rate * 100).toFixed(0)}%</span>
                      {metric.failure_count > 0 && <span style={{ color: '#f43f5e' }}>{metric.failure_count} fail</span>}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          <div className="sec-card" style={{ padding: '10px 12px', fontSize: 11, color: 'rgba(255,255,255,0.3)', lineHeight: 1.7 }}>
            {t('emailSecurity.freshclamNote')}
          </div>
        </div>
        )
      })()}

      {/* ═══ YARA ═══ */}
      {activeEngine === 'yara' && (() => {
        const yaraEnabled = pipelineConfig?.modules.find(m => m.id === 'yara_scan')?.enabled ?? true
        const yaraMetric = engineStatus?.module_metrics?.find(m => m.module_id === 'yara_scan')
        const isOnline = yaraEnabled && ((yaraMetric?.total_runs ?? 0) > 0 || modules.some(m => m.id === 'yara_scan'))

        // Group by category
        const catGroups = yaraRules.reduce((acc, r) => {
          const cat = r.category || 'custom'
          if (!acc[cat]) acc[cat] = []
          acc[cat].push(r)
          return acc
        }, {} as Record<string, any[]>)
        const catKeys = catOrder.filter(k => (catGroups[k]?.length ?? 0) > 0 || k === 'custom')
        const selCatKey = catKeys.find(k => expandedYaraCats.has(k))
        const selRulesRaw = selCatKey ? (catGroups[selCatKey] || []) : null
        const selRules = selRulesRaw?.filter((r: any) => !yaraSearch || r.rule_name.toLowerCase().includes(yaraSearch.toLowerCase()) || (r.description || '').toLowerCase().includes(yaraSearch.toLowerCase())) ?? null
        const enabledCount = yaraRules.filter(r => r.enabled).length
        const totalRuleCount = yaraRules.length

        return (
        <div className="av-panel">
          {/* Status bar */}
          <div className="yr-status-bar">
            <div className="yr-status-left">
              <div className={`yr-status-dot ${isOnline ? 'yr-status-dot--on' : yaraEnabled ? 'yr-status-dot--wait' : 'yr-status-dot--off'}`} />
              <span className="yr-status-text">{isOnline ? t('emailSecurity.onlineRunning') : yaraEnabled ? t('emailSecurity.awaitingFirstScan') : t('emailSecurity.notEnabled')}</span>
              <span className="yr-status-ver">yara-x / {yaraRules.length} rules / {enabledCount} active</span>
            </div>
            <div className="yr-status-right">
              {yaraMetric && yaraMetric.total_runs > 0 && <>
                <span className="yr-status-metric"><strong>{yaraMetric.total_runs.toLocaleString()}</strong> scans</span>
                <span className="yr-status-metric"><strong>{yaraMetric.avg_duration_ms.toFixed(0)}ms</strong> avg</span>
                <span className="yr-status-metric"><strong style={{ color: yaraMetric.success_rate >= 0.95 ? 'var(--accent-green)' : '#f59e0b' }}>{(yaraMetric.success_rate * 100).toFixed(1)}%</strong></span>
              </>}
            </div>
          </div>

          {/* Toolbar */}
          <div className="yr-toolbar">
            <div className="yr-toolbar-left">
              <div className="yr-search-box">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                <input value={yaraSearch} onChange={e => setYaraSearch(e.target.value)} placeholder={t('emailSecurity.searchRulesPlaceholder')} className="yr-search-input" />
                {yaraSearch && <button className="yr-search-clear" onClick={() => setYaraSearch('')}>&times;</button>}
              </div>
              <div className="yr-toolbar-tags">
                <span className="yr-tag yr-tag--builtin">{t('emailSecurity.builtinCount', { count: totalRuleCount })}</span>
              </div>
            </div>
            <div className="yr-toolbar-right">
              <button className="yr-btn-add"
                onClick={() => { setEditingYaraRule(null); setYaraForm({ rule_name: '', category: 'custom', severity: 'high', rule_source: '', description: '' }); setYaraValidation(null); setShowYaraEditor(true) }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 5v14m-7-7h14"/></svg>
                {t('emailSecurity.addRule')}
              </button>
              <label className="sec-toggle sec-toggle--sm" title={yaraEnabled ? t('emailSecurity.yaraScanEnabled') : t('emailSecurity.yaraScanDisabled')}>
                <input type="checkbox" checked={yaraEnabled} onChange={() => onToggleModule('yara_scan')} />
                <span className="sec-toggle-slider" />
              </label>
            </div>
          </div>

          {/* Category stat cards */}
          <div className="yr-hero">
            {catKeys.map(cat => {
              const isActive = expandedYaraCats.has(cat)
              const color = catColors[cat] || '#6b7280'
              const rules = catGroups[cat] || []
              const enabled = rules.filter((r: any) => r.enabled).length
              return (
                <div key={cat} className={`yr-stat ${isActive ? 'yr-stat--active' : ''}`}
                  style={{ '--yr-color': color } as React.CSSProperties}
                  onClick={() => setExpandedYaraCats(prev => { const n = new Set<string>(); if (!prev.has(cat)) n.add(cat); return n })}>
                  <div className="yr-stat-icon" style={{ color }}>{catIcons[cat]}</div>
                  <div className="yr-stat-num" style={{ color: isActive ? color : 'var(--text-primary)' }}>{rules.length}</div>
                  <div className="yr-stat-label">{catNames[cat] || cat}</div>
                  <div className="yr-stat-sub">{t('emailSecurity.enabledOf', { enabled, total: rules.length })}</div>
                </div>
              )
            })}
          </div>

          {/* Rules table */}
          {selRules && selCatKey ? (
            <div className="yr-table">
              <div className="yr-table-title">
                <div className="yr-table-title-bar" style={{ background: catColors[selCatKey] || '#6b7280' }} />
                <span className="yr-table-title-icon" style={{ color: catColors[selCatKey] }}>{catIcons[selCatKey]}</span>
                <span className="yr-table-title-text">{catNames[selCatKey] || selCatKey}</span>
                <span className="yr-table-title-count">{yaraSearch && selRulesRaw && selRules.length !== selRulesRaw.length ? t('emailSecurity.filteredItemCount', { filtered: selRules.length, total: selRulesRaw.length }) : t('emailSecurity.itemCount', { count: selRules.length })}</span>
                <button className="yr-table-close" onClick={() => setExpandedYaraCats(new Set())} title={t('emailSecurity.collapse')}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                </button>
              </div>
              <div className="yr-table-head">
                <span>{t('emailSecurity.ruleName')}</span><span>{t('emailSecurity.description')}</span><span>{t('emailSecurity.source')}</span><span>{t('emailSecurity.severity')}</span><span>{t('emailSecurity.hits')}</span><span></span>
              </div>
              {selRules.length === 0 && yaraSearch ? (
                <div className="yr-table-empty">{t('emailSecurity.noMatchingRules', { search: yaraSearch })}</div>
              ) : selRules.map((rule: any) => (
                <div key={rule.id} className={`yr-rule-row ${!rule.enabled ? 'yr-rule-row--disabled' : ''}`}
                  onClick={() => { setEditingYaraRule(rule); setYaraForm({ rule_name: rule.rule_name, category: rule.category, severity: rule.severity, rule_source: rule.rule_source, description: rule.description }); setYaraValidation(null); setShowYaraEditor(true) }}>
                  <span className="yr-rule-name" style={{ color: rule.enabled ? (catColors[selCatKey] || '#6b7280') : 'var(--text-tertiary)' }}>{rule.rule_name}</span>
                  <span className="yr-rule-desc">{rule.description || '—'}</span>
                  <span className={`yr-rule-source ${'yr-rule-source--builtin'}`}>{t('emailSecurity.builtin')}</span>
                  <span className={`yr-sev yr-sev--${rule.severity}`}>{rule.severity === 'critical' ? 'CRIT' : rule.severity === 'high' ? 'HIGH' : 'MED'}</span>
                  <span className="yr-rule-hits">{(rule.hit_count ?? 0) > 0 ? rule.hit_count.toLocaleString() : '—'}</span>
                  <div className="yr-rule-toggle" onClick={e => e.stopPropagation()}>
                    <label className="sec-toggle sec-toggle--sm" style={{ transform: 'scale(0.75)' }}>
                      <input type="checkbox" checked={rule.enabled} onChange={() => toggleYaraRule(rule.id, !rule.enabled)} />
                      <span className="sec-toggle-slider" />
                    </label>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="yr-overview">
              <div className="yr-overview-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
              </div>
              <div className="yr-overview-title">{t('emailSecurity.selectCategoryToView')}</div>
              <div className="yr-overview-desc">{t('emailSecurity.clickCategoryCard')}</div>
              {yaraRules.length > 0 && (
                <div className="yr-overview-summary">
                  <div className="yr-overview-item">
                    <span className="yr-overview-val">{yaraRules.length}</span>
                    <span className="yr-overview-lbl">{t('emailSecurity.totalRules')}</span>
                  </div>
                  <div className="yr-overview-divider" />
                  <div className="yr-overview-item">
                    <span className="yr-overview-val" style={{ color: 'var(--accent-green)' }}>{enabledCount}</span>
                    <span className="yr-overview-lbl">{t('emailSecurity.enabled')}</span>
                  </div>
                  <div className="yr-overview-divider" />
                  <div className="yr-overview-item">
                    <span className="yr-overview-val" style={{ color: '#ef4444' }}>{yaraRules.filter(r => r.severity === 'critical').length}</span>
                    <span className="yr-overview-lbl">Critical</span>
                  </div>
                  <div className="yr-overview-divider" />
                  <div className="yr-overview-item">
                    <span className="yr-overview-val" style={{ color: '#f59e0b' }}>{yaraRules.filter(r => r.severity === 'high').length}</span>
                    <span className="yr-overview-lbl">High</span>
                  </div>
                  <div className="yr-overview-divider" />
                  <div className="yr-overview-item">
                    <span className="yr-overview-val" style={{ color: '#3b82f6' }}>{yaraRules.filter(r => r.severity === 'medium').length}</span>
                    <span className="yr-overview-lbl">Medium</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* -- Rule-editor modal -- */}
          {showYaraEditor && (
            <div className="yr-modal-overlay" onClick={() => setShowYaraEditor(false)}>
              <div className="yr-modal" onClick={e => e.stopPropagation()}>
                {/* Modal header */}
                <div className="yr-modal-header">
                  <div className="yr-modal-title-row">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span className="yr-modal-title">{editingYaraRule ? t('emailSecurity.editYaraRule') : t('emailSecurity.newYaraRule')}</span>
                    {editingYaraRule && <span className="yr-modal-badge">{editingYaraRule.source === 'builtin' ? t('emailSecurity.builtin') : t('emailSecurity.custom')}</span>}
                  </div>
                  <button onClick={() => setShowYaraEditor(false)} className="yr-modal-close">&times;</button>
                </div>

                {/* Form */}
                <div className="yr-modal-body">
                  <div className="yr-form-row">
                    <div className="yr-form-field">
                      <label className="yr-form-label">{t('emailSecurity.ruleName')} <span className="yr-form-req">*</span></label>
                      <input value={yaraForm.rule_name} onChange={e => setYaraForm(p => ({ ...p, rule_name: e.target.value }))}
                        placeholder="My_Custom_Rule" className="yr-form-input yr-form-input--mono"
                        disabled={editingYaraRule?.source === 'builtin'} />
                    </div>
                    <div className="yr-form-field">
                      <label className="yr-form-label">{t('emailSecurity.description')}</label>
                      <input value={yaraForm.description} onChange={e => setYaraForm(p => ({ ...p, description: e.target.value }))}
                        placeholder={t('emailSecurity.descriptionPlaceholder')} className="yr-form-input" />
                    </div>
                  </div>

                  <div className="yr-form-row">
                    <div className="yr-form-field">
                      <label className="yr-form-label">{t('emailSecurity.category')}</label>
                      <select value={yaraForm.category} onChange={e => setYaraForm(p => ({ ...p, category: e.target.value }))} className="yr-form-select">
                        <option value="malicious_document">{t('emailSecurity.catMaliciousDocument')}</option>
                        <option value="executable_disguise">{t('emailSecurity.catExecutableDisguise')}</option>
                        <option value="malware_family">{t('emailSecurity.catMalwareFamilyFull')}</option>
                        <option value="webshell">{t('emailSecurity.catWebshell')}</option>
                        <option value="advanced_threat">{t('emailSecurity.catAdvancedThreat')}</option>
                        <option value="evasion_technique">{t('emailSecurity.catEvasionTechnique')}</option>
                        <option value="custom">{t('emailSecurity.catCustom')}</option>
                      </select>
                    </div>
                    <div className="yr-form-field">
                      <label className="yr-form-label">{t('emailSecurity.severityLabel')}</label>
                      <select value={yaraForm.severity} onChange={e => setYaraForm(p => ({ ...p, severity: e.target.value }))} className="yr-form-select">
                        <option value="critical">{t('emailSecurity.severityCritical')}</option>
                        <option value="high">{t('emailSecurity.severityHigh')}</option>
                        <option value="medium">{t('emailSecurity.severityMedium')}</option>
                      </select>
                    </div>
                  </div>

                  <div className="yr-form-field">
                    <div className="yr-form-code-header">
                      <label className="yr-form-label">{t('emailSecurity.yaraRuleSource')} <span className="yr-form-req">*</span></label>
                      <div className="yr-form-code-actions">
                        {yaraValidation && (
                          <span className={`yr-form-validation ${yaraValidation.valid ? 'yr-form-validation--ok' : 'yr-form-validation--err'}`}>
                            {yaraValidation.valid ? (
                              <><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg> {t('emailSecurity.syntaxValid')}</>
                            ) : (
                              <><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> {yaraValidation.error}</>
                            )}
                          </span>
                        )}
                        <button onClick={validateYaraRule} className="yr-btn-validate" disabled={!yaraForm.rule_source.trim()}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                          {t('emailSecurity.validate')}
                        </button>
                      </div>
                    </div>
                    <div className="yr-code-editor">
                      <textarea value={yaraForm.rule_source} onChange={e => { setYaraForm(p => ({ ...p, rule_source: e.target.value })); setYaraValidation(null) }}
                        placeholder={'rule My_Rule {\n  meta:\n    description = "..."\n    severity = "high"\n  strings:\n    $s1 = "malicious" ascii\n  condition:\n    any of them\n}'}
                        rows={16} className="yr-code-textarea" spellCheck={false}
                        onKeyDown={e => {
                          if (e.key === 'Tab') {
                            e.preventDefault()
                            const ta = e.currentTarget
                            const start = ta.selectionStart
                            const end = ta.selectionEnd
                            const val = ta.value
                            setYaraForm(p => ({ ...p, rule_source: val.substring(0, start) + '  ' + val.substring(end) }))
                            setTimeout(() => { ta.selectionStart = ta.selectionEnd = start + 2 }, 0)
                          }
                        }} />
                    </div>
                  </div>
                </div>

                {/* Modal footer */}
                <div className="yr-modal-footer">
                  <div>
                    {editingYaraRule && editingYaraRule.source !== 'builtin' && (
                      <button onClick={() => { deleteYaraRule(editingYaraRule.id, editingYaraRule.source); setShowYaraEditor(false) }} className="yr-btn-delete">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        {t('emailSecurity.deleteRule')}
                      </button>
                    )}
                    {editingYaraRule?.source === 'builtin' && (
                      <span className="yr-modal-hint">{t('emailSecurity.builtinRuleViewOnly')}</span>
                    )}
                  </div>
                  <div className="yr-modal-actions">
                    <button onClick={() => setShowYaraEditor(false)} className="yr-btn-cancel">{t('emailSecurity.cancel')}</button>
                    <button onClick={saveYaraRule} disabled={yaraSaving || !yaraForm.rule_name.trim() || !yaraForm.rule_source.trim() || editingYaraRule?.source === 'builtin'}
                      className="yr-btn-save">
                      {yaraSaving ? t('emailSecurity.saving') : t('emailSecurity.saveRule')}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
        )
      })()}
    </>
  )
}
