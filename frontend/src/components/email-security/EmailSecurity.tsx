import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type {
  SecurityStats, EngineStatus, ModuleMetadata,
  ApiResponse, PipelineConfig, ModuleConfig, ContentRules, VerdictConfig,
} from '../../types'
import { apiFetch } from '../../utils/api'

// Sub-components (one per tab)
import OverviewTab from './OverviewTab'
import RiskVerdictTab from './RiskVerdictTab'
import ThreatSceneTab from './ThreatSceneTab'
import PipelineTab from './PipelineTab'
import AvScanTab from './AvScanTab'
import IocTab from './IocTab'
import IntelConfigTab from './IntelConfigTab'
import AiConfigTab from './AiConfigTab'
import WhitelistTab from './WhitelistTab'
import KeywordsTab from './KeywordsTab'

// ─── Shared type definitions ─────────────────────────────────────

type TabKey = 'overview' | 'risk' | 'sec-risk-scene' | 'pipeline' | 'av-clamav' | 'av-yara' | 'ioc' | 'intel' | 'ai' | 'whitelist' | 'keywords'

// ─── Shared constants (exported for PipelineGraph and sub-components) ─────

export const MODULE_DESC_KEYS: Record<string, string> = {
  content_scan: 'emailSecurity.moduleDescContentScan',
  html_scan: 'emailSecurity.moduleDescHtmlScan',
  attach_scan: 'emailSecurity.moduleDescAttachScan',
  attach_content: 'emailSecurity.moduleDescAttachContent',
  attach_hash: 'emailSecurity.moduleDescAttachHash',
  mime_scan: 'emailSecurity.moduleDescMimeScan',
  header_scan: 'emailSecurity.moduleDescHeaderScan',
  link_scan: 'emailSecurity.moduleDescLinkScan',
  link_reputation: 'emailSecurity.moduleDescLinkReputation',
  link_content: 'emailSecurity.moduleDescLinkContent',
  anomaly_detect: 'emailSecurity.moduleDescAnomalyDetect',
  semantic_scan: 'emailSecurity.moduleDescSemanticScan',
  domain_verify: 'emailSecurity.moduleDescDomainVerify',
  identity_anomaly: 'emailSecurity.moduleDescIdentityAnomaly',
  transaction_correlation: 'emailSecurity.moduleDescTransactionCorrelation',
  av_eml_scan: 'emailSecurity.moduleDescAvEmlScan',
  av_attach_scan: 'emailSecurity.moduleDescAvAttachScan',
  yara_scan: 'emailSecurity.moduleDescYaraScan',
  verdict: 'emailSecurity.moduleDescVerdict',
}

// Legacy accessor — consumers that import MODULE_DESC can be migrated later.
// For now this is kept as a function that requires a `t` function.
export function getModuleDesc(t: (key: string) => string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [id, key] of Object.entries(MODULE_DESC_KEYS)) {
    out[id] = t(key)
  }
  return out
}

// Keep MODULE_DESC export for backward compat — consumers should migrate to getModuleDesc(t)
export const MODULE_DESC: Record<string, string> = Object.fromEntries(
  Object.entries(MODULE_DESC_KEYS).map(([id]) => [id, id])
)

export const PILLAR_META_KEYS: Record<string, { labelKey: string; color: string }> = {
  content: { labelKey: 'emailSecurity.pillarContent', color: 'var(--accent-blue)' },
  attachment: { labelKey: 'emailSecurity.pillarAttachment', color: 'var(--accent-yellow)' },
  package: { labelKey: 'emailSecurity.pillarPackage', color: 'var(--accent-purple)' },
  link: { labelKey: 'emailSecurity.pillarLink', color: 'var(--accent-emerald)' },
  semantic: { labelKey: 'emailSecurity.pillarSemantic', color: 'var(--accent-orange, #f97316)' },
  verdict: { labelKey: 'emailSecurity.pillarVerdict', color: 'var(--accent-primary)' },
}

export function getPillarMeta(t: (key: string) => string): Record<string, { label: string; color: string }> {
  const out: Record<string, { label: string; color: string }> = {}
  for (const [id, meta] of Object.entries(PILLAR_META_KEYS)) {
    out[id] = { label: t(meta.labelKey), color: meta.color }
  }
  return out
}

// Legacy export kept for backward compat
export const PILLAR_META: Record<string, { label: string; color: string }> = Object.fromEntries(
  Object.entries(PILLAR_META_KEYS).map(([id, meta]) => [id, { label: id, color: meta.color }])
)

export const MODE_CN_KEYS: Record<string, string> = {
  builtin: 'emailSecurity.modeBuiltin',
  aionly: 'emailSecurity.modeAiOnly',
  hybrid: 'emailSecurity.modeHybrid',
}

export function getModeCN(t: (key: string) => string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [id, key] of Object.entries(MODE_CN_KEYS)) {
    out[id] = t(key)
  }
  return out
}

// Legacy export
export const MODE_CN: Record<string, string> = {
  builtin: 'builtin',
  aionly: 'aionly',
  hybrid: 'hybrid',
}

const VALID_TABS: TabKey[] = ['overview', 'risk', 'sec-risk-scene', 'pipeline', 'av-clamav', 'av-yara', 'ioc', 'intel', 'ai', 'whitelist', 'keywords']

// ─── Main shell component ────────────────────────────────────────

function EmailSecurity() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { tab: urlTab } = useParams<{ tab: string }>()
  const activeTab: TabKey = VALID_TABS.includes(urlTab as TabKey) ? (urlTab as TabKey) : 'overview'
  const setActiveTab = useCallback((key: TabKey) => navigate(`/security/${key}`), [navigate])

  // Shared state loaded on mount (shown in header + passed to tabs)
  const [stats, setStats] = useState<SecurityStats | null>(null)
  const [engineStatus, setEngineStatus] = useState<EngineStatus | null>(null)
  const [modules, setModules] = useState<ModuleMetadata[]>([])
  const [pipelineConfig, setPipelineConfig] = useState<PipelineConfig | null>(null)
  const [contentRules, setContentRules] = useState<ContentRules | null>(null)
  const [savingPipeline, setSavingPipeline] = useState(false)
  const [pipelineNotice, setPipelineNotice] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  // Compare key fields only instead of JSON.stringify on the whole object (too CPU-heavy)
  const prevStatsKeyRef = useRef('')
  const prevEngineKeyRef = useRef('')
  const isInitialLoadRef = useRef(true)

  // ─── Shared fetch functions ──────────────────────────────────

  const fetchStats = useCallback(async () => {
    // Skip hidden pages during interval refreshes, but always run the initial load
    if (document.hidden && !isInitialLoadRef.current) return
    isInitialLoadRef.current = false
    try {
      const [statsRes, engineRes] = await Promise.all([
        apiFetch('/api/security/stats'),
        apiFetch('/api/security/engine-status'),
      ])
      const statsData: ApiResponse<SecurityStats> = await statsRes.json()
      const engineData: ApiResponse<EngineStatus> = await engineRes.json()
      if (statsData.success && statsData.data) {
        const d = statsData.data
        const key = [
          d.total_scanned,
          d.high_threats_24h,
          d.ioc_count,
          ...['safe', 'low', 'medium', 'high', 'critical'].map(level => d.level_counts?.[level] ?? 0),
        ].join('-')
        if (key !== prevStatsKeyRef.current) {
          prevStatsKeyRef.current = key
          setStats(d)
        }
      }
      if (engineData.success && engineData.data) {
        const d = engineData.data
        const key = [
          d.running,
          d.email_engine_active,
          d.data_security_engine_active,
          d.total_sessions_processed,
          d.total_verdicts_produced,
          d.uptime_seconds,
          d.sessions_per_second,
          d.ai_service_available,
          d.reason ?? '',
        ].join('-')
        if (key !== prevEngineKeyRef.current) {
          prevEngineKeyRef.current = key
          setEngineStatus(d)
        }
      }
    } catch (e) {
      console.error('Failed to fetch security stats:', e)
      setLoadError(true)
    }
  }, [])

  const fetchModules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/modules')
      const data: ApiResponse<ModuleMetadata[]> = await res.json()
      if (data.success && data.data) setModules(data.data)
    } catch (e) {
      console.error('Failed to fetch modules:', e)
    }
  }, [])

  const fetchPipeline = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/pipeline')
      const data: ApiResponse<PipelineConfig> = await res.json()
      if (data.success && data.data) setPipelineConfig(data.data)
    } catch (e) {
      console.error('Failed to fetch pipeline config:', e)
    }
  }, [])

  const fetchContentRules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/content-rules')
      const data: ApiResponse<ContentRules> = await res.json()
      if (data.success && data.data) setContentRules(data.data)
    } catch (e) {
      console.error('Failed to fetch content rules:', e)
    }
  }, [])

  // ─── Initial load + periodic refresh ──────────────────────────

  useEffect(() => {
    setIsLoading(true)
    Promise.all([fetchStats(), fetchModules(), fetchPipeline()]).finally(() => setIsLoading(false))
    const interval = window.setInterval(fetchStats, 10000) // Match the engine heartbeat cadence.
    const handleVisibilityChange = () => {
      if (!document.hidden) fetchStats()
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => {
      window.clearInterval(interval)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [fetchStats, fetchModules, fetchPipeline])

  useEffect(() => {
    if (activeTab === 'pipeline') fetchContentRules()
  }, [activeTab, fetchContentRules])

  // ─── Pipeline config toggle/mode handlers ─────────────────────

  const toggleModule = (moduleId: string) => {
    if (!pipelineConfig) return
    const updated = {
      ...pipelineConfig,
      modules: pipelineConfig.modules.map(m =>
        m.id === moduleId ? { ...m, enabled: !m.enabled } : m
      ),
    }
    setPipelineConfig(updated)
    savePipeline(updated)
  }

  const changeModuleMode = (moduleId: string, mode: ModuleConfig['mode']) => {
    if (!pipelineConfig) return
    const updated: PipelineConfig = {
      ...pipelineConfig,
      modules: pipelineConfig.modules.map(m =>
        m.id === moduleId ? { ...m, mode } : m
      ),
    }
    setPipelineConfig(updated)
    savePipeline(updated)
  }

  const savePipeline = async (config: PipelineConfig): Promise<{ ok: boolean; error?: string }> => {
    setSavingPipeline(true)
    try {
      const res = await apiFetch('/api/security/pipeline', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      const data: ApiResponse<PipelineConfig> = await res.json()
      if (!res.ok || !data.success) {
        console.error('Failed to save pipeline config:', res.status, data.error)
        setPipelineNotice(null)
        fetchPipeline() // revert to server state
        return { ok: false, error: data.error ?? undefined }
      }
      setPipelineNotice(t('emailSecurity.pipelineRestartRequired'))
      return { ok: true }
    } catch (e) {
      console.error('Failed to save pipeline config:', e)
      setPipelineNotice(null)
      fetchPipeline()
      return { ok: false }
    } finally {
      setSavingPipeline(false)
    }
  }

  // Verdict thresholds are edited as a group in PipelineTab; the parent keeps
  // pipelineConfig as the single source of truth so later module toggles don't
  // revert the thresholds to stale values.
  const saveVerdictThresholds = async (patch: Partial<VerdictConfig>) => {
    if (!pipelineConfig) return { ok: false }
    const updated: PipelineConfig = {
      ...pipelineConfig,
      verdict_config: { ...pipelineConfig.verdict_config, ...patch },
    }
    const result = await savePipeline(updated)
    if (result.ok) setPipelineConfig(updated)
    return result
  }

  // ─── Tab bar definitions ──────────────────────────────────────

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'overview', label: t('emailSecurity.tabOverview') },
    { key: 'risk', label: t('emailSecurity.tabRisk') },
    { key: 'sec-risk-scene', label: t('emailSecurity.tabThreatScene') },
    { key: 'pipeline', label: t('emailSecurity.tabPipeline') },
    { key: 'av-clamav', label: t('emailSecurity.tabVirusScan') },
    { key: 'ioc', label: t('emailSecurity.tabIoc') },
    { key: 'intel', label: t('emailSecurity.tabIntel') },
    { key: 'ai', label: t('emailSecurity.tabAiConfig') },
    { key: 'whitelist', label: t('emailSecurity.tabWhitelist') },
    { key: 'keywords', label: t('emailSecurity.tabKeywords') },
  ]

  // ─── Render ───────────────────────────────────────────────────

  return (
    <div className="sec-dashboard">
      {/* -- Sticky header + tab bar (pinned while scrolling) -- */}
      <div className="sec-sticky-header">
        <div className="sec-header">
          <div className="sec-header-left">
            <h1 className="sec-title">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              {t('emailSecurity.title')}
            </h1>
            <span className="sec-engine-status" data-running={isEngineRunning(engineStatus)}>
              <span className="sec-status-dot" />
              {isEngineRunning(engineStatus)
                ? t('emailSecurity.engineRunning', { count: toDisplayNumber(engineStatus?.total_sessions_processed) })
                : t('emailSecurity.engineStopped')}
            </span>
          </div>
          {isEngineRunning(engineStatus) && (
            <div className="sec-header-right">
              <div className="sec-header-metric">
                <span className="sec-header-metric-val">{formatUptime(engineStatus?.uptime_seconds)}</span>
                <span className="sec-header-metric-lbl">{t('emailSecurity.uptime')}</span>
              </div>
              <div className="sec-header-metric">
                <span className="sec-header-metric-val">{toDisplayNumber(engineStatus?.sessions_per_second).toFixed(2)}/s</span>
                <span className="sec-header-metric-lbl">{t('emailSecurity.processingSpeed')}</span>
              </div>
              <div className="sec-header-metric">
                <span className="sec-header-metric-val" data-ok={engineStatus?.ai_service_available}>
                  {engineStatus?.ai_service_available ? t('emailSecurity.online') : t('emailSecurity.offline')}
                </span>
                <span className="sec-header-metric-lbl">{t('emailSecurity.aiService')}</span>
              </div>
            </div>
          )}
        </div>

        <div className="sec-tabs">
          {tabs.map(tab => (
            <button
              key={tab.key}
              className={`sec-tab ${activeTab === tab.key || (tab.key === 'av-clamav' && activeTab === 'av-yara') ? 'sec-tab--active' : ''}`}
              onClick={() => setActiveTab(tab.key)}
            >
              {tab.label}
            </button>
          ))}
          {savingPipeline && <span className="sec-saving-hint">{t('emailSecurity.saving')}</span>}
        </div>
      </div>

      {/* -- Content area -- */}
      <div className="sec-content">
        {isLoading && (
          <div className="sec-loading">
            <div className="sec-spinner" />
            {t('emailSecurity.loading')}
          </div>
        )}
        {!isLoading && loadError && !stats && (
          <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <p>{t('emailSecurity.loadFailed')}</p>
            <button
              className="sec-btn sec-btn--outline"
              style={{ marginTop: '12px' }}
              onClick={() => { setIsLoading(true); setLoadError(false); Promise.all([fetchStats(), fetchModules(), fetchPipeline()]).finally(() => setIsLoading(false)) }}
            >
              {t('emailSecurity.retry')}
            </button>
          </div>
        )}

        {/* Fallback: loading finished but no data is available (API returned success:false or the token expired) */}
        {!isLoading && !loadError && !stats && !engineStatus && activeTab === 'overview' && (
          <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <p>{t('emailSecurity.connectingEngine')}</p>
            <button
              className="sec-btn sec-btn--outline"
              style={{ marginTop: '12px' }}
              onClick={() => { setIsLoading(true); Promise.all([fetchStats(), fetchModules(), fetchPipeline()]).finally(() => setIsLoading(false)) }}
            >
              {t('emailSecurity.reload')}
            </button>
          </div>
        )}

        {/* === Tab content (delegated to sub-components) === */}

        {activeTab === 'overview' && !isLoading && (stats || engineStatus) && (
          <OverviewTab stats={stats} engineStatus={engineStatus} modules={modules} />
        )}

        {activeTab === 'risk' && <RiskVerdictTab />}

        {activeTab === 'sec-risk-scene' && <ThreatSceneTab />}

        {activeTab === 'pipeline' && (
          <PipelineTab
            modules={modules}
            engineStatus={engineStatus}
            pipelineConfig={pipelineConfig}
            contentRules={contentRules}
            notice={pipelineNotice}
            onToggleModule={toggleModule}
            onChangeMode={changeModuleMode}
            onSaveThresholds={saveVerdictThresholds}
          />
        )}

        {(activeTab === 'av-clamav' || activeTab === 'av-yara') && (
          <AvScanTab
            initialEngine={activeTab === 'av-yara' ? 'yara' : 'clamav'}
            modules={modules}
            engineStatus={engineStatus}
            pipelineConfig={pipelineConfig}
            onToggleModule={toggleModule}
            onEngineChange={(e) => setActiveTab(e === 'yara' ? 'av-yara' : 'av-clamav')}
          />
        )}

        {activeTab === 'ioc' && <IocTab />}

        {activeTab === 'intel' && (
          <IntelConfigTab
            stats={stats}
            onNavigateToIoc={() => setActiveTab('ioc')}
          />
        )}

        {activeTab === 'ai' && (
          <AiConfigTab
            engineStatus={engineStatus}
            onStatsRefresh={fetchStats}
          />
        )}

        {activeTab === 'whitelist' && <WhitelistTab />}

        {activeTab === 'keywords' && <KeywordsTab />}
      </div>
    </div>
  )
}

// ─── Utility functions ───────────────────────────────────────────

function toDisplayNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return fallback
}

function isEngineRunning(status: EngineStatus | null): boolean {
  return Boolean(status?.email_engine_active ?? status?.running)
}

function formatUptime(seconds: unknown): string {
  const safeSeconds = Math.max(0, Math.floor(toDisplayNumber(seconds)))
  const d = Math.floor(safeSeconds / 86400)
  const h = Math.floor((safeSeconds % 86400) / 3600)
  const m = Math.floor((safeSeconds % 3600) / 60)
  const s = safeSeconds % 60
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${s}s`
  return `${m}m ${s}s`
}

export default EmailSecurity
