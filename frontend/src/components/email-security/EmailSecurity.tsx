import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import type {
  SecurityStats, EngineStatus, ModuleMetadata,
  ApiResponse, PipelineConfig, ModuleConfig, ContentRules,
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

export const MODULE_DESC: Record<string, string> = {
  content_scan: '钓鱼关键词、BEC 话术、DLP 敏感数据检测',
  html_scan: '恶意 HTML 元素、脚本注入、事件处理器检测',
  attach_scan: '危险文件类型、双扩展名、MIME 不匹配、宏文档检测',
  attach_content: '文档文本提取 + 关键词/AI 内容分析',
  attach_hash: 'SHA256 本地黑名单 + 外部情报源比对',
  mime_scan: '嵌套深度、边界冲突、Content-Type 不符检测',
  header_scan: 'Received 链、From/Reply-To 不匹配、Header 注入检测',
  link_scan: 'IP 地址链接、同形字/Punycode、短链、href/文本不匹配检测',
  link_reputation: '本地域名黑名单 + 外部情报源查询',
  link_content: '抓取页面 → 表单检测 + AI 页面分析',
  anomaly_detect: '发件人基线偏离、频率/收件人/时间/附件行为异常',
  semantic_scan: '无语义乱码/生僻字/熵异常检测，识别垃圾混淆邮件',
  domain_verify: 'Received 主机名 + DKIM 域名 + 链接域名一致性验证，提供信任折扣',
  identity_anomaly: '首次联系人检测、通信模式突变、回复链异常分析',
  transaction_correlation: '银行账号识别、商业实体抽取、交易上下文语义关联',
  av_eml_scan: 'ClamAV 完整 EML 病毒签名扫描',
  av_attach_scan: 'ClamAV 逐附件病毒签名扫描',
  yara_scan: '内置 YARA 规则引擎，检测恶意文档、可执行伪装、恶意软件家族、脚本木马、高级威胁和逃逸技术',
  verdict: '收集全部模块结果 → 加权聚合 → 最终判定',
}

// -- Chinese pillar names + colors --
export const PILLAR_META: Record<string, { label: string; color: string }> = {
  content: { label: '邮件正文', color: 'var(--accent-blue)' },
  attachment: { label: '附件分析', color: 'var(--accent-yellow)' },
  package: { label: '封装结构', color: 'var(--accent-purple)' },
  link: { label: '链接分析', color: 'var(--accent-emerald)' },
  semantic: { label: '语义分析', color: 'var(--accent-orange, #f97316)' },
  verdict: { label: '最终判定', color: 'var(--accent-primary)' },
}

// -- Definitions for the eight engines (matching backend EngineId values) --
const ENGINES: { id: string; letter: string; name: string; color: string; desc: string; modules: string[] }[] = [
  { id: 'sender_reputation', letter: 'A', name: '发件人信誉', color: '#3b82f6',
    desc: 'SPF/DKIM/DMARC 验证、域名年龄、仿冒检测',
    modules: ['domain_verify'] },
  { id: 'content_analysis', letter: 'B', name: '内容分析', color: '#ef4444',
    desc: '邮件正文关键词、HTML 恶意元素、附件类型与内容、哈希信誉',
    modules: ['content_scan', 'html_scan', 'html_pixel_art', 'attach_scan', 'attach_content', 'attach_hash'] },
  { id: 'behavior_baseline', letter: 'C', name: '行为基线', color: '#eab308',
    desc: '发件人历史偏离检测、频率/收件人/时间/附件行为异常',
    modules: ['anomaly_detect'] },
  { id: 'url_analysis', letter: 'D', name: 'URL/链接分析', color: '#22c55e',
    desc: 'URL 模式检测、域名信誉查询、远程页面内容分析',
    modules: ['link_scan', 'link_reputation', 'link_content'] },
  { id: 'protocol_compliance', letter: 'E', name: '协议合规', color: '#a855f7',
    desc: '邮件头合规性、MIME 结构验证、编码异常检测',
    modules: ['header_scan', 'mime_scan'] },
  { id: 'semantic_intent', letter: 'F', name: '语义意图', color: '#f97316',
    desc: 'CJK 乱码检测 + NLP 钓鱼/诈骗意图分析',
    modules: ['semantic_scan'] },
  { id: 'identity_anomaly', letter: 'G', name: '身份异常', color: '#06b6d4',
    desc: '首次联系人、显示名/域名不匹配、通信模式突变',
    modules: ['identity_anomaly'] },
  { id: 'transaction_correlation', letter: 'H', name: '交易关联', color: '#ec4899',
    desc: '银行账号识别、商业实体抽取、紧迫性+金融实体组合检测',
    modules: ['transaction_correlation'] },
]

// Reverse mapping: module -> engine
const MODULE_ENGINE: Record<string, string> = {}
ENGINES.forEach(e => e.modules.forEach(m => { MODULE_ENGINE[m] = e.id }))

// Extra module metadata (timeout, type)
export const MODULE_EXTRA: Record<string, { timeout: string; type: 'cpu' | 'io' | 'mixed' }> = {
  content_scan: { timeout: '5s', type: 'cpu' },
  html_scan: { timeout: '5s', type: 'cpu' },
  html_pixel_art: { timeout: '3s', type: 'cpu' },
  attach_scan: { timeout: '5s', type: 'io' },
  attach_content: { timeout: '5s', type: 'cpu' },
  attach_hash: { timeout: '10s', type: 'io' },
  mime_scan: { timeout: '5s', type: 'cpu' },
  header_scan: { timeout: '5s', type: 'io' },
  link_scan: { timeout: '5s', type: 'cpu' },
  link_reputation: { timeout: '10s', type: 'io' },
  link_content: { timeout: '15s', type: 'io' },
  anomaly_detect: { timeout: '5s', type: 'mixed' },
  semantic_scan: { timeout: '65s', type: 'io' },
  domain_verify: { timeout: '3s', type: 'io' },
  identity_anomaly: { timeout: '5s', type: 'mixed' },
  transaction_correlation: { timeout: '5s', type: 'cpu' },
  verdict: { timeout: '1s', type: 'cpu' },
}

export const MODE_CN: Record<string, string> = {
  builtin: '内置规则',
  aionly: '纯 AI',
  hybrid: '混合模式',
}

const VALID_TABS: TabKey[] = ['overview', 'risk', 'sec-risk-scene', 'pipeline', 'av-clamav', 'av-yara', 'ioc', 'intel', 'ai', 'whitelist', 'keywords']

// ─── Main shell component ────────────────────────────────────────

function EmailSecurity() {
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
        const key = `${d.total_scanned}-${d.high_threats_24h}-${d.level_counts?.safe ?? 0}-${d.level_counts?.high ?? 0}-${d.level_counts?.critical ?? 0}-${d.ioc_count ?? 0}`
        if (key !== prevStatsKeyRef.current) {
          prevStatsKeyRef.current = key
          setStats(d)
        }
      }
      if (engineData.success && engineData.data) {
        const d = engineData.data
        const key = `${d.total_sessions_processed}-${d.total_verdicts_produced}-${d.email_engine_active}-${d.uptime_seconds}`
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
    const interval = setInterval(fetchStats, 15000) // 15s; fetchStats already checks page visibility internally
    return () => clearInterval(interval)
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

  const savePipeline = async (config: PipelineConfig) => {
    setSavingPipeline(true)
    try {
      const res = await apiFetch('/api/security/pipeline', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
      if (!res.ok) {
        console.error('Failed to save pipeline config:', res.status)
        fetchPipeline() // revert to server state
      }
    } catch (e) {
      console.error('Failed to save pipeline config:', e)
      fetchPipeline()
    } finally {
      setSavingPipeline(false)
    }
  }

  // ─── Tab bar definitions ──────────────────────────────────────

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'overview', label: '安全概览' },
    { key: 'risk', label: '风险邮件' },
    { key: 'sec-risk-scene', label: '威胁场景' },
    { key: 'pipeline', label: '检测模块' },
    { key: 'av-clamav', label: '病毒检测' },
    { key: 'ioc', label: 'IOC 管理' },
    { key: 'intel', label: '威胁情报' },
    { key: 'ai', label: 'AI 配置' },
    { key: 'whitelist', label: '白名单' },
    { key: 'keywords', label: '关键词' },
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
              邮件安全引擎
            </h1>
            <span className="sec-engine-status" data-running={isEngineRunning(engineStatus)}>
              <span className="sec-status-dot" />
              {isEngineRunning(engineStatus)
                ? `运行中 · 已处理 ${toDisplayNumber(engineStatus?.total_sessions_processed).toLocaleString()} 封`
                : '引擎未启动'}
            </span>
          </div>
          {isEngineRunning(engineStatus) && (
            <div className="sec-header-right">
              <div className="sec-header-metric">
                <span className="sec-header-metric-val">{formatUptime(engineStatus?.uptime_seconds)}</span>
                <span className="sec-header-metric-lbl">运行时长</span>
              </div>
              <div className="sec-header-metric">
                <span className="sec-header-metric-val">{toDisplayNumber(engineStatus?.sessions_per_second).toFixed(1)}/s</span>
                <span className="sec-header-metric-lbl">处理速度</span>
              </div>
              <div className="sec-header-metric">
                <span className="sec-header-metric-val" data-ok={engineStatus?.ai_service_available}>
                  {engineStatus?.ai_service_available ? '在线' : '离线'}
                </span>
                <span className="sec-header-metric-lbl">AI 服务</span>
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
          {savingPipeline && <span className="sec-saving-hint">保存中...</span>}
        </div>
      </div>

      {/* -- Content area -- */}
      <div className="sec-content">
        {isLoading && (
          <div className="sec-loading">
            <div className="sec-spinner" />
            加载中...
          </div>
        )}
        {!isLoading && loadError && !stats && (
          <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <p>数据加载失败，请检查网络连接</p>
            <button
              className="sec-btn sec-btn--outline"
              style={{ marginTop: '12px' }}
              onClick={() => { setIsLoading(true); setLoadError(false); Promise.all([fetchStats(), fetchModules(), fetchPipeline()]).finally(() => setIsLoading(false)) }}
            >
              重试
            </button>
          </div>
        )}

        {/* Fallback: loading finished but no data is available (API returned success:false or the token expired) */}
        {!isLoading && !loadError && !stats && !engineStatus && activeTab === 'overview' && (
          <div className="empty-state" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <p>正在连接引擎...</p>
            <button
              className="sec-btn sec-btn--outline"
              style={{ marginTop: '12px' }}
              onClick={() => { setIsLoading(true); Promise.all([fetchStats(), fetchModules(), fetchPipeline()]).finally(() => setIsLoading(false)) }}
            >
              重新加载
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
            onToggleModule={toggleModule}
            onChangeMode={changeModuleMode}
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
  const safeSeconds = toDisplayNumber(seconds)
  const d = Math.floor(safeSeconds / 86400)
  const h = Math.floor((safeSeconds % 86400) / 3600)
  const m = Math.floor((safeSeconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

export default EmailSecurity
