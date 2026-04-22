import { useState, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { EngineStatus, ModuleMetadata, PipelineConfig, ModuleConfig, ContentRules } from '../../types'

// ════════════════════════════════════════════════════
// Types & Props
// ════════════════════════════════════════════════════

interface EngineDef {
  id: string; letter: string; labelKey: string; color: string; modules: string[]
}

interface Props {
  modules: ModuleMetadata[]
  engineStatus: EngineStatus | null
  pipelineConfig: PipelineConfig | null
  contentRules: ContentRules | null
  onToggleModule: (id: string) => void
  onChangeMode: (id: string, mode: ModuleConfig['mode']) => void
}

// ════════════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════════════

const ENGINES: EngineDef[] = [
  { id: 'A', letter: 'A', labelKey: 'emailSecurity.engineSenderVerify', color: '#3b82f6', modules: ['domain_verify'] },
  { id: 'B', letter: 'B', labelKey: 'emailSecurity.engineContentAnalysis', color: '#00f0ff', modules: ['content_scan', 'html_scan', 'html_pixel_art', 'attach_scan', 'attach_content', 'attach_hash'] },
  { id: 'C', letter: 'C', labelKey: 'emailSecurity.engineBehaviorBaseline', color: '#a855f7', modules: ['anomaly_detect'] },
  { id: 'D', letter: 'D', labelKey: 'emailSecurity.engineUrlAnalysis', color: '#f59e0b', modules: ['link_scan', 'link_reputation', 'link_content'] },
  { id: 'E', letter: 'E', labelKey: 'emailSecurity.engineProtocolCompliance', color: '#10b981', modules: ['header_scan', 'mime_scan'] },
  { id: 'F', letter: 'F', labelKey: 'emailSecurity.engineSemanticIntent', color: '#f43f5e', modules: ['semantic_scan'] },
  { id: 'G', letter: 'G', labelKey: 'emailSecurity.engineIdentityAnomaly', color: '#06b6d4', modules: ['identity_anomaly'] },
  { id: 'H', letter: 'H', labelKey: 'emailSecurity.engineTransactionCorrelation', color: '#ec4899', modules: ['transaction_correlation'] },
  { id: 'I', letter: 'I', labelKey: 'emailSecurity.engineVirusYara', color: '#dc2626', modules: ['av_eml_scan', 'av_attach_scan', 'yara_scan'] },
]

const MODULE_CN_KEYS: Record<string, string> = {
  content_scan: 'emailSecurity.modContentScan', html_scan: 'emailSecurity.modHtmlScan', html_pixel_art: 'emailSecurity.modPixelTracking',
  attach_scan: 'emailSecurity.modAttachType', attach_content: 'emailSecurity.modAttachContent', attach_hash: 'emailSecurity.modHashReputation',
  mime_scan: 'emailSecurity.modMimeScan', header_scan: 'emailSecurity.modHeaderScan', link_scan: 'emailSecurity.modUrlPattern',
  link_reputation: 'emailSecurity.modUrlReputation', link_content: 'emailSecurity.modUrlContent', anomaly_detect: 'emailSecurity.modAnomalyDetect',
  semantic_scan: 'emailSecurity.modSemanticScan', domain_verify: 'emailSecurity.modDomainVerify', identity_anomaly: 'emailSecurity.modIdentityAnomaly',
  transaction_correlation: 'emailSecurity.modTransactionCorrelation', av_eml_scan: 'emailSecurity.modAvEmlScan', av_attach_scan: 'emailSecurity.modAvAttachScan', yara_scan: 'emailSecurity.modYaraScan',
}

const MODULE_DESC_KEYS: Record<string, string> = {
  content_scan: 'emailSecurity.descContentScan',
  html_scan: 'emailSecurity.descHtmlScan',
  html_pixel_art: 'emailSecurity.descPixelTracking',
  attach_scan: 'emailSecurity.descAttachType',
  attach_content: 'emailSecurity.descAttachContent',
  attach_hash: 'emailSecurity.descHashReputation',
  mime_scan: 'emailSecurity.descMimeScan',
  header_scan: 'emailSecurity.descHeaderScan',
  link_scan: 'emailSecurity.descUrlPattern',
  link_reputation: 'emailSecurity.descUrlReputation',
  link_content: 'emailSecurity.descUrlContent',
  anomaly_detect: 'emailSecurity.descAnomalyDetect',
  semantic_scan: 'emailSecurity.descSemanticScan',
  domain_verify: 'emailSecurity.descDomainVerify',
  identity_anomaly: 'emailSecurity.descIdentityAnomaly',
  transaction_correlation: 'emailSecurity.descTransactionCorrelation',
  av_eml_scan: 'emailSecurity.descAvEmlScan',
  av_attach_scan: 'emailSecurity.descAvAttachScan',
  yara_scan: 'emailSecurity.descYaraScan',
}

const MODULE_DEPS: Record<string, string> = {
  attach_content: 'attach_scan', attach_hash: 'attach_scan', link_content: 'link_scan',
}

// ════════════════════════════════════════════════════
// Layout — wider aspect ratio, engines spaced out
// ════════════════════════════════════════════════════

const W = 1400, H = 920
const INX = 50, INY = H / 2
const EX = 220, EW = 680, EH = 78, EGAP = 12
const FX = 1060, FY = H / 2
const VX = 1260, VY = H / 2

function eY(i: number) {
  const total = ENGINES.length * EH + (ENGINES.length - 1) * EGAP
  return (H - total) / 2 + i * (EH + EGAP) + EH / 2
}

// ════════════════════════════════════════════════════
// SVG sub-components
// ════════════════════════════════════════════════════

function Conn({ x1, y1, x2, y2, color }: { x1: number; y1: number; x2: number; y2: number; color: string }) {
  const dx = (x2 - x1) * 0.45
  const d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`
  // Use midpoint markers as static indicators instead of animateMotion particles to eliminate continuous GPU repaints
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeOpacity={0.08} strokeWidth={1.5} />
      <path d={d} fill="none" stroke={color} strokeOpacity={0.25} strokeWidth={1.5} strokeDasharray="6 4" className="pg-flow-dash" />
      <circle cx={mx} cy={my} r={2.5} fill={color} opacity={0.7} className="pg-particle" />
    </g>
  )
}

function InNode({ total, rate }: { total: number; rate: number }) {
  const { t } = useTranslation()
  return (
    <g transform={`translate(${INX},${INY})`}>
      <rect x={-44} y={-30} width={88} height={60} rx={10} className="pg-node-bg" stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
      <text textAnchor="middle" y={-8} className="pg-label" fill="rgba(255,255,255,0.85)" fontSize={12} fontWeight={600}>{t('emailSecurity.emailInput')}</text>
      <text textAnchor="middle" y={10} className="pg-mono" fill="rgba(255,255,255,0.4)" fontSize={10}>{total > 0 ? total.toLocaleString() : '—'}</text>
      {rate > 0 && <text textAnchor="middle" y={22} className="pg-mono" fill="rgba(255,255,255,0.3)" fontSize={9}>{rate.toFixed(1)}/s</text>}
    </g>
  )
}

function EngNode({ eng, y, enabled, total, sel, onClick }: {
  eng: EngineDef; y: number; enabled: number; total: number; sel: boolean; onClick: () => void
}) {
  const { t } = useTranslation()
  return (
    <g transform={`translate(${EX},${y})`} onClick={e => { e.stopPropagation(); onClick() }} style={{ cursor: 'pointer' }} className="pg-engine">
      <rect x={0} y={-EH / 2} width={EW} height={EH} rx={10} className="pg-node-bg"
        stroke={sel ? eng.color : 'rgba(255,255,255,0.07)'} strokeWidth={sel ? 1.5 : 1} />
      <rect x={0} y={-EH / 2} width={EW} height={2} rx={1} fill={eng.color} opacity={sel ? 0.9 : 0.5} />
      {sel && <rect x={-2} y={-EH / 2 - 2} width={EW + 4} height={EH + 4} rx={12} fill="none" stroke={eng.color} strokeWidth={1} opacity={0.15} />}
      <rect x={14} y={-16} width={32} height={32} rx={7} fill={eng.color} />
      <text x={30} y={5} textAnchor="middle" fill="#fff" fontSize={14} fontWeight={700}>{eng.letter}</text>
      <text x={58} y={-4} fill="rgba(255,255,255,0.9)" fontSize={13} fontWeight={600} className="pg-label">{t(eng.labelKey)}</text>
      <text x={58} y={14} fill="rgba(255,255,255,0.35)" fontSize={11} className="pg-mono">{t('emailSecurity.modulesOf', { enabled, total })}</text>
      {eng.modules.slice(0, 8).map((mid, mi) => (
        <g key={mid} transform={`translate(${220 + mi * 72},-16)`}>
          <rect width={64} height={7} rx={3} fill="rgba(255,255,255,0.06)" />
          <rect width={64} height={7} rx={3} fill={eng.color} opacity={0.4} />
          <text y={22} fill="rgba(255,255,255,0.4)" fontSize={10} className="pg-mono">{(t(MODULE_CN_KEYS[mid]) || mid).slice(0, 5)}</text>
        </g>
      ))}
      {/* Click hint */}
      <text x={EW - 14} y={4} textAnchor="end" fill="rgba(255,255,255,0.15)" fontSize={10}>{'>'}</text>
    </g>
  )
}

function FusNode() {
  const { t } = useTranslation()
  const r = 42
  const pts = Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i - Math.PI / 2
    return `${FX + r * Math.cos(a)},${FY + r * Math.sin(a)}`
  }).join(' ')
  return (
    <g>
      <polygon points={pts} fill="none" stroke="url(#fusionGrad)" strokeWidth={2} opacity={0.3} className="pg-fusion-glow" />
      <polygon points={pts} className="pg-node-bg" stroke="url(#fusionGrad)" strokeWidth={1.5} />
      <circle cx={FX} cy={FY} r={22} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={1} strokeDasharray="4 3" className="pg-fusion-ring" />
      <circle cx={FX} cy={FY} r={8} fill="url(#fusionGrad)" opacity={0.6} className="pg-fusion-core" />
      {ENGINES.slice(0, 6).map((eng, i) => {
        const a = (Math.PI / 3) * i - Math.PI / 2, dr = r + 8
        return <circle key={eng.id} cx={FX + dr * Math.cos(a)} cy={FY + dr * Math.sin(a)} r={3.5} fill={eng.color} opacity={0.7} />
      })}
      <text x={FX} y={FY - 4} textAnchor="middle" fill="rgba(255,255,255,0.85)" fontSize={10} fontWeight={600} className="pg-label">{t('emailSecurity.dsFusion')}</text>
      <text x={FX} y={FY + 9} textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize={8} className="pg-mono">{t('emailSecurity.murphyCombination')}</text>
    </g>
  )
}

function VerdNode() {
  const { t } = useTranslation()
  return (
    <g transform={`translate(${VX},${VY})`}>
      <rect x={-40} y={-30} width={80} height={60} rx={10} className="pg-node-bg" stroke="rgba(34,211,238,0.2)" strokeWidth={1} />
      <path d="M0,-14 l6,2 v5c0,5-6,8-6,8s-6-3-6-8v-5z" fill="none" stroke="#22d3ee" strokeWidth={1.2} opacity={0.7} />
      <text textAnchor="middle" y={12} fill="rgba(255,255,255,0.85)" fontSize={11} fontWeight={600} className="pg-label">{t('emailSecurity.verdict')}</text>
    </g>
  )
}

// ════════════════════════════════════════════════════
// Detail Panel
// ════════════════════════════════════════════════════

function Panel({ eng, modules, engineStatus, pipelineConfig, contentRules, onClose, onToggle, onChangeMode }: {
  eng: EngineDef; modules: ModuleMetadata[]; engineStatus: EngineStatus | null
  pipelineConfig: PipelineConfig | null; contentRules: ContentRules | null
  onClose: () => void; onToggle: (id: string) => void; onChangeMode: (id: string, mode: ModuleConfig['mode']) => void
}) {
  const { t } = useTranslation()
  const [rulesOpen, setRulesOpen] = useState(false)
  const engMods = eng.modules.map(mid => modules.find(m => m.id === mid)).filter(Boolean) as ModuleMetadata[]

  return (
    <div className="pg-panel" onClick={e => e.stopPropagation()}>
      <div className="pg-panel-header" style={{ borderColor: eng.color }}>
        <div className="pg-panel-title">
          <span className="pg-panel-badge" style={{ background: eng.color }}>{eng.letter}</span>
          <span>{t(eng.labelKey)}</span>
        </div>
        <button className="pg-panel-close" onClick={onClose}>&times;</button>
      </div>
      <div className="pg-panel-body">
        {engMods.map(mod => {
          const metric = engineStatus?.module_metrics?.find(m => m.module_id === mod.id)
          const cfg = pipelineConfig?.modules.find(m => m.id === mod.id)
          const enabled = cfg?.enabled ?? true
          const mode = cfg?.mode ?? 'builtin'
          const rate = metric ? metric.success_rate * 100 : -1
          const dep = MODULE_DEPS[mod.id]
          const isContentScan = mod.id === 'content_scan'

          return (
            <div key={mod.id} className={`pg-panel-mod ${!enabled ? 'pg-panel-mod--off' : ''}`}>
              <div className="pg-panel-mod-top">
                <div className="pg-panel-mod-name">
                  {t(MODULE_CN_KEYS[mod.id]) || mod.id}
                  {mod.supports_ai && <span className="pg-ai-tag">AI</span>}
                </div>
                <label className="sec-toggle sec-toggle--sm">
                  <input type="checkbox" checked={enabled} onChange={() => onToggle(mod.id)} />
                  <span className="sec-toggle-slider" />
                </label>
              </div>
              <p className="pg-panel-mod-desc">{t(MODULE_DESC_KEYS[mod.id]) || mod.description}</p>
              {dep && <div className="pg-panel-dep">{t('emailSecurity.dependsOn', { module: t(MODULE_CN_KEYS[dep]) || dep })}</div>}

              {/* Performance stats */}
              {metric && metric.total_runs > 0 && (
                <div className="pg-panel-stats">
                  <div className="pg-panel-bar-track">
                    <div className="pg-panel-bar-fill" style={{
                      width: `${rate}%`,
                      background: rate >= 95 ? '#10b981' : rate >= 80 ? '#f59e0b' : '#f43f5e',
                    }} />
                  </div>
                  <div className="pg-panel-nums">
                    <span style={{ color: rate >= 95 ? '#10b981' : rate >= 80 ? '#f59e0b' : '#f43f5e' }}>{rate.toFixed(0)}%</span>
                    <span>{metric.avg_duration_ms.toFixed(0)}ms</span>
                    <span>{metric.total_runs.toLocaleString()} {t('emailSecurity.times')}</span>
                    {metric.failure_count > 0 && <span style={{ color: '#f43f5e' }}>{metric.failure_count} {t('emailSecurity.failures')}</span>}
                  </div>
                </div>
              )}

              {/* AI mode toggle */}
              {mod.supports_ai && (
                <div className="pg-panel-mode">
                  {(['builtin', 'hybrid', 'aionly'] as const).map(m => (
                    <button key={m} className={`pg-mode-btn ${mode === m ? 'pg-mode-btn--on' : ''}`}
                      onClick={() => onChangeMode(mod.id, m)} disabled={!enabled}>
                      {m === 'builtin' ? t('emailSecurity.modeRules') : m === 'hybrid' ? t('emailSecurity.modeHybrid') : 'AI'}
                    </button>
                  ))}
                </div>
              )}

              {/* content_scan rules */}
              {isContentScan && contentRules && (
                <div className="pg-panel-rules">
                  <button className="pg-panel-rules-btn" onClick={() => setRulesOpen(!rulesOpen)}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                      style={{ transform: rulesOpen ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }}><path d="M9 18l6-6-6-6"/></svg>
                    {t('emailSecurity.ruleLibrary', { count: contentRules.phishing_keywords.length + contentRules.bec_phrases.length + contentRules.dlp_patterns.length })}
                  </button>
                  {rulesOpen && (
                    <div className="pg-panel-rules-body">
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">{t('emailSecurity.phishingKeywords', { count: contentRules.phishing_keywords.length })}</div>
                        <div className="pg-rules-tags">
                          {contentRules.phishing_keywords.map(kw => <span key={kw} className="pg-rules-tag pg-rules-tag--ph">{kw}</span>)}
                        </div>
                        <div className="pg-rules-score">{t('emailSecurity.perMatchScore', { score: contentRules.scoring.phishing_per_keyword, max: contentRules.scoring.phishing_max })}</div>
                      </div>
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">{t('emailSecurity.becPhrases', { count: contentRules.bec_phrases.length })}</div>
                        <div className="pg-rules-tags">
                          {contentRules.bec_phrases.map(p => <span key={p} className="pg-rules-tag pg-rules-tag--bec">{p}</span>)}
                        </div>
                        <div className="pg-rules-score">{t('emailSecurity.perMatchScore', { score: contentRules.scoring.bec_per_phrase, max: contentRules.scoring.bec_max })}</div>
                      </div>
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">{t('emailSecurity.dlpSensitiveData', { count: contentRules.dlp_patterns.length })}</div>
                        {contentRules.dlp_patterns.map(p => (
                          <div key={p.id} className="pg-rules-dlp">
                            <span className="pg-rules-dlp-name">{p.name}</span>
                            <span className="pg-rules-dlp-desc">{p.description}</span>
                            <code className="pg-rules-dlp-pat">{p.pattern}</code>
                            <span className="pg-rules-dlp-w">+{p.score_weight}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
        <div className="pg-panel-footer">
          <span className="pg-panel-footer-label">{t('emailSecurity.outputToDsFusion')}</span>
          <span className="pg-panel-footer-desc">{t('emailSecurity.dsFusionDesc')}</span>
        </div>
      </div>
    </div>
  )
}

// ════════════════════════════════════════════════════
// Main
// ════════════════════════════════════════════════════

export default function PipelineGraph({ modules, engineStatus, pipelineConfig, contentRules, onToggleModule, onChangeMode }: Props) {
  const [sel, setSel] = useState<string | null>(null)
  const selEng = useMemo(() => ENGINES.find(e => e.id === sel), [sel])

  const enabledCount = useCallback((eng: EngineDef) =>
    eng.modules.filter(mid => (pipelineConfig?.modules.find(m => m.id === mid)?.enabled ?? true)).length
  , [pipelineConfig])

  const total = engineStatus?.total_sessions_processed ?? 0
  const rate = engineStatus?.sessions_per_second ?? 0

  return (
    <div className="pg-wrap" onClick={() => setSel(null)}>
      <svg className="pg-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="pgGrid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={0.5} />
          </pattern>
          <linearGradient id="fusionGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00f0ff" /><stop offset="100%" stopColor="#a855f7" />
          </linearGradient>
          <filter id="pgGlow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        <rect width={W} height={H} className="pg-bg" />
        <rect width={W} height={H} fill="url(#pgGrid)" />
        <circle cx={W - 100} cy={80} r={250} fill="rgba(0,240,255,0.02)" />
        <circle cx={100} cy={H - 80} r={200} fill="rgba(168,85,247,0.02)" />

        {ENGINES.map((eng, i) => <Conn key={`i${eng.id}`} x1={INX + 44} y1={INY} x2={EX} y2={eY(i)} color={eng.color} />)}
        {ENGINES.map((eng, i) => <Conn key={`e${eng.id}`} x1={EX + EW} y1={eY(i)} x2={FX - 45} y2={FY} color={eng.color} />)}
        <Conn x1={FX + 45} y1={FY} x2={VX - 40} y2={VY} color="#22d3ee" />

        <InNode total={total} rate={rate} />
        {ENGINES.map((eng, i) => (
          <EngNode key={eng.id} eng={eng} y={eY(i)} enabled={enabledCount(eng)} total={eng.modules.length}
            sel={sel === eng.id} onClick={() => setSel(prev => prev === eng.id ? null : eng.id)} />
        ))}
        <FusNode />
        <VerdNode />
      </svg>

      {selEng && (
        <Panel eng={selEng} modules={modules} engineStatus={engineStatus}
          pipelineConfig={pipelineConfig} contentRules={contentRules}
          onClose={() => setSel(null)} onToggle={onToggleModule} onChangeMode={onChangeMode} />
      )}
    </div>
  )
}
