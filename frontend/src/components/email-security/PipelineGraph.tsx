import { useState, useCallback, useMemo } from 'react'
import type { EngineStatus, ModuleMetadata, PipelineConfig, ModuleConfig, ContentRules } from '../../types'

// ════════════════════════════════════════════════════
// Types & Props
// ════════════════════════════════════════════════════

interface EngineDef {
  id: string; letter: string; label: string; color: string; modules: string[]
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
  { id: 'A', letter: 'A', label: '发件人验证', color: '#3b82f6', modules: ['domain_verify'] },
  { id: 'B', letter: 'B', label: '内容分析', color: '#00f0ff', modules: ['content_scan', 'html_scan', 'html_pixel_art', 'attach_scan', 'attach_content', 'attach_hash'] },
  { id: 'C', letter: 'C', label: '行为基线', color: '#a855f7', modules: ['anomaly_detect'] },
  { id: 'D', letter: 'D', label: 'URL 分析', color: '#f59e0b', modules: ['link_scan', 'link_reputation', 'link_content'] },
  { id: 'E', letter: 'E', label: '协议合规', color: '#10b981', modules: ['header_scan', 'mime_scan'] },
  { id: 'F', letter: 'F', label: '语义意图', color: '#f43f5e', modules: ['semantic_scan'] },
  { id: 'G', letter: 'G', label: '身份异常', color: '#06b6d4', modules: ['identity_anomaly'] },
  { id: 'H', letter: 'H', label: '交易关联', color: '#ec4899', modules: ['transaction_correlation'] },
  { id: 'I', letter: 'I', label: '病毒 / YARA', color: '#dc2626', modules: ['av_eml_scan', 'av_attach_scan', 'yara_scan'] },
]

const MODULE_CN: Record<string, string> = {
  content_scan: '内容检测', html_scan: 'HTML 检测', html_pixel_art: '像素追踪',
  attach_scan: '附件类型', attach_content: '附件内容', attach_hash: '哈希信誉',
  mime_scan: 'MIME 检测', header_scan: '邮件头检测', link_scan: 'URL 模式',
  link_reputation: 'URL 信誉', link_content: 'URL 内容', anomaly_detect: '异常行为',
  semantic_scan: '语义检测', domain_verify: '域名验证', identity_anomaly: '身份异常',
  transaction_correlation: '交易关联', av_eml_scan: '邮件病毒', av_attach_scan: '附件病毒', yara_scan: 'YARA 规则',
}

const MODULE_DESC: Record<string, string> = {
  content_scan: '钓鱼关键词、BEC 话术、DLP 敏感数据检测',
  html_scan: '恶意 HTML 元素、脚本注入、事件处理器检测',
  html_pixel_art: 'HTML 像素追踪检测、隐藏图片/1px 信标',
  attach_scan: '危险文件类型、双扩展名、MIME 不匹配检测',
  attach_content: '文档文本提取 + 关键词/AI 内容分析',
  attach_hash: 'SHA256 本地黑名单 + 外部情报源比对',
  mime_scan: '嵌套深度、边界冲突、Content-Type 不符检测',
  header_scan: 'Received 链、From/Reply-To 不匹配、Header 注入',
  link_scan: 'IP 地址链接、同形字/Punycode、短链检测',
  link_reputation: '本地域名黑名单 + 外部情报源查询',
  link_content: '抓取页面 → 表单检测 + AI 页面分析',
  anomaly_detect: '发件人基线偏离、频率/收件人/时间异常',
  semantic_scan: '乱码/熵异常检测 + NLP 钓鱼意图分析',
  domain_verify: 'SPF/DKIM/DMARC 验证、域名年龄、仿冒检测',
  identity_anomaly: '首次联系人、显示名/域名不匹配、模式突变',
  transaction_correlation: '银行账号识别、商业实体、紧迫性+金融组合',
  av_eml_scan: 'ClamAV 完整 EML 病毒签名扫描',
  av_attach_scan: 'ClamAV 逐附件病毒签名扫描',
  yara_scan: '内置 YARA 规则引擎，检测恶意文档、可执行伪装、恶意软件家族、脚本木马、高级威胁和逃逸技术',
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
  return (
    <g transform={`translate(${INX},${INY})`}>
      <rect x={-44} y={-30} width={88} height={60} rx={10} className="pg-node-bg" stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
      <text textAnchor="middle" y={-8} className="pg-label" fill="rgba(255,255,255,0.85)" fontSize={12} fontWeight={600}>邮件输入</text>
      <text textAnchor="middle" y={10} className="pg-mono" fill="rgba(255,255,255,0.4)" fontSize={10}>{total > 0 ? total.toLocaleString() : '—'}</text>
      {rate > 0 && <text textAnchor="middle" y={22} className="pg-mono" fill="rgba(255,255,255,0.3)" fontSize={9}>{rate.toFixed(1)}/s</text>}
    </g>
  )
}

function EngNode({ eng, y, enabled, total, sel, onClick }: {
  eng: EngineDef; y: number; enabled: number; total: number; sel: boolean; onClick: () => void
}) {
  return (
    <g transform={`translate(${EX},${y})`} onClick={e => { e.stopPropagation(); onClick() }} style={{ cursor: 'pointer' }} className="pg-engine">
      <rect x={0} y={-EH / 2} width={EW} height={EH} rx={10} className="pg-node-bg"
        stroke={sel ? eng.color : 'rgba(255,255,255,0.07)'} strokeWidth={sel ? 1.5 : 1} />
      <rect x={0} y={-EH / 2} width={EW} height={2} rx={1} fill={eng.color} opacity={sel ? 0.9 : 0.5} />
      {sel && <rect x={-2} y={-EH / 2 - 2} width={EW + 4} height={EH + 4} rx={12} fill="none" stroke={eng.color} strokeWidth={1} opacity={0.15} />}
      <rect x={14} y={-16} width={32} height={32} rx={7} fill={eng.color} />
      <text x={30} y={5} textAnchor="middle" fill="#fff" fontSize={14} fontWeight={700}>{eng.letter}</text>
      <text x={58} y={-4} fill="rgba(255,255,255,0.9)" fontSize={13} fontWeight={600} className="pg-label">{eng.label}</text>
      <text x={58} y={14} fill="rgba(255,255,255,0.35)" fontSize={11} className="pg-mono">{enabled}/{total} 模块</text>
      {eng.modules.slice(0, 8).map((mid, mi) => (
        <g key={mid} transform={`translate(${220 + mi * 72},-16)`}>
          <rect width={64} height={7} rx={3} fill="rgba(255,255,255,0.06)" />
          <rect width={64} height={7} rx={3} fill={eng.color} opacity={0.4} />
          <text y={22} fill="rgba(255,255,255,0.4)" fontSize={10} className="pg-mono">{(MODULE_CN[mid] || mid).slice(0, 5)}</text>
        </g>
      ))}
      {/* Click hint */}
      <text x={EW - 14} y={4} textAnchor="end" fill="rgba(255,255,255,0.15)" fontSize={10}>{'>'}</text>
    </g>
  )
}

function FusNode() {
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
      <text x={FX} y={FY - 4} textAnchor="middle" fill="rgba(255,255,255,0.85)" fontSize={10} fontWeight={600} className="pg-label">D-S 融合</text>
      <text x={FX} y={FY + 9} textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize={8} className="pg-mono">Murphy 合成</text>
    </g>
  )
}

function VerdNode() {
  return (
    <g transform={`translate(${VX},${VY})`}>
      <rect x={-40} y={-30} width={80} height={60} rx={10} className="pg-node-bg" stroke="rgba(34,211,238,0.2)" strokeWidth={1} />
      <path d="M0,-14 l6,2 v5c0,5-6,8-6,8s-6-3-6-8v-5z" fill="none" stroke="#22d3ee" strokeWidth={1.2} opacity={0.7} />
      <text textAnchor="middle" y={12} fill="rgba(255,255,255,0.85)" fontSize={11} fontWeight={600} className="pg-label">裁决</text>
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
  const [rulesOpen, setRulesOpen] = useState(false)
  const engMods = eng.modules.map(mid => modules.find(m => m.id === mid)).filter(Boolean) as ModuleMetadata[]

  return (
    <div className="pg-panel" onClick={e => e.stopPropagation()}>
      <div className="pg-panel-header" style={{ borderColor: eng.color }}>
        <div className="pg-panel-title">
          <span className="pg-panel-badge" style={{ background: eng.color }}>{eng.letter}</span>
          <span>{eng.label}</span>
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
                  {MODULE_CN[mod.id] || mod.id}
                  {mod.supports_ai && <span className="pg-ai-tag">AI</span>}
                </div>
                <label className="sec-toggle sec-toggle--sm">
                  <input type="checkbox" checked={enabled} onChange={() => onToggle(mod.id)} />
                  <span className="sec-toggle-slider" />
                </label>
              </div>
              <p className="pg-panel-mod-desc">{MODULE_DESC[mod.id] || mod.description}</p>
              {dep && <div className="pg-panel-dep">依赖 {MODULE_CN[dep] || dep}</div>}

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
                    <span>{metric.total_runs.toLocaleString()} 次</span>
                    {metric.failure_count > 0 && <span style={{ color: '#f43f5e' }}>{metric.failure_count} 失败</span>}
                  </div>
                </div>
              )}

              {/* AI mode toggle */}
              {mod.supports_ai && (
                <div className="pg-panel-mode">
                  {(['builtin', 'hybrid', 'aionly'] as const).map(m => (
                    <button key={m} className={`pg-mode-btn ${mode === m ? 'pg-mode-btn--on' : ''}`}
                      onClick={() => onChangeMode(mod.id, m)} disabled={!enabled}>
                      {m === 'builtin' ? '规则' : m === 'hybrid' ? '混合' : 'AI'}
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
                    规则库 ({contentRules.phishing_keywords.length + contentRules.bec_phrases.length + contentRules.dlp_patterns.length})
                  </button>
                  {rulesOpen && (
                    <div className="pg-panel-rules-body">
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">钓鱼关键词 ({contentRules.phishing_keywords.length})</div>
                        <div className="pg-rules-tags">
                          {contentRules.phishing_keywords.map(kw => <span key={kw} className="pg-rules-tag pg-rules-tag--ph">{kw}</span>)}
                        </div>
                        <div className="pg-rules-score">每匹配 +{contentRules.scoring.phishing_per_keyword}，上限 {contentRules.scoring.phishing_max}</div>
                      </div>
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">BEC 短语 ({contentRules.bec_phrases.length})</div>
                        <div className="pg-rules-tags">
                          {contentRules.bec_phrases.map(p => <span key={p} className="pg-rules-tag pg-rules-tag--bec">{p}</span>)}
                        </div>
                        <div className="pg-rules-score">每匹配 +{contentRules.scoring.bec_per_phrase}，上限 {contentRules.scoring.bec_max}</div>
                      </div>
                      <div className="pg-rules-sec">
                        <div className="pg-rules-sec-title">DLP 敏感数据 ({contentRules.dlp_patterns.length})</div>
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
          <span className="pg-panel-footer-label">输出至 D-S 融合</span>
          <span className="pg-panel-footer-desc">引擎内 Dempster 组合 → BPA (Bel, Dis, Unc) → Murphy 加权</span>
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
