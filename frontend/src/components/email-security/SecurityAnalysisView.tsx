import { useState, useMemo } from 'react'
import type { SecurityVerdict, ModuleResult } from '../../types'

// ════════════════════════════════════════════════════════════════
// Props
// ════════════════════════════════════════════════════════════════

interface SecurityAnalysisViewProps {
  verdict: SecurityVerdict | null
  moduleResults: ModuleResult[]
  expandedModules: Set<string> | null
  toggleModuleExpand: (id: string) => void
  feedbackDone: boolean
  feedbackType: string | null
  feedbackComment: string
  feedbackSubmitting: boolean
  setFeedbackType: (t: any) => void
  setFeedbackComment: (c: string) => void
  submitFeedback: () => void
}

// ════════════════════════════════════════════════════════════════
// Design Constants
// ════════════════════════════════════════════════════════════════

const ENGINE_COLORS: Record<string, string> = {
  sender_reputation: '#3b82f6',
  content_analysis: '#00f0ff',
  behavior_baseline: '#a855f7',
  url_analysis: '#f59e0b',
  protocol_compliance: '#10b981',
  semantic_intent: '#f43f5e',
  identity_anomaly: '#6366f1',
  transaction_correlation: '#ec4899',
}

const ENGINE_SHORT: Record<string, string> = {
  sender_reputation: '信誉', content_analysis: '内容', behavior_baseline: '行为',
  url_analysis: '链接', protocol_compliance: '合规', semantic_intent: '语义',
  identity_anomaly: '身份', transaction_correlation: '交易',
}

const ENGINE_LETTER: Record<string, string> = {
  sender_reputation: 'A', content_analysis: 'B', behavior_baseline: 'C',
  url_analysis: 'D', protocol_compliance: 'E', semantic_intent: 'F',
  identity_anomaly: 'G', transaction_correlation: 'H',
}

const ENGINE_CN: Record<string, string> = {
  sender_reputation: '发件人信誉', content_analysis: '内容分析', behavior_baseline: '行为基线',
  url_analysis: 'URL分析', protocol_compliance: '协议合规', semantic_intent: '语义意图',
  identity_anomaly: '身份异常', transaction_correlation: '交易关联',
}

const THREAT_CN: Record<string, string> = {
  safe: '安全', low: '低危', medium: '中危', high: '高危', critical: '危急',
}

const MODULE_CN: Record<string, string> = {
  content_scan: '内容检测', html_scan: 'HTML检测', html_pixel_art: '像素艺术检测',
  attach_scan: '附件类型检测', attach_content: '附件内容检测', attach_hash: '附件哈希信誉',
  mime_scan: 'MIME结构检测', header_scan: '邮件头检测', link_scan: 'URL模式检测',
  link_reputation: 'URL信誉查询', link_content: 'URL内容检测', anomaly_detect: '异常行为检测',
  semantic_scan: '语义检测', domain_verify: '域名验证', identity_anomaly: '身份行为异常',
  transaction_correlation: '交易语义关联', av_eml_scan: '邮件病毒扫描', av_attach_scan: '附件病毒扫描', yara_scan: 'YARA规则扫描',
  verdict: '综合判定',
}

const PILLAR_CN: Record<string, string> = {
  content: '正文', attachment: '附件', package: '封装', link: '链接', semantic: '语义',
}

const ENGINE_ORDER = [
  'sender_reputation', 'content_analysis', 'behavior_baseline', 'url_analysis',
  'protocol_compliance', 'semantic_intent', 'identity_anomaly', 'transaction_correlation',
]

const PILLAR_ORDER = ['content', 'attachment', 'link', 'package', 'semantic']

const MONO = "'JetBrains Mono', monospace"

// ════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════

function threatColor(level: string): string {
  switch (level) {
    case 'critical': return '#dc2626'
    case 'high': return '#ea580c'
    case 'medium': return '#ca8a04'
    case 'low': return '#2563eb'
    case 'safe': return '#16a34a'
    default: return '#6b7280'
  }
}

function engineScore(bpa: { b: number; d: number; u: number } | undefined): number {
  if (!bpa) return 0
  const denom = bpa.b + bpa.d + bpa.u
  if (denom === 0) return 0
  return Math.round((bpa.b / denom) * 100)
}

function scoreIndicatorColor(score: number): string {
  if (score === 0) return '#16a34a'
  if (score < 30) return '#ca8a04'
  return '#dc2626'
}

function scoreIndicatorLabel(score: number): string {
  if (score === 0) return '\u2713'
  return String(score)
}

// ════════════════════════════════════════════════════════════════
// Styles
// ════════════════════════════════════════════════════════════════

const S = {
  card: {
    background: 'rgba(255,255,255,0.02)',
    border: '1px solid rgba(255,255,255,0.06)',
    borderRadius: 14,
    padding: '20px 24px',
    marginBottom: 16,
  } as React.CSSProperties,
  cardTitle: {
    fontSize: 13,
    fontWeight: 600,
    color: 'rgba(255,255,255,0.55)',
    letterSpacing: 1,
    textTransform: 'uppercase' as const,
    marginBottom: 16,
  } as React.CSSProperties,
  mono: {
    fontFamily: MONO,
  } as React.CSSProperties,
  // AnalysisFlow
  flowRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 0,
    overflowX: 'auto' as const,
    padding: '10px 8px',
  } as React.CSSProperties,
  flowNode: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: 4,
    flexShrink: 0,
  } as React.CSSProperties,
  flowConnector: {
    width: 12,
    height: 2,
    background: 'rgba(255,255,255,0.06)',
    flexShrink: 0,
    marginTop: -20,
  } as React.CSSProperties,
  flowLongConnector: {
    width: 24,
    height: 2,
    flexShrink: 0,
    marginTop: -20,
    background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent)',
  } as React.CSSProperties,
  flowLabel: {
    fontSize: 10,
    color: 'rgba(255,255,255,0.35)',
    whiteSpace: 'nowrap' as const,
    marginTop: 4,
    letterSpacing: '0.3px',
  } as React.CSSProperties,
  // Radar
  radarWrap: {
    display: 'flex',
    gap: 24,
    alignItems: 'center',
    flexWrap: 'wrap' as const,
  } as React.CSSProperties,
  // Module list
  moduleRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '8px 12px',
    borderRadius: 8,
    cursor: 'pointer',
    transition: 'background 0.15s',
  } as React.CSSProperties,
  moduleRowLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    flex: 1,
    minWidth: 0,
  } as React.CSSProperties,
  moduleRowRight: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    flexShrink: 0,
  } as React.CSSProperties,
  bpaBar: {
    height: 10,
    borderRadius: 5,
    display: 'flex',
    overflow: 'hidden',
    background: 'rgba(255,255,255,0.04)',
  } as React.CSSProperties,
  bpaBarThin: {
    height: 4,
    borderRadius: 2,
    display: 'flex',
    overflow: 'hidden',
    background: 'rgba(255,255,255,0.04)',
  } as React.CSSProperties,
  bpaSeg: (color: string, pct: number) => ({
    width: `${pct}%`,
    background: color,
    minWidth: pct > 0.5 ? 1 : 0,
    transition: 'width 0.3s',
  } as React.CSSProperties),
  evidenceItem: {
    padding: '6px 10px',
    background: 'rgba(255,255,255,0.02)',
    borderRadius: 6,
    marginTop: 4,
    fontSize: 12,
  } as React.CSSProperties,
  // Fusion
  metricCard: {
    flex: 1,
    minWidth: 100,
    background: 'rgba(255,255,255,0.03)',
    borderRadius: 10,
    padding: '14px 16px',
    textAlign: 'center' as const,
  } as React.CSSProperties,
  breakerAlert: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 8,
    padding: '10px 14px',
    borderRadius: 8,
    marginTop: 12,
    fontSize: 12,
    lineHeight: 1.5,
  } as React.CSSProperties,
  feedbackBtn: {
    padding: '6px 14px',
    borderRadius: 8,
    border: '1px solid rgba(255,255,255,0.1)',
    background: 'rgba(255,255,255,0.04)',
    color: 'rgba(255,255,255,0.7)',
    cursor: 'pointer',
    fontSize: 12,
    transition: 'all 0.15s',
  } as React.CSSProperties,
}

// ════════════════════════════════════════════════════════════════
// Component
// ════════════════════════════════════════════════════════════════

export default function SecurityAnalysisView({
  verdict,
  moduleResults,
  expandedModules,
  toggleModuleExpand,
  feedbackDone,
  feedbackType,
  feedbackComment,
  feedbackSubmitting,
  setFeedbackType,
  setFeedbackComment,
  submitFeedback,
}: SecurityAnalysisViewProps) {
  const [selectedEngine, setSelectedEngine] = useState<string | null>(null)

  // Build engine BPA lookup from fusion_details
  const engineBpaMap = useMemo(() => {
    const m = new Map<string, { b: number; d: number; u: number }>()
    if (verdict?.fusion_details?.engine_details) {
      for (const ed of verdict.fusion_details.engine_details) {
        m.set(ed.engine_id, ed.bpa ?? { b: 0, d: 0, u: 1 })
      }
    }
    return m
  }, [verdict])

  // Modules grouped by engine
  const modulesByEngine = useMemo(() => {
    const m = new Map<string, ModuleResult[]>()
    for (const mr of moduleResults) {
      const eid = mr.engine_id ?? 'unknown'
      if (!m.has(eid)) m.set(eid, [])
      m.get(eid)!.push(mr)
    }
    return m
  }, [moduleResults])

  if (!verdict) {
    return (
      <div style={{ ...S.card, textAlign: 'center', padding: 40, color: 'rgba(255,255,255,0.3)' }}>
        此邮件尚未进行安全分析
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* -- Section 1: AnalysisFlow (compact single row) -- */}
      <div style={{
        ...S.card,
        padding: '10px 16px',
        display: 'flex',
        alignItems: 'center',
        gap: 0,
        overflowX: 'auto',
      }}>
        <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginRight: 10, flexShrink: 0 }}>检测流程</span>

        {/* Input */}
        <div title="邮件输入" style={{
          width: 28, height: 28, borderRadius: 7, flexShrink: 0,
          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.4)" strokeWidth="1.5">
            <rect x="2" y="4" width="20" height="16" rx="2" /><polyline points="2 4 12 13 22 4" />
          </svg>
        </div>
        <div style={{ width: 16, height: 1, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />

        {/* Engine nodes */}
        {ENGINE_ORDER.map((eid, i) => {
          const color = ENGINE_COLORS[eid] ?? '#6b7280'
          const bpa = engineBpaMap.get(eid)
          const score = engineScore(bpa)
          const indColor = scoreIndicatorColor(score)
          const indLabel = scoreIndicatorLabel(score)
          return (
            <div key={eid} style={{ display: 'flex', alignItems: 'center' }}>
              <div
                title={`${ENGINE_CN[eid] ?? eid} (${ENGINE_SHORT[eid]})`}
                style={{ position: 'relative', cursor: 'pointer', flexShrink: 0 }}
                onClick={() => setSelectedEngine(prev => prev === eid ? null : eid)}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: 6,
                  background: `${color}14`,
                  border: `1px solid ${color}30`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: selectedEngine === eid ? `0 0 0 2px ${color}` : 'none',
                  transition: 'box-shadow 0.15s',
                }}>
                  <span style={{ fontFamily: MONO, fontWeight: 700, fontSize: 12, color }}>
                    {ENGINE_LETTER[eid] ?? '?'}
                  </span>
                </div>
                <div style={{
                  position: 'absolute', top: -3, right: -3,
                  width: 13, height: 13, borderRadius: 7,
                  background: indColor, border: '1.5px solid #0a0b0f',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 7, fontFamily: MONO, fontWeight: 700, color: '#fff', lineHeight: 1,
                }}>
                  {indLabel}
                </div>
              </div>
              {i < ENGINE_ORDER.length - 1 && (
                <div style={{ width: 6, height: 1, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />
              )}
            </div>
          )
        })}

        <div style={{ width: 16, height: 1, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />

        {/* Fusion */}
        <div title="D-S 证据融合" style={{
          width: 28, height: 28, borderRadius: 7, flexShrink: 0,
          background: 'linear-gradient(135deg, rgba(0,240,255,0.08), rgba(168,85,247,0.08))',
          border: '1px solid rgba(0,240,255,0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(0,240,255,0.6)" strokeWidth="1.5">
            <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5" />
          </svg>
        </div>
        <div style={{ width: 10, height: 1, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} />

        {/* Verdict */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0,
          padding: '4px 10px 4px 6px', borderRadius: 6,
          background: `${threatColor(verdict.threat_level)}12`,
          border: `1px solid ${threatColor(verdict.threat_level)}25`,
        }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={threatColor(verdict.threat_level)} strokeWidth="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span style={{ fontSize: 11, fontWeight: 600, color: threatColor(verdict.threat_level) }}>
            {THREAT_CN[verdict.threat_level] ?? verdict.threat_level}
          </span>
        </div>
      </div>

      {/* -- Section 2: detection-module results -- */}
      <div style={S.card}>
        <div style={S.cardTitle}>检测模块</div>
        {selectedEngine ? (
          <EngineDetail
            engineId={selectedEngine}
            bpa={engineBpaMap.get(selectedEngine)}
            modules={modulesByEngine.get(selectedEngine) ?? []}
            expandedModules={expandedModules}
            toggleModuleExpand={toggleModuleExpand}
            weight={verdict.fusion_details?.credibility_weights?.[selectedEngine]}
            onClose={() => setSelectedEngine(null)}
          />
        ) : (
          <ModuleList
            moduleResults={moduleResults}
            expandedModules={expandedModules}
            toggleModuleExpand={toggleModuleExpand}
          />
        )}
      </div>

      {/* ── Section 3: FusionPanel ── */}
      {verdict.fusion_details && (
        <FusionPanel fusion={verdict.fusion_details} />
      )}

      {/* ── Feedback ── */}
      <FeedbackSection
        feedbackDone={feedbackDone}
        feedbackType={feedbackType}
        feedbackComment={feedbackComment}
        feedbackSubmitting={feedbackSubmitting}
        setFeedbackType={setFeedbackType}
        setFeedbackComment={setFeedbackComment}
        submitFeedback={submitFeedback}
      />
    </div>
  )
}

// ════════════════════════════════════════════════════════════════
// RadarChart (SVG)
// ════════════════════════════════════════════════════════════════

export function RadarChart({ pillarPcts, riskPct, threatLevel, size: sizeProp }: {
  pillarPcts: Record<string, number>
  riskPct: number
  threatLevel: string
  size?: number
}) {
  const size = sizeProp ?? 260
  const cx = size / 2
  const cy = size / 2
  const maxR = size * 0.30
  const axes = PILLAR_ORDER
  const n = axes.length
  const angleStep = (2 * Math.PI) / n
  const startAngle = -Math.PI / 2 // start from top

  function polarToXY(angle: number, r: number): [number, number] {
    return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)]
  }

  // Grid circles
  const gridLevels = [0.25, 0.5, 0.75, 1.0]

  // Score polygon points (INVERTED: 0=full radius=safe, 100=center=dangerous)
  const polyPoints = axes.map((pillar, i) => {
    const score = pillarPcts[pillar] ?? 0
    const r = maxR * (1 - score / 100)
    const angle = startAngle + i * angleStep
    return polarToXY(angle, r)
  })
  const polyPath = polyPoints.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x},${y}`).join(' ') + ' Z'

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <defs>
        {/* Gradient fill for the polygon area */}
        <radialGradient id="radarFill" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={threatColor(threatLevel)} stopOpacity="0.25" />
          <stop offset="100%" stopColor={threatColor(threatLevel)} stopOpacity="0.04" />
        </radialGradient>
        {/* Outer glow */}
        <filter id="radarGlow">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* Grid circles - gradient opacity */}
      {gridLevels.map((level, i) => (
        <circle
          key={level}
          cx={cx} cy={cy} r={maxR * level}
          fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={1}
          strokeDasharray={i < gridLevels.length - 1 ? '3 3' : 'none'}
        />
      ))}

      {/* Radial lines + labels */}
      {axes.map((pillar, i) => {
        const angle = startAngle + i * angleStep
        const [lx, ly] = polarToXY(angle, maxR + size * 0.14)
        const [ex, ey] = polarToXY(angle, maxR)
        const score = pillarPcts[pillar] ?? 0
        return (
          <g key={pillar}>
            <line
              x1={cx} y1={cy} x2={ex} y2={ey}
              stroke="rgba(255,255,255,0.05)" strokeWidth={1}
            />
            {/* Pillar label */}
            <text
              x={lx} y={ly - 7}
              textAnchor="middle" dominantBaseline="central"
              fill="rgba(255,255,255,0.55)" fontSize={12} fontWeight={500}
            >
              {PILLAR_CN[pillar] ?? pillar}
            </text>
            {/* Score */}
            <text
              x={lx} y={ly + 8}
              textAnchor="middle" dominantBaseline="central"
              fill={score > 50 ? threatColor(threatLevel) : 'rgba(255,255,255,0.35)'}
              fontSize={12} fontWeight={700} fontFamily={MONO}
            >
              {score}
            </text>
          </g>
        )
      })}

      {/* Score polygon - gradient fill + glowing outline */}
      <path
        d={polyPath}
        fill="url(#radarFill)"
        stroke={threatColor(threatLevel)}
        strokeWidth={1.5}
        strokeLinejoin="round"
        filter="url(#radarGlow)"
        opacity={0.9}
      />

      {/* Score dots - larger and brighter */}
      {polyPoints.map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r={5} fill={threatColor(threatLevel)} opacity={0.15} />
          <circle cx={x} cy={y} r={3} fill={threatColor(threatLevel)} />
        </g>
      ))}

      {/* Center risk - larger type size */}
      <text
        x={cx} y={cy - 8}
        textAnchor="middle" dominantBaseline="central"
        fill={threatColor(threatLevel)}
        fontSize={28} fontWeight={800} fontFamily={MONO}
      >
        {riskPct}
      </text>
      <text
        x={cx} y={cy + 14}
        textAnchor="middle" dominantBaseline="central"
        fill="rgba(255,255,255,0.4)" fontSize={11} fontWeight={500}
      >
        综合风险
      </text>
    </svg>
  )
}

// ════════════════════════════════════════════════════════════════
// EngineDetail
// ════════════════════════════════════════════════════════════════

function EngineDetail({ engineId, bpa, modules, expandedModules, toggleModuleExpand, weight, onClose }: {
  engineId: string
  bpa: { b: number; d: number; u: number } | undefined
  modules: ModuleResult[]
  expandedModules: Set<string> | null
  toggleModuleExpand: (id: string) => void
  weight: number | undefined
  onClose: () => void
}) {
  const color = ENGINE_COLORS[engineId] ?? '#6b7280'
  const score = engineScore(bpa)
  const safeBpa = bpa ?? { b: 0, d: 0, u: 1 }

  return (
    <div>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 14px', borderRadius: 10,
        background: `${color}12`, border: `1px solid ${color}30`,
        marginBottom: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 28, height: 28, borderRadius: 6,
            background: `${color}25`, color, fontFamily: MONO, fontWeight: 700, fontSize: 14,
          }}>
            {ENGINE_LETTER[engineId] ?? '?'}
          </span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.85)' }}>
              {ENGINE_CN[engineId] ?? engineId}
            </div>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', fontFamily: MONO }}>
              score={score} {weight != null && `w=${weight.toFixed(2)}`}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)',
            cursor: 'pointer', fontSize: 18, padding: 4,
          }}
        >
          &times;
        </button>
      </div>

      {/* BPA bar */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>BPA 分布</div>
        <div style={S.bpaBar}>
          <div style={S.bpaSeg('#dc2626', safeBpa.b * 100)} />
          <div style={S.bpaSeg('#16a34a', safeBpa.d * 100)} />
          <div style={S.bpaSeg('#6b7280', safeBpa.u * 100)} />
        </div>
        <div style={{
          display: 'flex', gap: 12, marginTop: 4, fontSize: 10, fontFamily: MONO,
          color: 'rgba(255,255,255,0.4)',
        }}>
          <span>B={safeBpa.b.toFixed(2)}</span>
          <span>D={safeBpa.d.toFixed(2)}</span>
          <span>U={safeBpa.u.toFixed(2)}</span>
        </div>
      </div>

      {/* Sub-modules */}
      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 6 }}>
        子模块 ({modules.length})
      </div>
      {modules.map(mr => {
        const isSafe = mr.threat_level === 'safe'
        const isOpen = expandedModules?.has(mr.module_id) ?? !isSafe
        return (
          <div key={mr.module_id} style={{ marginBottom: 4 }}>
            <div
              style={{
                ...S.moduleRow,
                opacity: isSafe && !isOpen ? 0.4 : 1,
                background: isOpen ? 'rgba(255,255,255,0.03)' : 'transparent',
              }}
              onClick={() => toggleModuleExpand(mr.module_id)}
            >
              <div style={S.moduleRowLeft}>
                <span style={{
                  width: 6, height: 6, borderRadius: 3, flexShrink: 0,
                  background: threatColor(mr.threat_level),
                }} />
                <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {MODULE_CN[mr.module_id] ?? mr.module_name}
                </span>
              </div>
              <div style={S.moduleRowRight}>
                <span style={{ fontSize: 10, color: threatColor(mr.threat_level), fontWeight: 500 }}>
                  {THREAT_CN[mr.threat_level] ?? mr.threat_level}
                </span>
                <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: MONO }}>
                  {mr.duration_ms}ms
                </span>
                <svg
                  width="10" height="10" viewBox="0 0 24 24" fill="none"
                  stroke="rgba(255,255,255,0.3)" strokeWidth="2"
                  style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}
                >
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
            </div>
            {isOpen && <ModuleExpandedContent mr={mr} />}
          </div>
        )
      })}
    </div>
  )
}

// ════════════════════════════════════════════════════════════════
// ModuleList (default right panel)
// ════════════════════════════════════════════════════════════════

function ModuleList({ moduleResults, expandedModules, toggleModuleExpand }: {
  moduleResults: ModuleResult[]
  expandedModules: Set<string> | null
  toggleModuleExpand: (id: string) => void
}) {
  if (moduleResults.length === 0) {
    return <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: 13, padding: 12 }}>暂无模块结果</div>
  }

  return (
    <div>
      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8 }}>
        检测模块 ({moduleResults.length})
      </div>
      {moduleResults.map(mr => {
        const isSafe = mr.threat_level === 'safe'
        const isOpen = expandedModules?.has(mr.module_id) ?? !isSafe
        return (
          <div key={mr.module_id} style={{ marginBottom: 2 }}>
            <div
              style={{
                ...S.moduleRow,
                opacity: isSafe && !isOpen ? 0.4 : 1,
                background: isOpen ? 'rgba(255,255,255,0.03)' : 'transparent',
              }}
              onClick={() => toggleModuleExpand(mr.module_id)}
            >
              <div style={S.moduleRowLeft}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                  background: threatColor(mr.threat_level),
                  boxShadow: !isSafe ? `0 0 6px ${threatColor(mr.threat_level)}60` : 'none',
                }} />
                <span style={{ fontSize: 13, fontWeight: 500, color: isSafe ? 'rgba(255,255,255,0.5)' : 'rgba(255,255,255,0.85)' }}>
                  {MODULE_CN[mr.module_id] ?? mr.module_name}
                </span>
                <span style={{
                  fontSize: 10, color: 'rgba(255,255,255,0.3)',
                  background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4,
                  flexShrink: 0,
                }}>
                  {PILLAR_CN[mr.pillar] ?? mr.pillar}
                </span>
              </div>
              <div style={S.moduleRowRight}>
                <span style={{
                  fontSize: 11, fontWeight: 600, color: threatColor(mr.threat_level),
                  padding: '1px 6px', borderRadius: 4,
                  background: !isSafe ? `${threatColor(mr.threat_level)}15` : 'transparent',
                }}>
                  {THREAT_CN[mr.threat_level] ?? mr.threat_level}
                </span>
                <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: MONO }}>
                  {mr.duration_ms > 999 ? `${(mr.duration_ms / 1000).toFixed(1)}s` : `${mr.duration_ms}ms`}
                </span>
                <svg
                  width="12" height="12" viewBox="0 0 24 24" fill="none"
                  stroke="rgba(255,255,255,0.3)" strokeWidth="2"
                  style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}
                >
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
            </div>
            {isOpen && <ModuleExpandedContent mr={mr} />}
          </div>
        )
      })}
    </div>
  )
}

// ════════════════════════════════════════════════════════════════
// ModuleExpandedContent (shared between EngineDetail & ModuleList)
// ════════════════════════════════════════════════════════════════

function ModuleExpandedContent({ mr }: { mr: ModuleResult }) {
  return (
    <div style={{ padding: '4px 12px 10px 26px' }}>
      <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', margin: '0 0 6px', lineHeight: 1.5 }}>
        {mr.summary}
      </p>

      {/* BPA bar */}
      {mr.bpa && mr.bpa.b != null && (
        <div style={{ marginBottom: 6 }}>
          <div style={S.bpaBar}>
            <div style={S.bpaSeg('#dc2626', (mr.bpa.b ?? 0) * 100)} />
            <div style={S.bpaSeg('#16a34a', (mr.bpa.d ?? 0) * 100)} />
            <div style={S.bpaSeg('#6b7280', (mr.bpa.u ?? 0) * 100)} />
          </div>
          <div style={{
            display: 'flex', gap: 10, marginTop: 3, fontSize: 9, fontFamily: MONO,
            color: 'rgba(255,255,255,0.35)',
          }}>
            <span>B={(mr.bpa.b ?? 0).toFixed(2)}</span>
            <span>D={(mr.bpa.d ?? 0).toFixed(2)}</span>
            <span>U={(mr.bpa.u ?? 0).toFixed(2)}</span>
          </div>
        </div>
      )}

      {/* Evidence */}
      {mr.evidence.length > 0 && (
        <div>
          {mr.evidence.map((ev, idx) => (
            <div key={idx} style={S.evidenceItem}>
              <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.55)' }}>{ev.description}</div>
              {ev.location && (
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginTop: 2 }}>{ev.location}</div>
              )}
              {ev.snippet && (
                <code style={{
                  display: 'block', fontSize: 10, color: 'rgba(255,255,255,0.4)',
                  fontFamily: MONO, marginTop: 3, padding: '4px 6px',
                  background: 'rgba(255,255,255,0.02)', borderRadius: 4,
                  overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                }}>
                  {ev.snippet}
                </code>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ════════════════════════════════════════════════════════════════
// FusionPanel
// ════════════════════════════════════════════════════════════════

function FusionPanel({ fusion }: { fusion: NonNullable<SecurityVerdict['fusion_details']> }) {
  const bpa = fusion.fused_bpa
  const kConflict = fusion.k_conflict ?? 0
  const riskSingle = fusion.risk_single ?? 0
  const eta = fusion.eta ?? 0
  const engines = Array.isArray(fusion.engine_details) ? fusion.engine_details : []
  const weights = fusion.credibility_weights ?? {}
  const eps = bpa.epsilon ?? 0

  // Sort engines by bel descending for comparison
  const sortedEngines = useMemo(() => {
    return [...engines].sort((a, b) => (b.bpa?.b ?? 0) - (a.bpa?.b ?? 0))
  }, [engines])

  function kColor(k: number): string {
    if (k < 0.1) return '#16a34a'
    if (k <= 0.3) return '#ca8a04'
    return '#dc2626'
  }

  function kLabel(k: number): string {
    if (k < 0.1) return '低冲突'
    if (k <= 0.3) return '中冲突'
    return '高冲突'
  }

  return (
    <div style={S.card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <span style={S.cardTitle}>D-S 证据融合</span>
        {fusion.fusion_method && (
          <span style={{
            fontSize: 10, color: 'rgba(255,255,255,0.3)',
            background: 'rgba(255,255,255,0.04)', padding: '2px 8px', borderRadius: 4,
          }}>
            {fusion.fusion_method}
          </span>
        )}
      </div>

      {/* Fused BPA bar */}
      <div style={{ marginBottom: 16 }}>
        <div style={S.bpaBar}>
          <div style={S.bpaSeg('#dc2626', bpa.b * 100)} title={`Belief: ${(bpa.b * 100).toFixed(1)}%`} />
          <div style={S.bpaSeg('#16a34a', bpa.d * 100)} title={`Disbelief: ${(bpa.d * 100).toFixed(1)}%`} />
          <div style={S.bpaSeg('#6b7280', bpa.u * 100)} title={`Uncertainty: ${(bpa.u * 100).toFixed(1)}%`} />
          {eps > 0.001 && (
            <div style={S.bpaSeg('#4c1d95', eps * 100)} title={`Epsilon: ${(eps * 100).toFixed(2)}%`} />
          )}
        </div>
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 6,
          fontSize: 11, color: 'rgba(255,255,255,0.45)',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#dc2626', flexShrink: 0 }} />
            Bel (恶意) <span style={{ fontFamily: MONO }}>{(bpa.b * 100).toFixed(1)}%</span>
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#16a34a', flexShrink: 0 }} />
            Dis (正常) <span style={{ fontFamily: MONO }}>{(bpa.d * 100).toFixed(1)}%</span>
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#6b7280', flexShrink: 0 }} />
            Unc (不确定) <span style={{ fontFamily: MONO }}>{(bpa.u * 100).toFixed(1)}%</span>
          </span>
          {eps > 0.001 && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: '#4c1d95', flexShrink: 0 }} />
              m(empty) <span style={{ fontFamily: MONO }}>{(eps * 100).toFixed(2)}%</span>
            </span>
          )}
        </div>
      </div>

      {/* Key Metrics — compact inline row */}
      <div style={{
        display: 'flex', gap: 16, marginBottom: 14, flexWrap: 'wrap',
        fontSize: 12, color: 'rgba(255,255,255,0.45)', alignItems: 'baseline',
      }}>
        <span>
          冲突 K <span style={{ fontFamily: MONO, fontWeight: 600, color: kColor(kConflict), fontSize: 13 }}>{kConflict.toFixed(3)}</span>
          <span style={{ fontSize: 10, marginLeft: 4, color: kColor(kConflict) }}>{kLabel(kConflict)}</span>
        </span>
        <span style={{ color: 'rgba(255,255,255,0.1)' }}>|</span>
        <span>
          风险 R <span style={{ fontFamily: MONO, fontWeight: 600, color: riskSingle >= eta ? '#f87171' : '#4ade80', fontSize: 13 }}>{riskSingle.toFixed(3)}</span>
        </span>
        <span style={{ color: 'rgba(255,255,255,0.1)' }}>|</span>
        <span>
          阈值 η <span style={{ fontFamily: MONO, fontWeight: 600, color: 'rgba(255,255,255,0.55)', fontSize: 13 }}>{eta.toFixed(3)}</span>
        </span>
      </div>

      {/* Circuit breaker alerts */}
      {fusion.circuit_breaker && (
        <div style={{
          ...S.breakerAlert,
          background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.2)',
        }}>
          <span style={{ fontSize: 14, flexShrink: 0 }}>&#9889;</span>
          <div style={{ color: 'rgba(255,255,255,0.6)' }}>
            <strong style={{ color: '#dc2626' }}>单信号断路器激活</strong>
            : 模块 <strong>{MODULE_CN[fusion.circuit_breaker.trigger_module_id] ?? fusion.circuit_breaker.trigger_module_id}</strong>
            {' '}信念值 <span style={{ fontFamily: MONO }}>{fusion.circuit_breaker.trigger_belief.toFixed(2)}</span>
            {' '}被融合压制 (原始风险 <span style={{ fontFamily: MONO }}>{fusion.circuit_breaker.original_risk.toFixed(4)}</span>)
            ，已提升至地板 <span style={{ fontFamily: MONO, color: '#dc2626' }}>{fusion.circuit_breaker.floor_value.toFixed(2)}</span>
          </div>
        </div>
      )}

      {fusion.convergence_breaker && (
        <div style={{
          ...S.breakerAlert,
          background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)',
        }}>
          <span style={{ fontSize: 14, flexShrink: 0 }}>&#9888;</span>
          <div style={{ color: 'rgba(255,255,255,0.6)' }}>
            <strong style={{ color: '#ca8a04' }}>收敛断路器激活</strong>
            : {fusion.convergence_breaker.modules_flagged} 个模块独立标记威胁但被 D-S 融合压制
            (原始风险 <span style={{ fontFamily: MONO }}>{fusion.convergence_breaker.original_risk.toFixed(4)}</span>)
            ，已提升至 <span style={{ fontFamily: MONO, color: '#ca8a04' }}>{fusion.convergence_breaker.floor_value.toFixed(2)}</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
              {fusion.convergence_breaker.flagged_modules.map(mid => (
                <span key={mid} style={{
                  fontSize: 10, padding: '1px 6px', borderRadius: 4,
                  background: 'rgba(234,179,8,0.12)', color: '#ca8a04',
                }}>
                  {MODULE_CN[mid] ?? mid}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Engine BPA comparison */}
      {sortedEngines.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8 }}>
            各引擎 BPA 对比
          </div>
          {sortedEngines.map(eng => {
            const eBpa = eng.bpa ?? { b: 0, d: 0, u: 1 }
            const color = ENGINE_COLORS[eng.engine_id] ?? '#6b7280'
            const w = weights[eng.engine_id]
            return (
              <div key={eng.engine_id} style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6,
              }}>
                {/* ID badge */}
                <span style={{
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  width: 22, height: 22, borderRadius: 5, flexShrink: 0,
                  background: `${color}20`, color, fontFamily: MONO, fontWeight: 700, fontSize: 11,
                }}>
                  {ENGINE_LETTER[eng.engine_id] ?? '?'}
                </span>
                {/* Mini BPA bar */}
                <div style={{ flex: 1 }}>
                  <div style={S.bpaBarThin}>
                    <div style={S.bpaSeg('#dc2626', eBpa.b * 100)} />
                    <div style={S.bpaSeg('#16a34a', eBpa.d * 100)} />
                    <div style={S.bpaSeg('#6b7280', eBpa.u * 100)} />
                  </div>
                </div>
                {/* Bel percentage */}
                <span style={{
                  fontSize: 10, fontFamily: MONO, color: 'rgba(255,255,255,0.45)',
                  width: 38, textAlign: 'right', flexShrink: 0,
                }}>
                  {(eBpa.b * 100).toFixed(0)}%
                </span>
                {w != null && (
                  <span style={{
                    fontSize: 9, color: 'rgba(255,255,255,0.2)', fontFamily: MONO,
                    width: 36, textAlign: 'right', flexShrink: 0,
                  }}>
                    w={w.toFixed(2)}
                  </span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ════════════════════════════════════════════════════════════════
// FeedbackSection
// ════════════════════════════════════════════════════════════════

function FeedbackSection({
  feedbackDone, feedbackType, feedbackComment, feedbackSubmitting,
  setFeedbackType, setFeedbackComment, submitFeedback,
}: {
  feedbackDone: boolean
  feedbackType: string | null
  feedbackComment: string
  feedbackSubmitting: boolean
  setFeedbackType: (t: any) => void
  setFeedbackComment: (c: string) => void
  submitFeedback: () => void
}) {
  const FEEDBACK_MAP: Record<string, string> = {
    legitimate: '正常邮件',
    phishing: '钓鱼邮件',
    spoofing: '仿冒邮件',
    social_engineering: '社会工程学',
    other_threat: '其他威胁',
  }

  return (
    <div style={{ ...S.card, paddingTop: 14, paddingBottom: 14 }}>
      {feedbackDone ? (
        <div style={{ textAlign: 'center', color: '#16a34a', fontSize: 13 }}>
          反馈已提交，将用于模型优化
        </div>
      ) : feedbackType ? (
        <div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', marginBottom: 8 }}>
            标记为: <strong style={{ color: 'rgba(255,255,255,0.7)' }}>{FEEDBACK_MAP[feedbackType] ?? feedbackType}</strong> -- 添加备注 (可选):
          </div>
          <textarea
            value={feedbackComment}
            onChange={(e) => setFeedbackComment(e.target.value)}
            placeholder="请描述判断依据 (可选)..."
            rows={2}
            style={{
              width: '100%', background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8,
              color: 'rgba(255,255,255,0.7)', fontSize: 12, padding: '8px 10px',
              resize: 'vertical', outline: 'none',
            }}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8, justifyContent: 'flex-end' }}>
            <button
              style={{
                ...S.feedbackBtn,
                opacity: feedbackSubmitting ? 0.5 : 1,
              }}
              disabled={feedbackSubmitting}
              onClick={submitFeedback}
            >
              {feedbackSubmitting ? '提交中...' : '提交反馈'}
            </button>
            <button
              style={S.feedbackBtn}
              onClick={() => { setFeedbackType(null); setFeedbackComment('') }}
            >
              取消
            </button>
          </div>
        </div>
      ) : (
        <div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', marginBottom: 10 }}>
            这封邮件实际是什么?
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(FEEDBACK_MAP).map(([key, label]) => (
              <button
                key={key}
                style={{
                  ...S.feedbackBtn,
                  borderColor: key === 'legitimate' ? 'rgba(22,163,74,0.3)' : 'rgba(255,255,255,0.1)',
                  color: key === 'legitimate' ? '#16a34a' : 'rgba(255,255,255,0.6)',
                }}
                onClick={() => setFeedbackType(key)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
