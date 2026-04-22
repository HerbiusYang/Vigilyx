import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
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

const ENGINE_SHORT_KEYS: Record<string, string> = {
  sender_reputation: 'emailSecurity.engineShortReputation',
  content_analysis: 'emailSecurity.engineShortContent',
  behavior_baseline: 'emailSecurity.engineShortBehavior',
  url_analysis: 'emailSecurity.engineShortUrl',
  protocol_compliance: 'emailSecurity.engineShortCompliance',
  semantic_intent: 'emailSecurity.engineShortSemantic',
  identity_anomaly: 'emailSecurity.engineShortIdentity',
  transaction_correlation: 'emailSecurity.engineShortTransaction',
}

const ENGINE_LETTER: Record<string, string> = {
  sender_reputation: 'A', content_analysis: 'B', behavior_baseline: 'C',
  url_analysis: 'D', protocol_compliance: 'E', semantic_intent: 'F',
  identity_anomaly: 'G', transaction_correlation: 'H',
}

const ENGINE_CN_KEYS: Record<string, string> = {
  sender_reputation: 'emailSecurity.engineReputation',
  content_analysis: 'emailSecurity.engineContent',
  behavior_baseline: 'emailSecurity.engineBehavior',
  url_analysis: 'emailSecurity.engineUrl',
  protocol_compliance: 'emailSecurity.engineCompliance',
  semantic_intent: 'emailSecurity.engineSemantic',
  identity_anomaly: 'emailSecurity.engineIdentity',
  transaction_correlation: 'emailSecurity.engineTransaction',
}

const THREAT_CN_KEYS: Record<string, string> = {
  safe: 'emailSecurity.threatSafe',
  low: 'emailSecurity.threatLow',
  medium: 'emailSecurity.threatMedium',
  high: 'emailSecurity.threatHigh',
  critical: 'emailSecurity.threatCritical',
}

const MODULE_CN_KEYS: Record<string, string> = {
  content_scan: 'emailSecurity.moduleContentScan',
  html_scan: 'emailSecurity.moduleHtmlScan',
  html_pixel_art: 'emailSecurity.modulePixelArt',
  attach_scan: 'emailSecurity.moduleAttachScan',
  attach_content: 'emailSecurity.moduleAttachContent',
  attach_hash: 'emailSecurity.moduleAttachHash',
  mime_scan: 'emailSecurity.moduleMimeScan',
  header_scan: 'emailSecurity.moduleHeaderScan',
  link_scan: 'emailSecurity.moduleLinkScan',
  link_reputation: 'emailSecurity.moduleLinkReputation',
  link_content: 'emailSecurity.moduleLinkContent',
  anomaly_detect: 'emailSecurity.moduleAnomalyDetect',
  semantic_scan: 'emailSecurity.moduleSemanticScan',
  domain_verify: 'emailSecurity.moduleDomainVerify',
  identity_anomaly: 'emailSecurity.moduleIdentityAnomaly',
  transaction_correlation: 'emailSecurity.moduleTransactionCorrelation',
  av_eml_scan: 'emailSecurity.moduleAvEmlScan',
  av_attach_scan: 'emailSecurity.moduleAvAttachScan',
  yara_scan: 'emailSecurity.moduleYaraScan',
  verdict: 'emailSecurity.moduleVerdict',
}

const PILLAR_CN_KEYS: Record<string, string> = {
  content: 'emailSecurity.pillarContent',
  attachment: 'emailSecurity.pillarAttachment',
  package: 'emailSecurity.pillarPackage',
  link: 'emailSecurity.pillarLink',
  semantic: 'emailSecurity.pillarSemantic',
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

type SemanticAiStatus = 'ok' | 'disabled' | 'cooldown' | 'timeout' | 'error'

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

function readString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null
}

function readNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function getSemanticAiState(mr: ModuleResult): {
  status: SemanticAiStatus
  labelKey: string
  color: string
  background: string
  border: string
  messageKey: string | null
  messageParams: Record<string, unknown>
  retryAfterSecs: number | null
  timeoutSecs: number | null
} | null {
  if (mr.module_id !== 'semantic_scan') return null

  const details = asRecord(mr.details) ?? {}
  const rawStatus = readString(details.nlp_status)
  const retryAfterSecs = readNumber(details.nlp_retry_after_secs)
  const timeoutSecs = readNumber(details.nlp_timeout_secs)
  let status: SemanticAiStatus | null = null

  if (rawStatus === 'ok' || rawStatus === 'disabled' || rawStatus === 'cooldown' || rawStatus === 'timeout' || rawStatus === 'error') {
    status = rawStatus
  } else if (details.nlp_enabled === true) {
    status = 'ok'
  } else if (details.nlp_configured === false) {
    status = 'disabled'
  } else if (details.nlp_skipped_temporarily === true) {
    status = 'cooldown'
  } else if (mr.evidence.some(ev => /timeout/i.test(ev.description))) {
    status = 'timeout'
  } else if (/not configured|not enabled/i.test(mr.summary)) {
    status = 'disabled'
  }

  if (!status) return null

  const messageInfo = ((): { key: string; params: Record<string, unknown> } => {
    switch (status) {
      case 'ok':
        return { key: 'emailSecurity.aiMessageOk', params: {} }
      case 'disabled':
        return { key: 'emailSecurity.aiMessageDisabled', params: {} }
      case 'cooldown':
        return retryAfterSecs != null
          ? { key: 'emailSecurity.aiMessageCooldownWithRetry', params: { seconds: retryAfterSecs } }
          : { key: 'emailSecurity.aiMessageCooldown', params: {} }
      case 'timeout':
        return timeoutSecs != null
          ? { key: 'emailSecurity.aiMessageTimeoutWithSecs', params: { seconds: timeoutSecs } }
          : { key: 'emailSecurity.aiMessageTimeout', params: {} }
      case 'error':
        return { key: 'emailSecurity.aiMessageError', params: {} }
    }
  })()

  const messageKey = messageInfo.key
  const messageParams = messageInfo.params

  switch (status) {
    case 'ok':
      return {
        status,
        labelKey: 'emailSecurity.aiLabelEnabled',
        color: '#16a34a',
        background: 'rgba(22,163,74,0.12)',
        border: 'rgba(22,163,74,0.28)',
        messageKey,
        messageParams,
        retryAfterSecs,
        timeoutSecs,
      }
    case 'disabled':
      return {
        status,
        labelKey: 'emailSecurity.aiLabelNotConfigured',
        color: '#9ca3af',
        background: 'rgba(156,163,175,0.12)',
        border: 'rgba(156,163,175,0.24)',
        messageKey,
        messageParams,
        retryAfterSecs,
        timeoutSecs,
      }
    case 'cooldown':
      return {
        status,
        labelKey: 'emailSecurity.aiLabelCooldown',
        color: '#f59e0b',
        background: 'rgba(245,158,11,0.12)',
        border: 'rgba(245,158,11,0.28)',
        messageKey,
        messageParams,
        retryAfterSecs,
        timeoutSecs,
      }
    case 'timeout':
      return {
        status,
        labelKey: 'emailSecurity.aiLabelTimeout',
        color: '#ea580c',
        background: 'rgba(234,88,12,0.12)',
        border: 'rgba(234,88,12,0.28)',
        messageKey,
        messageParams,
        retryAfterSecs,
        timeoutSecs,
      }
    case 'error':
      return {
        status,
        labelKey: 'emailSecurity.aiLabelError',
        color: '#dc2626',
        background: 'rgba(220,38,38,0.12)',
        border: 'rgba(220,38,38,0.28)',
        messageKey,
        messageParams,
        retryAfterSecs,
        timeoutSecs,
      }
  }
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
  const { t } = useTranslation()
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
        {t('emailSecurity.noAnalysisYet')}
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
        <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginRight: 10, flexShrink: 0 }}>{t('emailSecurity.detectionFlow')}</span>

        {/* Input */}
        <div title={t('emailSecurity.emailInput')} style={{
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
                title={`${ENGINE_CN_KEYS[eid] ? t(ENGINE_CN_KEYS[eid]) : eid} (${ENGINE_SHORT_KEYS[eid] ? t(ENGINE_SHORT_KEYS[eid]) : eid})`}
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
        <div title={t('emailSecurity.dsFusion')} style={{
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
            {THREAT_CN_KEYS[verdict.threat_level] ? t(THREAT_CN_KEYS[verdict.threat_level]) : verdict.threat_level}
          </span>
        </div>
      </div>

      {/* -- Section 2: detection-module results -- */}
      <div style={S.card}>
        <div style={S.cardTitle}>{t('emailSecurity.detectionModules')}</div>
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
  const { t } = useTranslation()
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
              {PILLAR_CN_KEYS[pillar] ? t(PILLAR_CN_KEYS[pillar]) : pillar}
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
        {t('emailSecurity.overallRisk')}
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
  const { t } = useTranslation()
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
              {ENGINE_CN_KEYS[engineId] ? t(ENGINE_CN_KEYS[engineId]) : engineId}
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
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>{t('emailSecurity.bpaDistribution')}</div>
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
        {t('emailSecurity.subModulesCount', { count: modules.length })}
      </div>
      {modules.map(mr => {
        const isSafe = mr.threat_level === 'safe'
        const isOpen = expandedModules?.has(mr.module_id) ?? !isSafe
        const semanticAiState = getSemanticAiState(mr)
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
                  {MODULE_CN_KEYS[mr.module_id] ? t(MODULE_CN_KEYS[mr.module_id]) : mr.module_name}
                </span>
                {semanticAiState && (
                  <span style={{
                    fontSize: 10,
                    color: semanticAiState.color,
                    background: semanticAiState.background,
                    border: `1px solid ${semanticAiState.border}`,
                    padding: '1px 6px',
                    borderRadius: 999,
                    flexShrink: 0,
                  }}>
                    {t(semanticAiState.labelKey)}
                  </span>
                )}
              </div>
              <div style={S.moduleRowRight}>
                <span style={{ fontSize: 10, color: threatColor(mr.threat_level), fontWeight: 500 }}>
                  {THREAT_CN_KEYS[mr.threat_level] ? t(THREAT_CN_KEYS[mr.threat_level]) : mr.threat_level}
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
  const { t } = useTranslation()

  if (moduleResults.length === 0) {
    return <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: 13, padding: 12 }}>{t('emailSecurity.noModuleResults')}</div>
  }

  return (
    <div>
      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8 }}>
        {t('emailSecurity.detectionModulesCount', { count: moduleResults.length })}
      </div>
      {moduleResults.map(mr => {
        const isSafe = mr.threat_level === 'safe'
        const isOpen = expandedModules?.has(mr.module_id) ?? !isSafe
        const semanticAiState = getSemanticAiState(mr)
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
                  {MODULE_CN_KEYS[mr.module_id] ? t(MODULE_CN_KEYS[mr.module_id]) : mr.module_name}
                </span>
                {semanticAiState && (
                  <span style={{
                    fontSize: 10,
                    color: semanticAiState.color,
                    background: semanticAiState.background,
                    border: `1px solid ${semanticAiState.border}`,
                    padding: '1px 6px',
                    borderRadius: 999,
                    flexShrink: 0,
                  }}>
                    {t(semanticAiState.labelKey)}
                  </span>
                )}
                <span style={{
                  fontSize: 10, color: 'rgba(255,255,255,0.3)',
                  background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4,
                  flexShrink: 0,
                }}>
                  {PILLAR_CN_KEYS[mr.pillar] ? t(PILLAR_CN_KEYS[mr.pillar]) : mr.pillar}
                </span>
              </div>
              <div style={S.moduleRowRight}>
                <span style={{
                  fontSize: 11, fontWeight: 600, color: threatColor(mr.threat_level),
                  padding: '1px 6px', borderRadius: 4,
                  background: !isSafe ? `${threatColor(mr.threat_level)}15` : 'transparent',
                }}>
                  {THREAT_CN_KEYS[mr.threat_level] ? t(THREAT_CN_KEYS[mr.threat_level]) : mr.threat_level}
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
  const { t } = useTranslation()
  const semanticAiState = getSemanticAiState(mr)

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

      {semanticAiState && (
        <div style={{
          ...S.evidenceItem,
          marginBottom: mr.evidence.length > 0 ? 6 : 0,
          background: semanticAiState.background,
          border: `1px solid ${semanticAiState.border}`,
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}>
            <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.55)' }}>{t('emailSecurity.aiNlpStatus')}</span>
            <span style={{
              fontSize: 10,
              color: semanticAiState.color,
              background: 'rgba(255,255,255,0.02)',
              border: `1px solid ${semanticAiState.border}`,
              padding: '1px 6px',
              borderRadius: 999,
            }}>
              {t(semanticAiState.labelKey)}
            </span>
            {semanticAiState.retryAfterSecs != null && (
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: MONO }}>
                retry~{semanticAiState.retryAfterSecs}s
              </span>
            )}
            {semanticAiState.status === 'timeout' && semanticAiState.timeoutSecs != null && (
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: MONO }}>
                timeout={semanticAiState.timeoutSecs}s
              </span>
            )}
          </div>
          {semanticAiState.messageKey && (
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.65)', marginTop: 6, lineHeight: 1.5 }}>
              {t(semanticAiState.messageKey, semanticAiState.messageParams)}
            </div>
          )}
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
  const { t } = useTranslation()
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
    if (k < 0.1) return t('emailSecurity.conflictLow')
    if (k <= 0.3) return t('emailSecurity.conflictMedium')
    return t('emailSecurity.conflictHigh')
  }

  return (
    <div style={S.card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <span style={S.cardTitle}>{t('emailSecurity.dsFusion')}</span>
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
            Bel ({t('emailSecurity.bpaMalicious')}) <span style={{ fontFamily: MONO }}>{(bpa.b * 100).toFixed(1)}%</span>
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#16a34a', flexShrink: 0 }} />
            Dis ({t('emailSecurity.bpaNormal')}) <span style={{ fontFamily: MONO }}>{(bpa.d * 100).toFixed(1)}%</span>
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#6b7280', flexShrink: 0 }} />
            Unc ({t('emailSecurity.bpaUncertain')}) <span style={{ fontFamily: MONO }}>{(bpa.u * 100).toFixed(1)}%</span>
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
          {t('emailSecurity.conflictK')} <span style={{ fontFamily: MONO, fontWeight: 600, color: kColor(kConflict), fontSize: 13 }}>{kConflict.toFixed(3)}</span>
          <span style={{ fontSize: 10, marginLeft: 4, color: kColor(kConflict) }}>{kLabel(kConflict)}</span>
        </span>
        <span style={{ color: 'rgba(255,255,255,0.1)' }}>|</span>
        <span>
          {t('emailSecurity.riskR')} <span style={{ fontFamily: MONO, fontWeight: 600, color: riskSingle >= eta ? '#f87171' : '#4ade80', fontSize: 13 }}>{riskSingle.toFixed(3)}</span>
        </span>
        <span style={{ color: 'rgba(255,255,255,0.1)' }}>|</span>
        <span>
          {t('emailSecurity.thresholdEta')} <span style={{ fontFamily: MONO, fontWeight: 600, color: 'rgba(255,255,255,0.55)', fontSize: 13 }}>{eta.toFixed(3)}</span>
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
            <strong style={{ color: '#dc2626' }}>{t('emailSecurity.circuitBreakerActivated')}</strong>
            : {t('emailSecurity.circuitBreakerModule')} <strong>{MODULE_CN_KEYS[fusion.circuit_breaker.trigger_module_id] ? t(MODULE_CN_KEYS[fusion.circuit_breaker.trigger_module_id]) : fusion.circuit_breaker.trigger_module_id}</strong>
            {' '}{t('emailSecurity.circuitBreakerBelief')} <span style={{ fontFamily: MONO }}>{fusion.circuit_breaker.trigger_belief.toFixed(2)}</span>
            {' '}{t('emailSecurity.circuitBreakerSuppressed')} (<span style={{ fontFamily: MONO }}>{fusion.circuit_breaker.original_risk.toFixed(4)}</span>)
            {t('emailSecurity.circuitBreakerRaisedTo')} <span style={{ fontFamily: MONO, color: '#dc2626' }}>{fusion.circuit_breaker.floor_value.toFixed(2)}</span>
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
            <strong style={{ color: '#ca8a04' }}>{t('emailSecurity.convergenceBreakerActivated')}</strong>
            : {t('emailSecurity.convergenceBreakerDesc', { count: fusion.convergence_breaker.modules_flagged })}
            (<span style={{ fontFamily: MONO }}>{fusion.convergence_breaker.original_risk.toFixed(4)}</span>)
            {t('emailSecurity.convergenceBreakerRaisedTo')} <span style={{ fontFamily: MONO, color: '#ca8a04' }}>{fusion.convergence_breaker.floor_value.toFixed(2)}</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
              {fusion.convergence_breaker.flagged_modules.map(mid => (
                <span key={mid} style={{
                  fontSize: 10, padding: '1px 6px', borderRadius: 4,
                  background: 'rgba(234,179,8,0.12)', color: '#ca8a04',
                }}>
                  {MODULE_CN_KEYS[mid] ? t(MODULE_CN_KEYS[mid]) : mid}
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
            {t('emailSecurity.engineBpaComparison')}
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
  const { t } = useTranslation()

  const FEEDBACK_MAP_KEYS: Record<string, string> = {
    legitimate: 'emailSecurity.feedbackLegitimate',
    phishing: 'emailSecurity.feedbackPhishing',
    spoofing: 'emailSecurity.feedbackSpoofing',
    social_engineering: 'emailSecurity.feedbackSocialEngineering',
    other_threat: 'emailSecurity.feedbackOtherThreat',
  }

  return (
    <div style={{ ...S.card, paddingTop: 14, paddingBottom: 14 }}>
      {feedbackDone ? (
        <div style={{ textAlign: 'center', color: '#16a34a', fontSize: 13 }}>
          {t('emailSecurity.feedbackSubmitted')}
        </div>
      ) : feedbackType ? (
        <div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', marginBottom: 8 }}>
            {t('emailSecurity.feedbackMarkedAs')}: <strong style={{ color: 'rgba(255,255,255,0.7)' }}>{FEEDBACK_MAP_KEYS[feedbackType] ? t(FEEDBACK_MAP_KEYS[feedbackType]) : feedbackType}</strong> -- {t('emailSecurity.feedbackAddNote')}:
          </div>
          <textarea
            value={feedbackComment}
            onChange={(e) => setFeedbackComment(e.target.value)}
            placeholder={t('emailSecurity.feedbackPlaceholder')}
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
              {feedbackSubmitting ? t('emailSecurity.feedbackSubmitting') : t('emailSecurity.feedbackSubmit')}
            </button>
            <button
              style={S.feedbackBtn}
              onClick={() => { setFeedbackType(null); setFeedbackComment('') }}
            >
              {t('emailSecurity.feedbackCancel')}
            </button>
          </div>
        </div>
      ) : (
        <div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', marginBottom: 10 }}>
            {t('emailSecurity.feedbackQuestion')}
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(FEEDBACK_MAP_KEYS).map(([key, labelKey]) => (
              <button
                key={key}
                style={{
                  ...S.feedbackBtn,
                  borderColor: key === 'legitimate' ? 'rgba(22,163,74,0.3)' : 'rgba(255,255,255,0.1)',
                  color: key === 'legitimate' ? '#16a34a' : 'rgba(255,255,255,0.6)',
                }}
                onClick={() => setFeedbackType(key)}
              >
                {t(labelKey)}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
