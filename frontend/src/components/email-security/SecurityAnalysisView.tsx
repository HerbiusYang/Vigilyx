import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type {
  EpistemicState,
  ModuleResult,
  SecurityVerdict,
  ShadowFusionResult,
} from '../../types'
import { formatDurationMs } from '../../utils/format'
import { MODULE_NAME_KEYS } from './moduleI18n'
import { categoryLabel } from './categoryLabels'

// ════════════════════════════════════════════════════════════════
// Props
// ════════════════════════════════════════════════════════════════

interface SecurityAnalysisViewProps {
  verdict: SecurityVerdict | null
  moduleResults: ModuleResult[]
  expandedModules: Set<string> | null
  toggleModuleExpand: (id: string) => void
  onOpenFeedback?: () => void
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

const EVIDENCE_CLUSTER_NAME_KEYS: Record<string, string> = {
  inherited_gateway_prior: 'emailSecurity.clusterInheritedGatewayPrior',
  delivery_integrity: 'emailSecurity.clusterDeliveryIntegrity',
  sender_identity_authenticity: 'emailSecurity.clusterSenderIdentityAuthenticity',
  link_and_html_deception: 'emailSecurity.clusterLinkAndHtmlDeception',
  payload_malware: 'emailSecurity.clusterPayloadMalware',
  external_reputation_ioc: 'emailSecurity.clusterExternalReputationIoc',
  social_engineering_intent: 'emailSecurity.clusterSocialEngineeringIntent',
  business_sensitivity: 'emailSecurity.clusterBusinessSensitivity',
}

const THREAT_CN_KEYS: Record<string, string> = {
  safe: 'emailSecurity.threatSafe',
  low: 'emailSecurity.threatLow',
  medium: 'emailSecurity.threatMedium',
  high: 'emailSecurity.threatHigh',
  critical: 'emailSecurity.threatCritical',
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

function engineScore(bpa: { b: number; d: number; u: number } | undefined): number | null {
  if (!bpa) return null
  const denom = bpa.b + bpa.d + bpa.u
  if (denom === 0) return null
  return Math.round((bpa.b / denom) * 100)
}

function scoreIndicatorColor(score: number | null): string {
  if (score === null) return '#6b7280'
  if (score === 0) return '#16a34a'
  if (score < 30) return '#ca8a04'
  return '#dc2626'
}

function scoreIndicatorLabel(score: number | null): string {
  if (score === null) return '–'
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

function readBoolean(value: unknown): boolean {
  return value === true
}

export type ModuleExecutionState = 'timeout' | 'failed' | 'dependency_unavailable'

export function getModuleExecutionState(mr: ModuleResult): ModuleExecutionState | null {
  const details = asRecord(mr.details)
  const status = readString(details?.execution_status)
  if (status === 'timeout' || mr.categories.includes('inspection_module_timeout')) return 'timeout'
  if (status === 'failed' || mr.categories.includes('inspection_module_failed')) return 'failed'
  if (
    status === 'dependency_unavailable' ||
    mr.categories.includes('inspection_dependency_unavailable')
  ) return 'dependency_unavailable'
  return null
}

export function isModuleUnavailable(mr: ModuleResult): boolean {
  return getModuleExecutionState(mr) !== null
}

function moduleExecutionColor(state: ModuleExecutionState | null, threatLevel: string): string {
  if (state === 'timeout') return '#f59e0b'
  if (state === 'dependency_unavailable') return '#f59e0b'
  if (state === 'failed') return '#ef4444'
  return threatColor(threatLevel)
}

function moduleExecutionLabelKey(state: ModuleExecutionState): string {
  if (state === 'timeout') return 'emailSecurity.moduleStatusTimeout'
  if (state === 'dependency_unavailable') return 'emailSecurity.moduleStatusDependencyUnavailable'
  return 'emailSecurity.moduleStatusFailed'
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

interface NlpVisualData {
  modelType: string | null
  topLabel: string | null
  maliciousProbability: number | null
  probabilities: Array<[string, number]>
}

const NLP_LABEL_COLORS: Record<string, string> = {
  legitimate: '#16a34a',
  spam: '#ca8a04',
  phishing: '#dc2626',
  scam: '#dc2626',
  bec: '#dc2626',
  spoofing: '#dc2626',
  social_engineering: '#ea580c',
  other_threat: '#ea580c',
}

function nlpLabelColor(label: string): string {
  return NLP_LABEL_COLORS[label] ?? '#6b7280'
}

function nlpGaugeColor(probability: number): string {
  if (probability >= 0.65) return '#dc2626'
  if (probability >= 0.4) return '#ea580c'
  return '#16a34a'
}

/** Extract NLP label probabilities from semantic_scan details.nlp_details (AI /analyze/content response). */
function getNlpVisualData(mr: ModuleResult): NlpVisualData | null {
  if (mr.module_id !== 'semantic_scan') return null
  const nlpDetails = asRecord(asRecord(mr.details)?.nlp_details)
  if (!nlpDetails) return null
  const rawProbabilities = asRecord(nlpDetails.probabilities)
  if (!rawProbabilities) return null
  const probabilities = Object.entries(rawProbabilities)
    .filter((entry): entry is [string, number] => typeof entry[1] === 'number' && Number.isFinite(entry[1]))
    .sort((a, b) => b[1] - a[1])
  if (probabilities.length === 0) return null
  return {
    modelType: readString(nlpDetails.model_type),
    topLabel: readString(nlpDetails.top_label),
    maliciousProbability: readNumber(nlpDetails.malicious_probability),
    probabilities,
  }
}

interface LlmAnalysisData {
  provider: string | null
  model: string | null
  verdict: string | null
  confidence: number | null
  reasoning: string | null
  injectionSuspected: boolean
}

/** Extract the advisory LLM second opinion from semantic_scan details.nlp_details.llm_analysis. */
function getLlmAnalysis(mr: ModuleResult): LlmAnalysisData | null {
  if (mr.module_id !== 'semantic_scan') return null
  const llm = asRecord(asRecord(asRecord(mr.details)?.nlp_details)?.llm_analysis)
  if (!llm) return null
  return {
    provider: readString(llm.provider),
    model: readString(llm.model),
    verdict: readString(llm.verdict),
    confidence: readNumber(llm.confidence),
    reasoning: readString(llm.reasoning),
    injectionSuspected: readBoolean(llm.injection_suspected),
  }
}

function llmVerdictColor(verdict: string | null): string {
  switch (verdict) {
    case 'safe': return '#16a34a'
    case 'low': return '#65a30d'
    case 'medium': return '#ea580c'
    case 'high':
    case 'critical': return '#dc2626'
    default: return '#6b7280'
  }
}

interface SemanticClaimObservation {
  sourceSpanId: string
  sourcePart: string
  actorRole: string
  targetRole: string
  speechAct: string
  polarity: string
  quoteStatus: string
  actions: string[]
  objects: string[]
  linkCount: number
  counterContextCount: number
}

interface SemanticScenarioObservation {
  scenarioId: string
  resolution: string
  resolutionReason: string | null
  coverage: string
  claimCount: number
  linkCount: number
  counterContextCount: number
}

interface SemanticLinkObservation {
  linkId: string
  extractionSource: string
  transportStatus: string
  contentStatus: string
  ownershipStatus: string
}

interface SemanticObservationData {
  schemaVersion: number | null
  coverage: string
  coverageReason: string | null
  claims: SemanticClaimObservation[]
  scenarios: SemanticScenarioObservation[]
  links: SemanticLinkObservation[]
}

function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string' && item.length > 0)
}

function readRecordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return []
  return value.map(asRecord).filter((item): item is Record<string, unknown> => item !== null)
}

/** Read observation-only semantic facts without treating them as a verdict. */
function getSemanticObservationData(mr: ModuleResult): SemanticObservationData | null {
  if (mr.module_id !== 'semantic_scan') return null
  const details = asRecord(mr.details)
  const context = asRecord(details?.semantic_context)
  if (!context) return null

  const claims = readRecordArray(context.claims).map(claim => ({
    sourceSpanId: readString(claim.source_span_id) ?? 'unknown',
    sourcePart: readString(claim.source_part) ?? 'unknown',
    actorRole: readString(claim.actor_role) ?? 'unknown',
    targetRole: readString(claim.target_role) ?? 'unknown',
    speechAct: readString(claim.speech_act) ?? 'unknown',
    polarity: readString(claim.polarity) ?? 'unknown',
    quoteStatus: readString(claim.quote_or_forward_status) ?? 'unknown',
    actions: readStringArray(claim.actions),
    objects: readStringArray(claim.objects),
    linkCount: readStringArray(claim.link_ids).length,
    counterContextCount: readStringArray(claim.counter_context_ids).length,
  })).sort((left, right) => Number(right.sourcePart === 'header') - Number(left.sourcePart === 'header'))

  const scenarios = readRecordArray(details?.semantic_scenarios).map(scenario => ({
    scenarioId: readString(scenario.scenario_id) ?? 'unknown',
    resolution: readString(scenario.resolution) ?? 'candidate',
    resolutionReason: readString(scenario.resolution_reason),
    coverage: readString(scenario.coverage) ?? 'unknown',
    claimCount: readStringArray(scenario.claim_ids).length,
    linkCount: readStringArray(scenario.link_ids).length,
    counterContextCount: readStringArray(scenario.counter_context_ids).length,
  }))

  const links = readRecordArray(context.links).map(link => ({
    linkId: readString(link.link_id) ?? 'unknown',
    extractionSource: readString(link.extraction_source) ?? 'unknown',
    transportStatus: readString(link.transport_status) ?? 'unknown',
    contentStatus: readString(link.content_status) ?? 'unknown',
    ownershipStatus: readString(link.ownership_status) ?? 'unknown',
  }))

  return {
    schemaVersion: readNumber(context.schema_version),
    coverage: readString(context.coverage) ?? 'unknown',
    coverageReason: readString(context.coverage_reason),
    claims,
    scenarios,
    links,
  }
}

interface TextClassifierData {
  status: string
  modelId: string | null
  route: string | null
  probability: number | null
  threshold: number | null
  fired: boolean
  shadow: boolean
  textUnits: number | null
  activeFeatures: number | null
  belowTrainingLength: boolean
  diagnostic: string | null
}

/**
 * Read one compiled local text classifier outcome.
 * Feature names are email tokens, so top_features is intentionally not read.
 */
function readTextClassifierOutcome(value: unknown): TextClassifierData | null {
  const outcome = asRecord(value)
  const status = readString(outcome?.status)
  if (!outcome || !status) return null

  return {
    status,
    modelId: readString(outcome.model_id),
    route: readString(outcome.route),
    probability: readNumber(outcome.probability),
    threshold: readNumber(outcome.threshold),
    fired: readBoolean(outcome.fired),
    shadow: readBoolean(outcome.shadow),
    textUnits: readNumber(outcome.text_units),
    activeFeatures: readNumber(outcome.active_features),
    belowTrainingLength: readBoolean(outcome.below_training_length),
    diagnostic: readString(outcome.diagnostic),
  }
}

function getTextClassifierData(mr: ModuleResult): TextClassifierData | null {
  if (mr.module_id !== 'semantic_scan') return null
  return readTextClassifierOutcome(asRecord(mr.details)?.semantic_text_classifier)
}

interface IntentModelData {
  status: string
  /** `scored`: the model alone judges semantics and its hits enter the verdict. */
  scored: boolean
  modelVersion: string | null
  score: number | null
  threshold: number | null
  flagged: boolean
  members: { name: string; logit: number }[]
  roundTripMs: number | null
  inputTruncated: boolean
  reason: string | null
}

/** Intent ensemble outcome recorded by semantic_scan, in shadow or scored mode. */
function getIntentModelData(mr: ModuleResult): IntentModelData | null {
  if (mr.module_id !== 'semantic_scan') return null
  const outcome = asRecord(asRecord(mr.details)?.semantic_intent_model)
  const status = readString(outcome?.status)
  if (!outcome || !status) return null
  const members = Object.entries(asRecord(outcome.members) ?? {}).flatMap(([name, value]) => {
    const logit = readNumber(value)
    return logit == null ? [] : [{ name, logit }]
  })
  return {
    status,
    scored: readString(outcome.mode) === 'scored',
    modelVersion: readString(outcome.model_version),
    score: readNumber(outcome.score),
    threshold: readNumber(outcome.threshold),
    flagged: readBoolean(outcome.flagged),
    members,
    roundTripMs: readNumber(outcome.round_trip_ms),
    inputTruncated: readBoolean(outcome.input_truncated),
    reason: readString(outcome.reason),
  }
}

/** Compact score tag on the semantic_scan row; amber when a scored hit raised the module. */
const IntentModelTag = ({ mr }: { mr: ModuleResult }) => {
  const { t } = useTranslation()
  const intentModel = getIntentModelData(mr)
  if (!intentModel || intentModel.status !== 'ok' || intentModel.score == null) return null
  const hit = intentModel.scored && intentModel.flagged
  const color = hit ? '#f59e0b' : '#38bdf8'
  return (
    <span
      data-testid="semantic-intent-tag"
      title={t(intentModel.scored ? 'emailSecurity.intentModelBadgeScored' : 'emailSecurity.intentModelBadgeShadow')}
      style={{
        fontSize: 10,
        color,
        background: hit ? 'rgba(245,158,11,0.12)' : 'rgba(56,189,248,0.08)',
        border: `1px solid ${hit ? 'rgba(245,158,11,0.32)' : 'rgba(56,189,248,0.28)'}`,
        padding: '1px 6px',
        borderRadius: 999,
        flexShrink: 0,
        fontFamily: MONO,
      }}
    >
      {t('emailSecurity.intentModelTag', { score: intentModel.score.toFixed(2) })}
    </span>
  )
}

interface AttachmentSemanticSource {
  filename: string
  findingCount: number
  classifier: TextClassifierData | null
}

interface AttachmentSemanticData {
  sources: AttachmentSemanticSource[]
  skipped: { filename: string; reason: string }[]
}

/** Read attachment text analyzed by the semantic engine. */
function getAttachmentSemanticData(mr: ModuleResult): AttachmentSemanticData | null {
  if (mr.module_id !== 'semantic_scan') return null
  const attachments = asRecord(asRecord(mr.details)?.semantic_attachment_sources)
  if (!attachments) return null
  const sources = readRecordArray(attachments.sources).map(source => ({
    filename: readString(source.filename) ?? 'unknown',
    findingCount: readNumber(source.finding_count) ?? 0,
    classifier: readTextClassifierOutcome(source.text_classifier),
  }))
  const skipped = readRecordArray(attachments.skipped).map(entry => ({
    filename: readString(entry.filename) ?? 'unknown',
    reason: readString(entry.reason) ?? 'unknown',
  }))
  if (sources.length === 0 && skipped.length === 0) return null
  return { sources, skipped }
}

const SEMANTIC_DISPLAY_LIMIT = 8

function semanticValueKey(value: string): string {
  return `emailSecurity.semanticValue.${value}`
}

function semanticScenarioKey(value: string): string {
  return `emailSecurity.semanticScenario.${value}`
}

function semanticResolutionReasonKey(value: string): string {
  return `emailSecurity.semanticResolutionReason.${value}`
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
  onOpenFeedback,
}: SecurityAnalysisViewProps) {
  const { t } = useTranslation()
  const [selectedEngine, setSelectedEngine] = useState<string | null>(null)

  // Only legacy A-H summaries belong in this per-engine lookup. The default
  // clustered strategy exposes cluster diagnostics under different IDs.
  const engineBpaMap = useMemo(() => {
    const m = new Map<string, { b: number; d: number; u: number }>()
    if (verdict?.fusion_details?.engine_details) {
      for (const ed of verdict.fusion_details.engine_details) {
        if (ENGINE_LETTER[ed.engine_id] && ed.bpa) m.set(ed.engine_id, ed.bpa)
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

  const linkReputationUnavailable = moduleResults.find(
    mr => mr.module_id === 'link_reputation' && isModuleUnavailable(mr),
  )

  if (!verdict && moduleResults.length > 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div role="status" style={{
          ...S.card,
          padding: '12px 14px',
          color: 'rgba(255,255,255,0.62)',
        }}>
          {t('emailSecurity.verdictUnavailableModulesShown')}
        </div>
        <div style={S.card}>
          <div style={{ ...S.cardTitle, display: 'flex', justifyContent: 'space-between', gap: 12 }}>
            <span>{t('emailSecurity.detectionModules')}</span>
            <span style={{ color: 'rgba(255,255,255,0.42)', fontSize: 12, fontWeight: 500 }}>
              {t('emailSecurity.detectionModulesCount', { count: moduleResults.length })}
            </span>
          </div>
          <ModuleList
            moduleResults={moduleResults}
            expandedModules={expandedModules}
            toggleModuleExpand={toggleModuleExpand}
          />
        </div>
      </div>
    )
  }

  if (!verdict) {
    return (
      <div style={{ ...S.card, textAlign: 'center', padding: 40, color: 'rgba(255,255,255,0.3)' }}>
        {t('emailSecurity.noAnalysisYet')}
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {linkReputationUnavailable && (
        <div role="status" style={{
          ...S.card,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
          padding: '12px 14px',
          color: 'rgba(255,255,255,0.78)',
          background: 'rgba(245,158,11,0.08)',
          border: '1px solid rgba(245,158,11,0.3)',
        }}>
          <span aria-hidden="true" style={{ color: '#f59e0b', fontSize: 16, lineHeight: 1 }}>!</span>
          <div>
            <div style={{ color: '#fbbf24', fontSize: 12, fontWeight: 700, marginBottom: 3 }}>
              {t('emailSecurity.linkReputationUnavailableTitle')}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.58)', fontSize: 11, lineHeight: 1.5 }}>
              {t('emailSecurity.linkReputationUnavailableMessage', {
                status: t(moduleExecutionLabelKey(getModuleExecutionState(linkReputationUnavailable)!)),
              })}
            </div>
          </div>
        </div>
      )}

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
            {verdict.threat_level === 'safe' && (verdict.inspection_coverage === 'limited' || verdict.fusion_details?.primary_result?.epistemic_state === 'unknown') ? t('emailSecurity.threatUncertain') : THREAT_CN_KEYS[verdict.threat_level] ? t(THREAT_CN_KEYS[verdict.threat_level]) : verdict.threat_level}
          </span>
        </div>
      </div>

      {/* -- Section 2: detection-module results -- */}
      <div style={S.card}>
        <div style={{
          ...S.cardTitle,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          whiteSpace: 'nowrap',
        }}>
          <span>{t('emailSecurity.detectionModules')}</span>
          <span style={{
            fontSize: 12,
            fontWeight: 500,
            letterSpacing: 0,
            textTransform: 'none',
            color: 'rgba(255,255,255,0.42)',
          }}>
            {t('emailSecurity.detectionModulesCount', { count: moduleResults.length })}
          </span>
        </div>
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

      {onOpenFeedback && (
        <button type="button" style={S.feedbackBtn} onClick={onOpenFeedback}>
          {t('emailSecurity.feedbackReviewAction')}
        </button>
      )}
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
              score={score ?? '—'} {weight != null && `w=${weight.toFixed(2)}`}
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
      {bpa ? <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>{t('emailSecurity.bpaDistribution')}</div>
        <div style={S.bpaBar}>
          <div style={S.bpaSeg('#dc2626', bpa.b * 100)} />
          <div style={S.bpaSeg('#16a34a', bpa.d * 100)} />
          <div style={S.bpaSeg('#6b7280', bpa.u * 100)} />
        </div>
        <div style={{
          display: 'flex', gap: 12, marginTop: 4, fontSize: 10, fontFamily: MONO,
          color: 'rgba(255,255,255,0.4)',
        }}>
          <span>B={bpa.b.toFixed(2)}</span>
          <span>D={bpa.d.toFixed(2)}</span>
          <span>U={bpa.u.toFixed(2)}</span>
        </div>
      </div> : <div role="status" style={{ ...S.card, marginBottom: 12, color: 'rgba(255,255,255,0.5)', fontSize: 11 }}>
        {t('emailSecurity.engineBpaUnavailable')}
      </div>}

      {/* Sub-modules */}
      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 6 }}>
        {t('emailSecurity.subModulesCount', { count: modules.length })}
      </div>
      {modules.map(mr => {
        const executionState = getModuleExecutionState(mr)
        const displayColor = moduleExecutionColor(executionState, mr.threat_level)
        const isSafe = mr.threat_level === 'safe' && executionState === null
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
                  background: displayColor,
                }} />
                <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {MODULE_NAME_KEYS[mr.module_id] ? t(MODULE_NAME_KEYS[mr.module_id]) : mr.module_name}
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
                <IntentModelTag mr={mr} />
              </div>
              <div style={S.moduleRowRight}>
                <span style={{ fontSize: 10, color: displayColor, fontWeight: 500 }}>
                  {executionState
                    ? t(moduleExecutionLabelKey(executionState))
                    : (THREAT_CN_KEYS[mr.threat_level] ? t(THREAT_CN_KEYS[mr.threat_level]) : mr.threat_level)}
                </span>
                <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: MONO }}>
                  {formatDurationMs(mr.duration_ms)}
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
      {moduleResults.map(mr => {
        const executionState = getModuleExecutionState(mr)
        const displayColor = moduleExecutionColor(executionState, mr.threat_level)
        const isSafe = mr.threat_level === 'safe' && executionState === null
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
                  background: displayColor,
                  boxShadow: !isSafe ? `0 0 6px ${displayColor}60` : 'none',
                }} />
                <span style={{ fontSize: 13, fontWeight: 500, color: isSafe ? 'rgba(255,255,255,0.5)' : 'rgba(255,255,255,0.85)' }}>
                  {MODULE_NAME_KEYS[mr.module_id] ? t(MODULE_NAME_KEYS[mr.module_id]) : mr.module_name}
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
                <IntentModelTag mr={mr} />
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
                  fontSize: 11, fontWeight: 600, color: displayColor,
                  padding: '1px 6px', borderRadius: 4,
                  background: !isSafe ? `${displayColor}15` : 'transparent',
                }}>
                  {executionState
                    ? t(moduleExecutionLabelKey(executionState))
                    : (THREAT_CN_KEYS[mr.threat_level] ? t(THREAT_CN_KEYS[mr.threat_level]) : mr.threat_level)}
                </span>
                <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: MONO }}>
                  {formatDurationMs(mr.duration_ms)}
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
  const nlpVisualData = getNlpVisualData(mr)
  const llmAnalysis = getLlmAnalysis(mr)
  const semanticObservation = getSemanticObservationData(mr)
  const textClassifier = getTextClassifierData(mr)
  const intentModel = getIntentModelData(mr)
  const attachmentSemantics = getAttachmentSemanticData(mr)

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

      {semanticObservation && (
        <section
          aria-label={t('emailSecurity.semanticObservationTitle')}
          data-testid="semantic-observation"
          style={{
            ...S.evidenceItem,
            marginBottom: 6,
            border: '1px solid rgba(59,130,246,0.25)',
            background: 'rgba(59,130,246,0.06)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.75)' }}>
              {t('emailSecurity.semanticObservationTitle')}
            </span>
            <span style={{
              fontSize: 10,
              color: '#60a5fa',
              border: '1px solid rgba(96,165,250,0.4)',
              padding: '1px 6px',
              borderRadius: 999,
            }}>
              {t('emailSecurity.semanticObservationBadge')}
            </span>
            {semanticObservation.schemaVersion != null && (
              <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', fontFamily: MONO }}>
                schema-v{semanticObservation.schemaVersion}
              </span>
            )}
          </div>
          <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 5, lineHeight: 1.5 }}>
            {t('emailSecurity.semanticObservationAdvisory')}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 6, fontSize: 10 }}>
            <span>{t('emailSecurity.semanticCoverage')}: {t(semanticValueKey(semanticObservation.coverage), semanticObservation.coverage)}</span>
            <span>{t('emailSecurity.semanticClaims')}: {semanticObservation.claims.length}</span>
            <span>{t('emailSecurity.semanticScenarios')}: {semanticObservation.scenarios.length}</span>
            <span>{t('emailSecurity.semanticLinks')}: {semanticObservation.links.length}</span>
          </div>
          {semanticObservation.coverageReason && (
            <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 5, lineHeight: 1.5 }}>
              {t('emailSecurity.semanticCoverageReason')}: {semanticObservation.coverageReason}
            </div>
          )}

          {semanticObservation.claims.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)', marginBottom: 4 }}>
                {t('emailSecurity.semanticClaims')}
              </div>
              {semanticObservation.claims.slice(0, SEMANTIC_DISPLAY_LIMIT).map((claim, index) => (
                <div key={`${claim.sourceSpanId}-${index}`} style={{
                  fontSize: 10,
                  color: 'rgba(255,255,255,0.55)',
                  padding: '4px 6px',
                  marginBottom: 3,
                  background: 'rgba(0,0,0,0.12)',
                  borderRadius: 4,
                  lineHeight: 1.5,
                }}>
                  <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
                    <span>#{index + 1}</span>
                    <span>{t('emailSecurity.semanticSource')}: {t(semanticValueKey(claim.sourcePart), claim.sourcePart)}</span>
                    <span>{t('emailSecurity.semanticActor')}: {t(semanticValueKey(claim.actorRole), claim.actorRole)}</span>
                    <span>{t('emailSecurity.semanticTarget')}: {t(semanticValueKey(claim.targetRole), claim.targetRole)}</span>
                    <span>{t('emailSecurity.semanticSpeechAct')}: {t(semanticValueKey(claim.speechAct), claim.speechAct)}</span>
                    <span>{t('emailSecurity.semanticPolarity')}: {t(semanticValueKey(claim.polarity), claim.polarity)}</span>
                    <span>{t('emailSecurity.semanticQuoteState')}: {t(semanticValueKey(claim.quoteStatus), claim.quoteStatus)}</span>
                  </div>
                  {(claim.actions.length > 0 || claim.objects.length > 0) && (
                    <div style={{ color: 'rgba(255,255,255,0.38)', fontFamily: MONO }}>
                      {claim.actions.length > 0 && `${t('emailSecurity.semanticAction')}: ${claim.actions.join(', ')}`}
                      {claim.actions.length > 0 && claim.objects.length > 0 && ' · '}
                      {claim.objects.length > 0 && `${t('emailSecurity.semanticObject')}: ${claim.objects.join(', ')}`}
                    </div>
                  )}
                  {(claim.linkCount > 0 || claim.counterContextCount > 0) && (
                    <div style={{ color: 'rgba(255,255,255,0.32)' }}>
                      {t('emailSecurity.semanticLinkedEvidence')}: {claim.linkCount}
                      {' · '}{t('emailSecurity.semanticCounterContext')}: {claim.counterContextCount}
                    </div>
                  )}
                </div>
              ))}
              {semanticObservation.claims.length > SEMANTIC_DISPLAY_LIMIT && (
                <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)' }}>
                  {t('emailSecurity.semanticMoreItems', { count: semanticObservation.claims.length - SEMANTIC_DISPLAY_LIMIT })}
                </div>
              )}
            </div>
          )}

          {semanticObservation.scenarios.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)', marginBottom: 4 }}>
                {t('emailSecurity.semanticScenarios')}
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {semanticObservation.scenarios.slice(0, SEMANTIC_DISPLAY_LIMIT).map((scenario, index) => (
                  <span key={`${scenario.scenarioId}-${index}`} title={scenario.scenarioId} style={{
                    fontSize: 10,
                    color: 'rgba(255,255,255,0.6)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    padding: '2px 6px',
                    borderRadius: 999,
                  }}>
                    {t(semanticScenarioKey(scenario.scenarioId), scenario.scenarioId)} · {t(`emailSecurity.semanticResolution.${scenario.resolution}`, scenario.resolution)}
                    {' · '}{t(semanticValueKey(scenario.coverage), scenario.coverage)}
                    {' · '}{t('emailSecurity.semanticSupportingClaims')}: {scenario.claimCount}
                    {' · '}{t('emailSecurity.semanticLinkedEvidence')}: {scenario.linkCount}
                    {scenario.counterContextCount > 0 && (
                      <> · {t('emailSecurity.semanticCounterContext')}: {scenario.counterContextCount}</>
                    )}
                    {scenario.resolutionReason && (
                      <> · {t(semanticResolutionReasonKey(scenario.resolutionReason), scenario.resolutionReason)}</>
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}

          {semanticObservation.links.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)', marginBottom: 4 }}>
                {t('emailSecurity.semanticLinkVerification')}
              </div>
              {semanticObservation.links.slice(0, SEMANTIC_DISPLAY_LIMIT).map((link, index) => (
                <div key={`${link.linkId}-${index}`} style={{
                  display: 'flex', gap: 7, flexWrap: 'wrap', fontSize: 10,
                  color: 'rgba(255,255,255,0.45)', lineHeight: 1.5,
                }}>
                  <span style={{ fontFamily: MONO }}>link-{link.linkId.slice(0, 8)}</span>
                  <span>{t('emailSecurity.semanticExtraction')}: {t(semanticValueKey(link.extractionSource), link.extractionSource)}</span>
                  <span>{t('emailSecurity.semanticTransport')}: {t(semanticValueKey(link.transportStatus), link.transportStatus)}</span>
                  <span>{t('emailSecurity.semanticContent')}: {t(semanticValueKey(link.contentStatus), link.contentStatus)}</span>
                  <span>{t('emailSecurity.semanticOwnership')}: {t(semanticValueKey(link.ownershipStatus), link.ownershipStatus)}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {textClassifier && (
        <section
          aria-label={t('emailSecurity.textClassifierTitle')}
          data-testid="semantic-text-classifier"
          style={{
            ...S.evidenceItem,
            marginBottom: 6,
            border: '1px solid rgba(168,85,247,0.25)',
            background: 'rgba(168,85,247,0.06)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.75)' }}>
              {t('emailSecurity.textClassifierTitle')}
            </span>
            {textClassifier.status === 'scored' && (
              <span style={{
                fontSize: 10,
                color: '#c084fc',
                border: '1px solid rgba(192,132,252,0.4)',
                padding: '1px 6px',
                borderRadius: 999,
              }}>
                {t(textClassifier.shadow ? 'emailSecurity.textClassifierBadgeShadow' : 'emailSecurity.textClassifierBadgeReview')}
              </span>
            )}
            {textClassifier.modelId && (
              <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', fontFamily: MONO }}>
                {textClassifier.modelId}
              </span>
            )}
          </div>
          {textClassifier.status === 'scored' && (
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 5, lineHeight: 1.5 }}>
              {t(textClassifier.shadow ? 'emailSecurity.textClassifierShadowAdvisory' : 'emailSecurity.textClassifierReviewAdvisory')}
            </div>
          )}
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 6, fontSize: 10 }}>
            <span>{t('emailSecurity.textClassifierStatusLabel')}: {t(`emailSecurity.textClassifierStatus.${textClassifier.status}`, textClassifier.status)}</span>
            {textClassifier.status === 'scored' && (
              <span style={{ color: textClassifier.fired ? '#f59e0b' : undefined }}>
                {t('emailSecurity.textClassifierResult')}: {t(textClassifier.fired ? 'emailSecurity.textClassifierFired' : 'emailSecurity.textClassifierNotFired')}
              </span>
            )}
            {textClassifier.probability != null && (
              <span style={{ fontFamily: MONO }}>
                {t('emailSecurity.textClassifierProbability')}: {(textClassifier.probability * 100).toFixed(1)}%
                {textClassifier.threshold != null && ` / ${t('emailSecurity.textClassifierThreshold')} ${(textClassifier.threshold * 100).toFixed(1)}%`}
              </span>
            )}
            {textClassifier.route && (
              <span>{t('emailSecurity.textClassifierRouteLabel')}: {t(`emailSecurity.textClassifierRoute.${textClassifier.route}`, textClassifier.route)}</span>
            )}
            {textClassifier.textUnits != null && (
              <span>{t('emailSecurity.textClassifierTextUnits')}: {textClassifier.textUnits}</span>
            )}
            {textClassifier.status === 'scored' && textClassifier.activeFeatures != null && (
              <span>{t('emailSecurity.textClassifierActiveFeatures')}: {textClassifier.activeFeatures}</span>
            )}
          </div>
          {textClassifier.belowTrainingLength && (
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 5, lineHeight: 1.5 }}>
              {t('emailSecurity.textClassifierBelowTrainingLength')}
            </div>
          )}
          {textClassifier.diagnostic && (
            <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 5, lineHeight: 1.5 }}>
              {t('emailSecurity.textClassifierDiagnostic')}: {textClassifier.diagnostic}
            </div>
          )}
        </section>
      )}

      {intentModel && (
        <section
          aria-label={t('emailSecurity.intentModelTitle')}
          data-testid="semantic-intent-model"
          style={{
            ...S.evidenceItem,
            marginBottom: 6,
            border: '1px solid rgba(56,189,248,0.25)',
            background: 'rgba(56,189,248,0.06)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.75)' }}>
              {t('emailSecurity.intentModelTitle')}
            </span>
            <span style={{
              fontSize: 10,
              color: intentModel.scored ? '#f59e0b' : '#38bdf8',
              border: `1px solid ${intentModel.scored ? 'rgba(245,158,11,0.4)' : 'rgba(56,189,248,0.4)'}`,
              padding: '1px 6px',
              borderRadius: 999,
            }}>
              {t(intentModel.scored ? 'emailSecurity.intentModelBadgeScored' : 'emailSecurity.intentModelBadgeShadow')}
            </span>
            {intentModel.modelVersion && (
              <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', fontFamily: MONO }}>
                {intentModel.modelVersion}
              </span>
            )}
          </div>
          <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 5, lineHeight: 1.5 }}>
            {t(intentModel.scored ? 'emailSecurity.intentModelAdvisoryScored' : 'emailSecurity.intentModelAdvisory')}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 6, fontSize: 10 }}>
            <span>{t('emailSecurity.intentModelStatusLabel')}: {t(`emailSecurity.intentModelStatus.${intentModel.status}`, intentModel.status)}</span>
            {intentModel.status === 'ok' && (
              <span style={{ color: intentModel.flagged ? '#f59e0b' : undefined }}>
                {t('emailSecurity.intentModelResult')}: {t(intentModel.flagged ? 'emailSecurity.intentModelFlagged' : 'emailSecurity.intentModelNotFlagged')}
              </span>
            )}
            {intentModel.score != null && (
              <span style={{ fontFamily: MONO }}>
                {t('emailSecurity.intentModelScore')}: {intentModel.score.toFixed(2)}
                {intentModel.threshold != null && ` / ${t('emailSecurity.intentModelThreshold')} ${intentModel.threshold.toFixed(2)}`}
              </span>
            )}
            {intentModel.members.length > 0 && (
              <span style={{ fontFamily: MONO }}>
                {t('emailSecurity.intentModelMembers')}: {intentModel.members.map(member => `${member.name} ${member.logit.toFixed(2)}`).join(' · ')}
              </span>
            )}
            {intentModel.roundTripMs != null && (
              <span>{t('emailSecurity.intentModelLatency')}: {intentModel.roundTripMs} ms</span>
            )}
          </div>
          {intentModel.inputTruncated && (
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 5, lineHeight: 1.5 }}>
              {t('emailSecurity.intentModelTruncated')}
            </div>
          )}
          {intentModel.reason && (
            <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 5, lineHeight: 1.5 }}>
              {t('emailSecurity.intentModelReason')}: {intentModel.reason}
            </div>
          )}
        </section>
      )}

      {attachmentSemantics && (
        <section
          aria-label={t('emailSecurity.attachmentSemanticTitle')}
          data-testid="semantic-attachments"
          style={{
            ...S.evidenceItem,
            marginBottom: 6,
            border: '1px solid rgba(20,184,166,0.25)',
            background: 'rgba(20,184,166,0.06)',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,0.75)' }}>
            {t('emailSecurity.attachmentSemanticTitle')}
          </div>
          {attachmentSemantics.sources.map((source, index) => (
            <div key={`${source.filename}-${index}`} style={{
              display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 6, fontSize: 10,
              color: 'rgba(255,255,255,0.6)', lineHeight: 1.5,
            }}>
              <span style={{ fontFamily: MONO, color: 'rgba(255,255,255,0.75)' }} title={source.filename}>
                {source.filename}
              </span>
              <span style={{ color: source.findingCount > 0 ? '#f59e0b' : undefined }}>
                {t('emailSecurity.attachmentSemanticFindings')}: {source.findingCount}
              </span>
              {source.classifier && (
                <span>
                  {t('emailSecurity.textClassifierTitle')}: {t(`emailSecurity.textClassifierStatus.${source.classifier.status}`, source.classifier.status)}
                  {source.classifier.status === 'scored' && (
                    <>
                      {' · '}{t(source.classifier.fired ? 'emailSecurity.textClassifierFired' : 'emailSecurity.textClassifierNotFired')}
                      {source.classifier.probability != null && ` · ${(source.classifier.probability * 100).toFixed(1)}%`}
                    </>
                  )}
                </span>
              )}
            </div>
          ))}
          {attachmentSemantics.skipped.length > 0 && (
            <div style={{ marginTop: 6, fontSize: 10, color: 'rgba(255,255,255,0.4)', lineHeight: 1.5 }}>
              {t('emailSecurity.attachmentSemanticSkipped')}:{' '}
              {attachmentSemantics.skipped.map(entry => (
                `${entry.filename} (${t(`emailSecurity.attachmentSemanticSkipReason.${entry.reason}`, entry.reason)})`
              )).join(', ')}
            </div>
          )}
        </section>
      )}

      {/* NLP label probabilities */}
      {nlpVisualData && (
        <div className="sa-nlp-visual" style={{ marginBottom: mr.evidence.length > 0 ? 6 : 0 }}>
          <div className="sa-nlp-header">
            <span className="sa-nlp-title">{t('email.nlpProbabilities')}</span>
            {nlpVisualData.modelType && <span className="sa-nlp-model">{nlpVisualData.modelType}</span>}
          </div>
          {nlpVisualData.maliciousProbability != null && (
            <div className="sa-nlp-gauge">
              <div className="sa-nlp-gauge-label">
                <span>{t('email.nlpMaliciousProbability')}</span>
                <span className="sa-nlp-gauge-val" style={{ color: nlpGaugeColor(nlpVisualData.maliciousProbability) }}>
                  {(nlpVisualData.maliciousProbability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="sa-nlp-gauge-bar">
                <div
                  className="sa-nlp-gauge-fill"
                  style={{
                    width: `${Math.min(100, Math.max(0, nlpVisualData.maliciousProbability * 100))}%`,
                    background: nlpGaugeColor(nlpVisualData.maliciousProbability),
                  }}
                />
              </div>
            </div>
          )}
          <div className="sa-nlp-probs">
            {nlpVisualData.probabilities.map(([label, probability]) => (
              <div key={label} className="sa-nlp-prob-row">
                <span className="sa-nlp-prob-label">
                  {label}
                  {label === nlpVisualData.topLabel && (
                    <span className="sa-nlp-top-badge">{t('email.nlpTopLabel')}</span>
                  )}
                </span>
                <span className="sa-nlp-prob-bar-wrap">
                  <span
                    className="sa-nlp-prob-bar"
                    style={{
                      width: `${Math.min(100, Math.max(0, probability * 100))}%`,
                      background: nlpLabelColor(label),
                    }}
                  />
                </span>
                <span className="sa-nlp-prob-val">{(probability * 100).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* LLM second opinion (advisory, only when local NLP result was uncertain) */}
      {llmAnalysis && (
        <div style={{
          ...S.evidenceItem,
          marginBottom: mr.evidence.length > 0 ? 6 : 0,
          border: `1px solid ${llmVerdictColor(llmAnalysis.verdict)}44`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.55)' }}>
              {t('email.llmAnalysis', 'LLM 二次研判')}
            </span>
            {llmAnalysis.provider && (
              <span style={{
                fontSize: 10, color: 'rgba(255,255,255,0.45)', fontFamily: MONO,
                background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)',
                padding: '1px 6px', borderRadius: 999,
              }}>
                {llmAnalysis.provider}{llmAnalysis.model ? ` / ${llmAnalysis.model}` : ''}
              </span>
            )}
            {llmAnalysis.verdict && (
              <span style={{
                fontSize: 10, color: llmVerdictColor(llmAnalysis.verdict),
                background: 'rgba(255,255,255,0.02)',
                border: `1px solid ${llmVerdictColor(llmAnalysis.verdict)}`,
                padding: '1px 6px', borderRadius: 999,
              }}>
                {llmAnalysis.verdict}
              </span>
            )}
            {llmAnalysis.confidence != null && (
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: MONO }}>
                {t('email.llmConfidence', '置信度')} {(llmAnalysis.confidence * 100).toFixed(0)}%
              </span>
            )}
            {llmAnalysis.injectionSuspected && (
              <span style={{
                fontSize: 10, fontWeight: 600, color: '#dc2626',
                background: 'rgba(220,38,38,0.08)',
                border: '1px solid #dc2626',
                padding: '1px 6px', borderRadius: 999,
              }}>
                {t('email.llmInjectionSuspected', '疑似提示注入')}
              </span>
            )}
          </div>
          {llmAnalysis.reasoning && (
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.65)', marginTop: 6, lineHeight: 1.5 }}>
              {llmAnalysis.reasoning}
            </div>
          )}
          <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginTop: 6, lineHeight: 1.5 }}>
            {t('email.llmAdvisoryHint', 'LLM 研判可能受邮件内容影响，仅供参考')}
          </div>
        </div>
      )}

      {/* Detection categories */}
      {mr.categories.length > 0 && (
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 4,
          marginBottom: mr.evidence.length > 0 ? 6 : 0,
        }}>
          {mr.categories.map(category => (
            <span
              key={category}
              title={category}
              style={{
                fontSize: 10, color: 'rgba(255,255,255,0.6)', fontFamily: MONO,
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.1)',
                padding: '1px 6px', borderRadius: 999,
              }}
            >
              {categoryLabel(category)}
            </span>
          ))}
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

const EPISTEMIC_STATE_KEYS: Record<EpistemicState, string> = {
  unknown: 'emailSecurity.fusionStateUnknown',
  threat_supported: 'emailSecurity.fusionStateThreatSupported',
  normal_supported: 'emailSecurity.fusionStateNormalSupported',
  conflicted: 'emailSecurity.fusionStateConflicted',
}

function latestClusteredDsV2(
  shadowResults: ShadowFusionResult[] | undefined,
): ShadowFusionResult | null {
  if (!Array.isArray(shadowResults)) return null

  let latest: ShadowFusionResult | null = null
  for (const result of shadowResults) {
    if (result?.model === 'clustered_ds_v2') latest = result
  }
  return latest
}

function FusionPanel({ fusion }: { fusion: NonNullable<SecurityVerdict['fusion_details']> }) {
  const primary = fusion.primary_result
  return <FusionModelPanel
    shadow={primary ?? latestClusteredDsV2(fusion.shadow_results)}
    authoritative={primary?.model === 'clustered_ds_v2'}
  />
}

function FusionModelPanel({ shadow, authoritative = false }: { shadow: ShadowFusionResult | null; authoritative?: boolean }) {
  const { t } = useTranslation()

  if (!shadow) {
    return (
      <section
        aria-label={t(authoritative ? 'emailSecurity.fusionV2Authoritative' : 'emailSecurity.fusionV2Experimental')}
        data-testid="fusion-v2-empty"
        style={{
          ...S.card,
          marginBottom: 0,
          paddingTop: 16,
          paddingBottom: 16,
          borderStyle: 'dashed',
          background: 'rgba(139,92,246,0.025)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ ...S.cardTitle, marginBottom: 0 }}>{t(authoritative ? 'emailSecurity.fusionV2PrimaryTitle' : 'emailSecurity.fusionV2Latest')}</span>
          <span style={{
            fontSize: 10, color: '#a78bfa', fontWeight: 600,
            background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.22)',
            padding: '2px 8px', borderRadius: 999,
          }}>
            {t(authoritative ? 'emailSecurity.fusionV2Authoritative' : 'emailSecurity.fusionV2Experimental')}
          </span>
        </div>
        <p style={{ margin: '9px 0 0', fontSize: 12, color: 'rgba(255,255,255,0.38)' }}>
          {t('emailSecurity.fusionV2Unavailable')}
        </p>
      </section>
    )
  }

  const bpa = shadow.fused_bpa
  const eps = bpa.epsilon ?? 0
  const constraints = Array.isArray(shadow.active_constraints) ? shadow.active_constraints : []
  const epistemicKey = EPISTEMIC_STATE_KEYS[shadow.epistemic_state] ?? EPISTEMIC_STATE_KEYS.unknown
  const artifacts = Math.max(0, shadow.artifact_count ?? 0)
  const fallbackArtifacts = Math.max(0, shadow.fallback_artifact_count ?? 0)

  return (
    <section
      aria-label={t(authoritative ? 'emailSecurity.fusionV2Authoritative' : 'emailSecurity.fusionV2Experimental')}
      data-testid={authoritative ? "fusion-v2-primary" : "fusion-v2"}
      style={{
        ...S.card,
        marginBottom: 0,
        borderColor: 'rgba(139,92,246,0.22)',
        background: 'linear-gradient(135deg, rgba(139,92,246,0.055), rgba(255,255,255,0.018))',
      }}
    >
      <div style={{
        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
        gap: 14, marginBottom: 14, flexWrap: 'wrap',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ ...S.cardTitle, marginBottom: 0 }}>{t(authoritative ? 'emailSecurity.fusionV2PrimaryTitle' : 'emailSecurity.fusionV2Latest')}</span>
            <span style={{
              fontSize: 10, color: '#a78bfa', fontWeight: 600,
              background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.22)',
              padding: '2px 8px', borderRadius: 999,
            }}>
              {t(authoritative ? 'emailSecurity.fusionV2Authoritative' : 'emailSecurity.fusionV2Experimental')}
            </span>
          </div>
          <div style={{ marginTop: 6, fontSize: 11, color: 'rgba(255,255,255,0.35)' }}>
            {t(authoritative ? 'emailSecurity.fusionV2PrimaryDescription' : 'emailSecurity.fusionV2Disclaimer')}
          </div>
        </div>
        <span style={{
          fontFamily: MONO, fontSize: 10, color: 'rgba(255,255,255,0.32)',
          background: 'rgba(255,255,255,0.035)', padding: '3px 8px', borderRadius: 5,
        }}>
          {shadow.model} · v{shadow.model_version}
        </span>
      </div>

      <div
        role="img"
        aria-label={t('emailSecurity.fusionBpaAria', {
          belief: (bpa.b * 100).toFixed(1),
          disbelief: (bpa.d * 100).toFixed(1),
          uncertainty: (bpa.u * 100).toFixed(1),
        })}
        style={{ marginBottom: 15 }}
      >
        <div style={{ ...S.bpaBar, height: 10 }}>
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
          <span>Bel ({t('emailSecurity.bpaMalicious')}) <b style={{ fontFamily: MONO }}>{(bpa.b * 100).toFixed(1)}%</b></span>
          <span>Dis ({t('emailSecurity.bpaNormal')}) <b style={{ fontFamily: MONO }}>{(bpa.d * 100).toFixed(1)}%</b></span>
          <span>Unc ({t('emailSecurity.bpaUncertain')}) <b style={{ fontFamily: MONO }}>{(bpa.u * 100).toFixed(1)}%</b></span>
        </div>
      </div>

      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(132px, 1fr))',
        gap: 8, marginBottom: constraints.length > 0 || shadow.constraint_conflict ? 14 : 0,
      }}>
        <ShadowMetric
          label={t('emailSecurity.fusionRiskConstrained')}
          value={`${(shadow.risk_constrained * 100).toFixed(1)}%`}
          accent="#c4b5fd"
        />
        <ShadowMetric
          label={t('emailSecurity.fusionRiskBase')}
          value={`${(shadow.risk_base * 100).toFixed(1)}%`}
        />
        <ShadowMetric label={t('emailSecurity.fusionEpistemicState')} value={t(epistemicKey)} />
        <ShadowMetric label={t('emailSecurity.conflictK')} value={(shadow.k_conflict ?? 0).toFixed(3)} />
        <ShadowMetric
          label={t('emailSecurity.fusionArtifacts')}
          value={String(artifacts)}
          hint={fallbackArtifacts > 0
            ? t('emailSecurity.fusionFallbackArtifacts', { count: fallbackArtifacts })
            : undefined}
        />
        <ShadowMetric label={t('emailSecurity.fusionConstraints')} value={String(constraints.length)} />
      </div>

      {authoritative && <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', margin: '0 0 12px' }}>
        {t('emailSecurity.fusionSeverityThresholds')}
      </p>}
      {authoritative && constraints.some(c => c.id === 'operator_identity_review_minimum') && <div role="note" style={{ ...S.breakerAlert, color: '#fbbf24', marginBottom: 12 }}>
        {t('emailSecurity.identityReviewMinimumExplanation')}
      </div>}
      {authoritative && shadow.source_details.length > 0 && <div style={{ marginBottom: 12 }}>
        {shadow.source_details.map(source => <div key={source.engine_id} style={{ display: 'flex', gap: 10, fontSize: 11, marginBottom: 5 }}>
          <span>{EVIDENCE_CLUSTER_NAME_KEYS[source.engine_id] ? t(EVIDENCE_CLUSTER_NAME_KEYS[source.engine_id]) : source.engine_name}</span>
          <span style={{ fontFamily: MONO }}>Bel {(source.bpa.b * 100).toFixed(1)}%</span>
        </div>)}
      </div>}
      {constraints.length > 0 && (
        <div style={{ marginTop: 2 }}>
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.34)', marginBottom: 7 }}>
            {t('emailSecurity.fusionActiveConstraints')}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {constraints.map(constraint => (
              <span
                key={constraint.id}
                title={constraint.basis.join(', ')}
                style={{
                  fontSize: 10, fontFamily: MONO, color: '#c4b5fd',
                  background: 'rgba(139,92,246,0.09)', border: '1px solid rgba(139,92,246,0.18)',
                  padding: '3px 7px', borderRadius: 5,
                }}
              >
                {constraint.id} [{constraint.lower.toFixed(2)}, {constraint.upper.toFixed(2)}]
              </span>
            ))}
          </div>
        </div>
      )}

      {shadow.constraint_conflict && (
        <div role="alert" style={{
          ...S.breakerAlert,
          background: 'rgba(234,88,12,0.08)', border: '1px solid rgba(234,88,12,0.22)',
          color: 'rgba(255,255,255,0.6)',
        }}>
          <span aria-hidden="true">&#9888;</span>
          <span>
            <strong style={{ color: '#fb923c' }}>{t('emailSecurity.fusionConstraintConflict')}</strong>
            {' '}{shadow.constraint_conflict.constraint_ids.join(', ')}
            {' '}[{shadow.constraint_conflict.effective_lower.toFixed(2)}, {shadow.constraint_conflict.effective_upper.toFixed(2)}]
          </span>
        </div>
      )}
    </section>
  )
}

function ShadowMetric({ label, value, hint, accent }: {
  label: string
  value: string
  hint?: string
  accent?: string
}) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.055)',
      borderRadius: 8, padding: '9px 10px', minWidth: 0,
    }}>
      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.34)', marginBottom: 4 }}>{label}</div>
      <div style={{
        fontFamily: MONO, fontSize: 14, fontWeight: 650,
        color: accent ?? 'rgba(255,255,255,0.68)', overflowWrap: 'anywhere',
      }}>
        {value}
      </div>
      {hint && <div style={{ marginTop: 3, fontSize: 9, color: '#f59e0b' }}>{hint}</div>}
    </div>
  )
}

