// Protocol types
export type Protocol = 'SMTP' | 'POP3' | 'IMAP' | 'HTTP' | 'UNKNOWN'

// Session status
export type SessionStatus = 'active' | 'completed' | 'timeout' | 'error'

export type PrivacyResourceType = 'session' | 'http_session' | 'attachment'
export type PrivacyScope = 'body' | 'html' | 'headers' | 'verdict' | 'attachment_download' | 'eml_download' | 'http_body'
type PrivacyAccessRequestStatus = 'requested' | 'approved' | 'rejected' | 'revoked' | 'expired'

export interface PrivacyResourceRef {
  resource_type: PrivacyResourceType
  resource_id: string
}

export interface PrivacyLease {
  request_id: string
  resource_type: PrivacyResourceType
  resource_id: string
  scopes: PrivacyScope[]
  expires_at: string
  uses_remaining: number
  lease_handle: string
}

export interface PrivacyAccessRequest {
  request_id: string
  requester_id: string
  approver_id?: string | null
  resource_type: PrivacyResourceType
  resource_id: string
  scopes: PrivacyScope[]
  purpose: string
  status: PrivacyAccessRequestStatus
  created_at: string
  expires_at: string
  approved_at?: string | null
  rejected_at?: string | null
}

export interface PrivacyAccessContext {
  current_user: {
    id: string
    role_id: string
    username: string
    display_name: string
    role: string
    permissions: string[]
    factor_configured: boolean
  }
  active_leases: PrivacyLease[]
}

// Traffic statistics
export interface TrafficStats {
  total_sessions: number
  active_sessions: number
  total_packets: number
  total_bytes: number
  smtp_sessions: number
  pop3_sessions: number
  imap_sessions: number
  packets_per_second: number
  bytes_per_second: number
}

// Email attachment
interface EmailAttachment {
  filename: string
  content_type: string
  size: number
  hash: string
  content_base64?: string
}

// Email link
interface EmailLink {
  url: string
  text: string | null
  suspicious: boolean
}

// SMTP authentication info
interface SmtpAuthInfo {
  auth_method: string
  username?: string | null
  auth_success?: boolean | null
}

// SMTP dialog entry
interface SmtpDialogEntry {
  direction: 'inbound' | 'outbound'
  command: string
  size: number
  timestamp: string
}

// Email content
export interface EmailContent {
  headers: [string, string][]
  body_text: string | null
  body_html: string | null
  attachments: EmailAttachment[]
  links: EmailLink[]
  raw_size: number
  is_complete: boolean
  is_encrypted: boolean
  smtp_dialog?: SmtpDialogEntry[]
}

// Email session
export interface EmailSession {
  id: string
  protocol: Protocol
  client_ip: string
  client_port: number
  server_ip: string
  server_port: number
  started_at: string
  ended_at: string | null
  status: SessionStatus
  packet_count: number
  total_bytes: number
  mail_from: string | null
  rcpt_to: string[]
  subject: string | null
  // Email content
  content: EmailContent
  email_count: number
  error_reason?: string | null
  message_id?: string | null
  auth_info?: SmtpAuthInfo | null
  threat_level?: string | null
  threat_type?: ThreatType | null
  classification?: string | null
  source: 'sniffer' | 'mta_proxy' | 'import'
  privacy?: { state: 'redacted' | 'revealed'; scopes?: PrivacyScope[] }
}

// ============================================
// Security engine types
// ============================================

// Threat level
type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical'

// Primary malicious-email classification. It is a separate result axis, but
// malicious families are exposed only when ThreatLevel is Medium or higher.
type ThreatType =
  | 'phishing'
  | 'bec_fraud'
  | 'malware_delivery'
  | 'mailbox_enumeration'
  | 'social_engineering'
  | 'injection_abuse'
  | 'malicious_other'

// Detection pillar
type Pillar = 'content' | 'attachment' | 'package' | 'link' | 'semantic'

// Inspection coverage
type InspectionCoverage = 'unknown' | 'complete' | 'limited'

// D-S BPA quadruple (v5.0 TBM)
interface Bpa {
  b: number       // belief (malicious confidence)
  d: number       // disbelief (benign confidence)
  u: number       // uncertainty
  epsilon?: number // open-world leakage m(∅), default 0
}

// Strategy-specific BPA diagnostic. Default clustered_ds_v2 returns evidence
// cluster BPA values combined once after causal-artifact deduplication.
interface EngineBpaDetail {
  engine_id: string
  engine_name: string
  bpa: Bpa
  modules: string[]
  key_factors?: string[]
}

export type EpistemicState = 'unknown' | 'threat_supported' | 'normal_supported' | 'conflicted'

interface RiskConstraintTrace {
  id: string
  lower: number
  upper: number
  basis: string[]
}

interface RiskConstraintConflict {
  effective_lower: number
  effective_upper: number
  constraint_ids: string[]
}

export interface ShadowFusionResult {
  model: string
  model_version: number
  fused_bpa: Bpa
  k_conflict: number
  risk_base: number
  risk_constrained: number
  epistemic_state: EpistemicState
  source_details: EngineBpaDetail[]
  active_constraints: RiskConstraintTrace[]
  constraint_conflict?: RiskConstraintConflict
  artifact_count: number
  fallback_artifact_count: number
}

// D-S fusion details
export interface FusionDetails {
  fused_bpa: Bpa
  k_conflict: number
  risk_single: number
  eta: number
  engine_details: EngineBpaDetail[]
  credibility_weights: Record<string, number>
  // v5.0 TBM extensions
  novelty?: number
  k_cross?: number
  betp?: number
  fusion_method?: string
  // Post-fusion safety circuit breaker
  circuit_breaker?: {
    // Legacy field name; clustered_ds_v2 stores an evidence-cluster label here.
    trigger_module_id: string
    // Legacy strategies store module belief; clustered_ds_v2 stores source score.
    trigger_belief: number
    floor_value: number
    original_risk: number
  }
  // Multi-signal convergence breaker
  convergence_breaker?: {
    modules_flagged: number
    floor_value: number
    original_risk: number
    flagged_modules: string[]
  }
  // Experimental results computed in parallel; never authoritative.
  primary_result?: ShadowFusionResult
  shadow_results?: ShadowFusionResult[]
}

// Full security verdict
export interface SecurityVerdict {
  inspection_coverage?: InspectionCoverage
  coverage_reasons?: string[]
  id: string
  session_id: string
  threat_level: ThreatLevel
  threat_type?: ThreatType | null
  classification?: string | null
  confidence: number
  categories: string[]
  summary: string
  pillar_scores: Record<string, number>
  modules_run: number
  modules_flagged: number
  total_duration_ms: number
  created_at: string
  fusion_details?: FusionDetails
}

// Module detection result
export interface ModuleResult {
  module_id: string
  module_name: string
  pillar: Pillar
  threat_level: ThreatLevel
  confidence: number
  categories: string[]
  summary: string
  evidence: Evidence[]
  details: any
  duration_ms: number
  analyzed_at: string
  bpa?: Bpa
  engine_id?: string
}

// Evidence
export interface Evidence {
  description: string
  location?: string
  snippet?: string
}

// IOC entry
export interface IocEntry {
  id: string
  indicator: string
  ioc_type: string
  source: string
  verdict: string
  confidence: number
  first_seen: string
  last_seen: string
  hit_count: number
  context?: string
  expires_at?: string
}

interface IocShadowScore {
  prior_log_odds: number
  raw_log_likelihood_ratio: number
  decayed_log_likelihood_ratio: number
  log_odds: number
  probability: number
  decay_factor: number
  evidence_count: number
  evidence_interval_lower: number
  evidence_interval_upper: number
}

export interface IocShadowTelemetry {
  ioc_type: string
  indicator: string
  traffic: {
    observed_count: number
    outbound_count: number
    inbound_count: number
    unknown_direction_count: number
    provisional_threat_count: number
    distinct_session_count: number
    distinct_activity_count: number
    first_seen: string
    last_seen: string
  }
  outcomes: {
    malicious: number
    normal: number
    unresolved: number
  }
  score: IocShadowScore
  prior_source: string
  calibration_status: string
  half_life_hours: number
  age_seconds: number
  clusters: Array<{
    cluster: string
    observations: number
    distinct_activities: number
    detector_families: number
    external_providers: number
  }>
  actionability: 'shadow_only' | string
}

export interface IocCalibrationSummary {
  status: string
  labeled_observations: number
  malicious_observations: number
  normal_observations: number
  brier_score: number | null
  reliability: Array<{
    lower: number
    upper: number
    sample_count: number
    predicted_mean: number
    observed_malicious_rate: number
  }>
  note: string
}

// Disposition rule
export interface DispositionRule {
  id: string
  name: string
  description?: string
  enabled: boolean
  priority: number
  conditions: string
  actions: string
  created_at: string
  updated_at: string
}

// External login hourly bucket
interface HourlyLoginEntry {
  hour: string
  smtp: number
  pop3: number
  imap: number
  http: number
  total: number
}

// External login statistics (24h)
export interface ExternalLoginStats {
  hourly: HourlyLoginEntry[]
  total_24h: number
  smtp_24h: number
  pop3_24h: number
  imap_24h: number
  http_24h: number
  success_24h: number
  failed_24h: number
  unique_ips_24h: number
}

// Security statistics
interface DeliveryNodeComparisonStats {
  node_index: number
  server_ips?: string[]
  comparable_total: number
  vendor_blocked_total: number
  vendor_passed_total: number
  terminal_delivered_total?: number
  vendor_unconfirmed_total?: number
  vigilyx_risky_total?: number
  both_threat_total: number
  vigilyx_only_threat_total: number
  vendor_only_threat_total: number
  both_threat_rate: number
  vigilyx_only_threat_rate: number
  vendor_only_threat_rate: number
  vendor_unconfirmed_rate?: number
}

export type DeliveryRiskDetailKind =
  | 'first_hop'
  | 'risky_first_hop'
  | 'reused_hop'
  | 'dangerous_forwarded'
  | 'node_settled'
  | 'node_risky'
  | 'node_rejected'
  | 'node_forwarded'
  | 'terminal_delivered'
  | 'agreement'
  | 'disagreement'
  | 'both_threat'
  | 'vigilyx_only'
  | 'vendor_only'
  | 'safe_passed'
  | 'unconfirmed'

export interface DeliveryRiskDetailItem {
  chain_id: string
  session_id: string
  hop_index: number
  server_ip: string
  observed_at: string
  threat_level: string | null
  action_evidence: 'first_hop' | 'reused_hop' | 'explicit_rejection' | 'path_termination' | 'terminal_delivery' | 'forwarded' | 'unconfirmed'
  message_id: string | null
  mail_from: string | null
  rcpt_to: string[]
  subject: string | null
}

export interface DeliveryRiskDetailPage {
  items: DeliveryRiskDetailItem[]
  total: number
  limit: number
  offset: number
  snapshot_at: string
  scope: 'all_history'
  kind: DeliveryRiskDetailKind
  server_ip: string | null
}

export interface SecurityStats {
  total_scanned: number
  level_counts: Record<string, number>
  high_threats_24h: number
  ioc_count: number
  level_counts_24h?: Record<string, number>
  analyzed_24h?: number
  analyzed_previous_24h?: number
  high_threats_previous_24h?: number
  alerts_24h?: number
  quarantined_24h?: number
  first_hop_emails_total?: number
  first_hop_dangerous_total?: number
  downstream_reused_hops_total?: number
  dangerous_forwarded_total?: number
  dangerous_forwarded_rate?: number
  delivery_node_comparisons?: DeliveryNodeComparisonStats[]
  terminal_mail_servers?: string[]
  delivery_stats_as_of?: string
  delivery_stats_scope?: 'all_history'
}

// Engine status
export interface EngineStatus {
  running: boolean
  uptime_seconds: number
  total_sessions_processed: number
  total_verdicts_produced: number
  sessions_per_second: number
  ai_service_available: boolean
  last_session_at?: string
  module_metrics: ModuleMetric[]
  // Process-level extension fields
  email_engine_active?: boolean
  data_security_engine_active?: boolean
  ds_sessions_processed?: number
  ds_incidents_detected?: number
  reason?: string
}

// Module metrics
interface ModuleMetric {
  module_id: string
  total_runs: number
  avg_duration_ms: number
  max_duration_ms: number
  min_duration_ms: number
  success_rate: number
  failure_count: number
  timeout_count: number
}

// Module metadata
export interface ModuleMetadata {
  id: string
  name: string
  pillar: string
  description: string
  supports_ai: boolean
  depends_on: string[]
  engine_id: string | null
}

// Pipeline module configuration
export interface ModuleConfig {
  id: string
  enabled: boolean
  mode: 'builtin' | 'aionly' | 'hybrid'
  config: any
  condition?: {
    min_threat_level?: ThreatLevel
    depends_module?: string
  }
}

// Verdict aggregation configuration
export interface VerdictConfig {
  aggregation: string
  weights: Record<string, number>
  pillar_weights: Record<string, number>
  eta: number
  correlation_matrix?: number[]
  engine_weights: Record<string, number>
  default_epsilon: number
  alert_belief_threshold: number
  alert_floor_factor: number
  convergence_min_modules: number
  convergence_base_floor: number
  convergence_belief_threshold: number
}

// Pipeline configuration
export interface PipelineConfig {
  version: number
  modules: ModuleConfig[]
  verdict_config: VerdictConfig
}

// Verdict + mail metadata (risk mail list)
export interface VerdictWithMeta {
  verdict_id: string
  session_id: string
  threat_level: string
  threat_type?: ThreatType | null
  classification?: string | null
  risk_score: number | null
  confidence: number
  categories: string[]
  summary: string
  modules_run: number
  modules_flagged: number
  total_duration_ms: number
  created_at: string
  mail_from: string | null
  rcpt_to: string | null
  subject: string | null
  protocol: string | null
  client_ip: string | null
  server_ip: string | null
}

// API response
export interface ApiResponse<T> {
  success: boolean
  data: T | null
  error: string | null
}

// Paginated response
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  limit: number
  total_pages: number
  /** Session lists can omit the exact count while still supporting next-page navigation. */
  has_more?: boolean
  total_is_exact?: boolean
  next_cursor?: string | null
}

export interface SessionCountResponse {
  total: number
  total_pages: number
  counted_at?: string
  /** False when `total` is the database estimate after the exact count timed out. */
  exact?: boolean
}

// Login response
export interface LoginResponse {
  success: boolean
  expires_in: number | null
  error: string | null
  /** True when the user logged in with the default password for the first time; the frontend should force a password change. */
  must_change_password?: boolean
}

// System metrics
export interface SystemMetrics {
  cpu_usage: number
  memory_used: number
  memory_total: number
  memory_percent: number
  uptime_secs: number
  active_sessions: number
}

// AI service configuration
export interface AiServiceConfig {
  enabled: boolean
  service_url: string
  provider: string
  api_key: string
  api_key_set: boolean
  model: string
  temperature: number
  max_tokens: number
  timeout_secs: number
}

export interface IntelSourceConfig {
  otx_enabled: boolean
  vt_scrape_enabled: boolean
  vt_scrape_url: string | null
  virustotal_api_key: string | null
  virustotal_api_key_set: boolean
  abuseipdb_enabled: boolean
  abuseipdb_api_key: string | null
  abuseipdb_api_key_set: boolean
}

// Mail alert configuration
export interface EmailAlertConfig {
  enabled: boolean
  smtp_host: string
  smtp_port: number
  smtp_username: string
  smtp_password: string
  smtp_password_set?: boolean
  smtp_tls: string
  allow_plaintext_smtp?: boolean
  from_address: string
  admin_email: string
  min_threat_level: string
  notify_recipient: boolean
  notify_admin: boolean
}

export interface WechatAlertConfig {
  enabled: boolean
  webhook_url: string
  webhook_url_set?: boolean
  min_threat_level: string
  mentioned_mobile_list: string[]
}

// Alert severity (P0-P3)
export type AlertLevel = 'P0' | 'P1' | 'P2' | 'P3'

// Security alert record
export interface AlertRecord {
  id: string
  verdict_id: string
  session_id: string
  alert_level: AlertLevel
  expected_loss: number
  return_period: number
  cvar: number
  risk_final: number
  k_conflict: number
  cusum_alarm: boolean
  rationale: string
  acknowledged: boolean
  acknowledged_by?: string
  acknowledged_at?: string
  created_at: string
}

// DLP mode
interface DlpPattern {
  id: string
  name: string
  description: string
  pattern: string
  score_weight: number
}

// Content detection rule
export interface ContentRules {
  phishing_keywords: string[]
  bec_phrases: string[]
  dlp_patterns: DlpPattern[]
  scoring: {
    phishing_per_keyword: number
    phishing_max: number
    bec_per_phrase: number
    bec_max: number
  }
}

// ============================================
// Data security type (HTTP protocol analysis)
// ============================================

// Data security event type
type DataSecurityIncidentType = 'draft_box_abuse' | 'file_transit_abuse' | 'self_sending' | 'volume_anomaly' | 'jrt_compliance_violation'

// Data security severity
type DataSecuritySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

// Data security event
export interface DataSecurityIncident {
  id: string
  http_session_id: string
  incident_type: DataSecurityIncidentType
  severity: DataSecuritySeverity
  confidence: number
  summary: string
  evidence: Evidence[]
  details: any
  dlp_matches: string[]
  client_ip: string
  detected_user: string | null
  request_url: string
  host: string | null
  method: string
  created_at: string
}

// Hourly stats bucket
interface HourlyBucket {
  hour: string
  count: number
}

// Data security statistics
export interface DataSecurityStats {
  total_incidents: number
  draft_abuse_count: number
  file_transit_count: number
  self_send_count: number
  volume_anomaly_count: number
  jrt_compliance_count?: number
  high_severity_24h: number
  incidents_by_severity: Record<string, number>
  hourly_sessions?: HourlyBucket[]
  hourly_email_reviews?: HourlyBucket[]
  hourly_incidents?: HourlyBucket[]
}

// Data security engine status
export interface DataSecurityEngineStatus {
  running: boolean
  http_sessions_processed: number
  incidents_detected: number
}

// Unified outbound email data-security review (mirror + MTA proxy)
export type EmailReviewSource = 'sniffer' | 'mta_proxy' | 'import'
type EmailReviewDirection = 'inbound' | 'outbound' | 'internal' | 'unknown'
export type EmailAuditClass = 'confirmed_outbound' | 'outbound_candidate' | 'attribution_pending' | 'legacy'
export type EmailInspectionStatus = 'inspected' | 'encrypted' | 'incomplete' | 'failed'
export type EmailDlpResult = 'clean' | 'hit' | 'unknown'
export type EmailReviewAction = 'audit' | 'allow' | 'alert' | 'quarantine' | 'block' | 'reject' | 'tempfail'
type EmailDlpEvidenceDetail = { count?: number; present?: boolean } | string[]

export interface EmailDataSecurityReview {
  id: string
  session_id: string
  dedupe_key: string
  source: EmailReviewSource
  direction: EmailReviewDirection
  audit_class: EmailAuditClass
  direction_reason?: string | null
  inspection_reason?: string | null
  inspection_status: EmailInspectionStatus
  dlp_result: EmailDlpResult
  max_jrt_level?: number | null
  dlp_matches: string[]
  dlp_details?: Record<string, EmailDlpEvidenceDetail> | null
  action: EmailReviewAction
  delivery_status?: string | null
  quarantine_id?: string | null
  verdict_id?: string | null
  client_ip: string
  mail_from?: string | null
  external_recipient_domains: string[]
  recipient_count: number
  subject?: string | null
  content_hash?: string | null
  attachment_count: number
  attachments_scanned: number
  attachment_inspection_complete: boolean
  encrypted: boolean
  created_at: string
  updated_at: string
}

export interface EmailDataSecurityStats {
  total: number
  inspected: number
  encrypted: number
  incomplete: number
  failed: number
  dlp_hits: number
  quarantined: number
  blocked: number
  rejected: number
  unknown_direction: number
  confirmed_outbound: number
  outbound_candidates: number
  attribution_pending: number
  incomplete_sessions: number
}

// HTTP session (data security)
export interface HttpSessionItem {
  id: string
  client_ip: string
  client_port: number
  server_ip: string
  server_port: number
  method: string
  uri: string
  host: string | null
  content_type: string | null
  request_body_size: number
  request_body: string | null
  response_status: number | null
  uploaded_filename: string | null
  uploaded_file_size: number | null
  detected_user: string | null
  detected_sender: string | null
  detected_recipients: string[]
  detected_file_type: string | null
  body_is_binary: boolean
  file_type_mismatch: string | null
  body_temp_file: string | null
  timestamp: string
  network_session_id: string | null
  privacy?: { state: 'redacted' | 'revealed'; scopes?: PrivacyScope[] }
}

// Threat scene types
type ThreatSceneType = 'bulk_mailing' | 'bounce_harvest' | 'internal_domain_impersonation'
type ThreatSceneStatus = 'active' | 'acknowledged' | 'auto_blocked' | 'resolved'

export interface ThreatScene {
  id: string
  scene_type: ThreatSceneType
  actor: string
  actor_type: string
  target_domain: string | null
  time_window_start: string
  time_window_end: string
  email_count: number
  unique_recipients: number
  bounce_count: number
  sample_subjects: string[]
  sample_recipients: string[]
  threat_level: ThreatLevel
  status: ThreatSceneStatus
  auto_blocked: boolean
  ioc_id: string | null
  details: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ThreatSceneRule {
  scene_type: ThreatSceneType
  enabled: boolean
  config: Record<string, unknown>
  updated_at: string
}

interface SceneTypeStats {
  active: number
  acknowledged: number
  auto_blocked: number
  resolved: number
  total_24h: number
}

export interface ThreatSceneStats {
  bulk_mailing: SceneTypeStats
  bounce_harvest: SceneTypeStats
  internal_domain_impersonation: SceneTypeStats
}
