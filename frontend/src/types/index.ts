// Protocol types
export type Protocol = 'SMTP' | 'POP3' | 'IMAP' | 'UNKNOWN'

// Session status
export type SessionStatus = 'active' | 'completed' | 'timeout' | 'error'

// Traffic direction
export type Direction = 'inbound' | 'outbound'

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
export interface EmailAttachment {
  filename: string
  content_type: string
  size: number
  hash: string
  content_base64?: string
}

// Email link
export interface EmailLink {
  url: string
  text: string | null
  suspicious: boolean
}

// SMTP authentication info
export interface SmtpAuthInfo {
  auth_method: string
  username: string | null
  password: string | null
  auth_success: boolean | null
}

// SMTP dialog entry
export interface SmtpDialogEntry {
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
  error_reason: string | null
  message_id: string | null
  auth_info: SmtpAuthInfo | null
  threat_level: string | null
}

// Email packet
export interface EmailPacket {
  id: string
  session_id: string
  protocol: Protocol
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  direction: Direction
  size: number
  timestamp: string
  command: string | null
  raw_data: string | null
}

// WebSocket message
export interface WsMessage {
  type: 'NewSession' | 'SessionUpdate' | 'StatsUpdate' | 'SecurityVerdict' | 'DataSecurityAlert' | 'Ping' | 'Pong'
  data: TrafficStats | WsSessionSignal | SecurityVerdictSummary | DataSecurityIncident | null
}

export interface WsSessionSignal {
  id: string
  protocol: Protocol
  status: SessionStatus
  threat_level?: string | null
}

// ============================================
// Security engine types
// ============================================

// Threat level
export type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical'

// Detection pillar
export type Pillar = 'content' | 'attachment' | 'package' | 'link' | 'semantic'

// Security verdict summary (WebSocket push)
export interface SecurityVerdictSummary {
  verdict_id: string
  session_id: string
  threat_level: string
  confidence: number
  categories: string[]
  summary: string
  modules_run: number
  modules_flagged: number
  total_duration_ms: number
}

// D-S BPA quadruple (v5.0 TBM)
export interface Bpa {
  b: number       // belief (malicious confidence)
  d: number       // disbelief (benign confidence)
  u: number       // uncertainty
  epsilon?: number // open-world leakage m(∅), default 0
}

// Engine BPA detail
export interface EngineBpaDetail {
  engine_id: string
  engine_label: string
  bpa: Bpa
  module_count: number
  source_modules: string[]
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
    trigger_module_id: string
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
}

// Full security verdict
export interface SecurityVerdict {
  id: string
  session_id: string
  threat_level: ThreatLevel
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

// Whitelist entry
export interface WhitelistEntry {
  id: string
  entry_type: string
  value: string
  description?: string
  created_at: string
  created_by: string
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
export interface HourlyLoginEntry {
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
export interface SecurityStats {
  total_scanned: number
  level_counts: Record<string, number>
  high_threats_24h: number
  ioc_count: number
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
export interface ModuleMetric {
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

// HMM posterior probabilities for attack stages
export interface HmmPhaseResult {
  normal: number
  reconnaissance: number
  trust_building: number
  attack_execution: number
  harvest: number
  dominant_state: string
  temporal_risk: number
}

// Communication graph anomaly result
export interface GraphAnomalyResult {
  is_anomalous: boolean
  pattern_label: string
  anomaly_score: number
}

// Hawkes self-exciting process result
export interface HawkesResult {
  intensity: number
  intensity_ratio: number
  burst_detected: boolean
}

// Temporal analysis result
export interface TemporalResult {
  sender_key: string
  cusum_alarm: boolean
  cusum_s_pos: number
  ewma_drift_score: number
  ewma_drifting: boolean
  sender_risk: number
  sender_watchlisted: boolean
  hmm_phase?: HmmPhaseResult
  graph_anomaly?: GraphAnomalyResult
  hawkes?: HawkesResult
  temporal_risk: number
  risk_upgraded: boolean
}

// DLP mode
export interface DlpPattern {
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
export type DataSecurityIncidentType = 'draft_box_abuse' | 'file_transit_abuse' | 'self_sending' | 'jrt_compliance_violation'

// Data security severity
export type DataSecuritySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

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
export interface HourlyBucket {
  hour: string
  count: number
}

// Data security statistics
export interface DataSecurityStats {
  total_incidents: number
  draft_abuse_count: number
  file_transit_count: number
  self_send_count: number
  jrt_compliance_count?: number
  high_severity_24h: number
  incidents_by_severity: Record<string, number>
  hourly_sessions?: HourlyBucket[]
  hourly_incidents?: HourlyBucket[]
}

// Data security engine status
export interface DataSecurityEngineStatus {
  running: boolean
  http_sessions_processed: number
  incidents_detected: number
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
}

// Threat scene types
export type ThreatSceneType = 'bulk_mailing' | 'bounce_harvest'
export type ThreatSceneStatus = 'active' | 'acknowledged' | 'auto_blocked' | 'resolved'

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

export interface SceneTypeStats {
  active: number
  acknowledged: number
  auto_blocked: number
  resolved: number
  total_24h: number
}

export interface ThreatSceneStats {
  bulk_mailing: SceneTypeStats
  bounce_harvest: SceneTypeStats
}
