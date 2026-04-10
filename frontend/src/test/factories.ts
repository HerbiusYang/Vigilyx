import type {
  TrafficStats,
  EmailSession,
  EmailContent,
  SecurityVerdict,
  SystemMetrics,
  WsMessage,
  ApiResponse,
  IocEntry,
} from '../types'

export function createTrafficStats(overrides: Partial<TrafficStats> = {}): TrafficStats {
  return {
    total_sessions: 100,
    active_sessions: 5,
    total_packets: 10000,
    total_bytes: 5242880,
    smtp_sessions: 60,
    pop3_sessions: 20,
    imap_sessions: 20,
    packets_per_second: 50,
    bytes_per_second: 25600,
    ...overrides,
  }
}

export function createEmailContent(overrides: Partial<EmailContent> = {}): EmailContent {
  return {
    headers: [
      ['From', 'sender@example.com'],
      ['To', 'recipient@example.com'],
      ['Subject', 'Test email'],
    ],
    body_text: 'This is a test email body.',
    body_html: null,
    attachments: [],
    links: [],
    raw_size: 1024,
    is_complete: true,
    is_encrypted: false,
    ...overrides,
  }
}

export function createEmailSession(overrides: Partial<EmailSession> = {}): EmailSession {
  return {
    id: 'session-001',
    protocol: 'SMTP',
    client_ip: '192.168.1.100',
    client_port: 45678,
    server_ip: '10.0.0.1',
    server_port: 25,
    started_at: '2026-03-20T10:00:00Z',
    ended_at: '2026-03-20T10:05:00Z',
    status: 'completed',
    packet_count: 42,
    total_bytes: 8192,
    mail_from: 'sender@example.com',
    rcpt_to: ['recipient@example.com'],
    subject: 'Test email subject',
    content: createEmailContent(),
    email_count: 1,
    error_reason: null,
    message_id: '<test-msg-001@example.com>',
    auth_info: null,
    threat_level: null,
    ...overrides,
  }
}

export function createSecurityVerdict(overrides: Partial<SecurityVerdict> = {}): SecurityVerdict {
  return {
    id: 'verdict-001',
    session_id: 'session-001',
    threat_level: 'safe',
    confidence: 0.95,
    categories: [],
    summary: 'No threats detected',
    pillar_scores: { content: 0.05, link: 0.02, attachment: 0.0 },
    modules_run: 15,
    modules_flagged: 0,
    total_duration_ms: 120,
    created_at: '2026-03-20T10:05:01Z',
    ...overrides,
  }
}

export function createSystemMetrics(overrides: Partial<SystemMetrics> = {}): SystemMetrics {
  return {
    cpu_usage: 35.5,
    memory_used: 4294967296,
    memory_total: 8589934592,
    memory_percent: 50.0,
    uptime_secs: 86400,
    active_sessions: 5,
    ...overrides,
  }
}

export function createWsMessage(overrides: Partial<WsMessage> = {}): WsMessage {
  return {
    type: 'StatsUpdate',
    data: createTrafficStats(),
    ...overrides,
  }
}

export function createApiResponse<T>(data: T, overrides: Partial<ApiResponse<T>> = {}): ApiResponse<T> {
  return {
    success: true,
    data,
    error: null,
    ...overrides,
  }
}

export function createIocEntry(overrides: Partial<IocEntry> = {}): IocEntry {
  return {
    id: 'ioc-001',
    indicator: 'malicious.example.com',
    ioc_type: 'domain',
    source: 'manual',
    verdict: 'malicious',
    confidence: 0.9,
    first_seen: '2026-03-19T08:00:00Z',
    last_seen: '2026-03-20T10:00:00Z',
    hit_count: 3,
    ...overrides,
  }
}
