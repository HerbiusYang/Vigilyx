import type {
  EmailSession,
  EmailContent,
  SecurityVerdict,
} from '../types'

function createEmailContent(overrides: Partial<EmailContent> = {}): EmailContent {
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
    threat_type: null,
    source: 'sniffer',
    ...overrides,
  }
}

export function createSecurityVerdict(overrides: Partial<SecurityVerdict> = {}): SecurityVerdict {
  return {
    id: 'verdict-001',
    session_id: 'session-001',
    threat_level: 'safe',
    threat_type: null,
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
