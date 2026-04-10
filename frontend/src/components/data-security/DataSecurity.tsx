import { useState, useEffect, useCallback, useRef, memo, useMemo } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import type {
  DataSecurityIncident, DataSecurityStats, DataSecurityEngineStatus,
  HttpSessionItem, ApiResponse, PaginatedResponse, Evidence
} from '../../types'
import { apiFetch } from '../../utils/api'

type TabKey = 'overview' | 'policy' | 'incidents' | 'http-sessions' | 'settings'

// -- IP input expansion helpers --
function expandIpInput(raw: string): string[] {
  const trimmed = raw.trim()
  if (!trimmed) return []
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3}(?:\/\d{1,3})+)$/.exec(trimmed)
  if (match) {
    const prefix = match[1]
    const parts = match[2].split('/')
    return parts.map(p => prefix + p)
  }
  return [trimmed]
}

// -- Constants --
const INCIDENT_TYPE_CN: Record<string, string> = { draft_box_abuse: '草稿箱滥用风险', file_transit_abuse: '文件中转站风险', self_sending: '自发自收风险', jrt_compliance_violation: 'JR/T合规告警' }
const INCIDENT_TYPE_DESC: Record<string, string> = { draft_box_abuse: '用户通过 Webmail 草稿箱保存含敏感数据的内容', file_transit_abuse: '用户通过 Webmail 文件中转站上传含敏感信息的文件', self_sending: '用户通过 Webmail 给自己发送含敏感数据的邮件（发件人 = 收件人）', jrt_compliance_violation: 'JR/T 0197-2020 敏感数据累计数量达到监管阈值' }
const INCIDENT_TYPE_COLOR: Record<string, string> = { draft_box_abuse: '#a855f7', file_transit_abuse: '#3b82f6', self_sending: '#f97316', jrt_compliance_violation: '#ef4444' }
const INCIDENT_TYPE_ICON: Record<string, JSX.Element> = {
  draft_box_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  file_transit_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  self_sending: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
  jrt_compliance_violation: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
}
const SEVERITY_COLOR: Record<string, string> = { info: '#6b7280', low: '#3b82f6', medium: '#eab308', high: '#f97316', critical: '#ef4444' }
const SEVERITY_BG: Record<string, string> = { info: 'rgba(107,114,128,.12)', low: 'rgba(59,130,246,.12)', medium: 'rgba(234,179,8,.12)', high: 'rgba(249,115,22,.12)', critical: 'rgba(239,68,68,.12)' }
const SEVERITY_CN: Record<string, string> = { info: '信息', low: '低危', medium: '中危', high: '高危', critical: '严重' }
const DLP_MATCH_CN: Record<string, string> = { credit_card: '信用卡号', id_number: '身份证号', phone_number: '手机号', bank_card: '银行卡号', customer_address: '客户住址', sensitive_extension: '高风险文件类型', email_address: '电子邮箱', passport_number: '护照号', social_credit_code: '社会信用代码', credential_leak: '凭证泄露', swift_code: 'SWIFT代码', cvv_code: 'CVV安全码', executable_upload: '可执行文件', file_type_mismatch: '文件伪装', encrypted_archive: '加密压缩包', encrypted_pdf: '加密PDF', jrt_compliance_c3: 'C3敏感级超限', jrt_compliance_c4: 'C4高敏感级超限', biometric_data: '生物特征', medical_health: '健康医疗', vehicle_info: '车辆信息', property_info: '不动产信息', income_info: '收入/薪资', geo_location: '地理位置', otp_verification: '验证码/OTP', loan_credit_info: '贷款/信贷', insurance_policy: '保险保单', family_relation: '家庭关系', employee_info: '员工信息', judicial_record: '司法记录', education_info: '学历信息', business_license: '营业执照' }
const DLP_JRT_LEVEL: Record<string, number> = { credential_leak: 4, cvv_code: 4, credit_card: 4, biometric_data: 4, medical_health: 4, id_number: 3, phone_number: 3, bank_card: 3, customer_address: 3, email_address: 3, passport_number: 3, iban: 3, large_amount: 3, bank_account_context: 3, contract_number: 3, vehicle_info: 3, property_info: 3, income_info: 3, geo_location: 3, otp_verification: 3, loan_credit_info: 3, insurance_policy: 3, family_relation: 3, swift_code: 2, tax_id: 2, employee_info: 2, judicial_record: 2, education_info: 2, business_license: 2, social_credit_code: 1 }
const JRT_LEVEL_COLOR: Record<number, string> = { 4: '#ef4444', 3: '#f97316', 2: '#eab308', 1: '#22c55e' }
const JRT_LEVEL_LABEL: Record<number, string> = { 4: 'C4', 3: 'C3', 2: 'C2', 1: 'C1' }
const METHOD_COLOR: Record<string, string> = { GET: '#22d3ee', POST: '#f97316', PUT: '#eab308', DELETE: '#ef4444', PATCH: '#a855f7' }

// -- Privacy masking --
const PRIVACY_KEY = 'vigilyx_ds_privacy_mode'
/** IP: 192.168.1.100 → 192.168.*.* */
function maskIp(ip: string): string {
  if (!ip) return ip
  const parts = ip.split('.')
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`
  return ip.replace(/:[\da-f]+:[\da-f]+$/i, ':*:*') // IPv6
}
/** User: user@domain.com -> us***@domain.com */
function maskUser(u: string): string {
  if (!u) return u
  const at = u.indexOf('@')
  if (at > 0) {
    const local = u.slice(0, at)
    const domain = u.slice(at)
    return (local.length <= 2 ? local[0] + '***' : local.slice(0, 2) + '***') + domain
  }
  return u.length <= 2 ? u[0] + '***' : u.slice(0, 2) + '***'
}
/** URL: /path?token=abc123&key=xxx → /path?token=***&key=*** */
function maskUrl(url: string): string {
  if (!url) return url
  const qi = url.indexOf('?')
  if (qi < 0) return url
  const path = url.slice(0, qi)
  const qs = url.slice(qi + 1)
  const masked = qs.replace(/=([^&]*)/g, '=***')
  return path + '?' + masked
}
/** Mask evidence snippets and request bodies as a whole. */
const MASKED_BODY = '██████ 隐私保护已启用，敏感内容已隐藏 ██████'
const MASKED_SNIPPET = '██ 内容已脱敏 ██'

// -- Utilities --
function formatTime(ts: string): string {
  let n = ts
  if (ts && !ts.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(ts)) n = ts + 'Z'
  const d = new Date(n)
  const p = (x: number) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function formatSize(b: number): string {
  if (b === 0) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1048576).toFixed(1)} MB`
}

function sanitizeDownloadName(name: string): string {
  const cleaned = name.replace(/[\\/\u0000-\u001f\u007f"]/g, '').trim()
  return cleaned || 'http-request-body.redacted.txt'
}

function getDownloadName(headers: Headers, fallback: string): string {
  const disposition = headers.get('content-disposition')
  if (!disposition) return sanitizeDownloadName(fallback)

  const encodedMatch = disposition.match(/filename\*\s*=\s*([^;]+)/i)
  if (encodedMatch) {
    const encoded = encodedMatch[1].trim().replace(/^UTF-8''/i, '').replace(/^"(.*)"$/, '$1')
    try {
      return sanitizeDownloadName(decodeURIComponent(encoded))
    } catch {
      return sanitizeDownloadName(encoded)
    }
  }

  const plainMatch = disposition.match(/filename\s*=\s*("?)([^";]+)\1/i)
  if (plainMatch) {
    return sanitizeDownloadName(plainMatch[2])
  }

  return sanitizeDownloadName(fallback)
}

function formatRelativeTime(ts: string): string {
  let n = ts
  if (ts && !ts.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(ts)) n = ts + 'Z'
  const d = new Date(n)
  const diffMs = Date.now() - d.getTime()
  if (diffMs < 0) return formatTime(ts)
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return '刚刚'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin} 分钟前`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr} 小时前`
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 7) return `${diffDay} 天前`
  return formatTime(ts)
}

// -- Badge component --
const SeverityBadge = memo(function SeverityBadge({ severity }: { severity: string }) {
  const c = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info
  const bg = SEVERITY_BG[severity] || SEVERITY_BG.info
  return <span className="ds3-sev-badge" style={{ background: bg, color: c }}><span className="ds3-sev-badge-dot" style={{ background: c }} />{SEVERITY_CN[severity] || severity}</span>
})

const IncidentTypeBadge = memo(function IncidentTypeBadge({ type: t }: { type: string }) {
  const c = INCIDENT_TYPE_COLOR[t] || '#8b949e'
  return <span className="ds3-type-badge" style={{ background: c + '12', color: c }}>{INCIDENT_TYPE_ICON[t]}{INCIDENT_TYPE_CN[t] || t}</span>
})

const MethodBadge = memo(function MethodBadge({ method }: { method: string }) {
  const c = METHOD_COLOR[method] || 'var(--text-secondary)'
  return <span className="ds3-method-badge" style={{ background: c + '15', color: c }}>{method}</span>
})

// ═══════════════════════════════════════════
// Tab 1: Overview
// ═══════════════════════════════════════════
function OverviewTab({ stats, engineStatus, loadFailed }: {
  stats: DataSecurityStats | null
  engineStatus: DataSecurityEngineStatus | null
  loadFailed?: boolean
}) {
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sortedSev = useMemo(() => {
    if (!stats) return []
    return sevOrder
      .filter(s => (stats.incidents_by_severity[s] ?? 0) > 0)
      .map(s => ({ severity: s, count: stats.incidents_by_severity[s] || 0 }))
  }, [stats?.incidents_by_severity])

  // Trend chart - dual Y axes: left = HTTP sessions, right = security incidents
  const chart = useMemo(() => {
    if (!stats?.hourly_sessions || stats.hourly_sessions.length === 0) return null
    const sd = stats.hourly_sessions
    const im = new Map((stats.hourly_incidents || []).map(b => [b.hour, b.count]))
    const id = sd.map(b => ({ hour: b.hour, count: im.get(b.hour) || 0 }))
    const mcS = Math.max(...sd.map(b => b.count), 1)  // Left axis: max session count
    const mcI = Math.max(...id.map(b => b.count), 1)   // Right axis: max incident count
    const H = 120, pL = 32, pR = 32, pT = 8, pB = 14, W = 700
    const pW = W - pL - pR, pH = H - pT - pB, bW = pW / sd.length
    const mkP = (d: { count: number }[], maxVal: number) => d.map((b, i) => ({ x: pL + (i + 0.5) * bW, y: pT + pH - (b.count / maxVal) * pH }))
    // Catmull-Rom smooth
    const mkS = (pts: { x: number; y: number }[]) => {
      if (pts.length < 2) return ''
      let d = `M ${pts[0].x},${pts[0].y}`
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)]
        d += ` C ${p1.x + (p2.x - p0.x) / 6},${p1.y + (p2.y - p0.y) / 6} ${p2.x - (p3.x - p1.x) / 6},${p2.y - (p3.y - p1.y) / 6} ${p2.x},${p2.y}`
      }
      return d
    }
    const mkA = (l: string, pts: { x: number; y: number }[]) =>
      pts.length < 2 ? '' : `${l} L ${pts[pts.length - 1].x},${pT + pH} L ${pts[0].x},${pT + pH} Z`
    const sp = mkP(sd, mcS), ip = mkP(id, mcI), sl = mkS(sp), il = mkS(ip)
    return {
      sd, id, mcS, mcI, H, pL, pR, pT, pW, pH, bW, W, sp, ip,
      sa: mkA(sl, sp), sl, ia: mkA(il, ip), il,
      hi: id.some(b => b.count > 0),
      ts: sd.reduce((s, b) => s + b.count, 0),
      ti: id.reduce((s, b) => s + b.count, 0),
    }
  }, [stats?.hourly_sessions, stats?.hourly_incidents])

  if (!stats) {
    if (loadFailed) return (
      <div className="ds3-empty-full">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="1.5" style={{ opacity: 0.4 }}>
          <circle cx="12" cy="12" r="10" /><path d="M16 16s-1.5-2-4-2-4 2-4 2M9 9h.01M15 9h.01" />
        </svg>
        <p>数据加载失败</p>
      </div>
    )
    return <div className="sec-loading"><div className="sec-spinner" /></div>
  }

  const typeStats = [
    { key: 'self_sending', count: stats.self_send_count },
    { key: 'draft_box_abuse', count: stats.draft_abuse_count },
    { key: 'file_transit_abuse', count: stats.file_transit_count },
    { key: 'jrt_compliance_violation', count: stats.jrt_compliance_count || 0 },
  ]
  const mtc = Math.max(...typeStats.map(t => t.count), 1)

  return (
    <div className="ds3-overview">
      {/* Engine status bar */}
      {engineStatus && (
        <div className="ds3-engine-bar">
          <div className="ds3-engine-left">
            <span className={`ds3-engine-dot ${engineStatus.running ? 'ds3-engine-dot--on' : 'ds3-engine-dot--off'}`} />
            <span className="ds3-engine-text">
              数据安全引擎{engineStatus.running ? <b style={{ color: '#22c55e' }}>运行中</b> : <b style={{ color: '#ef4444' }}>已停止</b>}
            </span>
            <span className="ds3-engine-sep" />
            <span className="ds3-engine-text">已处理 <b className="sec-mono" style={{ color: 'var(--text-primary)', fontSize: 15 }}>{engineStatus.http_sessions_processed.toLocaleString()}</b> 会话</span>
            <span className="ds3-engine-sep" />
            <span className="ds3-engine-text">发现 <b className="sec-mono" style={{ color: '#f97316', fontSize: 15 }}>{engineStatus.incidents_detected.toLocaleString()}</b> 事件</span>
          </div>
          <div className="ds3-engine-right">
            {sortedSev.map(({ severity, count }) => (
              <span key={severity} className="ds3-sev-pill" style={{ background: SEVERITY_BG[severity], color: SEVERITY_COLOR[severity] }}>
                {SEVERITY_CN[severity]} {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Hero section: 2 cards in a symmetric layout */}
      <div className="ds3-hero-row">
        <div className="ds3-hero-card" style={{ '--hero-color': '#22d3ee' } as React.CSSProperties}>
          <div className="ds3-hero-glow" style={{ background: 'radial-gradient(circle at 85% 30%, rgba(34,211,238,0.06), transparent 60%)' }} />
          <div className="ds3-hero-main">
            <div className="ds3-hero-icon" style={{ background: 'rgba(34,211,238,0.1)', color: '#22d3ee' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div className="ds3-hero-text">
              <div className="ds3-hero-label">安全事件总数</div>
              <div className="ds3-hero-sub">
                {typeStats.filter(t => t.count > 0).map(t =>
                  <span key={t.key} style={{ color: INCIDENT_TYPE_COLOR[t.key] }}>{INCIDENT_TYPE_CN[t.key]} {t.count}</span>
                ).reduce((a: React.ReactNode[], b, i) => i === 0 ? [b] : [...a, <span key={`sep${i}`} style={{ color: 'var(--text-tertiary)', margin: '0 4px' }}>·</span>, b], [] as React.ReactNode[])}
              </div>
            </div>
            <div className="ds3-hero-value sec-mono" style={{ color: '#22d3ee' }}>{stats.total_incidents.toLocaleString()}</div>
          </div>
        </div>
        <div className="ds3-hero-card" style={{ '--hero-color': stats.high_severity_24h > 0 ? '#ef4444' : '#22c55e' } as React.CSSProperties}>
          <div className="ds3-hero-glow" style={{ background: stats.high_severity_24h > 0 ? 'radial-gradient(circle at 85% 30%, rgba(239,68,68,0.06), transparent 60%)' : 'radial-gradient(circle at 85% 30%, rgba(34,197,94,0.04), transparent 60%)' }} />
          <div className="ds3-hero-main">
            <div className="ds3-hero-icon" style={{
              background: stats.high_severity_24h > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
              color: stats.high_severity_24h > 0 ? '#ef4444' : '#22c55e',
            }}>
              {stats.high_severity_24h > 0
                ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                : <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></svg>}
            </div>
            <div className="ds3-hero-text">
              <div className="ds3-hero-label">24 小时高危事件</div>
              <div className="ds3-hero-sub">{stats.high_severity_24h > 0 ? '需立即处置' : '当前无高危威胁'}</div>
            </div>
            <div className="ds3-hero-value sec-mono" style={{ color: stats.high_severity_24h > 0 ? '#ef4444' : '#22c55e' }}>{stats.high_severity_24h}</div>
          </div>
        </div>
      </div>

      {/* Trend chart - full width */}
      <div className="ds3-chart-card ds3-chart-card--full">
        <div className="ds3-chart-head">
          <div>
            <div className="ds3-chart-title">24 小时数据安全趋势</div>
            <div style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 3 }}>
              HTTP 会话 <span className="sec-mono" style={{ color: '#22d3ee', fontWeight: 600 }}>{chart?.ts.toLocaleString() || '0'}</span>
              {chart?.hi && <> · 安全事件 <span className="sec-mono" style={{ color: '#f97316', fontWeight: 600 }}>{chart.ti}</span></>}
            </div>
          </div>
          <div className="ds3-chart-legend">
            <span><span className="ds3-legend-dot" style={{ background: '#22d3ee' }} />HTTP 会话</span>
            {chart?.hi && <span><span className="ds3-legend-dot" style={{ background: '#f97316' }} />安全事件</span>}
          </div>
        </div>
          {chart ? (
            <svg viewBox={`0 0 ${chart.W} ${chart.H}`} className="ds3-chart-svg">
              <defs>
                <linearGradient id="dg3s" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity="0.2" /><stop offset="100%" stopColor="#22d3ee" stopOpacity="0" /></linearGradient>
                <linearGradient id="dg3i" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f97316" stopOpacity="0.2" /><stop offset="100%" stopColor="#f97316" stopOpacity="0" /></linearGradient>
                <filter id="dgl3"><feGaussianBlur stdDeviation="2.5" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
              </defs>
              {/* Left Y axis: HTTP sessions (cyan) */}
              {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
                const y = chart.pT + chart.pH * (1 - f)
                return <g key={`l${i}`}>
                  <line x1={chart.pL} y1={y} x2={chart.pL + chart.pW} y2={y} stroke="rgba(255,255,255,.04)" strokeWidth="0.5" strokeDasharray={f === 0 ? undefined : '2 4'} />
                  <text x={chart.pL - 5} y={y + 2.5} textAnchor="end" fill="#22d3ee" fontSize="7.5" fontFamily="var(--font-mono)" opacity="0.6">{Math.round(chart.mcS * f)}</text>
                </g>
              })}
              {/* Right Y axis: security incidents (orange) */}
              {chart.hi && [0, 0.25, 0.5, 0.75, 1].map((f, i) => {
                const y = chart.pT + chart.pH * (1 - f)
                return <text key={`r${i}`} x={chart.pL + chart.pW + 5} y={y + 2.5} textAnchor="start" fill="#f97316" fontSize="7.5" fontFamily="var(--font-mono)" opacity="0.6">{Math.round(chart.mcI * f)}</text>
              })}
              <path d={chart.sa} fill="url(#dg3s)" />
              <path d={chart.sl} fill="none" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" filter="url(#dgl3)" />
              {chart.hi && <>
                <path d={chart.ia} fill="url(#dg3i)" />
                <path d={chart.il} fill="none" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" strokeDasharray="4 2" />
              </>}
              {/* Data points */}
              {chart.sp.map((p, i) => chart.sd[i].count > 0 && (
                <circle key={`s${i}`} cx={p.x} cy={p.y} r="2" fill="#0b0e14" stroke="#22d3ee" strokeWidth="1.5" />
              ))}
              {chart.hi && chart.ip.map((p, i) => chart.id[i].count > 0 && (
                <circle key={`i${i}`} cx={p.x} cy={p.y} r="2" fill="#0b0e14" stroke="#f97316" strokeWidth="1.5" />
              ))}
              {/* X-axis time labels */}
              {chart.sd.map((b, i) => {
                const show = chart.sd.length <= 6 || i % Math.ceil(chart.sd.length / 8) === 0 || i === chart.sd.length - 1
                // hour format is "MM-DD HH:00"; only show the time portion on the X axis
                const timeLabel = b.hour.includes(' ') ? b.hour.split(' ')[1] : b.hour
                return show ? <text key={i} x={chart.pL + (i + 0.5) * chart.bW} y={chart.H - 2} textAnchor="middle" fill="var(--text-tertiary)" fontSize="7.5" fontFamily="var(--font-mono)">{timeLabel}</text> : null
              })}
              {/* Hover interaction layer: one transparent rect + guideline + tooltip per column */}
              {chart.sd.map((b, i) => {
                const x = chart.pL + i * chart.bW
                const cx = chart.pL + (i + 0.5) * chart.bW
                const sCount = b.count
                const iCount = chart.id[i].count
                return <g key={`hover${i}`} className="ds3-chart-hover-col">
                  <rect x={x} y={chart.pT} width={chart.bW} height={chart.pH} fill="transparent" />
                  <line className="ds3-chart-hover-line" x1={cx} y1={chart.pT} x2={cx} y2={chart.pT + chart.pH} stroke="#22d3ee" strokeWidth="0.5" strokeDasharray="2 2" opacity="0" />
                  {/* Tooltip background + text */}
                  <g className="ds3-chart-hover-tip" opacity="0">
                    <rect x={cx - 48} y={chart.pT - 2} width={96} height={chart.hi ? 34 : 22} rx="4" fill="rgba(11,14,20,0.94)" stroke="rgba(34,211,238,0.15)" strokeWidth="0.5" />
                    <text x={cx} y={chart.pT + 8} textAnchor="middle" fontSize="8" fontFamily="var(--font-mono)" fontWeight="700" fill="#e2e8f0">{b.hour}</text>
                    <text x={cx - 40} y={chart.pT + 18} fontSize="6.5" fill="#22d3ee">&#9679;</text>
                    <text x={cx - 34} y={chart.pT + 18} fontSize="7.5" fontFamily="var(--font-mono)" fill="#22d3ee">会话 {sCount.toLocaleString()}</text>
                    {chart.hi && <>
                      <text x={cx - 40} y={chart.pT + 28} fontSize="6.5" fill="#f97316">&#9679;</text>
                      <text x={cx - 34} y={chart.pT + 28} fontSize="7.5" fontFamily="var(--font-mono)" fill="#f97316">事件 {iCount}</text>
                    </>}
                  </g>
                </g>
              })}
            </svg>
          ) : (
            <div className="ds3-chart-empty">暂无趋势数据</div>
          )}
        </div>

      {/* Detection-scenario distribution - 4 columns */}
      <div className="ds3-scenarios">
        {typeStats.map(t => {
          const c = INCIDENT_TYPE_COLOR[t.key]
          const pct = mtc > 0 ? (t.count / mtc) * 100 : 0
          return (
            <div key={t.key} className="ds3-scenario-card" style={{ '--sc-color': c } as React.CSSProperties}>
              <div className="ds3-scenario-top">
                <div className="ds3-scenario-icon" style={{ background: c + '12', color: c }}>{INCIDENT_TYPE_ICON[t.key]}</div>
                <div className="ds3-scenario-num sec-mono" style={{ color: t.count > 0 ? c : 'var(--text-tertiary)' }}>{t.count}</div>
              </div>
              <div className="ds3-scenario-name">{INCIDENT_TYPE_CN[t.key]}</div>
              <div className="ds3-scenario-bar"><div style={{ width: `${pct}%`, background: `linear-gradient(90deg,${c},${c}66)` }} /></div>
              <div className="ds3-scenario-desc">{INCIDENT_TYPE_DESC[t.key]}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════
// Tab 2: Security policies
// ═══════════════════════════════════════════
function PolicyTab() {
  return (
    <div className="ds3-policy">
      {/* 1) Top hero - large title + 3 parameters */}
      <div className="pol-hero">
        <div className="pol-hero-left">
          <div className="pol-hero-badge">JR/T 0197-2020</div>
          <h2 className="pol-hero-title">金融数据安全分级指南</h2>
          <p className="pol-hero-sub">数据生命周期安全规范 · 附录A 数据安全级别与防护要求</p>
        </div>
        <div className="pol-hero-params">
          {[['24h', '合规窗口'], ['30m/1h', '冷却周期'], ['用户/IP', '独立追踪']].map(([v, l]) => (
            <div key={l} className="pol-hero-param">
              <span className="pol-hero-param-val sec-mono">{v}</span>
              <span className="pol-hero-param-label">{l}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 2) Compliance thresholds - 2 large cards */}
      <div className="pol-thresh-row">
        {[
          { level: 'C4', label: '高敏感级', color: '#ef4444', num: 50, result: 'Critical', desc: '泄露可直接造成财产损失（传统鉴别信息）', items: ['密码/凭证', 'CVV安全码', '信用卡号', '生物特征', '健康医疗'] },
          { level: 'C3', label: '敏感级', color: '#f97316', num: 500, result: 'High', desc: '泄露可识别个人身份或造成较大损失', items: ['身份证号', '手机号', '银行卡号', '客户住址', '护照号', 'IBAN', '大额金额', '合同号', '车辆信息', '不动产', '收入/薪资', '地理位置', 'OTP验证码', '贷款/信贷', '保险保单', '家庭关系'] },
        ].map(t => (
          <div key={t.level} className="pol-thresh" style={{ '--c': t.color } as React.CSSProperties}>
            <div className="pol-thresh-head">
              <span className="pol-thresh-badge" style={{ background: t.color + '18', color: t.color }}>{t.level} {t.label}</span>
              <span className="pol-thresh-arrow">→</span>
              <span className="pol-thresh-result" style={{ color: t.color }}>{t.result}</span>
            </div>
            <div className="pol-thresh-body">
              <div className="pol-thresh-num sec-mono" style={{ color: t.color }}>{t.num}<span className="pol-thresh-unit">条/24h</span></div>
              <div className="pol-thresh-desc">{t.desc}</div>
            </div>
            <div className="pol-thresh-tags">
              {t.items.map(i => <span key={i} className="pol-tag" style={{ background: t.color + '0c', color: t.color, borderColor: t.color + '22' }}>{i}</span>)}
            </div>
          </div>
        ))}
      </div>

      {/* 3) Data classification tower - 4 layers from red to green */}
      <div className="pol-tower">
        <div className="pol-tower-title">数据分类对照 — JR/T 0197-2020 附录 A</div>
        {[
          { level: 4, label: '高敏感', color: '#ef4444', desc: '泄露可直接造成财产损失（传统鉴别信息）', items: ['密码/凭证', 'CVV安全码', '信用卡号', '生物特征', '健康医疗'] },
          { level: 3, label: '敏感', color: '#f97316', desc: '泄露可识别个人身份或财产状况', items: ['身份证号', '手机号', '银行卡号', '客户住址', '护照号', 'IBAN', '大额金额', '银行账户上下文', '合同号', '车辆信息', '不动产', '收入/薪资', '地理位置', 'OTP验证码', '贷款/信贷', '保险保单', '家庭关系'] },
          { level: 2, label: '内部', color: '#eab308', desc: '内部业务信息（需分隔符才触发）', items: ['SWIFT/BIC代码', '税务ID', '员工信息', '司法记录', '学历信息', '营业执照'] },
          { level: 1, label: '公开', color: '#22c55e', desc: '可公开查询的企业信息', items: ['统一社会信用代码'] },
        ].map(r => (
          <div key={r.level} className="pol-tower-row">
            <div className="pol-tower-side" style={{ background: r.color + '08', borderRight: `3px solid ${r.color}` }}>
              <span className="sec-mono" style={{ fontSize: 18, fontWeight: 800, color: r.color }}>C{r.level}</span>
              <span style={{ fontSize: 11, color: r.color, fontWeight: 600 }}>{r.label}</span>
            </div>
            <div className="pol-tower-main">
              <span className="pol-tower-desc">{r.desc}</span>
              <div className="pol-tower-tags">
                {r.items.map(i => <span key={i} className="pol-tag" style={{ background: r.color + '0c', color: r.color, borderColor: r.color + '1a' }}>{i}</span>)}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 4) Detection scenarios - 3 columns */}
      <div className="pol-detect">
        <div className="pol-detect-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          合规检测体系
        </div>
        <div className="pol-detect-grid">
          {[
            { icon: INCIDENT_TYPE_ICON.draft_box_abuse, color: '#a855f7', title: '草稿箱滥用风险', desc: '拦截通过草稿箱保存敏感数据的隐蔽外传（Coremail compose body 智能提取，过滤 email_address 单独命中）', trigger: 'POST compose.jsp + Coremail body 解析 + DLP 命中', output: 'C4→高危 | C3→中危 | C2→低危' },
            { icon: INCIDENT_TYPE_ICON.file_transit_abuse, color: '#3b82f6', title: '文件中转站风险', desc: '拦截上传敏感文件：DOCX/XLSX/PDF/OLE 文档提取文本扫描，纯文本直接扫描，检测加密压缩包和加密 PDF（二进制文件自动过滤 swift_code 误报）', trigger: 'POST upload + 文件内容 DLP + magic bytes + 分块去重', output: '加密/伪装/可执行→高危 | 其余按JR/T级别' },
            { icon: INCIDENT_TYPE_ICON.self_sending, color: '#f97316', title: '自发自收风险', desc: '拦截用户给自己发送含敏感数据的邮件', trigger: 'SMTP 发件人=收件人 + 邮件内容 DLP 命中', output: 'C4→高危 | C3→中危 | C2→低危' },
          ].map((s, idx) => (
            <div key={idx} className="pol-detect-lane">
              <div className="pol-detect-head" style={{ color: s.color }}>
                <span style={{ width: 32, height: 32, borderRadius: 8, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', background: s.color + '12' }}>{s.icon}</span>
                <span style={{ fontSize: 15, fontWeight: 700 }}>{s.title}</span>
              </div>
              <p className="pol-detect-desc">{s.desc}</p>
              <div className="pol-detect-rule">
                <div className="pol-detect-label">触发</div>
                <div className="pol-detect-value">{s.trigger}</div>
              </div>
              <div className="pol-detect-rule">
                <div className="pol-detect-label">输出</div>
                <div className="pol-detect-value" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{s.output}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="pol-detect-footer">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
          JR/T 0197-2020 合规追踪 — <strong style={{ color: '#ef4444' }}>C4 高敏感 ≥50 条/24h → Critical</strong>，<strong style={{ color: '#f97316' }}>C3+ 敏感 ≥500 条/24h → High</strong>（按用户/IP 独立计算，1h 冷却）
        </div>
      </div>

      {/* 5) Supporting policies - 2 columns */}
      <div className="pol-aux-row">
        {[
          { emoji: '🌙', bg: 'rgba(168,85,247,.1)', title: '非工作时间加权', desc: '08:00–18:00 以外及周末，严重度自动 +1 级（可在设置中配置）', chips: [['Medium', '#f97316', 'High'], ['High', '#ef4444', 'Critical']] },
          { emoji: '⚡', bg: 'rgba(249,115,22,.1)', title: '批量异常检测', desc: '同一用户/IP 连续敏感操作（30 分钟冷却）', chips: [['≥5次', '#eab308', '中危'], ['≥10次', '#f97316', '高危'], ['≥15次', '#ef4444', '严重']] },
        ].map(a => (
          <div key={a.title} className="pol-aux">
            <div style={{ width: 40, height: 40, borderRadius: 10, background: a.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20, flexShrink: 0 }}>{a.emoji}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{a.title}</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 8 }}>{a.desc}</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {a.chips.map(([from, color, to]) => (
                  <span key={from} className="ds3-aux-chip">{from} → <b style={{ color: color as string }}>{to}</b></span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════
// Incident detail panel - v2 deep redesign
// ═══════════════════════════════════════════
function IncidentDetail({ incident, onClose, privacyMode }: { incident: DataSecurityIncident; onClose: () => void; privacyMode: boolean }) {
  const [rs, setRs] = useState<HttpSessionItem | null>(null)
  const [rl, setRl] = useState(false)
  const [showBody, setShowBody] = useState(false)
  const sc = SEVERITY_COLOR[incident.severity] || SEVERITY_COLOR.info
  const confPct = Math.round(incident.confidence * 100)

  useEffect(() => {
    if (!incident.http_session_id) return
    let c = false
    setRl(true)
    apiFetch(`/api/data-security/http-sessions/${incident.http_session_id}`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<HttpSessionItem> | null) => { if (!c && d?.success && d.data) setRs(d.data) })
      .catch(() => {})
      .finally(() => { if (!c) setRl(false) })
    return () => { c = true }
  }, [incident.http_session_id])

  return (
    <div className="ds3-detail ds3-detail--v2">
      {/* Severity-themed hero header */}
      <div className="ds3-dtl-hero" style={{ '--sev-color': sc } as React.CSSProperties}>
        <div className="ds3-dtl-hero-glow" />
        <div className="ds3-dtl-hero-content">
          <div className="ds3-dtl-hero-left">
            <div className="ds3-dtl-sev-ring" style={{ borderColor: sc, boxShadow: `0 0 12px ${sc}33` }}>
              <span style={{ color: sc, fontWeight: 800, fontSize: 11, textTransform: 'uppercase' }}>{SEVERITY_CN[incident.severity]}</span>
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4, flexWrap: 'wrap' }}>
                <IncidentTypeBadge type={incident.incident_type} />
              </div>
              <div className="ds3-dtl-id sec-mono">
                {incident.id.slice(0, 8)} · {formatRelativeTime(incident.created_at)}
              </div>
            </div>
          </div>
          <div className="ds3-dtl-hero-right">
            {/* Confidence gauge */}
            <div className="ds3-conf-gauge" title={`置信度 ${confPct}%`}>
              <svg viewBox="0 0 44 44" width="44" height="44">
                <circle cx="22" cy="22" r="18" fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="3" />
                <circle cx="22" cy="22" r="18" fill="none" stroke={sc} strokeWidth="3"
                  strokeDasharray={`${confPct * 1.131} ${113.1 - confPct * 1.131}`}
                  strokeDashoffset="28.3" strokeLinecap="round"
                  style={{ transition: 'stroke-dasharray 0.6s ease' }} />
              </svg>
              <span className="ds3-conf-val sec-mono" style={{ color: sc }}>{confPct}</span>
            </div>
            <button className="ds3-close-btn" onClick={onClose}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
            </button>
          </div>
        </div>
      </div>

      {/* Summary */}
      <div className="ds3-dtl-summary">{incident.summary}</div>

      {/* Metadata */}
      <div className="ds3-detail-section">
        <div className="ds3-section-label">关联信息</div>
        <div className="ds3-dtl-meta">
          {([
            ['客户端 IP', privacyMode ? maskIp(incident.client_ip) : incident.client_ip,
              <svg key="ip" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" /></svg>],
            ['用户', privacyMode ? maskUser(incident.detected_user || '') || '—' : incident.detected_user || '—',
              <svg key="user" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>],
            ['主机', incident.host || '—',
              <svg key="host" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>],
          ] as [string, string, JSX.Element][]).map(([l, v, icon], i) => (
            <div key={i} className="ds3-dtl-meta-item">
              <span className="ds3-dtl-meta-icon">{icon}</span>
              <div className="ds3-dtl-meta-text">
                <span className="ds3-dtl-meta-k">{l}</span>
                <span className="ds3-dtl-meta-v sec-mono">{v}</span>
              </div>
            </div>
          ))}
        </div>
        {incident.request_url && (
          <div className="ds3-dtl-url">
            {incident.method && <MethodBadge method={incident.method} />}
            <span className="sec-mono" style={{ fontSize: 11, color: 'var(--text-secondary)', wordBreak: 'break-all', flex: 1 }}>{privacyMode ? maskUrl(incident.request_url) : incident.request_url}</span>
          </div>
        )}
      </div>

      {/* DLP Matches */}
      {incident.dlp_matches.length > 0 && (
        <div className="ds3-detail-section">
          <div className="ds3-section-label">
            敏感数据命中
            <span className="ds3-section-cnt">{incident.dlp_matches.length}</span>
          </div>
          <div className="ds3-dtl-dlp-grid">
            {incident.dlp_matches.map((m, i) => {
              const jl = DLP_JRT_LEVEL[m], jc = jl ? JRT_LEVEL_COLOR[jl] : '#ef4444'
              return (
                <div key={i} className="ds3-dtl-dlp-chip" style={{ '--dlp-c': jc } as React.CSSProperties}>
                  {jl && <span className="ds3-dtl-dlp-lv" style={{ background: jc }}>{JRT_LEVEL_LABEL[jl]}</span>}
                  <span className="ds3-dtl-dlp-name">{DLP_MATCH_CN[m] || m}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Evidence Chain */}
      {incident.evidence.length > 0 && (
        <div className="ds3-detail-section">
          <div className="ds3-section-label">
            证据链
            <span className="ds3-section-cnt">{incident.evidence.length}</span>
          </div>
          <div className="ds3-dtl-evidence">
            {incident.evidence.map((ev: Evidence, i: number) => (
              <div key={i} className="ds3-evi-row">
                <div className="ds3-evi-gutter">
                  <div className="ds3-evi-num">{i + 1}</div>
                  {i < incident.evidence.length - 1 && <div className="ds3-evi-line" />}
                </div>
                <div className="ds3-evi-content">
                  <div className="ds3-evi-desc">{ev.description}</div>
                  {ev.location && <div className="ds3-evi-loc">{ev.location}</div>}
                  {ev.snippet && <pre className="ds3-evi-snippet sec-mono">{privacyMode ? MASKED_SNIPPET : ev.snippet}</pre>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Redacted request body */}
      <div className="ds3-detail-section" style={{ paddingBottom: 20 }}>
        <button className="ds3-collapse-btn ds3-collapse-btn--v2" onClick={() => setShowBody(!showBody)}>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ transform: showBody ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s ease' }}>
            <polyline points="9 18 15 12 9 6" />
          </svg>
          <span>请求体内容</span>
          {rs && rs.request_body_size > 0 && <span className="ds3-body-sz">{formatSize(rs.request_body_size)}</span>}
        </button>
        {showBody && (
          <div className="ds3-collapse-content">
            {rl ? <div className="ds3-inline-msg">加载中...</div>
              : rs?.request_body ? <pre className="ds3-code-block">{privacyMode ? MASKED_BODY : rs.request_body}</pre>
                : rs?.uploaded_filename ? (
                  privacyMode ? (
                    <div className="ds3-privacy-notice">隐私保护已启用 — 文件名及下载已禁用</div>
                  ) : (
                  <div className="ds3-dtl-file">
                    <div className="ds3-dtl-file-info">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                      <span className="sec-mono" style={{ color: 'var(--text-primary)' }}>{rs.uploaded_filename}</span>
                      {rs.uploaded_file_size != null && <span className="ds3-dtl-file-sz">{formatSize(rs.uploaded_file_size)}</span>}
                    </div>
                    <div className="ds3-inline-msg" style={{ color: 'var(--text-secondary)', marginBottom: 10 }}>
                      {rs.body_is_binary ? '二进制请求体仅保留元数据，原始导出已禁用。' : '导出内容为服务端脱敏后的文本副本。'}
                    </div>
                    <button
                      className="ds3-dl-btn ds3-dl-btn--v2"
                      disabled={rs.body_is_binary}
                      style={rs.body_is_binary ? { opacity: 0.55, cursor: 'not-allowed' } : undefined}
                      onClick={async () => {
                      if (rs.body_is_binary) return
                      try {
                        const r = await apiFetch(`/api/data-security/http-sessions/${rs.id}/body`)
                        if (!r.ok) {
                          const message = (await r.text().catch(() => '导出失败')).trim()
                          alert(message || '导出失败')
                          return
                        }
                        const b = await r.blob(), u = URL.createObjectURL(b), a = document.createElement('a')
                        a.href = u
                        a.download = getDownloadName(r.headers, rs.uploaded_filename || 'http-request-body.redacted.txt')
                        a.click()
                        URL.revokeObjectURL(u)
                      } catch { alert('下载失败') }
                    }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
                      导出脱敏内容
                    </button>
                  </div>)
                ) : <div className="ds3-inline-msg" style={{ color: 'var(--text-tertiary)' }}>{!rs ? '无法加载' : rs.request_body_size === 0 ? '请求体为空' : '请求体未存储'}</div>}
          </div>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════
// Tab 3: Security incidents - Master-Detail v2
// ═══════════════════════════════════════════
function IncidentsTab({ selectedId, onSelect, privacyMode }: { selectedId?: string; onSelect: (id: string | null) => void; privacyMode: boolean }) {
  const [incidents, setIncidents] = useState<DataSecurityIncident[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [selectedIncident, setSelectedIncident] = useState<DataSecurityIncident | null>(null)
  const [filterType, setFilterType] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [searchText, setSearchText] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const limit = 20

  useEffect(() => {
    if (!selectedId) { setSelectedIncident(null); return }
    const local = incidents.find(i => i.id === selectedId)
    if (local) { setSelectedIncident(local); return }
    let c = false
    apiFetch(`/api/data-security/incidents/${selectedId}`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<DataSecurityIncident> | null) => { if (!c && d?.success && d.data) setSelectedIncident(d.data) })
      .catch(() => {})
    return () => { c = true }
  }, [selectedId, incidents])

  const loadIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit) })
      if (filterType) params.set('incident_type', filterType)
      if (filterSeverity) params.set('severity', filterSeverity)
      if (appliedSearch) {
        if (/^\d{1,3}\./.test(appliedSearch)) params.set('client_ip', appliedSearch)
        else if (appliedSearch.includes('@')) params.set('user', appliedSearch)
        else params.set('keyword', appliedSearch)
      }
      const r = await apiFetch(`/api/data-security/incidents?${params}`)
      if (!r.ok) return
      const d: ApiResponse<PaginatedResponse<DataSecurityIncident>> = await r.json()
      if (d.success && d.data) { setIncidents(d.data.items); setTotal(d.data.total) }
    } catch (e) { console.error('加载事件列表失败:', e) }
    finally { setLoading(false) }
  }, [page, filterType, filterSeverity, appliedSearch])

  useEffect(() => { loadIncidents() }, [loadIncidents])
  useEffect(() => { const t = setInterval(() => { if (!document.hidden) loadIncidents() }, 30000); return () => clearInterval(t) }, [loadIncidents])
  useEffect(() => { const h = () => loadIncidents(); window.addEventListener('vigilyx:ws-reconnected', h); return () => window.removeEventListener('vigilyx:ws-reconnected', h) }, [loadIncidents])

  const tp = Math.ceil(total / limit)

  // Severity distribution of current page
  const sevStats = useMemo(() => {
    const m: Record<string, number> = {}
    incidents.forEach(inc => { m[inc.severity] = (m[inc.severity] || 0) + 1 })
    return m
  }, [incidents])

  const hasActiveFilters = filterType || filterSeverity || appliedSearch

  // Page numbers generation
  const pageNums = useMemo(() => {
    if (tp <= 7) return Array.from({ length: tp }, (_, i) => i + 1)
    const pages: (number | null)[] = [1]
    const start = Math.max(2, page - 1)
    const end = Math.min(tp - 1, page + 1)
    if (start > 2) pages.push(null) // ellipsis
    for (let i = start; i <= end; i++) pages.push(i)
    if (end < tp - 1) pages.push(null) // ellipsis
    pages.push(tp)
    return pages
  }, [page, tp])

  return (
    <div className="ds3-incidents ds3-incidents--v2">
      {/* Enhanced filter bar */}
      <div className="ds3-filter-bar ds3-filter-bar--v2">
        <div className="ds3-filters-left">
          <div className="ds3-filter-group">
            <span className="ds3-filter-label">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
              类型
            </span>
            {[{ v: '', l: '全部' }, { v: 'draft_box_abuse', l: '草稿箱' }, { v: 'file_transit_abuse', l: '文件中转' }, { v: 'self_sending', l: '自发自收' }, { v: 'jrt_compliance_violation', l: '合规告警' }].map(f => (
              <button key={f.v}
                className={`ds3-filter-pill ${filterType === f.v ? 'ds3-filter-pill--active' : ''}`}
                style={f.v && filterType === f.v ? { borderColor: INCIDENT_TYPE_COLOR[f.v], color: INCIDENT_TYPE_COLOR[f.v], background: INCIDENT_TYPE_COLOR[f.v] + '10' } : undefined}
                onClick={() => { setFilterType(f.v); setPage(1) }}>{f.l}</button>
            ))}
          </div>
          <div className="ds3-filter-sep" />
          <div className="ds3-filter-group">
            <span className="ds3-filter-label">级别</span>
            {[{ v: '', l: '全部' }, { v: 'critical', l: '严重' }, { v: 'high', l: '高危' }, { v: 'medium', l: '中危' }, { v: 'low', l: '低危' }].map(f => (
              <button key={f.v}
                className={`ds3-filter-pill ${filterSeverity === f.v ? 'ds3-filter-pill--active' : ''}`}
                style={f.v && filterSeverity === f.v ? { borderColor: SEVERITY_COLOR[f.v], color: SEVERITY_COLOR[f.v], background: SEVERITY_COLOR[f.v] + '10' } : undefined}
                onClick={() => { setFilterSeverity(f.v); setPage(1) }}>{f.l}</button>
            ))}
          </div>
        </div>
        <div className="ds3-filters-right">
          <form className="ds3-search-inline" onSubmit={e => { e.preventDefault(); setAppliedSearch(searchText.trim()); setPage(1) }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)} placeholder="IP / 用户 / 关键词" />
            {appliedSearch && (
              <button type="button" className="ds3-search-clear" onClick={() => { setSearchText(''); setAppliedSearch(''); setPage(1) }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            )}
          </form>
        </div>
      </div>

      {/* Severity distribution ribbon + total count */}
      <div className="ds3-ribbon">
        <div className="ds3-ribbon-stats">
          {incidents.length > 0 && ['critical', 'high', 'medium', 'low', 'info'].map(sev => {
            const cnt = sevStats[sev] || 0
            if (cnt === 0) return null
            const c = SEVERITY_COLOR[sev]
            return (
              <span key={sev} className="ds3-ribbon-chip" style={{ color: c, background: c + '10', borderColor: c + '20' }}>
                <span className="ds3-ribbon-dot" style={{ background: c }} />
                {SEVERITY_CN[sev]} <b className="sec-mono">{cnt}</b>
              </span>
            )
          })}
          {hasActiveFilters && (
            <button className="ds3-ribbon-clear" onClick={() => { setFilterType(''); setFilterSeverity(''); setSearchText(''); setAppliedSearch(''); setPage(1) }}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              清除筛选
            </button>
          )}
        </div>
        <span className="ds3-ribbon-total sec-mono">
          共 <b>{total.toLocaleString()}</b> 条{tp > 1 && <> · 第 {page}/{tp} 页</>}
        </span>
      </div>

      {/* Master-Detail */}
      <div className="ds3-split ds3-split--v2">
        <div className="ds3-master">
          {loading ? <div className="sec-loading"><div className="sec-spinner" /></div>
            : incidents.length === 0 ? (
              <div className="ds3-empty-full ds3-empty-full--v2">
                <div className="ds3-empty-icon-wrap">
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M9 12l2 2 4-4" opacity="0.4" />
                  </svg>
                </div>
                <p className="ds3-empty-title">暂无安全事件</p>
                <p className="ds3-empty-sub">{hasActiveFilters ? '尝试调整筛选条件' : '系统运行正常，未检测到安全事件'}</p>
              </div>
            ) : (
              <div className="ds3-card-list ds3-card-list--v2">
                {incidents.map(inc => {
                  const sel = selectedIncident?.id === inc.id
                  const sevC = SEVERITY_COLOR[inc.severity] || SEVERITY_COLOR.info
                  const confPct = Math.round(inc.confidence * 100)
                  return (
                    <div key={inc.id}
                      className={`ds3-card3 ${sel ? 'ds3-card3--sel' : ''}`}
                      onClick={() => onSelect(sel ? null : inc.id)}>
                      <div className="ds3-card3-stripe" style={{ background: sevC }} />
                      <div className="ds3-card3-body">
                        {/* Row 1: badges + conf + time */}
                        <div className="ds3-card3-head">
                          <SeverityBadge severity={inc.severity} />
                          <IncidentTypeBadge type={inc.incident_type} />
                          <span className="ds3-card3-conf sec-mono" style={{ color: sevC }}>{confPct}%</span>
                          <span className="ds3-card3-time sec-mono" title={formatTime(inc.created_at)}>{formatRelativeTime(inc.created_at)}</span>
                        </div>
                        {/* Row 2: summary */}
                        <div className="ds3-card3-sum">{inc.summary}</div>
                        {/* Row 3: meta chips inline */}
                        <div className="ds3-card3-foot">
                          {inc.detected_user && (
                            <span className="ds3-card3-chip ds3-card3-chip--user">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                              {privacyMode ? maskUser(inc.detected_user) : inc.detected_user}
                            </span>
                          )}
                          <span className="ds3-card3-chip ds3-card3-chip--ip sec-mono">{privacyMode ? maskIp(inc.client_ip) : inc.client_ip}</span>
                          {inc.dlp_matches.length > 0 && inc.dlp_matches.slice(0, 2).map((m, i) => {
                            const jl = DLP_JRT_LEVEL[m], jc = jl ? JRT_LEVEL_COLOR[jl] : '#ef4444'
                            return <span key={i} className="ds3-card3-chip ds3-card3-chip--dlp" style={{ color: jc, borderColor: jc + '30', background: jc + '08' }}>{DLP_MATCH_CN[m] || m}</span>
                          })}
                          {inc.dlp_matches.length > 2 && <span className="ds3-card3-chip ds3-card3-chip--more">+{inc.dlp_matches.length - 2}</span>}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

        </div>

        <div className="ds3-detail-pane">
          {selectedIncident ? (
            <IncidentDetail incident={selectedIncident} onClose={() => onSelect(null)} privacyMode={privacyMode} />
          ) : (
            <div className="ds3-detail-empty ds3-detail-empty--v2">
              <div className="ds3-empty-shield">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <div className="ds3-empty-shield-pulse" />
              </div>
              <p className="ds3-empty-t">选择事件查看详情</p>
              <p className="ds3-empty-h">点击左侧任意事件卡片查看完整分析报告</p>
            </div>
          )}
        </div>
      </div>

      {/* Pagination — outside ds3-split so it centers across full width */}
      {tp > 1 && (
        <div className="ds3-pagination ds3-pagination--v2">
          <button className="ds3-pg-btn" disabled={page <= 1} onClick={() => setPage(1)} title="首页">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>
          </button>
          <button className="ds3-pg-btn" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))} title="上一页">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="15 18 9 12 15 6"/></svg>
          </button>
          <div className="ds3-pg-nums">
            {pageNums.map((pn, i) => pn === null
              ? <span key={`e${i}`} className="ds3-pg-ellipsis">...</span>
              : <button key={pn} className={`ds3-pg-num ${page === pn ? 'ds3-pg-num--active' : ''}`} onClick={() => setPage(pn)}>{pn}</button>
            )}
          </div>
          <button className="ds3-pg-btn" disabled={page >= tp} onClick={() => setPage(p => p + 1)} title="下一页">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          </button>
          <button className="ds3-pg-btn" disabled={page >= tp} onClick={() => setPage(tp)} title="末页">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/></svg>
          </button>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════
// Tab 4: HTTP sessions
// ═══════════════════════════════════════════
function HttpSessionsTab({ selectedId, onSelect, privacyMode }: { selectedId?: string; onSelect: (id: string | null) => void; privacyMode: boolean }) {
  const [sessions, setSessions] = useState<HttpSessionItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const expandedId = selectedId || null
  const [detailSession, setDetailSession] = useState<HttpSessionItem | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [searchText, setSearchText] = useState('')
  const [filterMethod, setFilterMethod] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const limit = 20

  const loadSessions = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(limit) })
      if (filterMethod) params.set('method', filterMethod)
      if (appliedSearch) {
        if (/^\d{1,3}\./.test(appliedSearch)) params.set('client_ip', appliedSearch)
        else if (appliedSearch.includes('@')) params.set('user', appliedSearch)
        else params.set('keyword', appliedSearch)
      }
      const r = await apiFetch(`/api/data-security/http-sessions?${params}`)
      if (!r.ok) return
      const d: ApiResponse<PaginatedResponse<HttpSessionItem>> = await r.json()
      if (d.success && d.data) { setSessions(d.data.items); setTotal(d.data.total) }
    } catch (e) { console.error('加载 HTTP 会话失败:', e) }
    finally { setLoading(false) }
  }, [page, filterMethod, appliedSearch])

  useEffect(() => { loadSessions() }, [loadSessions])
  useEffect(() => { const t = setInterval(() => { if (!document.hidden) loadSessions() }, 30000); return () => clearInterval(t) }, [loadSessions])
  useEffect(() => { const h = () => loadSessions(); window.addEventListener('vigilyx:ws-reconnected', h); return () => window.removeEventListener('vigilyx:ws-reconnected', h) }, [loadSessions])

  useEffect(() => {
    if (!expandedId) { setDetailSession(null); return }
    let c = false
    setDetailLoading(true)
    apiFetch(`/api/data-security/http-sessions/${expandedId}`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ApiResponse<HttpSessionItem> | null) => { if (!c && d?.success && d.data) setDetailSession(d.data) })
      .catch(() => {})
      .finally(() => { if (!c) setDetailLoading(false) })
    return () => { c = true }
  }, [expandedId])

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="ds3-http">
      {/* Filter bar */}
      <div className="ds3-filter-bar">
        <div className="ds3-filter-group">
          <span className="ds3-filter-label">方法</span>
          {[{ v: '', l: '全部' }, { v: 'POST', l: 'POST' }, { v: 'GET', l: 'GET' }, { v: 'PUT', l: 'PUT' }].map(f => (
            <button key={f.v}
              className={`ds3-filter-pill ${filterMethod === f.v ? 'ds3-filter-pill--active' : ''}`}
              style={f.v && filterMethod === f.v ? { borderColor: METHOD_COLOR[f.v], color: METHOD_COLOR[f.v], background: METHOD_COLOR[f.v] + '10' } : undefined}
              onClick={() => { setFilterMethod(f.v); setPage(1) }}>{f.l}</button>
          ))}
        </div>
        <form className="ds3-search-form" onSubmit={e => { e.preventDefault(); setAppliedSearch(searchText.trim()); setPage(1) }}>
          <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)}
            placeholder="IP / 用户 / URL ..." className="ds3-search-input" />
          <button type="submit" className="ds3-filter-pill">搜索</button>
          {(appliedSearch || filterMethod) && <button type="button" className="ds3-filter-pill" style={{ fontSize: 11 }} onClick={() => { setSearchText(''); setAppliedSearch(''); setFilterMethod(''); setPage(1) }}>清除</button>}
        </form>
        <span className="sec-mono" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-tertiary)' }}>共 {total.toLocaleString()} 条</span>
      </div>

      {/* Expanded details */}
      {expandedId && (() => {
        const s = detailSession || sessions.find(x => x.id === expandedId)
        if (!s) return null
        return (
          <div className="ds3-http-detail">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>HTTP 会话详情</div>
              <button className="ds3-close-btn" onClick={() => onSelect(null)}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
              </button>
            </div>
            <div className="ds3-http-detail-grid">
              {[
                ['方法', <span style={{ color: METHOD_COLOR[s.method] || 'var(--text-primary)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{s.method}</span>],
                ['状态码', <span className="sec-mono">{s.response_status ?? '—'}</span>],
                ['客户端', <span className="sec-mono">{privacyMode ? maskIp(s.client_ip) + ':***' : s.client_ip + ':' + s.client_port}</span>],
                ['服务端', <span className="sec-mono">{privacyMode ? maskIp(s.server_ip) + ':***' : s.server_ip + ':' + s.server_port}</span>],
              ].map(([l, v], i) => <div key={i} className="ds3-http-field"><span className="ds3-http-field-label">{l as string}</span>{v}</div>)}
              <div className="ds3-http-field" style={{ gridColumn: 'span 2' }}><span className="ds3-http-field-label">Content-Type</span><span className="sec-mono" style={{ fontSize: 11 }}>{s.content_type || '—'}</span></div>
              <div className="ds3-http-field"><span className="ds3-http-field-label">Body 大小</span><span className="sec-mono">{formatSize(s.request_body_size)}{s.body_is_binary ? ' (二进制)' : ''}</span></div>
              <div className="ds3-http-field"><span className="ds3-http-field-label">用户</span><span className="sec-mono">{privacyMode ? maskUser(s.detected_user || '') || '—' : s.detected_user || '—'}</span></div>
              <div className="ds3-http-field" style={{ gridColumn: '1 / -1' }}>
                <span className="ds3-http-field-label">URL</span>
                <span className="sec-mono" style={{ color: '#22d3ee', wordBreak: 'break-all', fontSize: 11 }}>{s.host && <span style={{ color: 'var(--text-tertiary)' }}>{s.host}</span>}{privacyMode ? maskUrl(s.uri) : s.uri}</span>
              </div>
              {s.uploaded_filename && (
                <div className="ds3-http-field" style={{ gridColumn: '1 / -1' }}>
                  <span className="ds3-http-field-label">上传文件</span>
                  <span style={{ color: '#f97316' }} className="sec-mono">{privacyMode ? '***' + (s.uploaded_filename.includes('.') ? '.' + s.uploaded_filename.split('.').pop() : '') : s.uploaded_filename}</span>
                  {s.file_type_mismatch && <span style={{ fontSize: 10, color: '#f97316', marginLeft: 8 }}>⚠ {s.file_type_mismatch}</span>}
                </div>
              )}
            </div>
            {detailLoading ? <div style={{ padding: 12, color: 'var(--text-tertiary)', fontSize: 12 }}>加载中...</div>
              : s.request_body ? <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginBottom: 4 }}>请求体</div>
                <pre className="ds3-code-block">{privacyMode ? MASKED_BODY : s.request_body}</pre>
              </div> : null}
          </div>
        )
      })()}

      {/* Table */}
      <div className="ds3-table-wrap">
        <table className="ds3-table">
          <thead><tr>
            <th style={{ width: 120 }}>时间</th>
            <th>客户端 IP</th>
            <th>用户</th>
            <th style={{ width: 60 }}>方法</th>
            <th>URL</th>
            <th style={{ width: 80 }}>Body</th>
            <th>上传文件</th>
          </tr></thead>
          <tbody>
            {loading ? <tr><td colSpan={7}><div className="sec-loading"><div className="sec-spinner" /></div></td></tr>
              : sessions.length === 0 ? <tr><td colSpan={7}><div className="ds3-empty-full" style={{ padding: '3rem' }}><p>暂无 HTTP 会话</p></div></td></tr>
                : sessions.map(s => (
                  <tr key={s.id} className={expandedId === s.id ? 'ds3-row--active' : ''} onClick={() => onSelect(expandedId === s.id ? null : s.id)}>
                    <td className="sec-mono" style={{ fontSize: 11 }}>{formatTime(s.timestamp)}</td>
                    <td className="sec-mono" style={{ fontSize: 12 }}>{privacyMode ? maskIp(s.client_ip) : s.client_ip}</td>
                    <td style={{ fontSize: 12 }}>{s.detected_user ? (privacyMode ? maskUser(s.detected_user) : s.detected_user) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}</td>
                    <td><MethodBadge method={s.method} /></td>
                    <td className="sec-mono ds3-url-cell">{privacyMode ? maskUrl(s.uri) : s.uri}</td>
                    <td className="sec-mono" style={{ fontSize: 12 }}>{s.request_body_size > 0 ? formatSize(s.request_body_size) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}</td>
                    <td style={{ fontSize: 12 }}>
                      {s.uploaded_filename ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ color: '#f97316', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{privacyMode ? '***' + (s.uploaded_filename.includes('.') ? '.' + s.uploaded_filename.split('.').pop() : '') : s.uploaded_filename}</span>
                          {s.file_type_mismatch && <span style={{ fontSize: 9, padding: '1px 4px', borderRadius: 3, background: 'rgba(239,68,68,0.1)', color: '#ef4444', fontWeight: 600 }}>伪装</span>}
                        </span>
                      ) : <span style={{ color: 'var(--text-tertiary)' }}>—</span>}
                    </td>
                  </tr>
                ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="ds3-pagination">
          <button className="sec-page-btn" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>上一页</button>
          <span className="sec-mono" style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>第 {page} / {totalPages} 页</span>
          <button className="sec-page-btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>下一页</button>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════
// Settings tab (/data-security/settings)
// ═══════════════════════════════════════════
function SettingsTab() {
  // -- Sniffer configuration (webmail_servers / http_ports) --
  const [servers, setServers] = useState<string[]>([])
  const [ports, setPorts] = useState<number[]>([80, 443, 8080])
  const [newServer, setNewServer] = useState('')
  const [newPort, setNewPort] = useState('')
  const [snifferSaving, setSnifferSaving] = useState(false)
  const [snifferMsg, setSnifferMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // -- Time policy configuration --
  const [tp, setTp] = useState({ enabled: true, work_hour_start: 8, work_hour_end: 18, utc_offset_hours: 8, weekend_is_off_hours: true })
  const [tpSaving, setTpSaving] = useState(false)
  const [tpMsg, setTpMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // -- Syslog forwarding configuration --
  const [sl, setSl] = useState({ enabled: false, server_address: '', port: 514, protocol: 'udp', facility: 4, format: 'rfc5424', min_severity: 'medium' })
  const [slSaving, setSlSaving] = useState(false)
  const [slMsg, setSlMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [slTesting, setSlTesting] = useState(false)

  // Load configuration
  useEffect(() => {
    apiFetch('/api/config/sniffer').then(r => r.json()).then(d => {
      if (d.success && d.data) {
        setServers(d.data.webmail_servers || [])
        setPorts(d.data.http_ports || [80, 443, 8080])
      }
    }).catch(() => {})
    apiFetch('/api/config/time-policy').then(r => r.json()).then(d => {
      if (d.success && d.data) setTp(d.data)
    }).catch(() => {})
    apiFetch('/api/config/syslog').then(r => r.json()).then(d => {
      if (d.success && d.data) setSl(d.data)
    }).catch(() => {})
  }, [])

  const addServer = useCallback(() => {
    const ips = expandIpInput(newServer)
    const valid = ips.filter(ip => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip))
    if (valid.length > 0) { setServers(prev => [...new Set([...prev, ...valid])]); setNewServer('') }
  }, [newServer])

  const addPort = useCallback(() => {
    const p = parseInt(newPort)
    if (p > 0 && p <= 65535 && !ports.includes(p)) { setPorts(prev => [...prev, p].sort((a, b) => a - b)); setNewPort('') }
  }, [newPort, ports])

  const saveSniffer = useCallback(async () => {
    setSnifferSaving(true); setSnifferMsg(null)
    try {
      const r = await apiFetch('/api/config/sniffer', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ webmail_servers: servers, http_ports: ports }) })
      const d = await r.json()
      if (d.success) { setSnifferMsg({ ok: true, text: '已保存，Sniffer 正在重启...' }); setTimeout(() => setSnifferMsg(null), 8000) }
      else setSnifferMsg({ ok: false, text: d.error || '保存失败' })
    } catch { setSnifferMsg({ ok: false, text: '网络错误' }) }
    finally { setSnifferSaving(false) }
  }, [servers, ports])

  const saveTp = useCallback(async () => {
    if (tp.work_hour_start >= tp.work_hour_end) { setTpMsg({ ok: false, text: '开始时间必须小于结束时间' }); return }
    setTpSaving(true); setTpMsg(null)
    try {
      const r = await apiFetch('/api/config/time-policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tp) })
      const d = await r.json()
      if (d.success) { setTpMsg({ ok: true, text: '时间策略已保存' }); setTimeout(() => setTpMsg(null), 5000) }
      else setTpMsg({ ok: false, text: d.error || '保存失败' })
    } catch { setTpMsg({ ok: false, text: '网络错误' }) }
    finally { setTpSaving(false) }
  }, [tp])

  return (
    <div className="ds3-settings-page">
      {/* -- Section 1: HTTP traffic capture -- */}
      <div className="ds3-settings-card">
        <div className="ds3-settings-card-head">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span>HTTP 流量捕获</span>
        </div>
        <p className="ds3-settings-card-desc">配置 Webmail 服务器 IP 和 HTTP 端口。为空时不捕获 HTTP 流量，数据安全检测无法工作。</p>

        {/* Webmail servers */}
        <div className="ds3-settings-field">
          <div className="ds3-settings-field-label">Webmail 服务器 IP</div>
          {servers.length > 0 && (
            <div className="ds3-chip-row">
              {servers.map((ip, i) => (
                <span key={i} className="ds3-chip ds3-chip--cyan">
                  {ip}
                  <button className="ds3-chip-x" onClick={() => setServers(prev => prev.filter((_, idx) => idx !== i))}>&times;</button>
                </span>
              ))}
            </div>
          )}
          <div className="ds3-input-row">
            <input className="ds3-settings-input ds3-mono" value={newServer} onChange={e => setNewServer(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addServer() }}
              placeholder="输入 IP，回车添加（支持 192.168.1.10/11 简写）" />
            <button className="ds3-settings-add ds3-settings-add--cyan" onClick={addServer}>添加</button>
          </div>
        </div>

        {/* HTTP ports */}
        <div className="ds3-settings-field">
          <div className="ds3-settings-field-label">HTTP 监听端口</div>
          <div className="ds3-chip-row">
            {ports.map((port, i) => (
              <span key={i} className="ds3-chip ds3-chip--blue">
                {port}
                <button className="ds3-chip-x" onClick={() => setPorts(prev => prev.filter((_, idx) => idx !== i))}>&times;</button>
              </span>
            ))}
          </div>
          <div className="ds3-input-row">
            <input className="ds3-settings-input ds3-mono" type="number" min={1} max={65535} style={{ width: 120, textAlign: 'center' }}
              value={newPort} onChange={e => setNewPort(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addPort() }}
              placeholder="端口号" />
            <button className="ds3-settings-add ds3-settings-add--blue" onClick={addPort}>添加</button>
          </div>
        </div>

        {snifferMsg && <div className={`ds3-settings-msg ${snifferMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{snifferMsg.text}</div>}
        <div className="ds3-settings-save-row">
          <span className="ds3-settings-warn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            保存将自动重启 Sniffer，流量捕获短暂中断约 10 秒
          </span>
          <button className="ds3-settings-save-btn" onClick={saveSniffer} disabled={snifferSaving}>
            {snifferSaving ? '保存中...' : '保存并重启 Sniffer'}
          </button>
        </div>
      </div>

      {/* -- Section 2: after-hours weighting -- */}
      <div className="ds3-settings-card">
        <div className="ds3-settings-card-head">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
          <span>非工作时间加权</span>
        </div>
        <p className="ds3-settings-card-desc">非工作时间内检出的数据安全事件严重度自动提升一级（如 Medium → High）。</p>

        <label className="ds3-settings-toggle-row">
          <span>启用严重度提升</span>
          <input type="checkbox" checked={tp.enabled} onChange={e => setTp({ ...tp, enabled: e.target.checked })} className="ds3-settings-checkbox" />
        </label>

        <div className="ds3-settings-row">
          <span className="ds3-settings-label">工作时间</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <select value={tp.work_hour_start} onChange={e => setTp({ ...tp, work_hour_start: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
              {Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, '0')}:00</option>)}
            </select>
            <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>至</span>
            <select value={tp.work_hour_end} onChange={e => setTp({ ...tp, work_hour_end: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
              {Array.from({ length: 24 }, (_, i) => i + 1).map(h => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
            </select>
          </div>
        </div>

        <div className="ds3-settings-row">
          <span className="ds3-settings-label">时区</span>
          <select value={tp.utc_offset_hours} onChange={e => setTp({ ...tp, utc_offset_hours: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
            {[[-12,'UTC-12'],[-11,'UTC-11'],[-10,'UTC-10'],[-9,'UTC-9'],[-8,'UTC-8'],[-7,'UTC-7'],[-6,'UTC-6'],[-5,'UTC-5'],[-4,'UTC-4'],[-3,'UTC-3'],[-2,'UTC-2'],[-1,'UTC-1'],[0,'UTC'],[1,'UTC+1'],[2,'UTC+2'],[3,'UTC+3'],[4,'UTC+4'],[5,'UTC+5'],[5.5,'UTC+5:30'],[6,'UTC+6'],[7,'UTC+7'],[8,'UTC+8 (中国)'],[9,'UTC+9'],[10,'UTC+10'],[11,'UTC+11'],[12,'UTC+12'],[13,'UTC+13'],[14,'UTC+14']].map(([v, l]) => (
              <option key={v} value={v}>{l as string}</option>
            ))}
          </select>
        </div>

        <label className="ds3-settings-toggle-row">
          <span>周末视为非工作时间</span>
          <input type="checkbox" checked={tp.weekend_is_off_hours} onChange={e => setTp({ ...tp, weekend_is_off_hours: e.target.checked })} className="ds3-settings-checkbox" disabled={!tp.enabled} />
        </label>

        {tpMsg && <div className={`ds3-settings-msg ${tpMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{tpMsg.text}</div>}
        <div className="ds3-settings-save-row">
          <button className="ds3-settings-save-btn" onClick={saveTp} disabled={tpSaving}>
            {tpSaving ? '保存中...' : '保存时间策略'}
          </button>
        </div>
      </div>

      {/* -- Section 3: syslog forwarding -- */}
      <SyslogCard sl={sl} setSl={setSl} slSaving={slSaving} setSlSaving={setSlSaving} slMsg={slMsg} setSlMsg={setSlMsg} slTesting={slTesting} setSlTesting={setSlTesting} />
    </div>
  )
}

// ═══════════════════════════════════════════
// Shared syslog configuration card
// ═══════════════════════════════════════════
function SyslogCard({ sl, setSl, slSaving, setSlSaving, slMsg, setSlMsg, slTesting, setSlTesting }: {
  sl: { enabled: boolean; server_address: string; port: number; protocol: string; facility: number; format: string; min_severity: string }
  setSl: (v: typeof sl) => void
  slSaving: boolean; setSlSaving: (v: boolean) => void
  slMsg: { ok: boolean; text: string } | null; setSlMsg: (v: { ok: boolean; text: string } | null) => void
  slTesting: boolean; setSlTesting: (v: boolean) => void
}) {
  const saveSl = useCallback(async () => {
    if (sl.enabled && !sl.server_address) { setSlMsg({ ok: false, text: '请填写服务器地址' }); return }
    setSlSaving(true); setSlMsg(null)
    try {
      const r = await apiFetch('/api/config/syslog', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
      const d = await r.json()
      if (d.success) { setSlMsg({ ok: true, text: 'Syslog 配置已保存，重启引擎后生效' }); setTimeout(() => setSlMsg(null), 8000) }
      else setSlMsg({ ok: false, text: d.error || '保存失败' })
    } catch { setSlMsg({ ok: false, text: '网络错误' }) }
    finally { setSlSaving(false) }
  }, [sl, setSlSaving, setSlMsg])

  const testSl = useCallback(async () => {
    setSlTesting(true); setSlMsg(null)
    try {
      const r = await apiFetch('/api/config/syslog/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
      const d = await r.json()
      setSlMsg({ ok: d.success, text: d.success ? d.data : (d.error || '测试失败') })
    } catch { setSlMsg({ ok: false, text: '网络错误' }) }
    finally { setSlTesting(false) }
    setTimeout(() => setSlMsg(null), 8000)
  }, [sl, setSlTesting, setSlMsg])

  return (
    <div className="ds3-settings-card">
      <div className="ds3-settings-card-head">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
        <span>Syslog 事件转发</span>
      </div>
      <p className="ds3-settings-card-desc">将数据安全事件通过 Syslog 协议转发到外部 SIEM / 日志平台。保存后重启引擎生效。</p>

      <div className="ds3-settings-row" style={{ marginBottom: 16 }}>
        <span className="ds3-settings-label">启用转发</span>
        <label className="tp-switch">
          <input type="checkbox" checked={sl.enabled} onChange={e => setSl({ ...sl, enabled: e.target.checked })} />
          <span className="tp-switch-track" />
        </label>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px', gap: 12, marginBottom: 12 }}>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">服务器地址</div>
          <input className="ds3-settings-input ds3-mono" value={sl.server_address} onChange={e => setSl({ ...sl, server_address: e.target.value })} placeholder="IP 或主机名" disabled={!sl.enabled} />
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">端口</div>
          <input className="ds3-settings-input ds3-mono" type="number" min={1} max={65535} value={sl.port} onChange={e => setSl({ ...sl, port: Number(e.target.value) })} disabled={!sl.enabled} style={{ textAlign: 'center' }} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">协议</div>
          <select className="ds3-settings-select" value={sl.protocol} onChange={e => setSl({ ...sl, protocol: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
          </select>
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">消息格式</div>
          <select className="ds3-settings-select" value={sl.format} onChange={e => setSl({ ...sl, format: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="rfc5424">RFC 5424</option>
            <option value="rfc3164">RFC 3164</option>
          </select>
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">最低严重度</div>
          <select className="ds3-settings-select" value={sl.min_severity} onChange={e => setSl({ ...sl, min_severity: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="info">Info</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      <div className="ds3-settings-field" style={{ margin: '0 0 16px 0' }}>
        <div className="ds3-settings-field-label">Facility</div>
        <select className="ds3-settings-select" value={sl.facility} onChange={e => setSl({ ...sl, facility: Number(e.target.value) })} disabled={!sl.enabled} style={{ width: 200 }}>
          {[[0,'kern'],[1,'user'],[4,'auth'],[10,'authpriv'],[13,'audit'],[16,'local0'],[17,'local1'],[18,'local2'],[19,'local3'],[20,'local4'],[21,'local5'],[22,'local6'],[23,'local7']].map(([v, l]) => (
            <option key={v} value={v}>{v} — {l as string}</option>
          ))}
        </select>
      </div>

      {slMsg && <div className={`ds3-settings-msg ${slMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{slMsg.text}</div>}
      <div className="ds3-settings-save-row">
        <button className="ds3-settings-add ds3-settings-add--blue" onClick={testSl} disabled={!sl.enabled || !sl.server_address || slTesting}>
          {slTesting ? '测试中...' : '测试连接'}
        </button>
        <button className="ds3-settings-save-btn" onClick={saveSl} disabled={slSaving}>
          {slSaving ? '保存中...' : '保存 Syslog 配置'}
        </button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════
// Portal-only: after-hours weighting settings
// ═══════════════════════════════════════════
function TimePolicyTab() {
  const [tp, setTp] = useState({ enabled: true, work_hour_start: 8, work_hour_end: 18, utc_offset_hours: 8, weekend_is_off_hours: true })
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Syslog
  const [sl, setSl] = useState({ enabled: false, server_address: '', port: 514, protocol: 'udp', facility: 4, format: 'rfc5424', min_severity: 'medium' })
  const [slSaving, setSlSaving] = useState(false)
  const [slMsg, setSlMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [slTesting, setSlTesting] = useState(false)

  useEffect(() => {
    apiFetch('/api/config/time-policy').then(r => r.json()).then(d => {
      if (d.success && d.data) setTp(d.data)
    }).catch(() => {})
    apiFetch('/api/config/syslog').then(r => r.json()).then(d => {
      if (d.success && d.data) setSl(d.data)
    }).catch(() => {})
  }, [])

  const save = useCallback(async () => {
    if (tp.work_hour_start >= tp.work_hour_end) { setMsg({ ok: false, text: '开始时间必须小于结束时间' }); return }
    setSaving(true); setMsg(null)
    try {
      const r = await apiFetch('/api/config/time-policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tp) })
      const d = await r.json()
      if (d.success) { setMsg({ ok: true, text: '时间策略已保存' }); setTimeout(() => setMsg(null), 5000) }
      else setMsg({ ok: false, text: d.error || '保存失败' })
    } catch { setMsg({ ok: false, text: '网络错误' }) }
    finally { setSaving(false) }
  }, [tp])

  return (
    <div className="tp-center">
      {/* -- Time policies -- */}
      <div className="tp-card">
        <div className="tp-header">
          <div className="tp-icon-wrap">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
          </div>
          <div>
            <h3 className="tp-title">非工作时间加权</h3>
            <p className="tp-subtitle">非工作时间内检出的邮件安全事件，严重度自动提升一级</p>
          </div>
        </div>

        <div className="tp-body">
          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">启用严重度提升</span>
              <label className="tp-switch">
                <input type="checkbox" checked={tp.enabled} onChange={e => setTp({ ...tp, enabled: e.target.checked })} />
                <span className="tp-switch-track" />
              </label>
            </div>
            <p className="tp-field-hint">开启后，非工作时间事件等级自动 +1（如 Medium → High，最高 Critical）</p>
          </div>

          <div className="tp-divider" />

          <div className="tp-field">
            <span className="tp-field-label">工作时间段</span>
            <div className="tp-time-row">
              <select value={tp.work_hour_start} onChange={e => setTp({ ...tp, work_hour_start: Number(e.target.value) })} className="tp-select" disabled={!tp.enabled}>
                {Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, '0')}:00</option>)}
              </select>
              <span className="tp-time-sep">—</span>
              <select value={tp.work_hour_end} onChange={e => setTp({ ...tp, work_hour_end: Number(e.target.value) })} className="tp-select" disabled={!tp.enabled}>
                {Array.from({ length: 24 }, (_, i) => i + 1).map(h => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
              </select>
            </div>
          </div>

          <div className="tp-field">
            <span className="tp-field-label">时区</span>
            <select value={tp.utc_offset_hours} onChange={e => setTp({ ...tp, utc_offset_hours: Number(e.target.value) })} className="tp-select tp-select--wide" disabled={!tp.enabled}>
              {[[-12,'UTC-12'],[-11,'UTC-11'],[-10,'UTC-10'],[-9,'UTC-9'],[-8,'UTC-8'],[-7,'UTC-7'],[-6,'UTC-6'],[-5,'UTC-5'],[-4,'UTC-4'],[-3,'UTC-3'],[-2,'UTC-2'],[-1,'UTC-1'],[0,'UTC'],[1,'UTC+1'],[2,'UTC+2'],[3,'UTC+3'],[4,'UTC+4'],[5,'UTC+5'],[5.5,'UTC+5:30'],[6,'UTC+6'],[7,'UTC+7'],[8,'UTC+8 (中国)'],[9,'UTC+9'],[10,'UTC+10'],[11,'UTC+11'],[12,'UTC+12'],[13,'UTC+13'],[14,'UTC+14']].map(([v, l]) => (
                <option key={v} value={v}>{l as string}</option>
              ))}
            </select>
          </div>

          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">周末视为非工作时间</span>
              <label className="tp-switch">
                <input type="checkbox" checked={tp.weekend_is_off_hours} onChange={e => setTp({ ...tp, weekend_is_off_hours: e.target.checked })} disabled={!tp.enabled} />
                <span className="tp-switch-track" />
              </label>
            </div>
          </div>
        </div>

        {msg && <div className={`tp-msg ${msg.ok ? 'tp-msg--ok' : 'tp-msg--err'}`}>{msg.text}</div>}
        <div className="tp-footer">
          <button className="tp-save" onClick={save} disabled={saving}>
            {saving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>

      {/* ── Syslog ── */}
      <div className="tp-card tp-card--blue">
        <div className="tp-header">
          <div className="tp-icon-wrap tp-icon-wrap--blue">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
          </div>
          <div>
            <h3 className="tp-title">Syslog 事件转发</h3>
            <p className="tp-subtitle">将数据安全事件通过 Syslog 协议转发到外部 SIEM / 日志平台</p>
          </div>
        </div>

        <div className="tp-body">
          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">启用转发</span>
              <label className="tp-switch tp-switch--blue">
                <input type="checkbox" checked={sl.enabled} onChange={e => setSl({ ...sl, enabled: e.target.checked })} />
                <span className="tp-switch-track" />
              </label>
            </div>
          </div>

          <div className="tp-divider" />

          <div className="tp-grid tp-grid--2">
            <div className="tp-field">
              <span className="tp-field-label">服务器地址</span>
              <input className="tp-input" value={sl.server_address} onChange={e => setSl({ ...sl, server_address: e.target.value })} placeholder="IP 或主机名" disabled={!sl.enabled} />
            </div>
            <div className="tp-field">
              <span className="tp-field-label">端口</span>
              <input className="tp-input tp-input--center" type="number" min={1} max={65535} value={sl.port} onChange={e => setSl({ ...sl, port: Number(e.target.value) })} disabled={!sl.enabled} />
            </div>
          </div>

          <div className="tp-grid tp-grid--3">
            <div className="tp-field">
              <span className="tp-field-label">协议</span>
              <select className="tp-select tp-select--wide" value={sl.protocol} onChange={e => setSl({ ...sl, protocol: e.target.value })} disabled={!sl.enabled}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
              </select>
            </div>
            <div className="tp-field">
              <span className="tp-field-label">消息格式</span>
              <select className="tp-select tp-select--wide" value={sl.format} onChange={e => setSl({ ...sl, format: e.target.value })} disabled={!sl.enabled}>
                <option value="rfc5424">RFC 5424</option>
                <option value="rfc3164">RFC 3164</option>
              </select>
            </div>
            <div className="tp-field">
              <span className="tp-field-label">最低严重度</span>
              <select className="tp-select tp-select--wide" value={sl.min_severity} onChange={e => setSl({ ...sl, min_severity: e.target.value })} disabled={!sl.enabled}>
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div className="tp-field">
            <span className="tp-field-label">Facility</span>
            <select className="tp-select" value={sl.facility} onChange={e => setSl({ ...sl, facility: Number(e.target.value) })} disabled={!sl.enabled} style={{ width: 200 }}>
              {[[0,'kern'],[1,'user'],[4,'auth'],[10,'authpriv'],[13,'audit'],[16,'local0'],[17,'local1'],[18,'local2'],[19,'local3'],[20,'local4'],[21,'local5'],[22,'local6'],[23,'local7']].map(([v, l]) => (
                <option key={v} value={v}>{v} — {l as string}</option>
              ))}
            </select>
          </div>
        </div>

        {slMsg && <div className={`tp-msg ${slMsg.ok ? 'tp-msg--ok' : 'tp-msg--err'}`}>{slMsg.text}</div>}
        <div className="tp-footer">
          <button className="tp-btn-outline" onClick={async () => {
            setSlTesting(true); setSlMsg(null)
            try {
              const r = await apiFetch('/api/config/syslog/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
              const d = await r.json()
              setSlMsg({ ok: d.success, text: d.success ? d.data : (d.error || '测试失败') })
            } catch { setSlMsg({ ok: false, text: '网络错误' }) }
            finally { setSlTesting(false) }
            setTimeout(() => setSlMsg(null), 8000)
          }} disabled={!sl.enabled || !sl.server_address || slTesting}>
            {slTesting ? '测试中...' : '测试连接'}
          </button>
          <button className="tp-save tp-save--blue" onClick={async () => {
            if (sl.enabled && !sl.server_address) { setSlMsg({ ok: false, text: '请填写服务器地址' }); return }
            setSlSaving(true); setSlMsg(null)
            try {
              const r = await apiFetch('/api/config/syslog', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
              const d = await r.json()
              if (d.success) { setSlMsg({ ok: true, text: 'Syslog 配置已保存' }); setTimeout(() => setSlMsg(null), 5000) }
              else setSlMsg({ ok: false, text: d.error || '保存失败' })
            } catch { setSlMsg({ ok: false, text: '网络错误' }) }
            finally { setSlSaving(false) }
          }} disabled={slSaving}>
            {slSaving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════
// Main component
// ═══════════════════════════════════════════
export default function DataSecurity() {
  const location = useLocation()
  const navigate = useNavigate()

  // Support both /data-security/* and /portal/* path prefixes
  const basePath = location.pathname.startsWith('/portal') ? '/portal' : '/data-security'

  const { activeTab, selectedId } = useMemo(() => {
    const s = location.pathname.replace(new RegExp(`^${basePath}\\/?`), '')
    if (s === 'policy') return { activeTab: 'policy' as TabKey, selectedId: undefined }
    if (s.startsWith('incidents/')) return { activeTab: 'incidents' as TabKey, selectedId: s.replace('incidents/', '') }
    if (s === 'incidents') return { activeTab: 'incidents' as TabKey, selectedId: undefined }
    if (s.startsWith('http-sessions/')) return { activeTab: 'http-sessions' as TabKey, selectedId: s.replace('http-sessions/', '') }
    if (s === 'http-sessions') return { activeTab: 'http-sessions' as TabKey, selectedId: undefined }
    if (s === 'settings' || s === 'time-policy') return { activeTab: 'settings' as TabKey, selectedId: undefined }
    return { activeTab: 'overview' as TabKey, selectedId: undefined }
  }, [location.pathname, basePath])

  const isPortal = basePath === '/portal'

  const setActiveTab = useCallback((tab: TabKey) => {
    const settingsPath = isPortal ? `${basePath}/time-policy` : `${basePath}/settings`
    const routes: Record<TabKey, string> = { overview: basePath, policy: `${basePath}/policy`, incidents: `${basePath}/incidents`, 'http-sessions': `${basePath}/http-sessions`, settings: settingsPath }
    navigate(routes[tab])
  }, [navigate, basePath, isPortal])

  const [privacyMode, setPrivacyMode] = useState(() => localStorage.getItem(PRIVACY_KEY) !== 'false')
  const togglePrivacy = useCallback(() => {
    setPrivacyMode(prev => { const next = !prev; localStorage.setItem(PRIVACY_KEY, String(next)); return next })
  }, [])
  // Portal mode enforces privacy protection regardless of localStorage
  const effectivePrivacy = isPortal ? true : privacyMode

  const [stats, setStats] = useState<DataSecurityStats | null>(null)
  const [engineStatus, setEngineStatus] = useState<DataSecurityEngineStatus | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)

  const loadStats = useCallback(async () => {
    try {
      const [sr, er] = await Promise.all([apiFetch('/api/data-security/stats'), apiFetch('/api/data-security/engine-status')])
      if (!sr.ok || !er.ok) { setLoadFailed(true); return }
      const sd: ApiResponse<DataSecurityStats> = await sr.json()
      const ed: ApiResponse<DataSecurityEngineStatus> = await er.json()
      if (sd.success && sd.data) { setStats(sd.data); setLoadFailed(false) }
      if (ed.success && ed.data) setEngineStatus(ed.data)
    } catch { setLoadFailed(true) }
  }, [])

  const dbRef = useRef<number | null>(null)
  const dbLoad = useCallback(() => {
    if (dbRef.current) return
    dbRef.current = window.setTimeout(() => { dbRef.current = null; loadStats() }, 3000)
  }, [loadStats])

  useEffect(() => { const h = () => dbLoad(); window.addEventListener('vigilyx:dashboard-refresh', h); return () => window.removeEventListener('vigilyx:dashboard-refresh', h) }, [dbLoad])
  useEffect(() => { const h = () => loadStats(); window.addEventListener('vigilyx:ws-reconnected', h); return () => window.removeEventListener('vigilyx:ws-reconnected', h) }, [loadStats])
  useEffect(() => { loadStats(); const t = setInterval(loadStats, 15000); return () => clearInterval(t) }, [loadStats])

  const tabs: [TabKey, string, JSX.Element, number?][] = [
    ['overview', '概览', <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>],
    ['incidents', '安全事件', <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>, stats?.total_incidents],
    ['http-sessions', 'HTTP 会话', <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>],
    ['policy', '安全策略', <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>],
    ['settings', '设置', <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" /></svg>],
  ]

  return (
    <div className="sec-content ds3-page">
      <div className="ds3-tabs">
        {tabs.map(([k, l, ic, cnt]) => (
          <button key={k} className={`ds3-tab ${activeTab === k ? 'ds3-tab--active' : ''}`} onClick={() => setActiveTab(k)}>
            <span className="ds3-tab-icon">{ic}</span>
            {l}
            {cnt != null && cnt > 0 && <span className="ds3-tab-count">{cnt > 999 ? '999+' : cnt}</span>}
          </button>
        ))}

        {!isPortal && <button
          className={`ds3-privacy-toggle ${privacyMode ? 'ds3-privacy-toggle--active' : ''}`}
          onClick={togglePrivacy}
          title={privacyMode ? '隐私保护已开启 — 点击关闭' : '隐私保护已关闭 — 点击开启'}
        >
          {privacyMode
            ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" /><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
            : <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>}
          <span style={{ fontSize: 12 }}>{privacyMode ? '隐私保护' : '明文显示'}</span>
        </button>}
      </div>
      {activeTab === 'overview' && <OverviewTab stats={stats} engineStatus={engineStatus} loadFailed={loadFailed} />}
      {activeTab === 'policy' && <PolicyTab />}
      {activeTab === 'incidents' && <IncidentsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/incidents/${id}` : `${basePath}/incidents`)} privacyMode={effectivePrivacy} />}
      {activeTab === 'http-sessions' && <HttpSessionsTab selectedId={selectedId} onSelect={id => navigate(id ? `${basePath}/http-sessions/${id}` : `${basePath}/http-sessions`)} privacyMode={effectivePrivacy} />}
      {activeTab === 'settings' && (isPortal ? <TimePolicyTab /> : <SettingsTab />)}
    </div>
  )
}
