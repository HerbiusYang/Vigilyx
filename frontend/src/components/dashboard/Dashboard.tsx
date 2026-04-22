import React, { useState, useEffect, useCallback, useRef, useMemo, startTransition } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { ApiResponse, SecurityStats, ExternalLoginStats, VerdictWithMeta } from '../../types'
import { useSystemMetrics } from '../../hooks/useSystemMetrics'
import { useRealtimeTraffic } from '../../hooks/useRealtimeTraffic'
import { decodeMimeWord } from '../../utils/mime'
import { formatBytes, formatDate, formatHourLabel, getRelativeTime } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'


/** Module-level constant helper to avoid recreating it on every render. */
function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

const THREAT_LEVELS = [
  { key: 'safe', color: '#22c55e' },
  { key: 'low', color: '#3b82f6' },
  { key: 'medium', color: '#eab308' },
  { key: 'high', color: '#f97316' },
  { key: 'critical', color: '#ef4444' },
]

/** Threat level -> badge color class. */
function threatBadgeClass(level: string | null | undefined): string {
  switch (level) {
    case 'safe': return 'thr-safe'
    case 'low': return 'thr-low'
    case 'medium': return 'thr-med'
    case 'high': return 'thr-high'
    case 'critical': return 'thr-crit'
    default: return ''
  }
}

interface LoginChartBar {
  pct: number
  hourLabel: string
  showLabel: boolean
  smtp: number
  pop3: number
  imap: number
  http: number
  tooltip: string
}

const DashboardBanner = React.memo(function DashboardBanner({
  connected,
  effectivePps,
  effectiveBps,
}: {
  connected: boolean
  effectivePps: number
  effectiveBps: number
}) {
  const { t } = useTranslation()
  return (
    <div className={`db-banner ${connected ? 'online' : ''}`}>
      <div className="db-banner-left">
        <span className="db-pulse-dot" />
        <span className="db-banner-label">{connected ? t('dashboard.monitoring') : t('dashboard.disconnected')}</span>
      </div>
      <div className="db-banner-right">
        <div className="db-throughput">
          <span className="db-throughput-val">{effectivePps}</span>
          <span className="db-throughput-unit">pkt/s</span>
        </div>
        <div className="db-banner-divider" />
        <div className="db-throughput">
          <span className="db-throughput-val">{formatBytes(effectiveBps)}</span>
          <span className="db-throughput-unit">/s</span>
        </div>
      </div>
    </div>
  )
})

const RealtimeTrafficSection = React.memo(function RealtimeTrafficSection() {
  const { stats, connected } = useRealtimeTraffic()

  const trafficDerived = useMemo(() => {
    const totalSessions = stats?.total_sessions ?? 0
    const activeSessions = stats?.active_sessions ?? 0
    const totalBytes = stats?.total_bytes ?? 0
    const totalPackets = stats?.total_packets ?? 0
    const smtpSessions = stats?.smtp_sessions ?? 0
    const pop3Sessions = stats?.pop3_sessions ?? 0
    const imapSessions = stats?.imap_sessions ?? 0
    const protocolTotal = smtpSessions + pop3Sessions + imapSessions
    const smtpPct = protocolTotal > 0 ? Math.round((smtpSessions / protocolTotal) * 100) : 0
    const pop3Pct = protocolTotal > 0 ? Math.round((pop3Sessions / protocolTotal) * 100) : 0
    const imapPct = protocolTotal > 0 ? (100 - smtpPct - pop3Pct) : 0
    const effectivePps = Math.round(stats?.packets_per_second ?? 0)
    const effectiveBps = Math.round(stats?.bytes_per_second ?? 0)

    return {
      totalSessions,
      activeSessions,
      totalBytes,
      totalPackets,
      smtpSessions,
      pop3Sessions,
      imapSessions,
      protocolTotal,
      smtpPct,
      pop3Pct,
      imapPct,
      effectivePps,
      effectiveBps,
    }
  }, [stats])

  return (
    <>
      <DashboardBanner
        connected={connected}
        effectivePps={trafficDerived.effectivePps}
        effectiveBps={trafficDerived.effectiveBps}
      />
      <TrafficStatsCard
        totalSessions={trafficDerived.totalSessions}
        protocolTotal={trafficDerived.protocolTotal}
        smtpSessions={trafficDerived.smtpSessions}
        pop3Sessions={trafficDerived.pop3Sessions}
        imapSessions={trafficDerived.imapSessions}
        totalPackets={trafficDerived.totalPackets}
        effectivePps={trafficDerived.effectivePps}
        totalBytes={trafficDerived.totalBytes}
        effectiveBps={trafficDerived.effectiveBps}
        activeSessions={trafficDerived.activeSessions}
        connected={connected}
      />
      <ProtocolDistributionCard
        smtpPct={trafficDerived.smtpPct}
        pop3Pct={trafficDerived.pop3Pct}
        imapPct={trafficDerived.imapPct}
        smtpSessions={trafficDerived.smtpSessions}
        pop3Sessions={trafficDerived.pop3Sessions}
        imapSessions={trafficDerived.imapSessions}
      />
    </>
  )
})

const SecurityHeroCard = React.memo(function SecurityHeroCard({
  hasThreats,
  securityScore,
  scoreColor,
  totalScanned,
  secStats,
  secMaxCount,
}: {
  hasThreats: boolean
  securityScore: number | null
  scoreColor: string
  totalScanned: number
  secStats: SecurityStats | null
  secMaxCount: number
}) {
  const { stats, connected } = useRealtimeTraffic()
  const { t } = useTranslation()
  const activeSessions = stats?.active_sessions ?? 0

  return (
    <div className={`db-card db-sec-hero ${hasThreats ? 'alert' : ''}`} style={{ gridArea: 'sec' }}>
      <div className="db-sec-ring-zone">
        <div className="db-sec-ring-wrap">
          <svg className="db-sec-ring" viewBox="0 0 36 36">
            <circle cx="18" cy="18" r="15.9" fill="none" stroke="var(--bg-tertiary)" strokeWidth="2.4" />
            <circle
              cx="18"
              cy="18"
              r="15.9"
              fill="none"
              stroke={scoreColor}
              strokeWidth="2.4"
              strokeDasharray={`${securityScore ?? 0} 100`}
              strokeLinecap="round"
              style={{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%', transition: 'stroke-dasharray 0.8s ease, stroke 0.4s' }}
            />
          </svg>
          <div className="db-sec-ring-center">
            <span className="db-sec-ring-val" style={{ color: scoreColor }}>
              {securityScore !== null ? securityScore : '--'}
            </span>
            <span className="db-sec-ring-pct">{securityScore !== null ? '%' : ''}</span>
          </div>
        </div>
        <span className="db-sec-ring-label">{t('dashboard.securityScore')}</span>
      </div>

      <div className="db-sec-dist-zone">
        <div className="db-sec-dist-header">
          <div className="db-section-left">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <h3 className="db-section-title">{t('dashboard.threatDistribution')}</h3>
          </div>
          {totalScanned > 0 && (
            <span className="db-sec-total-badge">{totalScanned.toLocaleString()} {t('dashboard.emailUnit')}</span>
          )}
        </div>
        <div className="db-sec-bars">
          {THREAT_LEVELS.map(lv => {
            const count = secStats?.level_counts?.[lv.key] ?? 0
            const pct = secMaxCount > 0 ? (count / secMaxCount) * 100 : 0
            return (
              <div key={lv.key} className="db-sec-row">
                <span className="db-sec-label" style={{ color: lv.color }}>{t('dashboard.threat.' + lv.key)}</span>
                <div className="db-sec-track">
                  <div className="db-sec-fill" style={{
                    width: `${Math.max(2, pct)}%`,
                    background: `linear-gradient(90deg, ${lv.color}cc, ${lv.color})`,
                  }} />
                </div>
                <span className="db-sec-count">{count}</span>
              </div>
            )
          })}
        </div>
        <div className="db-sec-footnote">
          {secStats && secStats.high_threats_24h > 0 ? (
            <span className="db-sec-alert-tag">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              24h {t('dashboard.highThreatsPrefix')}: {secStats.high_threats_24h}
            </span>
          ) : (
            <span className="db-sec-ok-tag">{t('dashboard.noHighThreats24h')}</span>
          )}
        </div>
      </div>

      <div className="db-sec-kpi-zone">
        <div className="db-sec-kpi-item">
          <span className="db-sec-kpi-num">{totalScanned.toLocaleString()}</span>
          <span className="db-sec-kpi-label">{t('dashboard.analyzed')}</span>
        </div>
        <div className="db-sec-kpi-item">
          <div className="db-sec-kpi-live">
            <span className="db-sec-kpi-num">{activeSessions}</span>
            {connected && <span className="db-sec-live-dot" />}
          </div>
          <span className="db-sec-kpi-label">{t('dashboard.activeSessions')}</span>
        </div>
        <div className="db-sec-kpi-item">
          <span className="db-sec-kpi-num">{secStats?.ioc_count ?? 0}</span>
          <span className="db-sec-kpi-label">{t('dashboard.iocHits')}</span>
        </div>
        <Link to="/security" className="db-link db-sec-link">{t('dashboard.details')}</Link>
      </div>
    </div>
  )
})

const LoginCard = React.memo(function LoginCard({
  loginStats,
  loginChartData,
}: {
  loginStats: ExternalLoginStats | null
  loginChartData: LoginChartBar[]
}) {
  const { t } = useTranslation()
  return (
    <div className="db-card db-login" style={{ gridArea: 'login' }}>
      <div className="db-section-header">
        <div className="db-section-left">
          <span className="db-section-icon amber">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          </span>
          <h3 className="db-section-title">{t('dashboard.externalLogin24h')}</h3>
        </div>
        <div className="db-login-summary">
          <span className="db-login-num">{loginStats?.total_24h.toLocaleString() ?? '0'}</span>
          <span className="db-login-unit">{t('dashboard.timesUnit')}</span>
          <span className="db-login-sep">/</span>
          <span className="db-login-users">{loginStats?.unique_ips_24h ?? 0} IP</span>
          {loginStats && loginStats.failed_24h > 0 && (
            <span className="db-fail-badge">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {loginStats.failed_24h} {t('dashboard.failed')}
            </span>
          )}
        </div>
      </div>
      <div className="db-login-protos">
        <span className="db-proto-badge smtp"><span className="db-proto-dot" />SMTP <b>{loginStats?.smtp_24h?.toLocaleString() ?? 0}</b></span>
        <span className="db-proto-badge pop3"><span className="db-proto-dot" />POP3 <b>{loginStats?.pop3_24h?.toLocaleString() ?? 0}</b></span>
        <span className="db-proto-badge imap"><span className="db-proto-dot" />IMAP <b>{loginStats?.imap_24h?.toLocaleString() ?? 0}</b></span>
        <span className="db-proto-badge http"><span className="db-proto-dot" />HTTP <b>{loginStats?.http_24h?.toLocaleString() ?? 0}</b></span>
      </div>
      <div className="db-chart-wrap">
        <div className="db-chart">
          {loginChartData.length > 0 ? loginChartData.map((bar, i) => (
            <div key={i} className="db-bar-col">
              <div
                className="db-bar-stack"
                style={{ height: `${bar.pct}%` }}
                data-tooltip={bar.tooltip}
              >
                {bar.imap > 0 && <div className="db-bar-seg imap" style={{ flex: bar.imap }} />}
                {bar.pop3 > 0 && <div className="db-bar-seg pop3" style={{ flex: bar.pop3 }} />}
                {bar.smtp > 0 && <div className="db-bar-seg smtp" style={{ flex: bar.smtp }} />}
                {bar.http > 0 && <div className="db-bar-seg http" style={{ flex: bar.http }} />}
              </div>
              {bar.showLabel
                ? <span className="db-bar-label">{bar.hourLabel}</span>
                : <span className="db-bar-spacer" />}
            </div>
          )) : (
            <div className="db-chart-empty">{t('dashboard.noLoginData')}</div>
          )}
        </div>
      </div>
    </div>
  )
})

const RecentThreatsCard = React.memo(function RecentThreatsCard({
  loading,
  recentThreats,
}: {
  loading: boolean
  recentThreats: VerdictWithMeta[]
}) {
  const { t } = useTranslation()
  const [minuteTick, setMinuteTick] = useState(0)

  useEffect(() => {
    const timer = window.setInterval(() => {
      setMinuteTick(tick => tick + 1)
    }, 60_000)
    return () => window.clearInterval(timer)
  }, [])

  const feedItems = useMemo(() => recentThreats.map(v => ({
    verdictId: v.verdict_id,
    sessionId: v.session_id,
    protocolClass: v.protocol ? v.protocol.toLowerCase() : null,
    protocol: v.protocol,
    threatClass: threatBadgeClass(v.threat_level),
    subject: decodeMimeWord(v.subject) || t('notify.noSubject'),
    createdAt: v.created_at,
    relativeTime: getRelativeTime(v.created_at),
    mailFrom: v.mail_from || t('dashboard.unknown'),
  })), [recentThreats, minuteTick, t])

  return (
    <div className="db-card db-feed" style={{ gridArea: 'feed' }}>
      <div className="db-section-header">
        <div className="db-section-left">
          <span className="db-section-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          </span>
          <h3 className="db-section-title">{t('dashboard.emailSecurityEvents')}</h3>
        </div>
        <Link to="/security/risk" className="db-link">{t('dashboard.viewAll')}</Link>
      </div>
      <div className="db-feed-list">
        {loading ? (
          [1, 2, 3].map(i => (
            <div key={i} className="db-feed-skeleton">
              <div className="skeleton-line wide" />
              <div className="skeleton-line medium" />
            </div>
          ))
        ) : feedItems.length === 0 ? (
          <div className="db-empty">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ opacity: 0.3 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>{t('dashboard.noMediumAboveEvents')}</span>
          </div>
        ) : (
          feedItems.map(item => (
            <Link key={item.verdictId} to={`/emails/${item.sessionId}`} className="db-feed-item">
              <div className="db-feed-top">
                {item.protocol && item.protocolClass && <span className={`protocol-badge-sm ${item.protocolClass}`}>{item.protocol}</span>}
                {item.threatClass && <span className={`db-thr-dot ${item.threatClass}`} />}
                <span className="db-feed-subject">{item.subject}</span>
                <span className="db-feed-time" title={formatDate(item.createdAt)}>{item.relativeTime}</span>
              </div>
              <span className="db-feed-from">{item.mailFrom}</span>
            </Link>
          ))
        )}
      </div>
    </div>
  )
})

const TrafficStatsCard = React.memo(function TrafficStatsCard({
  totalSessions,
  protocolTotal,
  smtpSessions,
  pop3Sessions,
  imapSessions,
  totalPackets,
  effectivePps,
  totalBytes,
  effectiveBps,
  activeSessions,
  connected,
}: {
  totalSessions: number
  protocolTotal: number
  smtpSessions: number
  pop3Sessions: number
  imapSessions: number
  totalPackets: number
  effectivePps: number
  totalBytes: number
  effectiveBps: number
  activeSessions: number
  connected: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="db-card db-stats" style={{ gridArea: 'stats' }}>
      <div className="db-section-left db-stats-title">
        <span className="db-section-icon">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </span>
        <h3 className="db-section-title">{t('dashboard.trafficOverview')}</h3>
      </div>
      <div className="db-stats-grid">
        <div className="db-stats-cell">
          <span className="db-stats-num">{totalSessions.toLocaleString()}</span>
          <span className="db-stats-label">{t('dashboard.totalSessions')}</span>
          <span className="db-stats-sub">
            {protocolTotal > 0
              ? `SMTP ${smtpSessions} / POP3 ${pop3Sessions} / IMAP ${imapSessions}`
              : t('dashboard.waitingData')}
          </span>
        </div>
        <div className="db-stats-cell">
          <span className="db-stats-num">{totalPackets.toLocaleString()}</span>
          <span className="db-stats-label">{t('dashboard.packets')}</span>
          <span className="db-stats-sub accent">{effectivePps}/s</span>
        </div>
        <div className="db-stats-cell">
          <span className="db-stats-num">{formatBytes(totalBytes)}</span>
          <span className="db-stats-label">{t('dashboard.networkTraffic')}</span>
          <span className="db-stats-sub accent">{formatBytes(effectiveBps)}/s</span>
        </div>
        <div className="db-stats-cell">
          <span className="db-stats-num">{activeSessions}</span>
          <span className="db-stats-label">{t('dashboard.activeSessions')}</span>
          <span className={`db-stats-live ${connected ? 'on' : ''}`}>
            <span className="db-stats-live-dot" />
            {connected ? 'LIVE' : 'OFF'}
          </span>
        </div>
      </div>
    </div>
  )
})

const ProtocolDistributionCard = React.memo(function ProtocolDistributionCard({
  smtpPct,
  pop3Pct,
  imapPct,
  smtpSessions,
  pop3Sessions,
  imapSessions,
}: {
  smtpPct: number
  pop3Pct: number
  imapPct: number
  smtpSessions: number
  pop3Sessions: number
  imapSessions: number
}) {
  const { t } = useTranslation()
  return (
    <div className="db-card db-proto" style={{ gridArea: 'proto' }}>
      <div className="db-section-left">
        <span className="db-section-icon purple">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        </span>
        <h3 className="db-section-title">{t('dashboard.protocolDistribution')}</h3>
      </div>
      <div className="db-proto-bar">
        <div className="db-proto-seg smtp" style={{ width: `${smtpPct}%` }} title={`SMTP ${smtpPct}%`} />
        <div className="db-proto-seg pop3" style={{ width: `${pop3Pct}%` }} title={`POP3 ${pop3Pct}%`} />
        <div className="db-proto-seg imap" style={{ width: `${imapPct}%` }} title={`IMAP ${imapPct}%`} />
      </div>
      <div className="db-proto-stats">
        <div className="db-proto-item smtp">
          <span className="db-proto-name">SMTP</span>
          <span className="db-proto-count">{smtpSessions.toLocaleString()}</span>
          <span className="db-proto-pct">{smtpPct}%</span>
        </div>
        <div className="db-proto-item pop3">
          <span className="db-proto-name">POP3</span>
          <span className="db-proto-count">{pop3Sessions.toLocaleString()}</span>
          <span className="db-proto-pct">{pop3Pct}%</span>
        </div>
        <div className="db-proto-item imap">
          <span className="db-proto-name">IMAP</span>
          <span className="db-proto-count">{imapSessions.toLocaleString()}</span>
          <span className="db-proto-pct">{imapPct}%</span>
        </div>
      </div>
    </div>
  )
})

const SystemHealthCard = React.memo(function SystemHealthCard() {
  const sysMetrics = useSystemMetrics(30000) // 30s interval; system metrics do not need frequent refreshes
  const { t } = useTranslation()
  const { cpuPct, memPct, cpuBarColor, memBarColor } = useMemo(() => {
    const cpu = Math.min(sysMetrics?.cpu_usage ?? 0, 100)
    const mem = Math.min(sysMetrics?.memory_percent ?? 0, 100)
    return {
      cpuPct: cpu,
      memPct: mem,
      cpuBarColor: cpu > 80 ? 'var(--accent-red)' : cpu > 60 ? 'var(--accent-yellow)' : 'var(--accent-primary)',
      memBarColor: mem > 80 ? 'var(--accent-red)' : mem > 60 ? 'var(--accent-yellow)' : 'var(--accent-secondary)',
    }
  }, [sysMetrics])

  return (
    <div className="db-card db-sys" style={{ gridArea: 'sys' }}>
      <div className="db-section-left">
        <span className="db-section-icon green">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        </span>
        <h3 className="db-section-title">{t('dashboard.systemHealth')}</h3>
      </div>
      <div className="db-sys-metrics">
        <div className="db-sys-row">
          <span className="db-sys-label">CPU</span>
          <div className="db-sys-track">
            <div className="db-sys-fill" style={{ width: `${cpuPct}%`, background: cpuBarColor }} />
          </div>
          <span className="db-sys-val">{cpuPct.toFixed(0)}%</span>
        </div>
        <div className="db-sys-row">
          <span className="db-sys-label">{t('dashboard.memory')}</span>
          <div className="db-sys-track">
            <div className="db-sys-fill" style={{ width: `${memPct}%`, background: memBarColor }} />
          </div>
          <span className="db-sys-val">{memPct.toFixed(0)}%</span>
        </div>
        <div className="db-sys-mem-detail">
          {formatBytes(sysMetrics?.memory_used ?? 0)} / {formatBytes(sysMetrics?.memory_total ?? 0)}
        </div>
        <div className="db-sys-uptime">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>{formatUptime(sysMetrics?.uptime_secs ?? 0)}</span>
        </div>
      </div>
    </div>
  )
})

function useDashboardRefresh(callback: () => void, delayMs = 5000) {
  const callbackRef = useRef(callback)
  const timerRef = useRef(0)

  useEffect(() => {
    callbackRef.current = callback
  }, [callback])

  useEffect(() => {
    const onDashboardRefresh = () => {
      if (timerRef.current) return

      timerRef.current = window.setTimeout(() => {
        timerRef.current = 0
        callbackRef.current()
      }, delayMs)
    }

    window.addEventListener(EVENTS.DASHBOARD_REFRESH, onDashboardRefresh)
    window.addEventListener(EVENTS.WS_RECONNECTED, onDashboardRefresh)
    return () => {
      window.removeEventListener(EVENTS.DASHBOARD_REFRESH, onDashboardRefresh)
      window.removeEventListener(EVENTS.WS_RECONNECTED, onDashboardRefresh)
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [delayMs])
}

const SecurityHeroContainer = React.memo(function SecurityHeroContainer() {
  const [secStats, setSecStats] = useState<SecurityStats | null>(null)
  const secStatsSigRef = useRef('')

  const fetchSecurityStats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/stats')
      const data: ApiResponse<SecurityStats> = await res.json()
      if (data.success && data.data) {
        const nextSig = JSON.stringify({
          total_scanned: data.data.total_scanned,
          level_counts: data.data.level_counts,
          high_threats_24h: data.data.high_threats_24h,
          ioc_count: data.data.ioc_count,
        })
        if (nextSig !== secStatsSigRef.current) {
          secStatsSigRef.current = nextSig
          startTransition(() => {
            setSecStats(data.data)
          })
        }
      }
    } catch {
      // security engine may not be initialized
    }
  }, [])

  useEffect(() => {
    void fetchSecurityStats()
  }, [fetchSecurityStats])

  useDashboardRefresh(() => { void fetchSecurityStats() })

  const secDerived = useMemo(() => {
    const totalScanned = secStats?.total_scanned ?? 0
    const safeCount = secStats?.level_counts?.safe ?? 0
    const securityScore = totalScanned > 0 ? Math.round((safeCount / totalScanned) * 100) : null
    const scoreColor = securityScore === null ? 'var(--text-tertiary)'
      : securityScore >= 90 ? 'var(--accent-green)'
      : securityScore >= 70 ? 'var(--accent-yellow)'
      : securityScore >= 50 ? 'var(--accent-amber)'
      : 'var(--accent-red)'
    const secMaxCount = secStats
      ? Math.max(1, ...THREAT_LEVELS.map(lv => secStats.level_counts?.[lv.key] ?? 0))
      : 1
    const hasThreats = secStats
      ? ((secStats.level_counts?.high ?? 0) + (secStats.level_counts?.critical ?? 0)) > 0
      : false
    return { totalScanned, securityScore, scoreColor, secMaxCount, hasThreats }
  }, [secStats])

  return (
    <SecurityHeroCard
      hasThreats={secDerived.hasThreats}
      securityScore={secDerived.securityScore}
      scoreColor={secDerived.scoreColor}
      totalScanned={secDerived.totalScanned}
      secStats={secStats}
      secMaxCount={secDerived.secMaxCount}
    />
  )
})

const LoginCardContainer = React.memo(function LoginCardContainer() {
  const [loginStats, setLoginStats] = useState<ExternalLoginStats | null>(null)
  const loginStatsSigRef = useRef('')
  const { t } = useTranslation()

  const fetchLoginStats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/stats/external-logins')
      const data: ApiResponse<ExternalLoginStats> = await res.json()
      if (data.success && data.data) {
        const nextSig = JSON.stringify({
          total_24h: data.data.total_24h,
          smtp_24h: data.data.smtp_24h,
          pop3_24h: data.data.pop3_24h,
          imap_24h: data.data.imap_24h,
          http_24h: data.data.http_24h,
          success_24h: data.data.success_24h,
          failed_24h: data.data.failed_24h,
          unique_ips_24h: data.data.unique_ips_24h,
          hourly: data.data.hourly.map(item => [item.hour, item.total, item.smtp, item.pop3, item.imap, item.http]),
        })
        if (nextSig !== loginStatsSigRef.current) {
          loginStatsSigRef.current = nextSig
          startTransition(() => {
            setLoginStats(data.data)
          })
        }
      }
    } catch {
      // ignore transient login-stats failures
    }
  }, [])

  useEffect(() => {
    void fetchLoginStats()
  }, [fetchLoginStats])

  useDashboardRefresh(() => { void fetchLoginStats() })

  const loginChartData = useMemo<LoginChartBar[]>(() => {
    if (!loginStats || loginStats.hourly.length === 0) return []
    const maxVal = Math.max(1, ...loginStats.hourly.map(entry => entry.total))
    return loginStats.hourly.map((entry, index) => {
      const pct = Math.max(3, (entry.total / maxVal) * 100)
      const hourLabel = formatHourLabel(entry.hour)
      return {
        pct,
        hourLabel,
        showLabel: index % 3 === 0,
        smtp: entry.smtp,
        pop3: entry.pop3,
        imap: entry.imap,
        http: entry.http,
        tooltip: `${hourLabel}\nSMTP: ${entry.smtp}  POP3: ${entry.pop3}\nIMAP: ${entry.imap}  HTTP: ${entry.http}\n${t('dashboard.total')}: ${entry.total}`,
      }
    })
  }, [loginStats, t])

  return <LoginCard loginStats={loginStats} loginChartData={loginChartData} />
})

const RecentThreatsContainer = React.memo(function RecentThreatsContainer() {
  const [recentThreats, setRecentThreats] = useState<VerdictWithMeta[]>([])
  const [loading, setLoading] = useState(true)
  const recentThreatsSigRef = useRef('')

  const fetchRecentThreats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/verdicts?limit=8&threat_level=medium,high,critical')
      const data: ApiResponse<{ items: VerdictWithMeta[]; total: number }> = await res.json()
      if (data.success && data.data) {
        const items = data.data.items
        const nextSig = items
          .map(item => `${item.verdict_id}:${item.threat_level}:${item.created_at}:${item.session_id}`)
          .join('|')
        if (nextSig !== recentThreatsSigRef.current) {
          recentThreatsSigRef.current = nextSig
          startTransition(() => {
            setRecentThreats(items)
          })
        }
      }
    } catch (e) {
      console.error('Failed to fetch recent threats:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void fetchRecentThreats()
  }, [fetchRecentThreats])

  useDashboardRefresh(() => { void fetchRecentThreats() })

  return <RecentThreatsCard loading={loading} recentThreats={recentThreats} />
})

function Dashboard() {
  useEffect(() => {
    const onSettingsChanged = () => window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
    window.addEventListener('storage', onSettingsChanged)
    window.addEventListener(EVENTS.DISPLAY_SETTINGS_CHANGED, onSettingsChanged)
    return () => {
      window.removeEventListener('storage', onSettingsChanged)
      window.removeEventListener(EVENTS.DISPLAY_SETTINGS_CHANGED, onSettingsChanged)
    }
  }, [])

  return (
    <div className="db-grid">
      <RealtimeTrafficSection />
      <SecurityHeroContainer />
      <LoginCardContainer />
      <RecentThreatsContainer />
      <SystemHealthCard />
    </div>
  )
}

export default React.memo(Dashboard)
