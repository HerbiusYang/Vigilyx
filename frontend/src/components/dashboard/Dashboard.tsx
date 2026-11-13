import React, { useState, useEffect, useCallback, useRef, useMemo, startTransition } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type {
  ApiResponse,
  DeliveryRiskDetailItem,
  DeliveryRiskDetailKind,
  DeliveryRiskDetailPage,
  SecurityStats,
  ExternalLoginStats,
  VerdictWithMeta,
} from '../../types'
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
const RISK_LEVELS = THREAT_LEVELS.filter(level => level.key !== 'safe')

function formatSecurityPercent(value: number): string {
  if (value > 0 && value < 0.05) return '<0.1'
  return value.toFixed(1)
}

function formatDeliveryRiskRate(value: number, denominator: number): string {
  if (denominator <= 0) return '0.0%'
  return `${((value / denominator) * 100).toFixed(1)}%`
}

function formatDeliveryRiskMetric(value: number, denominator: number): string {
  return `${value.toLocaleString()} (${formatDeliveryRiskRate(value, denominator)})`
}

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
    </>
  )
})

const SecurityHeroCard = React.memo(function SecurityHeroCard({ secStats, unavailable }: { secStats: SecurityStats | null; unavailable: boolean }) {
  const { t } = useTranslation()
  const [distributionScope, setDistributionScope] = useState<'historical' | 'recent'>('historical')
  if (!secStats) {
    return (
      <div className="db-card db-sec-hero" style={{ gridArea: 'sec' }}>
        <header className="db-sec-head">
          <span className="db-sec-state-dot" aria-hidden="true" />
          <div className="db-section-left"><h3 className="db-section-title">{t('dashboard.securityPosture')}</h3></div>
          <div className="db-sec-head-meta"><Link to="/security" className="db-link db-sec-link">{t('dashboard.details')}</Link></div>
        </header>
        <p className="db-sec-unavailable" role="status">{t(unavailable ? 'dashboard.securityStatsUnavailable' : 'dashboard.securityStatsLoading')}</p>
      </div>
    )
  }
  const totalScanned = secStats.total_scanned
  const highThreats24h = secStats?.high_threats_24h ?? 0
  const isRecentScope = distributionScope === 'recent'
  const displayedLevelCounts: Record<string, number> = isRecentScope
    ? (secStats?.level_counts_24h ?? {})
    : (secStats?.level_counts ?? {})
  const displayedTotal = isRecentScope ? (secStats?.analyzed_24h ?? 0) : totalScanned
  const safeCount = displayedLevelCounts.safe ?? 0
  const riskCount = RISK_LEVELS
    .reduce((total, level) => total + (displayedLevelCounts[level.key] ?? 0), 0)
  const safePct = displayedTotal > 0 ? (safeCount / displayedTotal) * 100 : 0
  const riskPct = displayedTotal > 0 ? (riskCount / displayedTotal) * 100 : 0
  const postureState = highThreats24h >= 5 ? 'critical' : highThreats24h > 0 ? 'warning' : 'safe'
  const runtimeMetrics = [
    {
      label: t('dashboard.pendingAlerts'),
      description: t('dashboard.pendingAlertsHint'),
      title: t('dashboard.pendingAlertsSource'),
      value: secStats?.alerts_24h ?? 0,
    },
    {
      label: t('dashboard.quarantinedBlocked'),
      description: t('dashboard.quarantinedBlockedHint'),
      title: t('dashboard.quarantinedBlockedSource'),
      value: secStats?.quarantined_24h ?? 0,
    },
  ]

  return (
    <div className={'db-card db-sec-hero db-sec-hero--' + (unavailable ? 'stale' : postureState)} style={{ gridArea: 'sec' }}>
      <header className="db-sec-head">
        <span className="db-sec-state-dot" aria-hidden="true" />
        <div className="db-section-left">
          <h3 className="db-section-title">{t('dashboard.securityPosture')}</h3>
          <div className="db-sec-head-summary" aria-label={t('dashboard.historical')}>
            <span><b>{totalScanned.toLocaleString()}</b>{t('dashboard.analyzedHistorical')}</span>
            <span><b>{secStats?.ioc_count ?? 0}</b>{t('dashboard.iocRuleCount')}</span>
          </div>
        </div>
        <div className="db-sec-head-meta">
          <span>{t('dashboard.timeScope24h')}</span>
          <Link to="/security" className="db-link db-sec-link">{t('dashboard.details')}</Link>
        </div>
      </header>
      {unavailable && <p className="db-sec-stale" role="status">{t('dashboard.securityStatsStale')}</p>}

      <section className="db-sec-action">
        <div>
          <div className="db-sec-eyebrow"><i>01</i><span>{t('dashboard.actionDecision')}</span></div>
          <div className="db-sec-verdict">
            <div className="db-sec-verdict-line">
              <span className="db-sec-verdict-num">{highThreats24h}</span>
              <span className="db-sec-verdict-word">{t('dashboard.highCriticalMail')}</span>
            </div>
            <p>{highThreats24h > 0 ? t('dashboard.prioritizeHandling') : t('dashboard.noHighCritical24h')}</p>
          </div>
        </div>

        <div>
          <div className="db-sec-eyebrow"><i>&nbsp;</i><span>{t('dashboard.actionSide24h')}</span></div>
          <div className="db-sec-action-kpis">
            {runtimeMetrics.map(metric => (
              <div key={metric.label} className="db-sec-live-kpi" title={metric.title}>
                <span className="db-sec-live-label">{metric.label}</span>
                <strong className="db-sec-live-value">{metric.value.toLocaleString()}</strong>
                <span className="db-sec-live-description">{metric.description}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="db-sec-body">
        <div className="db-sec-mix">
          <div className="db-sec-eyebrow">
            <i>02</i><span>{t('dashboard.whatRisk')}</span>
            <span className="db-sec-scope">
              <button type="button" className={!isRecentScope ? 'is-active' : ''} onClick={() => setDistributionScope('historical')} aria-pressed={!isRecentScope}>{t('dashboard.historical')}</button>
              <button type="button" className={isRecentScope ? 'is-active' : ''} onClick={() => setDistributionScope('recent')} aria-pressed={isRecentScope} title={t('dashboard.levelDistribution24hSource')}>{t('dashboard.timeScope24h')}</button>
            </span>
          </div>
          <div className="db-sec-total-line" role="img" aria-label={t('dashboard.threatDistribution')}>
            <i style={{ width: `${safePct}%`, backgroundColor: THREAT_LEVELS[0].color }} />
            {RISK_LEVELS.map(level => {
              const count = displayedLevelCounts[level.key] ?? 0
              return <i key={level.key} style={{ width: `${displayedTotal > 0 ? (count / displayedTotal) * 100 : 0}%`, backgroundColor: level.color }} />
            })}
          </div>
          <div className="db-sec-total-caption">
            <span>{t('dashboard.safeSummary', { count: safeCount.toLocaleString(), pct: formatSecurityPercent(safePct) })}</span>
            <span>{t('dashboard.riskSummary', { count: riskCount.toLocaleString(), pct: formatSecurityPercent(riskPct) })}</span>
          </div>
          <svg className="db-sec-risk-zoom" viewBox="0 0 1000 26" preserveAspectRatio="none" aria-hidden="true">
            <polygon points={`${safePct * 10},0 1000,0 1000,26 0,26`} />
            <path d={`M${safePct * 10},0 L0,26`} />
            <path d="M1000,0 L1000,26" />
          </svg>
          <div className="db-sec-risk-bar" role="img" aria-label={t('dashboard.riskComposition')}>
            {RISK_LEVELS.map(level => {
              const count = displayedLevelCounts[level.key] ?? 0
              return count > 0 && riskCount > 0
                ? <i key={level.key} style={{ width: `${(count / riskCount) * 100}%`, backgroundColor: level.color }} />
                : null
            })}
          </div>
          <div className="db-sec-risk-legend">
            {RISK_LEVELS.map(level => {
              const count = displayedLevelCounts[level.key] ?? 0
              const riskPct = riskCount > 0 ? (count / riskCount) * 100 : 0
              const totalPct = displayedTotal > 0 ? (count / displayedTotal) * 100 : 0
              return (
                <div key={level.key} className={`db-sec-risk-item ${count === 0 ? 'is-zero' : ''}`}>
                  <span><i style={{ backgroundColor: level.color }} />{t(`dashboard.threat.${level.key}`)}</span>
                  <strong>{count.toLocaleString()}</strong>
                  <small>{t('dashboard.ofRisk', { pct: formatSecurityPercent(riskPct) })} · {t('dashboard.ofTotal', { pct: formatSecurityPercent(totalPct) })}</small>
                </div>
              )
            })}
          </div>
        </div>

        <div className="db-sec-trend">
          <div className="db-sec-eyebrow"><i>03</i><span>{t('dashboard.isWorsening')}</span></div>
          <div className="db-sec-trend-row db-sec-trend-row--primary">
            <span>{t('dashboard.highCritical')}</span>
            <div><strong className={`db-sec-trend-value is-${postureState}`}>{highThreats24h}</strong><em title={t('dashboard.previousHighCriticalSource')}>{t('dashboard.previousPeriodValue', { count: (secStats?.high_threats_previous_24h ?? 0).toLocaleString() })}</em></div>
            <small>{t('dashboard.comparePrevious24h')}</small>
          </div>
          <div className="db-sec-trend-row db-sec-trend-row--secondary">
            <span>{t('dashboard.analyzedEmails')}</span>
            <div><strong className="db-sec-trend-value is-neutral">{(secStats?.analyzed_24h ?? 0).toLocaleString()}</strong><em title={t('dashboard.analyzed24hSource')}>{t('dashboard.previousPeriodValue', { count: (secStats?.analyzed_previous_24h ?? 0).toLocaleString() })}</em></div>
            <small>{t('dashboard.comparePrevious24h')}</small>
          </div>
        </div>
      </section>
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
  error,
  onRetry,
  recentThreats,
}: {
  loading: boolean
  error: string | null
  onRetry: () => void
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
        ) : error ? (
          <div className="db-empty" role="alert">
            <span>{error}</span>
            <button type="button" className="db-link" onClick={onRetry}>{t('dashboard.retry')}</button>
          </div>
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
              : totalSessions > 0
                ? t('dashboard.nonMailTrafficDetected')
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

type DeliveryRiskComparisonState = 'agreement' | 'difference' | 'unknown' | 'all'

interface DeliveryRiskSelection {
  kind: DeliveryRiskDetailKind
  title: string
  expectedCount: number
  comparison: DeliveryRiskComparisonState
  serverIp?: string
}

function deliveryRiskItemComparison(item: DeliveryRiskDetailItem): Exclude<DeliveryRiskComparisonState, 'all'> {
  if (
    item.action_evidence === 'unconfirmed'
    || item.action_evidence === 'first_hop'
    || item.action_evidence === 'reused_hop'
  ) return 'unknown'
  const risky = item.threat_level != null && item.threat_level !== 'safe'
  const stopped = item.action_evidence === 'explicit_rejection' || item.action_evidence === 'path_termination'
  return risky === stopped ? 'agreement' : 'difference'
}

function DeliveryRiskDetailsDialog({
  selection,
  snapshotAt,
  onClose,
}: {
  selection: DeliveryRiskSelection
  snapshotAt: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [items, setItems] = useState<DeliveryRiskDetailItem[]>([])
  const [total, setTotal] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const dialogRef = useRef<HTMLElement>(null)
  const requestRef = useRef<AbortController | null>(null)

  const fetchPage = useCallback(async (offset: number) => {
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    offset === 0 ? setLoading(true) : setLoadingMore(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        kind: selection.kind,
        snapshot_at: snapshotAt,
        limit: '30',
        offset: String(offset),
      })
      if (selection.serverIp) params.set('server_ip', selection.serverIp)
      const response = await apiFetch(`/api/security/delivery-risk/details?${params.toString()}`, {
        signal: controller.signal,
      })
      const payload: ApiResponse<DeliveryRiskDetailPage> = await response.json()
      if (!payload.success || !payload.data) {
        throw new Error(payload.error || t('dashboard.deliveryRiskDetailLoadFailed'))
      }
      setTotal(payload.data.total)
      setItems(current => offset === 0 ? payload.data!.items : [...current, ...payload.data!.items])
    } catch (fetchError) {
      if (fetchError instanceof DOMException && fetchError.name === 'AbortError') return
      setError(fetchError instanceof Error ? fetchError.message : t('dashboard.deliveryRiskDetailLoadFailed'))
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false)
        setLoadingMore(false)
      }
    }
  }, [selection, snapshotAt, t])

  useEffect(() => {
    setItems([])
    setTotal(null)
    void fetchPage(0)
    return () => requestRef.current?.abort()
  }, [fetchPage])

  useEffect(() => {
    closeButtonRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  const comparisonLabel = (comparison: Exclude<DeliveryRiskComparisonState, 'all'>) => {
    if (comparison === 'agreement') return t('dashboard.deliveryRiskAgreement')
    if (comparison === 'difference') return t('dashboard.deliveryRiskDifference')
    return t('dashboard.deliveryRiskUnknown')
  }

  const evidenceLabel = (evidence: DeliveryRiskDetailItem['action_evidence']) => {
    switch (evidence) {
      case 'explicit_rejection': return t('dashboard.deliveryRiskEvidenceExplicit')
      case 'path_termination': return t('dashboard.deliveryRiskEvidenceInferred')
      case 'terminal_delivery': return t('dashboard.deliveryRiskEvidenceTerminal')
      case 'forwarded': return t('dashboard.deliveryRiskEvidenceForwarded')
      case 'unconfirmed': return t('dashboard.deliveryRiskEvidenceUnconfirmed')
      case 'reused_hop': return t('dashboard.deliveryRiskEvidenceReused')
      default: return t('dashboard.deliveryRiskEvidenceFirstHop')
    }
  }

  const keepFocusInDialog = (event: React.KeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Tab') return
    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
      'a[href], button:not(:disabled), [tabindex]:not([tabindex="-1"])',
    )
    if (!focusable || focusable.length === 0) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  return createPortal(
    <div
      className="db-delivery-detail-backdrop"
      onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}
    >
      <aside
        ref={dialogRef}
        className="db-delivery-detail-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="delivery-risk-detail-title"
        onKeyDown={keepFocusInDialog}
      >
        <header className="db-delivery-detail-head">
          <div>
            <span className={`db-delivery-detail-state is-${selection.comparison}`}>
              {selection.comparison === 'all'
                ? t('dashboard.deliveryRiskAllObservations')
                : comparisonLabel(selection.comparison)}
            </span>
            <h3 id="delivery-risk-detail-title">{selection.title}</h3>
            <p>
              {selection.serverIp && <code>{selection.serverIp}</code>}
              <span>{t('dashboard.deliveryRiskSnapshotAt', { time: formatDate(snapshotAt) })}</span>
            </p>
          </div>
          <div className="db-delivery-detail-head-actions">
            <strong>{selection.expectedCount.toLocaleString()}</strong>
            <span>{t('dashboard.deliveryRiskMessagesUnit')}</span>
            <button
              ref={closeButtonRef}
              type="button"
              className="db-delivery-detail-close"
              onClick={onClose}
              aria-label={t('dashboard.deliveryRiskCloseDetails')}
            >×</button>
          </div>
        </header>

        {total != null && total !== selection.expectedCount && (
          <div className="db-delivery-detail-mismatch" role="alert">
            {t('dashboard.deliveryRiskCountMismatch', {
              expected: selection.expectedCount.toLocaleString(),
              actual: total.toLocaleString(),
            })}
          </div>
        )}

        <div className="db-delivery-detail-body">
          {loading ? (
            <div className="db-delivery-detail-status">{t('app.loading')}</div>
          ) : error ? (
            <div className="db-delivery-detail-status" role="alert">
              <span>{error}</span>
              <button type="button" onClick={() => { void fetchPage(0) }}>{t('dashboard.retry')}</button>
            </div>
          ) : items.length === 0 ? (
            <div className="db-delivery-detail-status">{t('dashboard.deliveryRiskNoDetail')}</div>
          ) : (
            <div className="db-delivery-detail-list">
              {items.map((item, index) => {
                const comparison = deliveryRiskItemComparison(item)
                const subject = decodeMimeWord(item.subject) || t('notify.noSubject')
                return (
                  <article className="db-delivery-detail-item" key={`${item.session_id}:${item.hop_index}:${index}`}>
                    <div className="db-delivery-detail-item-main">
                      <div className="db-delivery-detail-item-badges">
                        <span className={`is-${comparison}`}>{comparisonLabel(comparison)}</span>
                        <span>{evidenceLabel(item.action_evidence)}</span>
                        {item.threat_level && (
                          <span className={`threat-badge threat-badge--${item.threat_level}`}>
                            {t(`emailSecurity.threat${item.threat_level.charAt(0).toUpperCase()}${item.threat_level.slice(1)}`)}
                          </span>
                        )}
                      </div>
                      <Link to={`/emails/${item.session_id}`} onClick={onClose}>{subject}</Link>
                      <p>
                        <span>{t('dashboard.deliveryRiskSender')}: {item.mail_from || t('dashboard.unknown')}</span>
                        <span>{t('dashboard.deliveryRiskRecipient')}: {item.rcpt_to.join(', ') || t('dashboard.unknown')}</span>
                      </p>
                    </div>
                    <div className="db-delivery-detail-item-meta">
                      <code>{item.server_ip}</code>
                      <span>{t('dashboard.deliveryRiskHopIndex', { index: item.hop_index + 1 })}</span>
                      <time dateTime={item.observed_at}>{formatDate(item.observed_at)}</time>
                    </div>
                  </article>
                )
              })}
            </div>
          )}
        </div>

        {!loading && !error && total != null && items.length < total && (
          <footer className="db-delivery-detail-foot">
            <span>{t('dashboard.deliveryRiskDetailProgress', { shown: items.length, total })}</span>
            <button
              type="button"
              disabled={loadingMore}
              onClick={() => { void fetchPage(items.length) }}
            >
              {loadingMore ? t('app.loading') : t('dashboard.deliveryRiskLoadMore')}
            </button>
          </footer>
        )}
      </aside>
    </div>,
    document.body,
  )
}

export const DeliveryRiskCard = React.memo(function DeliveryRiskCard({ secStats, unavailable }: { secStats: SecurityStats | null; unavailable: boolean }) {
  const { t } = useTranslation()
  const [selection, setSelection] = useState<DeliveryRiskSelection | null>(null)
  const returnFocusRef = useRef<HTMLElement | null>(null)
  const nodeComparisons = secStats?.delivery_stats_scope === 'all_history'
    ? secStats.delivery_node_comparisons ?? []
    : []
  const snapshotAt = secStats?.delivery_stats_as_of ?? ''

  const showDetails = useCallback((nextSelection: DeliveryRiskSelection) => {
    if (snapshotAt) {
      returnFocusRef.current = document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null
      setSelection(nextSelection)
    }
  }, [snapshotAt])

  const closeDetails = useCallback(() => {
    setSelection(null)
    window.requestAnimationFrame(() => returnFocusRef.current?.focus())
  }, [])

  const detailButtonTitle = snapshotAt
    ? t('dashboard.deliveryRiskOpenDetails')
    : t('dashboard.deliveryRiskDetailsUnavailable')

  return (
    <div className="db-card db-delivery-risk" style={{ gridArea: 'proto' }}>
      <header className="db-delivery-risk-head">
        <div className="db-section-left">
          <span className="db-section-icon amber">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 7h16"/><path d="M4 12h10"/><path d="M4 17h7"/><path d="m17 14 3 3-3 3"/><path d="M20 17h-6"/></svg>
          </span>
          <h3 className="db-section-title">{t('dashboard.deliveryRiskTitle')}</h3>
          <span className="db-section-subtitle">{t('dashboard.deliveryRiskWindow')}</span>
        </div>
      </header>

      <section className="db-delivery-risk-compare" aria-label={t('dashboard.deliveryRiskCapabilityCompare')}>
        {secStats && unavailable && <p className="db-delivery-risk-empty" role="status">{t('dashboard.securityStatsStale')}</p>}
        {!secStats ? (
          <p className="db-delivery-risk-empty" role="status">{t(unavailable ? 'dashboard.securityStatsUnavailable' : 'dashboard.securityStatsLoading')}</p>
        ) : nodeComparisons.length === 0 ? (
          <p className="db-delivery-risk-empty">{t('dashboard.deliveryRiskComparePending')}</p>
        ) : (
          <>
            {nodeComparisons.map(node => {
              const differentDecision = Math.max(
                0,
                node.vigilyx_only_threat_total + node.vendor_only_threat_total,
              )
              const sameDecision = Math.max(
                0,
                node.comparable_total
                  - node.vigilyx_only_threat_total
                  - node.vendor_only_threat_total,
              )
              const safePassed = Math.max(
                0,
                node.vendor_passed_total - node.vigilyx_only_threat_total,
              )

              return (
                <article
                  className="db-delivery-risk-node-card"
                  key={node.node_index}
                >
                  <header className="db-delivery-risk-node-head">
                    <div className="db-delivery-risk-node-identity">
                      <span>{t('dashboard.deliveryRiskNode', { index: node.node_index + 1 })}</span>
                      <code>{node.server_ips?.join(' · ') || 'auto'}</code>
                    </div>
                    <div className="db-delivery-risk-node-observed">
                      <span>{t('dashboard.deliveryRiskComparable')}</span>
                      <strong>{node.comparable_total.toLocaleString()}</strong>
                    </div>
                  </header>

                  <dl className="db-delivery-risk-node-metrics">
                    <div className="is-different">
                      <dt>{t('dashboard.deliveryRiskDifferentDecision')}</dt>
                      <dd>
                        <button
                          type="button"
                          className="db-delivery-risk-detail-trigger"
                          disabled={!snapshotAt}
                          title={detailButtonTitle}
                          aria-label={t('dashboard.deliveryRiskMetricAria', {
                            label: t('dashboard.deliveryRiskDifferentDecision'),
                            count: differentDecision.toLocaleString(),
                            rate: formatDeliveryRiskRate(differentDecision, node.comparable_total),
                          })}
                          onClick={() => showDetails({
                            kind: 'disagreement',
                            title: t('dashboard.deliveryRiskDifferentDecision'),
                            expectedCount: differentDecision,
                            comparison: 'difference',
                            serverIp: node.server_ips?.[0],
                          })}
                        >{formatDeliveryRiskMetric(differentDecision, node.comparable_total)}</button>
                        <span className="db-delivery-risk-breakdown">
                          <span>
                            <em>{t('dashboard.deliveryRiskVendorOnly')}</em>
                            <button
                              type="button"
                              className="db-delivery-risk-detail-trigger"
                              disabled={!snapshotAt}
                              title={detailButtonTitle}
                              aria-label={t('dashboard.deliveryRiskMetricAria', {
                                label: t('dashboard.deliveryRiskVendorOnly'),
                                count: node.vendor_only_threat_total.toLocaleString(),
                                rate: formatDeliveryRiskRate(node.vendor_only_threat_total, differentDecision),
                              })}
                              onClick={() => showDetails({
                                kind: 'vendor_only',
                                title: t('dashboard.deliveryRiskVendorOnly'),
                                expectedCount: node.vendor_only_threat_total,
                                comparison: 'difference',
                                serverIp: node.server_ips?.[0],
                              })}
                            >{formatDeliveryRiskMetric(node.vendor_only_threat_total, differentDecision)}</button>
                          </span>
                          <span>
                            <em>{t('dashboard.deliveryRiskRiskContinued')}</em>
                            <button
                              type="button"
                              className="db-delivery-risk-detail-trigger"
                              disabled={!snapshotAt}
                              title={detailButtonTitle}
                              aria-label={t('dashboard.deliveryRiskMetricAria', {
                                label: t('dashboard.deliveryRiskRiskContinued'),
                                count: node.vigilyx_only_threat_total.toLocaleString(),
                                rate: formatDeliveryRiskRate(node.vigilyx_only_threat_total, differentDecision),
                              })}
                              onClick={() => showDetails({
                                kind: 'vigilyx_only',
                                title: t('dashboard.deliveryRiskRiskContinued'),
                                expectedCount: node.vigilyx_only_threat_total,
                                comparison: 'difference',
                                serverIp: node.server_ips?.[0],
                              })}
                            >{formatDeliveryRiskMetric(node.vigilyx_only_threat_total, differentDecision)}</button>
                          </span>
                        </span>
                      </dd>
                    </div>
                    <div className="is-aligned">
                      <dt>{t('dashboard.deliveryRiskAligned')}</dt>
                      <dd>
                        <button
                          type="button"
                          className="db-delivery-risk-detail-trigger"
                          disabled={!snapshotAt}
                          title={detailButtonTitle}
                          aria-label={t('dashboard.deliveryRiskMetricAria', {
                            label: t('dashboard.deliveryRiskAligned'),
                            count: sameDecision.toLocaleString(),
                            rate: formatDeliveryRiskRate(sameDecision, node.comparable_total),
                          })}
                          onClick={() => showDetails({
                            kind: 'agreement',
                            title: t('dashboard.deliveryRiskAligned'),
                            expectedCount: sameDecision,
                            comparison: 'agreement',
                            serverIp: node.server_ips?.[0],
                          })}
                        >{formatDeliveryRiskMetric(sameDecision, node.comparable_total)}</button>
                        <span className="db-delivery-risk-breakdown">
                          <span>
                            <em>{t('dashboard.deliveryRiskBothThreat')}</em>
                            <button
                              type="button"
                              className="db-delivery-risk-detail-trigger"
                              disabled={!snapshotAt}
                              title={detailButtonTitle}
                              aria-label={t('dashboard.deliveryRiskMetricAria', {
                                label: t('dashboard.deliveryRiskBothThreat'),
                                count: node.both_threat_total.toLocaleString(),
                                rate: formatDeliveryRiskRate(node.both_threat_total, sameDecision),
                              })}
                              onClick={() => showDetails({
                                kind: 'both_threat',
                                title: t('dashboard.deliveryRiskBothThreat'),
                                expectedCount: node.both_threat_total,
                                comparison: 'agreement',
                                serverIp: node.server_ips?.[0],
                              })}
                            >{formatDeliveryRiskMetric(node.both_threat_total, sameDecision)}</button>
                          </span>
                          <span>
                            <em>{t('dashboard.deliveryRiskSafePassed')}</em>
                            <button
                              type="button"
                              className="db-delivery-risk-detail-trigger"
                              disabled={!snapshotAt}
                              title={detailButtonTitle}
                              aria-label={t('dashboard.deliveryRiskMetricAria', {
                                label: t('dashboard.deliveryRiskSafePassed'),
                                count: safePassed.toLocaleString(),
                                rate: formatDeliveryRiskRate(safePassed, sameDecision),
                              })}
                              onClick={() => showDetails({
                                kind: 'safe_passed',
                                title: t('dashboard.deliveryRiskSafePassed'),
                                expectedCount: safePassed,
                                comparison: 'agreement',
                                serverIp: node.server_ips?.[0],
                              })}
                            >{formatDeliveryRiskMetric(safePassed, sameDecision)}</button>
                          </span>
                        </span>
                      </dd>
                    </div>
                  </dl>
                </article>
              )
            })}
          </>
        )}
      </section>
      {selection && snapshotAt && (
        <DeliveryRiskDetailsDialog
          selection={selection}
          snapshotAt={snapshotAt}
          onClose={closeDetails}
        />
      )}
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
  const [secStatsUnavailable, setSecStatsUnavailable] = useState(false)
  const secStatsSigRef = useRef('')

  const fetchSecurityStats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/stats')
      const data: ApiResponse<SecurityStats> = await res.json()
      if (data.success && data.data) {
        setSecStatsUnavailable(false)
        const nextSig = JSON.stringify({
          total_scanned: data.data.total_scanned,
          level_counts: data.data.level_counts,
          high_threats_24h: data.data.high_threats_24h,
          ioc_count: data.data.ioc_count,
          level_counts_24h: data.data.level_counts_24h,
          analyzed_24h: data.data.analyzed_24h,
          analyzed_previous_24h: data.data.analyzed_previous_24h,
          high_threats_previous_24h: data.data.high_threats_previous_24h,
          alerts_24h: data.data.alerts_24h,
          quarantined_24h: data.data.quarantined_24h,
          first_hop_emails_total: data.data.first_hop_emails_total,
          first_hop_dangerous_total: data.data.first_hop_dangerous_total,
          downstream_reused_hops_total: data.data.downstream_reused_hops_total,
          dangerous_forwarded_total: data.data.dangerous_forwarded_total,
          dangerous_forwarded_rate: data.data.dangerous_forwarded_rate,
          delivery_node_comparisons: data.data.delivery_node_comparisons,
          terminal_mail_servers: data.data.terminal_mail_servers,
        })
        if (nextSig !== secStatsSigRef.current) {
          secStatsSigRef.current = nextSig
          startTransition(() => {
            setSecStats(data.data)
          })
        }
      } else {
        setSecStatsUnavailable(true)
      }
    } catch {
      setSecStatsUnavailable(true)
    }
  }, [])

  useEffect(() => {
    void fetchSecurityStats()
  }, [fetchSecurityStats])

  useDashboardRefresh(() => { void fetchSecurityStats() })

  return (
    <>
      <SecurityHeroCard secStats={secStats} unavailable={secStatsUnavailable} />
      <DeliveryRiskCard secStats={secStats} unavailable={secStatsUnavailable} />
    </>
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
  const [error, setError] = useState<string | null>(null)
  const recentThreatsSigRef = useRef('')
  const { t } = useTranslation()

  const fetchRecentThreats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/verdicts?limit=3&threat_level=medium,high,critical')
      if (!res.ok) throw new Error(t('dashboard.recentThreatsLoadFailed'))
      const data: ApiResponse<{ items: VerdictWithMeta[]; total: number }> = await res.json()
      if (!data.success || !data.data) throw new Error(data.error || t('dashboard.recentThreatsLoadFailed'))

      setError(null)
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
    } catch (e) {
      console.error('Failed to fetch recent threats:', e)
      setError(e instanceof Error && e.message ? e.message : t('dashboard.recentThreatsLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    void fetchRecentThreats()
  }, [fetchRecentThreats])

  useDashboardRefresh(() => { void fetchRecentThreats() })

  return <RecentThreatsCard loading={loading} error={error} onRetry={() => { void fetchRecentThreats() }} recentThreats={recentThreats} />
})

function Dashboard() {
  useEffect(() => {
    document.body.classList.add('dashboard-page')
    return () => document.body.classList.remove('dashboard-page')
  }, [])

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
