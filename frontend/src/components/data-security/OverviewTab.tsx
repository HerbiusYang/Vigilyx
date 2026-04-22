import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { DataSecurityStats, DataSecurityEngineStatus } from '../../types'
import {
  SEVERITY_COLOR, SEVERITY_BG, SEVERITY_CN,
  INCIDENT_TYPE_COLOR, INCIDENT_TYPE_CN, INCIDENT_TYPE_DESC, INCIDENT_TYPE_ICON,
} from './constants'

export function OverviewTab({ stats, engineStatus, loadFailed }: {
  stats: DataSecurityStats | null
  engineStatus: DataSecurityEngineStatus | null
  loadFailed?: boolean
}) {
  const { t } = useTranslation()
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
        <p>{t('dataSecurity.dataLoadFailed')}</p>
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
              {t('dataSecurity.dataSecurityEngine')}{engineStatus.running ? <b style={{ color: '#22c55e' }}>{t('dataSecurity.running')}</b> : <b style={{ color: '#ef4444' }}>{t('dataSecurity.stopped')}</b>}
            </span>
            <span className="ds3-engine-sep" />
            <span className="ds3-engine-text">{t('dataSecurity.processed')} <b className="sec-mono" style={{ color: 'var(--text-primary)', fontSize: 15 }}>{engineStatus.http_sessions_processed.toLocaleString()}</b> {t('dataSecurity.sessions')}</span>
            <span className="ds3-engine-sep" />
            <span className="ds3-engine-text">{t('dataSecurity.found')} <b className="sec-mono" style={{ color: '#f97316', fontSize: 15 }}>{engineStatus.incidents_detected.toLocaleString()}</b> {t('dataSecurity.incidents')}</span>
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
              <div className="ds3-hero-label">{t('dataSecurity.totalIncidents')}</div>
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
              <div className="ds3-hero-label">{t('dataSecurity.highSeverity24h')}</div>
              <div className="ds3-hero-sub">{stats.high_severity_24h > 0 ? t('dataSecurity.requireImmediate') : t('dataSecurity.noHighThreat')}</div>
            </div>
            <div className="ds3-hero-value sec-mono" style={{ color: stats.high_severity_24h > 0 ? '#ef4444' : '#22c55e' }}>{stats.high_severity_24h}</div>
          </div>
        </div>
      </div>

      {/* Trend chart - full width */}
      <div className="ds3-chart-card ds3-chart-card--full">
        <div className="ds3-chart-head">
          <div>
            <div className="ds3-chart-title">{t('dataSecurity.trend24h')}</div>
            <div style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 3 }}>
              {t('dataSecurity.httpSessions')} <span className="sec-mono" style={{ color: '#22d3ee', fontWeight: 600 }}>{chart?.ts.toLocaleString() || '0'}</span>
              {chart?.hi && <> · {t('dataSecurity.securityIncidents')} <span className="sec-mono" style={{ color: '#f97316', fontWeight: 600 }}>{chart.ti}</span></>}
            </div>
          </div>
          <div className="ds3-chart-legend">
            <span><span className="ds3-legend-dot" style={{ background: '#22d3ee' }} />{t('dataSecurity.httpSessions')}</span>
            {chart?.hi && <span><span className="ds3-legend-dot" style={{ background: '#f97316' }} />{t('dataSecurity.securityIncidents')}</span>}
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
                    <text x={cx - 34} y={chart.pT + 18} fontSize="7.5" fontFamily="var(--font-mono)" fill="#22d3ee">{t('dataSecurity.chartSession')} {sCount.toLocaleString()}</text>
                    {chart.hi && <>
                      <text x={cx - 40} y={chart.pT + 28} fontSize="6.5" fill="#f97316">&#9679;</text>
                      <text x={cx - 34} y={chart.pT + 28} fontSize="7.5" fontFamily="var(--font-mono)" fill="#f97316">{t('dataSecurity.chartIncident')} {iCount}</text>
                    </>}
                  </g>
                </g>
              })}
            </svg>
          ) : (
            <div className="ds3-chart-empty">{t('dataSecurity.noTrendData')}</div>
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
