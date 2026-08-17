import { useTranslation } from 'react-i18next'
import type { SecurityStats, EngineStatus, ModuleMetadata } from '../../types'
import { MODULE_NAME_KEYS } from './moduleI18n'

const THREAT_LEVEL_KEYS = ['safe', 'low', 'medium', 'high', 'critical'] as const
const THREAT_LEVEL_COLORS: Record<string, string> = {
  safe: '#22c55e',
  low: '#3b82f6',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

interface OverviewTabProps {
  stats: SecurityStats | null
  engineStatus: EngineStatus | null
  modules: ModuleMetadata[]
}

export default function OverviewTab({ stats, engineStatus }: OverviewTabProps) {
  const { t } = useTranslation()

  const THREAT_LEVELS = THREAT_LEVEL_KEYS.map(key => ({
    key,
    label: t(`emailSecurity.threat_${key}`),
    color: THREAT_LEVEL_COLORS[key],
  }))

  function getModuleName(id: string): string {
    const tKey = MODULE_NAME_KEYS[id]
    return tKey ? t(tKey) : id
  }

  function formatSuccessRate(rate: number): string {
    if (rate === 100) return '100%'
    if (rate >= 99) return `${rate.toFixed(2)}%`
    return `${rate.toFixed(1)}%`
  }

  const threatTotal = stats
    ? THREAT_LEVELS.reduce((sum, lv) => sum + (stats.level_counts?.[lv.key] ?? 0), 0)
    : 0

  return (
    <div className="sec-overview">
      {/* Stats card row */}
      <div className="sec-stats-row">
        <div className="sec-stat-card">
          <div className="sec-stat-icon" style={{ color: 'var(--accent-primary)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 7 12 13 21 7"/></svg>
          </div>
          <div className="sec-stat-body">
            <span className="sec-stat-val">{(stats?.total_scanned ?? 0).toLocaleString()}</span>
            <span className="sec-stat-lbl">{t('emailSecurity.scannedEmails')}</span>
          </div>
        </div>
        <div className="sec-stat-card">
          <div className="sec-stat-icon" style={{ color: 'var(--accent-yellow)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div className="sec-stat-body">
            <span className="sec-stat-val">{(stats?.ioc_count ?? 0).toLocaleString()}</span>
            <span className="sec-stat-lbl">{t('emailSecurity.iocIndicators')}</span>
          </div>
        </div>
        <div className="sec-stat-card">
          <div className="sec-stat-icon" style={{ color: 'var(--accent-emerald)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <div className="sec-stat-body">
            <span className="sec-stat-val">{(engineStatus?.total_verdicts_produced ?? 0).toLocaleString()}</span>
            <span className="sec-stat-lbl">{t('emailSecurity.verdictsProduced')}</span>
          </div>
        </div>
      </div>

      {/* Threat-level distribution - bar chart */}
      <div className="sec-card">
        <h3 className="sec-card-title">{t('emailSecurity.threatLevelDistribution')}</h3>
        {threatTotal === 0 ? (
          <div className="sec-empty-hint">{t('emailSecurity.noVerdictData')}</div>
        ) : (
          <>
            <div className="sec-threat-bar">
              {THREAT_LEVELS.map(lv => {
                const count = stats?.level_counts?.[lv.key] ?? 0
                const pct = threatTotal > 0 ? (count / threatTotal) * 100 : 0
                if (pct === 0) return null
                return (
                  <div
                    key={lv.key}
                    className="sec-threat-bar-seg"
                    style={{ width: `${pct}%`, backgroundColor: lv.color }}
                    title={`${lv.label}: ${count} (${pct.toFixed(1)}%)`}
                  />
                )
              })}
            </div>
            <div className="sec-threat-legend">
              {THREAT_LEVELS.map(lv => {
                const count = stats?.level_counts?.[lv.key] ?? 0
                return (
                  <div key={lv.key} className="sec-threat-legend-item">
                    <span className="sec-threat-dot" style={{ backgroundColor: lv.color }} />
                    <span className="sec-threat-label">{lv.label}</span>
                    <span className="sec-threat-count">{count}</span>
                  </div>
                )
              })}
            </div>
          </>
        )}
      </div>

      {/* -- Module performance overview (compact table) -- */}
      {engineStatus && engineStatus.module_metrics?.length > 0 && (
        <div className="sec-card">
          <h3 className="sec-card-title">{t('emailSecurity.modulePerformance')}</h3>
          <div className="sec-table-wrap">
            <table className="sec-table">
              <thead>
                <tr>
                  <th>{t('emailSecurity.thModule')}</th>
                  <th className="sec-th-r">{t('emailSecurity.thRuns')}</th>
                  <th className="sec-th-r">{t('emailSecurity.thAvgDuration')}</th>
                  <th className="sec-th-r">{t('emailSecurity.thSuccessRate')}</th>
                  <th className="sec-th-r">{t('emailSecurity.thFailures')}</th>
                  <th className="sec-th-r">{t('emailSecurity.thTimeouts')}</th>
                </tr>
              </thead>
              <tbody>
                {engineStatus.module_metrics.map(m => {
                  const rate = m.success_rate * 100
                  return (
                    <tr key={m.module_id}>
                      <td>
                        <span className="sec-module-name" title={m.module_id}>{getModuleName(m.module_id)}</span>
                      </td>
                      <td className="sec-td-r sec-mono">{m.total_runs.toLocaleString()}</td>
                      <td className="sec-td-r sec-mono">{m.avg_duration_ms.toFixed(1)}ms</td>
                      <td className="sec-td-r">
                        <div className="sec-rate-cell">
                          <div className="sec-rate-bar">
                            <div
                              className="sec-rate-bar-fill"
                              style={{
                                width: `${rate}%`,
                                backgroundColor: rate >= 95 ? 'var(--accent-green)' : rate >= 80 ? 'var(--accent-yellow)' : 'var(--accent-red)',
                              }}
                            />
                          </div>
                          <span className="sec-mono" style={{ color: rate >= 95 ? 'var(--accent-green)' : rate >= 80 ? 'var(--accent-yellow)' : 'var(--accent-red)' }}>
                            {formatSuccessRate(rate)}
                          </span>
                        </div>
                      </td>
                      <td className="sec-td-r sec-mono" style={{ color: m.failure_count > 0 ? 'var(--accent-red)' : undefined }}>{m.failure_count}</td>
                      <td className="sec-td-r sec-mono" style={{ color: m.timeout_count > 0 ? 'var(--accent-yellow)' : undefined }}>{m.timeout_count}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
