import type { SecurityStats, EngineStatus, ModuleMetadata } from '../../types'

const THREAT_LEVELS = [
  { key: 'safe', label: '安全', color: '#22c55e' },
  { key: 'low', label: '低危', color: '#3b82f6' },
  { key: 'medium', label: '中危', color: '#eab308' },
  { key: 'high', label: '高危', color: '#f97316' },
  { key: 'critical', label: '严重', color: '#ef4444' },
]

const MODULE_CN: Record<string, string> = {
  content_scan: '内容检测',
  html_scan: 'HTML 检测',
  attach_scan: '附件类型检测',
  attach_content: '附件内容检测',
  attach_hash: '附件哈希信誉',
  mime_scan: 'MIME 结构检测',
  header_scan: '邮件头检测',
  link_scan: 'URL 模式检测',
  link_reputation: 'URL 信誉查询',
  link_content: 'URL 内容检测',
  anomaly_detect: '异常行为检测',
  semantic_scan: '语义检测',
  domain_verify: '域名验证',
  identity_anomaly: '身份行为异常',
  transaction_correlation: '交易语义关联',
  av_eml_scan: '邮件病毒扫描',
  av_attach_scan: '附件病毒扫描',
  yara_scan: 'YARA 规则扫描',
  verdict: '综合判定',
}

function getModuleCN(id: string): string {
  return MODULE_CN[id] || id
}

interface OverviewTabProps {
  stats: SecurityStats | null
  engineStatus: EngineStatus | null
  modules: ModuleMetadata[]
}

export default function OverviewTab({ stats, engineStatus }: OverviewTabProps) {
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
            <span className="sec-stat-lbl">已扫描邮件</span>
          </div>
        </div>
        <div className="sec-stat-card">
          <div className="sec-stat-icon" style={{ color: 'var(--accent-yellow)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div className="sec-stat-body">
            <span className="sec-stat-val">{(stats?.ioc_count ?? 0).toLocaleString()}</span>
            <span className="sec-stat-lbl">IOC 指标</span>
          </div>
        </div>
        <div className="sec-stat-card">
          <div className="sec-stat-icon" style={{ color: 'var(--accent-emerald)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <div className="sec-stat-body">
            <span className="sec-stat-val">{(engineStatus?.total_verdicts_produced ?? 0).toLocaleString()}</span>
            <span className="sec-stat-lbl">已产出判定</span>
          </div>
        </div>
      </div>

      {/* Threat-level distribution - bar chart */}
      <div className="sec-card">
        <h3 className="sec-card-title">威胁等级分布</h3>
        {threatTotal === 0 ? (
          <div className="sec-empty-hint">暂无判定数据</div>
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
          <h3 className="sec-card-title">模块性能</h3>
          <div className="sec-table-wrap">
            <table className="sec-table">
              <thead>
                <tr>
                  <th>模块</th>
                  <th className="sec-th-r">执行</th>
                  <th className="sec-th-r">平均耗时</th>
                  <th className="sec-th-r">成功率</th>
                  <th className="sec-th-r">失败</th>
                  <th className="sec-th-r">超时</th>
                </tr>
              </thead>
              <tbody>
                {engineStatus.module_metrics.map(m => {
                  const rate = m.success_rate * 100
                  return (
                    <tr key={m.module_id}>
                      <td>
                        <span className="sec-module-name">{getModuleCN(m.module_id)}</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginLeft: 6 }}>{m.module_id}</span>
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
                            {rate.toFixed(0)}%
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
