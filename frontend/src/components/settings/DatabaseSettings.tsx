import { useState, useEffect, useCallback } from 'react'
import { formatBytes } from '../../utils/format'
import { apiFetch } from '../../utils/api'

type ClearMode = 'safe' | 'quick' | 'high_performance'

interface ClearResult {
  message: string
  mode: string
  elapsed_ms: number
}

const CLEAR_MODES: { key: ClearMode; label: string; desc: string; risk: string; icon: JSX.Element }[] = [
  {
    key: 'safe',
    label: '安全清理',
    desc: '事务删除 + VACUUM + ANALYZE，回收磁盘空间并更新查询统计。',
    risk: '速度最慢但最彻底，推荐日常维护使用。',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
  },
  {
    key: 'quick',
    label: '快速清理',
    desc: 'DROP TABLE 后重建表和索引，从头重建数据库结构。',
    risk: '速度较快，适合需要全新数据库的场景。',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
      </svg>
    ),
  },
  {
    key: 'high_performance',
    label: '极速清理',
    desc: '仅 DELETE，不执行 VACUUM，不会立即回收磁盘空间。',
    risk: '速度最快，适合对速度要求高于磁盘空间的场景。',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
      </svg>
    ),
  },
]

export default function DatabaseSettings() {
  const [dbSize, setDbSize] = useState<number>(0)
  const [autoRotateEnabled, setAutoRotateEnabled] = useState(true)
  const [rotateThreshold, setRotateThreshold] = useState(90)
  const [diskUsagePercent, setDiskUsagePercent] = useState(0)
  const [confirmMode, setConfirmMode] = useState<ClearMode | null>(null)
  const [confirmInput, setConfirmInput] = useState('')
  const [clearing, setClearing] = useState(false)
  const [result, setResult] = useState<ClearResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Factory reset
  const [factoryResetting, setFactoryResetting] = useState(false)
  const [factoryResetConfirm, setFactoryResetConfirm] = useState('')

  // Precise clear
  const [preciseClearing, setPreciseClearing] = useState(false)
  const [preciseResult, setPreciseResult] = useState<string | null>(null)
  const [preciseError, setPreciseError] = useState<string | null>(null)
  const [sessionOlderDays, setSessionOlderDays] = useState(30)

  const fetchDbSize = useCallback(async () => {
    try {
      const res = await apiFetch('/api/system/status')
      const data = await res.json()
      if (data.success && data.data) {
        setDbSize(data.data.database_size)
      }
    } catch {
      /* ignore */
    }
    // Load rotation settings
    try {
      const res = await apiFetch('/api/database/rotate-config')
      const data = await res.json()
      if (data.success && data.data) {
        setAutoRotateEnabled(data.data.enabled)
        setRotateThreshold(data.data.threshold_percent)
        setDiskUsagePercent(data.data.disk_usage_percent)
      }
    } catch {
      /* ignore */
    }
  }, [])

  useEffect(() => {
    fetchDbSize()
  }, [fetchDbSize])

  const updateRotateConfig = async (enabled: boolean, threshold: number) => {
    try {
      const res = await apiFetch('/api/database/rotate-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, threshold_percent: threshold }),
      })
      const data = await res.json()
      if (data.success && data.data) {
        setAutoRotateEnabled(data.data.enabled)
        setRotateThreshold(data.data.threshold_percent)
        setDiskUsagePercent(data.data.disk_usage_percent)
      }
    } catch {
      /* ignore */
    }
  }

  const handleClear = async (mode: ClearMode) => {
    setClearing(true)
    setResult(null)
    setError(null)

    try {
      const res = await apiFetch('/api/database/clear', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      })
      const data = await res.json()
      if (data.success && data.data) {
        setResult(data.data as ClearResult)
        fetchDbSize()
        // Notify other pages to refresh their statistics (Dashboard, etc.)
        window.dispatchEvent(new CustomEvent('vigilyx:stats-cleared'))
      } else {
        setError(data.error || '未知错误')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '请求失败')
    } finally {
      setClearing(false)
      setConfirmMode(null)
      setConfirmInput('')
    }
  }

  const handleFactoryReset = async () => {
    if (factoryResetConfirm !== 'RESET') return
    setFactoryResetting(true)
    setResult(null)
    setError(null)
    try {
      const res = await apiFetch('/api/database/factory-reset', { method: 'POST' })
      const data = await res.json()
      if (data.success && data.data) {
        setResult(data.data as ClearResult)
        // Re-login is required after reset
        setTimeout(() => {
          localStorage.clear()
          window.location.href = '/'
        }, 2000)
      } else {
        setError(data.error || '重置失败')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '请求失败')
    } finally {
      setFactoryResetting(false)
      setFactoryResetConfirm('')
    }
  }

  const handlePreciseClear = async (target: string, threatLevel?: string) => {
    const labels: Record<string, string> = {
      sessions: '邮件流量',
      'verdicts-high': '高危研判',
      'verdicts-medium': '中危研判',
      'verdicts-low': '低危研判',
      'verdicts-safe': '安全研判',
      'verdicts-all': '全部研判',
    }
    const label = labels[threatLevel ? `verdicts-${threatLevel}` : target] || target
    if (!confirm(`确定要删除${label}数据吗？此操作不可撤销。`)) return

    setPreciseClearing(true)
    setPreciseResult(null)
    setPreciseError(null)
    try {
      const body: Record<string, unknown> = { target }
      if (threatLevel) body.threat_level = threatLevel
      if (target === 'sessions') body.older_than_days = sessionOlderDays
      const res = await apiFetch('/api/database/precise-clear', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (data.success) {
        setPreciseResult(data.data?.details || '清理完成')
      } else {
        setPreciseError(data.error || '清理失败')
      }
    } catch (e: unknown) {
      setPreciseError(e instanceof Error ? e.message : '请求失败')
    } finally {
      setPreciseClearing(false)
    }
  }

  return (
    <>
    <div className="s-section-content">
      <div className="s-section-title-block">
        <div className="s-title-with-badge">
          <h2 className="s-section-title-row">
            <span className="s-section-icon database">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
            </span>
            数据库管理
          </h2>
          <span className="s-db-badge">{formatBytes(dbSize)}</span>
        </div>
        <p className="s-section-subtitle">清理和维护数据库，释放存储空间，保障系统运行效率</p>
      </div>

      {result && (
        <div className="s-alert success">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{result.message}（{result.mode} 模式，耗时 {result.elapsed_ms}ms）</span>
        </div>
      )}
      {error && (
        <div className="s-alert error">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          <span>{error}</span>
        </div>
      )}

      <div className="s-setting-group">
        <div className="s-setting-group-header">自动覆写 (数据轮转)</div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">当前磁盘使用率</span>
            <span className="s-setting-desc">数据库所在分区的磁盘占用百分比</span>
          </div>
          <div className="s-disk-bar">
            <div className="s-disk-bar-fill" style={{
              width: `${diskUsagePercent}%`,
              background: diskUsagePercent >= rotateThreshold
                ? 'var(--status-error)'
                : diskUsagePercent >= 70
                  ? 'var(--accent-yellow)'
                  : 'var(--status-healthy)'
            }} />
            <span className="s-disk-bar-label">{diskUsagePercent}%</span>
          </div>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">启用自动覆写</span>
            <span className="s-setting-desc">当磁盘使用率超过阈值时，自动删除最旧的 10% 数据来为新数据腾出空间</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={autoRotateEnabled} onChange={e => {
              setAutoRotateEnabled(e.target.checked)
              updateRotateConfig(e.target.checked, rotateThreshold)
            }} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">覆写触发阈值</span>
            <span className="s-setting-desc">磁盘使用率达到此值时触发自动删除旧数据（范围 50% ~ 99%）</span>
          </div>
          <div className="s-threshold-control">
            <input
              type="range"
              className="s-range"
              min={50}
              max={99}
              value={rotateThreshold}
              onChange={e => setRotateThreshold(Number(e.target.value))}
              onMouseUp={() => updateRotateConfig(autoRotateEnabled, rotateThreshold)}
              onTouchEnd={() => updateRotateConfig(autoRotateEnabled, rotateThreshold)}
            />
            <span className="s-threshold-value">{rotateThreshold}%</span>
          </div>
        </div>
      </div>

      <div className="s-section-divider-label">手动清理</div>

      <div className="s-db-cards">
        {CLEAR_MODES.map(mode => (
          <div key={mode.key} className={`s-db-card ${mode.key}`}>
            <div className="s-db-card-icon">{mode.icon}</div>
            <div className="s-db-card-body">
              <h3>{mode.label}</h3>
              <p className="s-db-card-desc">{mode.desc}</p>
              <p className="s-db-card-risk">{mode.risk}</p>
            </div>
            <button
              className="s-db-card-btn"
              onClick={() => {
                setConfirmMode(mode.key)
                setConfirmInput('')
                setResult(null)
                setError(null)
              }}
              disabled={clearing}
            >
              {clearing && confirmMode === mode.key ? '清理中...' : '执行'}
            </button>
          </div>
        ))}
      </div>

      <div className="s-section-divider-label">精准清理</div>

      {preciseResult && (
        <div className="s-alert success" style={{ marginBottom: 12 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{preciseResult}</span>
        </div>
      )}
      {preciseError && (
        <div className="s-alert error" style={{ marginBottom: 12 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          <span>{preciseError}</span>
        </div>
      )}

      <div className="s-setting-group">
        <div className="s-setting-group-header">邮件流量</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">清理邮件会话</span>
            <span className="s-setting-desc">删除指定天数前的邮件流量数据（设为 0 则清空全部）</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="number"
              min={0}
              max={365}
              value={sessionOlderDays}
              onChange={e => setSessionOlderDays(Number(e.target.value))}
              style={{ width: 60, padding: '4px 8px', borderRadius: 4, border: '1px solid var(--border-muted)', background: 'var(--bg-tertiary)', color: 'var(--text-primary)', textAlign: 'center' }}
            />
            <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>天前</span>
            <button
              className="s-btn-danger"
              onClick={() => handlePreciseClear('sessions')}
              disabled={preciseClearing}
              style={{ padding: '4px 12px', fontSize: 12, borderRadius: 4, background: 'var(--status-error)', color: '#fff', border: 'none', cursor: 'pointer', opacity: preciseClearing ? 0.5 : 1 }}
            >
              {preciseClearing ? '清理中...' : '清理'}
            </button>
          </div>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">安全研判</div>
        {[
          { level: 'high', label: '高危', color: '#f97316' },
          { level: 'medium', label: '中危', color: '#eab308' },
          { level: 'low', label: '低危', color: '#3b82f6' },
          { level: 'safe', label: '安全', color: '#22c55e' },
          { level: 'all', label: '全部研判', color: '#ef4444' },
        ].map(item => (
          <div className="s-setting-row" key={item.level}>
            <div className="s-setting-info">
              <span className="s-setting-label">
                <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: item.color, marginRight: 6 }} />
                清理{item.label}数据
              </span>
              <span className="s-setting-desc">
                {item.level === 'all' ? '删除所有安全研判记录' : `删除威胁等级为"${item.label}"的研判记录`}
              </span>
            </div>
            <button
              className="s-btn-danger"
              onClick={() => handlePreciseClear('verdicts', item.level)}
              disabled={preciseClearing}
              style={{ padding: '4px 12px', fontSize: 12, borderRadius: 4, background: item.level === 'all' ? '#ef4444' : item.color, color: '#fff', border: 'none', cursor: 'pointer', opacity: preciseClearing ? 0.5 : 1 }}
            >
              {preciseClearing ? '清理中...' : '清理'}
            </button>
          </div>
        ))}
      </div>

      {/* One-click system reset - danger zone */}
      <div style={{
        marginTop: 24, padding: 16, borderRadius: 10,
        border: '1px solid rgba(239,68,68,0.25)',
        background: 'rgba(239,68,68,0.03)',
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: '#ef4444', marginBottom: 6 }}>
          恢复出厂设置
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.6 }}>
          清空全部数据和配置，系统恢复到全新安装状态。此操作不可恢复。
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            value={factoryResetConfirm}
            onChange={e => setFactoryResetConfirm(e.target.value)}
            placeholder="输入 RESET 确认"
            style={{
              width: 160, padding: '6px 10px', borderRadius: 4, fontSize: 13,
              fontFamily: 'var(--font-mono)',
              border: '1px solid rgba(239,68,68,0.3)',
              background: 'var(--bg-tertiary)', color: 'var(--text-primary)',
              textAlign: 'center',
            }}
          />
          <button
            onClick={handleFactoryReset}
            disabled={factoryResetConfirm !== 'RESET' || factoryResetting}
            style={{
              padding: '6px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
              border: 'none',
              cursor: factoryResetConfirm === 'RESET' && !factoryResetting ? 'pointer' : 'not-allowed',
              background: factoryResetConfirm === 'RESET' ? '#ef4444' : 'var(--bg-tertiary)',
              color: factoryResetConfirm === 'RESET' ? '#fff' : 'var(--text-tertiary)',
              opacity: factoryResetting ? 0.5 : 1,
            }}
          >
            {factoryResetting ? '重置中...' : '恢复出厂设置'}
          </button>
        </div>
      </div>
    </div>

    {/* Confirmation Dialog */}
    {confirmMode && (
      <div className="s-overlay" onClick={() => setConfirmMode(null)}>
        <div className="s-dialog" onClick={e => e.stopPropagation()}>
          <div className="s-dialog-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <h3>确认清理数据库</h3>
          <p>
            即将以 <strong>{CLEAR_MODES.find(m => m.key === confirmMode)?.label}</strong> 模式清除所有数据，此操作不可撤销。
          </p>
          <p className="s-dialog-hint">
            请输入 <code>CLEAR</code> 确认操作：
          </p>
          <input
            type="text"
            className="s-dialog-input"
            value={confirmInput}
            onChange={e => setConfirmInput(e.target.value)}
            placeholder='输入 CLEAR'
            autoFocus
            onKeyDown={e => {
              if (e.key === 'Enter' && confirmInput === 'CLEAR') {
                handleClear(confirmMode)
              }
            }}
          />
          <div className="s-dialog-actions">
            <button className="s-btn-ghost" onClick={() => setConfirmMode(null)}>取消</button>
            <button
              className="s-btn-danger"
              disabled={confirmInput !== 'CLEAR' || clearing}
              onClick={() => handleClear(confirmMode)}
            >
              {clearing ? '清理中...' : '确认清理'}
            </button>
          </div>
        </div>
      </div>
    )}
    </>
  )
}
