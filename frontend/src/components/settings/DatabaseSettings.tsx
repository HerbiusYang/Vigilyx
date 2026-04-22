import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { formatBytes, syncServerClock } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'
import i18n from '../../i18n'

type ClearMode = 'safe' | 'quick'

interface ClearResult {
  message: string
  mode: string
  elapsed_ms: number
}

const CLEAR_CONFIRM_TOKEN = 'CLEAR'
const FACTORY_RESET_CONFIRM_TOKEN = 'RESET'

const getClearModes = (): { key: ClearMode; label: string; desc: string; risk: string; icon: JSX.Element }[] => [
  {
    key: 'safe',
    label: i18n.t('settings.database.modeSafe'),
    desc: i18n.t('settings.database.modeSafeDesc'),
    risk: i18n.t('settings.database.modeSafeRisk'),
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
  },
  {
    key: 'quick',
    label: i18n.t('settings.database.modeQuick'),
    desc: i18n.t('settings.database.modeQuickDesc'),
    risk: i18n.t('settings.database.modeQuickRisk'),
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
      </svg>
    ),
  },
]

export default function DatabaseSettings() {
  const { t } = useTranslation()
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
  const clearConfirmed = confirmInput.trim().toUpperCase() === CLEAR_CONFIRM_TOKEN
  const factoryResetConfirmed = factoryResetConfirm.trim().toUpperCase() === FACTORY_RESET_CONFIRM_TOKEN

  const getModeLabel = useCallback((mode: string) => {
    switch (mode) {
      case 'safe':
        return t('settings.database.modeSafe')
      case 'quick':
        return t('settings.database.modeQuick')
      case 'high_performance':
        return t('settings.database.modeHighPerf')
      default:
        return mode
    }
  }, [t])

  const fetchDbSize = useCallback(async () => {
    try {
      const res = await apiFetch('/api/system/status')
      const data = await res.json()
      if (data.success && data.data) {
        syncServerClock(data.data)
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
        window.dispatchEvent(new CustomEvent(EVENTS.STATS_CLEARED))
      } else {
        setError(data.error || t('settings.database.unknownError'))
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : t('settings.database.requestFailed'))
    } finally {
      setClearing(false)
      setConfirmMode(null)
      setConfirmInput('')
    }
  }

  const handleFactoryReset = async () => {
    if (!factoryResetConfirmed) return
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
        setError(data.error || t('settings.database.resetFailed'))
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : t('settings.database.requestFailed'))
    } finally {
      setFactoryResetting(false)
      setFactoryResetConfirm('')
    }
  }

  const handlePreciseClear = async (target: string, threatLevel?: string) => {
    const labels: Record<string, string> = {
      sessions: t('settings.database.emailTraffic'),
      'verdicts-high': t('settings.database.highVerdict'),
      'verdicts-medium': t('settings.database.mediumVerdict'),
      'verdicts-low': t('settings.database.lowVerdict'),
      'verdicts-safe': t('settings.database.safeVerdict'),
      'verdicts-all': t('settings.database.allVerdicts'),
    }
    const label = labels[threatLevel ? `verdicts-${threatLevel}` : target] || target
    if (!confirm(t('settings.database.confirmDelete', { label }))) return

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
        setPreciseResult(data.data?.details || t('settings.database.clearComplete'))
      } else {
        setPreciseError(data.error || t('settings.database.clearFailed'))
      }
    } catch (e: unknown) {
      setPreciseError(e instanceof Error ? e.message : t('settings.database.requestFailed'))
    } finally {
      setPreciseClearing(false)
    }
  }

  const CLEAR_MODES = getClearModes()

  return (
    <>
    <div className="s-section-content">
      <div className="s-section-title-block">
        <div className="s-title-with-badge">
          <h2 className="s-section-title-row">
            <span className="s-section-icon database">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
            </span>
            {t('settings.database.title')}
          </h2>
          <span className="s-db-badge">{formatBytes(dbSize)}</span>
        </div>
        <p className="s-section-subtitle">{t('settings.database.subtitle')}</p>
      </div>

      {result && (
        <div className="s-alert success">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{t('settings.database.resultInfo', { mode: getModeLabel(result.mode), elapsed: result.elapsed_ms })}</span>
        </div>
      )}
      {error && (
        <div className="s-alert error">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          <span>{error}</span>
        </div>
      )}

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.database.autoRotation')}</div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.database.currentDiskUsage')}</span>
            <span className="s-setting-desc">{t('settings.database.currentDiskUsageDesc')}</span>
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
            <span className="s-setting-label">{t('settings.database.enableAutoRotation')}</span>
            <span className="s-setting-desc">{t('settings.database.enableAutoRotationDesc')}</span>
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
            <span className="s-setting-label">{t('settings.database.rotationThreshold')}</span>
            <span className="s-setting-desc">{t('settings.database.rotationThresholdDesc')}</span>
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

      <div className="s-section-divider-label">{t('settings.database.manualClear')}</div>

      <div className="s-alert warning">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>{t('settings.database.manualClearNote')}</span>
      </div>

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
              {clearing && confirmMode === mode.key ? t('settings.database.clearing') : t('settings.database.execute')}
            </button>
          </div>
        ))}
      </div>

      <div className="s-section-divider-label">{t('settings.database.preciseClear')}</div>

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
        <div className="s-setting-group-header">{t('settings.database.emailTraffic')}</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.database.clearSessions')}</span>
            <span className="s-setting-desc">{t('settings.database.clearSessionsDesc')}</span>
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
            <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{t('settings.database.daysAgo', { days: sessionOlderDays })}</span>
            <button
              className="s-btn-danger"
              onClick={() => handlePreciseClear('sessions')}
              disabled={preciseClearing}
              style={{ padding: '4px 12px', fontSize: 12, borderRadius: 4, background: 'var(--status-error)', color: '#fff', border: 'none', cursor: 'pointer', opacity: preciseClearing ? 0.5 : 1 }}
            >
              {preciseClearing ? t('settings.database.clearing') : t('settings.database.clear')}
            </button>
          </div>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.database.securityVerdicts')}</div>
        {[
          { level: 'high', label: t('settings.database.high'), color: '#f97316' },
          { level: 'medium', label: t('settings.database.medium'), color: '#eab308' },
          { level: 'low', label: t('settings.database.low'), color: '#3b82f6' },
          { level: 'safe', label: t('settings.database.safe'), color: '#22c55e' },
          { level: 'all', label: t('settings.database.allVerdicts'), color: '#ef4444' },
        ].map(item => (
          <div className="s-setting-row" key={item.level}>
            <div className="s-setting-info">
              <span className="s-setting-label">
                <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: item.color, marginRight: 6 }} />
                {t('settings.database.clearLabel', { label: item.label })}
              </span>
              <span className="s-setting-desc">
                {item.level === 'all' ? t('settings.database.deleteAllVerdicts') : t('settings.database.deleteVerdictLevel', { label: item.label })}
              </span>
            </div>
            <button
              className="s-btn-danger"
              onClick={() => handlePreciseClear('verdicts', item.level)}
              disabled={preciseClearing}
              style={{ padding: '4px 12px', fontSize: 12, borderRadius: 4, background: item.level === 'all' ? '#ef4444' : item.color, color: '#fff', border: 'none', cursor: 'pointer', opacity: preciseClearing ? 0.5 : 1 }}
            >
              {preciseClearing ? t('settings.database.clearing') : t('settings.database.clear')}
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
          {t('settings.database.factoryReset')}
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.6 }}>
          {t('settings.database.factoryResetDesc')}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            value={factoryResetConfirm}
            onChange={e => setFactoryResetConfirm(e.target.value)}
            placeholder={t('settings.database.factoryResetPlaceholder')}
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
            disabled={!factoryResetConfirmed || factoryResetting}
            style={{
              padding: '6px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
              border: 'none',
              cursor: factoryResetConfirmed && !factoryResetting ? 'pointer' : 'not-allowed',
              background: factoryResetConfirmed ? '#ef4444' : 'var(--bg-tertiary)',
              color: factoryResetConfirmed ? '#fff' : 'var(--text-tertiary)',
              opacity: factoryResetting ? 0.5 : 1,
            }}
          >
            {factoryResetting ? t('settings.database.resetting') : t('settings.database.factoryReset')}
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
          <h3>{t('settings.database.confirmClearTitle')}</h3>
          <p>
            {t('settings.database.confirmClearDesc', { mode: CLEAR_MODES.find(m => m.key === confirmMode)?.label })}
          </p>
          <p className="s-dialog-hint">
            {t('settings.database.confirmClearHint')}
          </p>
          <input
            type="text"
            className="s-dialog-input"
            value={confirmInput}
            onChange={e => setConfirmInput(e.target.value)}
            placeholder={t('settings.database.confirmClearPlaceholder')}
            autoFocus
            onKeyDown={e => {
              if (e.key === 'Enter' && clearConfirmed) {
                handleClear(confirmMode)
              }
            }}
          />
          <div className="s-dialog-actions">
            <button className="s-btn-ghost" onClick={() => setConfirmMode(null)}>{t('settings.database.cancel')}</button>
            <button
              className="s-btn-danger"
              disabled={!clearConfirmed || clearing}
              onClick={() => handleClear(confirmMode)}
            >
              {clearing ? t('settings.database.clearing') : t('settings.database.confirmClear')}
            </button>
          </div>
        </div>
      </div>
    )}
    </>
  )
}
