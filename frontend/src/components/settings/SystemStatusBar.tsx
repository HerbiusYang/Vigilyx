import React, { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { formatBytes, formatClockTime, syncServerClock } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { EVENTS } from '../../utils/events'

interface SnifferStatus {
  online: boolean
  connection_status: string
  remote_address: string | null
  capture_mode: string
  last_error: string | null
  retry_count: number
  last_update: string
  packets_processed: number
  bytes_processed: number
}

interface MtaStatus {
  online: boolean
  downstream_host: string
  downstream_port: number
  active_connections: number
  last_update: string
}

interface SystemStatusData {
  api_online: boolean
  api_version: string
  database_online: boolean
  database_size: number
  redis_online: boolean
  sniffer: SnifferStatus
  mta: MtaStatus
  server_time: string
  server_timezone?: string
  server_utc_offset_minutes?: number
}

function SystemStatusBar() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<SystemStatusData | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [deployMode, setDeployMode] = useState(() => localStorage.getItem('vigilyx-deploy-mode') || 'mirror')
  const dropdownRef = useRef<HTMLDivElement>(null)
  const prevJson = useRef('')

  // Listen for deployment-mode changes
  useEffect(() => {
    const handler = (e: Event) => {
      const mode = (e as CustomEvent).detail
      if (mode === 'mirror' || mode === 'mta') setDeployMode(mode)
    }
    window.addEventListener(EVENTS.DEPLOY_MODE_CHANGED, handler)
    return () => window.removeEventListener(EVENTS.DEPLOY_MODE_CHANGED, handler)
  }, [])

  const fetchStatus = async () => {
    try {
      const res = await apiFetch('/api/system/status')
      const data = await res.json()
      if (data.success) {
        syncServerClock(data.data)
        const json = JSON.stringify(data.data)
        if (json !== prevJson.current) {
          prevJson.current = json
          setStatus(data.data)
        }
      }
    } catch (err) {
      // Fail silently
    }
  }

  useEffect(() => {
    fetchStatus()
    // 30s interval; skip when the page is hidden
    const interval = setInterval(() => {
      if (!document.hidden) fetchStatus()
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  // Close the dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setExpanded(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const getSnifferStatusColor = () => {
    if (!status) return '#6b7280'
    switch (status.sniffer.connection_status) {
      case 'connected': return '#22c55e'
      case 'connecting': return '#f59e0b'
      case 'error': return '#ef4444'
      default: return '#6b7280'
    }
  }

  const getSnifferStatusText = () => {
    if (!status) return t('settings.statusBar.loading')
    switch (status.sniffer.connection_status) {
      case 'connected': return t('settings.statusBar.running')
      case 'connecting': return t('settings.statusBar.connecting')
      case 'error': return t('settings.statusBar.error')
      default: return t('settings.statusBar.offline')
    }
  }

  const getOverallStatus = () => {
    if (!status) return { color: '#6b7280', text: t('settings.statusBar.detecting') }
    // Determine data-plane service state from the deployment mode
    const dataPlaneOk = deployMode === 'mta'
      ? status.mta?.online
      : status.sniffer.connection_status === 'connected'
    const dataPlaneError = deployMode === 'mta'
      ? (status.mta && !status.mta.online)
      : status.sniffer.connection_status === 'error'

    const allOk = status.api_online && status.database_online && dataPlaneOk
    const hasError = dataPlaneError || !status.database_online

    if (allOk) return { color: '#22c55e', text: t('settings.statusBar.normal') }
    if (hasError) return { color: '#ef4444', text: t('settings.statusBar.abnormal') }
    return { color: '#f59e0b', text: t('settings.statusBar.partial') }
  }

  const overall = getOverallStatus()

  return (
    <div className="system-status-bar" ref={dropdownRef}>
      <button
        className="status-bar-trigger"
        onClick={() => setExpanded(!expanded)}
        title={`${t('settings.statusBar.systemStatusColon')} ${overall.text}`}
      >
        <span className="status-indicator" style={{ backgroundColor: overall.color, boxShadow: `0 0 6px ${overall.color}55` }}></span>
        <span className="status-text">{overall.text}</span>
        <svg className={`status-chevron ${expanded ? 'status-chevron--open' : ''}`} width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>

      {expanded && status && (
        <div className="status-dropdown">
          <div className="dropdown-header">
            <span>{t('settings.statusBar.systemMonitor')}</span>
            <span className="update-time">
              {formatClockTime(status.server_time)}
            </span>
          </div>

          <div className="status-grid">
            {/* API status */}
            <div className="status-item">
              <div className="item-header">
                <span className="item-dot" style={{ backgroundColor: status.api_online ? '#22c55e' : '#ef4444' }}></span>
                <span className="item-name">{t('settings.statusBar.apiService')}</span>
              </div>
              <div className="item-detail">
                <span>{status.api_online ? t('settings.statusBar.running') : t('settings.statusBar.offline')}</span>
                <span className="version">v{status.api_version}</span>
              </div>
            </div>

            {/* Database status */}
            <div className="status-item">
              <div className="item-header">
                <span className="item-dot" style={{ backgroundColor: status.database_online ? '#22c55e' : '#ef4444' }}></span>
                <span className="item-name">{t('settings.statusBar.database')}</span>
              </div>
              <div className="item-detail">
                <span>{status.database_online ? t('settings.statusBar.normal') : t('settings.statusBar.abnormal')}</span>
                <span className="size">{formatBytes(status.database_size)}</span>
              </div>
            </div>

            {/* Data-plane service: show Sniffer or MTA based on deployment mode */}
            {deployMode === 'mta' ? (
              <div className="status-item">
                <div className="item-header">
                  <span className="item-dot" style={{ backgroundColor: status.mta?.online ? '#22c55e' : '#6b7280' }}></span>
                  <span className="item-name">{t('settings.statusBar.mtaGateway')}</span>
                </div>
                <div className="item-detail">
                  <span>{status.mta?.online ? t('settings.statusBar.running') : t('settings.statusBar.offline')}</span>
                  {status.mta?.online && <span className="mode">{status.mta.downstream_host}:{status.mta.downstream_port}</span>}
                </div>
                {status.mta?.online && status.mta.active_connections > 0 && (
                  <div className="item-stats">
                    <span>{status.mta.active_connections} {t('settings.statusBar.activeConnections')}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="status-item sniffer">
                <div className="item-header">
                  <span className="item-dot" style={{ backgroundColor: getSnifferStatusColor() }}></span>
                  <span className="item-name">{t('settings.statusBar.sniffer')}</span>
                </div>
                <div className="item-detail">
                  <span>{getSnifferStatusText()}</span>
                  <span className="mode">{status.sniffer.capture_mode || t('settings.statusBar.unknown')}</span>
                </div>
                {status.sniffer.connection_status === 'connected' && (
                  <div className="item-stats">
                    <span>{status.sniffer.packets_processed.toLocaleString()} {t('settings.statusBar.packets')}</span>
                    <span>{formatBytes(status.sniffer.bytes_processed)}</span>
                  </div>
                )}
                {status.sniffer.last_error && (
                  <div className="item-error">
                    {status.sniffer.last_error}
                  </div>
                )}
              </div>
            )}

            {/* Redis status */}
            <div className="status-item">
              <div className="item-header">
                <span className="item-dot" style={{ backgroundColor: status.redis_online ? '#22c55e' : '#6b7280' }}></span>
                <span className="item-name">Redis</span>
              </div>
              <div className="item-detail">
                <span>{status.redis_online ? t('settings.statusBar.connected') : t('settings.statusBar.unused')}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default React.memo(SystemStatusBar)
