import { useState, useEffect, useCallback } from 'react'
import { formatBytes } from '../../utils/format'
import { apiFetch } from '../../utils/api'
import { loadCachedUiPreferences, saveUiPreferencesPatch, syncUiPreferencesFromServer } from '../../utils/uiPreferences'

/** Live clock: refresh once per second. */
function LiveClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return <>{now.toLocaleString('zh-CN')}</>
}

export default function AboutSettings() {
  const cached = loadCachedUiPreferences()
  const [dbSize, setDbSize] = useState<number>(0)
  const [systemInfo, setSystemInfo] = useState<{
    api_version: string
    database_online: boolean
    redis_online: boolean
    sniffer_status: string
    server_time: string
  } | null>(null)

  // NTP
  const [ntpServers, setNtpServers] = useState(cached.about.ntp_servers)
  const [ntpInterval, setNtpInterval] = useState(cached.about.ntp_interval_minutes)
  const [ntpSaved, setNtpSaved] = useState(false)

  const saveNtpConfig = useCallback(() => {
    void saveUiPreferencesPatch({
      about: {
        ntp_servers: ntpServers,
        ntp_interval_minutes: ntpInterval,
      },
    })
      .then(() => {
        setNtpSaved(true)
        setTimeout(() => setNtpSaved(false), 3000)
      })
      .catch(() => {})
  }, [ntpServers, ntpInterval])

  // Fetch system info on mount
  useEffect(() => {
    (async () => {
      try {
        const prefs = await syncUiPreferencesFromServer()
        setNtpServers(prefs.about.ntp_servers)
        setNtpInterval(prefs.about.ntp_interval_minutes)

        const res = await apiFetch('/api/system/status')
        const data = await res.json()
        if (data.success && data.data) {
          setDbSize(data.data.database_size)
          setSystemInfo({
            api_version: data.data.api_version,
            database_online: data.data.database_online,
            redis_online: data.data.redis_online,
            sniffer_status: data.data.sniffer?.connection_status || 'unknown',
            server_time: data.data.server_time,
          })
        }
      } catch {
        /* ignore */
      }
    })()
  }, [])

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon about">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </span>
          关于系统
        </h2>
        <p className="s-section-subtitle">版本信息与系统运行状态</p>
      </div>

      <div className="s-about-hero">
        <div className="s-about-logo">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div className="s-about-name">Vigilyx</div>
        <div className="s-about-ver">v{systemInfo?.api_version || '0.9.0'}</div>
        <div className="s-about-tagline">邮件流量监控与威胁分析平台</div>
      </div>

      <div className="s-about-section-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        系统状态
      </div>
      <div className="s-about-grid">
        <div className="s-about-item">
          <span className="s-about-item-label">API 版本</span>
          <span className="s-about-item-value">{systemInfo?.api_version || '-'}</span>
        </div>
        <div className="s-about-item">
          <span className="s-about-item-label">数据库</span>
          <span className={`s-about-item-value ${systemInfo?.database_online ? 'ok' : 'err'}`}>
            <span className={`s-about-dot ${systemInfo?.database_online ? 'ok' : 'err'}`} />
            {systemInfo?.database_online ? '在线' : '离线'}
          </span>
        </div>
        <div className="s-about-item">
          <span className="s-about-item-label">Redis</span>
          <span className={`s-about-item-value ${systemInfo?.redis_online ? 'ok' : ''}`}>
            {systemInfo?.redis_online && <span className="s-about-dot ok" />}
            {systemInfo?.redis_online ? '已连接' : '未使用'}
          </span>
        </div>
        <div className="s-about-item">
          <span className="s-about-item-label">探针状态</span>
          <span className={`s-about-item-value ${systemInfo?.sniffer_status === 'connected' ? 'ok' : 'err'}`}>
            <span className={`s-about-dot ${systemInfo?.sniffer_status === 'connected' ? 'ok' : 'err'}`} />
            {systemInfo?.sniffer_status === 'connected' ? '运行中' : systemInfo?.sniffer_status || '-'}
          </span>
        </div>
        <div className="s-about-item">
          <span className="s-about-item-label">数据库大小</span>
          <span className="s-about-item-value">{formatBytes(dbSize)}</span>
        </div>
        <div className="s-about-item">
          <span className="s-about-item-label">服务器时间</span>
          <span className="s-about-item-value"><LiveClock /></span>
        </div>
      </div>

      <div className="s-about-section-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        NTP 时间同步
      </div>
      <div className="s-setting-group">
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">NTP 服务器</span>
            <span className="s-setting-desc">系统时间同步源，多个地址用逗号分隔</span>
          </div>
          <input
            className="s-input"
            style={{ width: 280, fontSize: 12 }}
            value={ntpServers}
            onChange={e => setNtpServers(e.target.value)}
            onBlur={saveNtpConfig}
            placeholder="ntp.aliyun.com, cn.ntp.org.cn"
          />
        </div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">同步间隔</span>
            <span className="s-setting-desc">自动校时周期（分钟）</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              className="s-input"
              type="number"
              style={{ width: 80, textAlign: 'center', fontSize: 12 }}
              value={ntpInterval}
              min={1}
              max={1440}
              onChange={e => setNtpInterval(Number(e.target.value))}
              onBlur={saveNtpConfig}
            />
            <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>分钟</span>
          </div>
        </div>
        {ntpSaved && (
          <div className="s-deploy-success" style={{ marginTop: 4 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            NTP 配置已保存
          </div>
        )}
      </div>

      <div className="s-about-section-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 18l6-6-6-6"/><path d="M8 6l-6 6 6 6"/></svg>
        技术架构
      </div>
      <div className="s-about-tech">
        <span className="s-about-tech-tag">Rust</span>
        <span className="s-about-tech-tag">React</span>
        <span className="s-about-tech-tag">TypeScript</span>
        <span className="s-about-tech-tag">PostgreSQL</span>
        <span className="s-about-tech-tag">mDeBERTa</span>
        <span className="s-about-tech-tag">HuggingFace</span>
      </div>

      <div className="s-about-footer">
        <span>Vigilyx &copy; 2026 &mdash; 邮件威胁检测与分析系统</span>
        <span className="s-about-footer-sub">Powered by Rust + AI</span>
      </div>
    </div>
  )
}
